"""
Email Breach Discovery Service

Checks whether an email address (or domain's email addresses) has appeared in
known data breach dumps using the XposedOrNot public API.

XposedOrNot (https://xposedornot.com): per-email lookups are free and keyless.
The domain-wide lookup needs an API key for a domain verified with XposedOrNot
(set XPOSEDORNOT_API_KEY); without one it is skipped.

This is intentionally different from git/code secret scanning (TruffleHog). This
service answers the question: "Has this company's email address appeared in breach
dumps circulating on the dark web?" — a direct credential-exposure risk signal.

Usage:
    service = EmailBreachService()
    result = await service.check_email("user@target.com")
    domain_result = await service.check_domain_breach_exposure("target.com")
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import httpx

logger = logging.getLogger(__name__)

# breach-analytics returns per-breach dates, data classes and password risk;
# check-email only returns a nested list of breach names.
_XON_EMAIL_URL = "https://api.xposedornot.com/v1/breach-analytics"
_XON_DOMAIN_URL = "https://api.xposedornot.com/v1/domain-breaches/"
_TIMEOUT = 15.0


@dataclass
class BreachRecord:
    """A single breach entry from XposedOrNot."""
    name: str
    date: Optional[str] = None
    records_exposed: Optional[int] = None
    data_classes: list[str] = field(default_factory=list)
    description: Optional[str] = None
    is_sensitive: bool = False
    is_verified: bool = True
    # plaintextpassword | easytocrack | hardtocrack | unknown
    password_risk: Optional[str] = None


@dataclass
class EmailBreachResult:
    """Result of an email breach lookup."""
    email: str
    success: bool = False
    error: Optional[str] = None

    # Core verdict
    breached: bool = False
    breach_count: int = 0
    breaches: list[BreachRecord] = field(default_factory=list)

    # Aggregated data types exposed across all breaches
    data_classes_exposed: list[str] = field(default_factory=list)

    # Metadata
    checked_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        return {
            "email": self.email,
            "success": self.success,
            "error": self.error,
            "breached": self.breached,
            "breach_count": self.breach_count,
            "data_classes_exposed": self.data_classes_exposed,
            "breaches": [
                {
                    "name": b.name,
                    "date": b.date,
                    "records_exposed": b.records_exposed,
                    "data_classes": b.data_classes,
                    "description": b.description,
                    "is_sensitive": b.is_sensitive,
                    "is_verified": b.is_verified,
                    "password_risk": b.password_risk,
                }
                for b in self.breaches
            ],
            "checked_at": self.checked_at,
        }


@dataclass
class DomainBreachResult:
    """Aggregated breach exposure for a domain."""
    domain: str
    success: bool = False
    error: Optional[str] = None

    total_breached_accounts: int = 0
    unique_breaches: list[str] = field(default_factory=list)
    data_classes_exposed: list[str] = field(default_factory=list)
    checked_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "success": self.success,
            "error": self.error,
            "total_breached_accounts": self.total_breached_accounts,
            "unique_breaches": self.unique_breaches,
            "data_classes_exposed": self.data_classes_exposed,
            "checked_at": self.checked_at,
        }


def _xon_api_key() -> Optional[str]:
    from app.core.config import settings

    return settings.XPOSEDORNOT_API_KEY or None


def _flatten_names(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [name for item in value for name in _flatten_names(item)]
    return []


def parse_breach_analytics(data: dict) -> list[BreachRecord]:
    """Parse ``/v1/breach-analytics`` (or the older ``check-email``) responses."""
    data = data or {}
    exposed = data.get("ExposedBreaches") or {}
    details = exposed.get("breaches_details") if isinstance(exposed, dict) else None
    records: list[BreachRecord] = []
    if isinstance(details, list):
        for b in details:
            if not isinstance(b, dict):
                continue
            dc = b.get("xposed_data") or ""
            if isinstance(dc, str):
                dc = [x.strip() for x in dc.split(";") if x.strip()]
            records.append(BreachRecord(
                name=b.get("breach") or b.get("name") or "Unknown",
                date=str(b.get("xposed_date")) if b.get("xposed_date") else None,
                records_exposed=b.get("xposed_records"),
                data_classes=list(dc),
                description=b.get("details"),
                is_verified=str(b.get("verified", "Yes")).lower() in {"yes", "true"},
                password_risk=b.get("password_risk"),
            ))
        return records
    # check-email shape: {"breaches": [["Name", "Name", ...]]}
    return [BreachRecord(name=n) for n in _flatten_names(data.get("breaches"))]


class EmailBreachService:
    """
    Email breach discovery via XposedOrNot.

    Rate limits: XposedOrNot is lenient for reasonable usage but has no
    official published rate limit. Batch operations include a small delay.
    """

    def __init__(self) -> None:
        self._cache: dict[str, EmailBreachResult] = {}

    async def check_email(self, email: str) -> EmailBreachResult:
        """
        Check if an email address appears in known breach dumps.

        Returns a result with the list of breaches and data types exposed.
        A 404 from XposedOrNot means the email was NOT found in any breach.
        """
        email = email.strip().lower()

        if email in self._cache:
            return self._cache[email]

        result = EmailBreachResult(email=email)

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(_XON_EMAIL_URL, params={"email": email})

            if resp.status_code == 404:
                # Not found in any breach — clean result
                result.success = True
                result.breached = False
                self._cache[email] = result
                return result

            if resp.status_code != 200:
                result.error = f"XposedOrNot returned HTTP {resp.status_code}"
                return result

            breach_records = parse_breach_analytics(resp.json())
            all_data_classes: set[str] = set()
            for record in breach_records:
                all_data_classes.update(record.data_classes)

            result.success = True
            result.breached = len(breach_records) > 0
            result.breach_count = len(breach_records)
            result.breaches = breach_records
            result.data_classes_exposed = sorted(all_data_classes)

            self._cache[email] = result

        except httpx.TimeoutException:
            result.error = "XposedOrNot request timed out"
        except Exception as exc:
            result.error = str(exc)
            logger.warning("EmailBreachService.check_email(%s) failed: %s", email, exc)

        return result

    async def check_domain_breach_exposure(self, domain: str) -> DomainBreachResult:
        """
        Get aggregate breach exposure for an entire domain.

        Returns total breached account count + unique breach names + data types.
        Useful at the org level: "How many @target.com addresses are in breach dumps?"
        """
        domain = domain.strip().lower().lstrip("@")
        result = DomainBreachResult(domain=domain)

        api_key = _xon_api_key()
        if not api_key:
            result.error = (
                "Skipped: XposedOrNot domain search needs XPOSEDORNOT_API_KEY "
                "for a domain verified with XposedOrNot."
            )
            return result

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(
                    _XON_DOMAIN_URL,
                    headers={"x-api-key": api_key},
                    json={"domain": domain},
                )

            if resp.status_code == 404:
                result.success = True
                result.total_breached_accounts = 0
                return result

            if resp.status_code != 200:
                result.error = f"XposedOrNot returned HTTP {resp.status_code}"
                return result

            data = resp.json()
            metrics = data.get("BreachMetrics") or data.get("metrics") or {}

            result.success = True
            result.total_breached_accounts = (
                metrics.get("total") or metrics.get("count") or 0
            )
            result.unique_breaches = [
                b if isinstance(b, str) else b.get("name", "")
                for b in (data.get("breaches") or [])
            ]
            dc_raw = metrics.get("xposed_data") or metrics.get("data_classes") or []
            if isinstance(dc_raw, str):
                dc_raw = [x.strip() for x in dc_raw.split(";") if x.strip()]
            result.data_classes_exposed = dc_raw

        except httpx.TimeoutException:
            result.error = "XposedOrNot domain request timed out"
        except Exception as exc:
            result.error = str(exc)
            logger.warning(
                "EmailBreachService.check_domain(%s) failed: %s", domain, exc
            )

        return result

    async def batch_check_emails(
        self, emails: list[str], max_concurrent: int = 5
    ) -> dict[str, EmailBreachResult]:
        """Check multiple emails concurrently with a small throttle."""
        sem = asyncio.Semaphore(max_concurrent)

        async def _check(email: str) -> tuple[str, EmailBreachResult]:
            async with sem:
                await asyncio.sleep(0.2)
                return email, await self.check_email(email)

        pairs = await asyncio.gather(*[_check(e) for e in emails], return_exceptions=True)
        return {
            email: res
            for email, res in pairs
            if not isinstance(res, BaseException) and isinstance(res, tuple)
        }  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_service: Optional[EmailBreachService] = None


def get_email_breach_service() -> EmailBreachService:
    global _service
    if _service is None:
        _service = EmailBreachService()
    return _service
