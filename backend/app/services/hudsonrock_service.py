"""Hudson Rock (Cavalier) community infostealer API client.

Keyless endpoints:
  - search-by-domain: how many employees and customers of a domain had a
    machine infected by an infostealer, and which of the domain's login URLs
    their stolen credentials were saved for.
  - search-by-email: infections tied to one address (date and counts; the
    passwords and logins it returns are already masked by Hudson Rock).

Nothing identifying the infected machine (computer name, IP, malware path) is
kept: it is personal data the platform does not need to prioritize a leak.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

import httpx

logger = logging.getLogger(__name__)

_BASE = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"
_TIMEOUT = 30.0

AUDIENCE_EMPLOYEE = "employee"
AUDIENCE_USER = "user"


class HudsonRockError(Exception):
    pass


def _parse_dt(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


@dataclass
class StealerUrl:
    url: str
    host: Optional[str]
    audience: str
    occurrence: int


@dataclass
class DomainStealerResult:
    domain: str
    total: int = 0
    employees: int = 0
    users: int = 0
    third_parties: int = 0
    last_employee_compromised: Optional[datetime] = None
    last_user_compromised: Optional[datetime] = None
    stealer_families: Dict[str, int] = field(default_factory=dict)
    employee_password_strength: Dict[str, Any] = field(default_factory=dict)
    urls: List[StealerUrl] = field(default_factory=list)

    def summary(self) -> Dict[str, Any]:
        top = sorted(self.urls, key=lambda u: -u.occurrence)
        return {
            "domain": self.domain,
            "total": self.total,
            "employees": self.employees,
            "users": self.users,
            "third_parties": self.third_parties,
            "last_employee_compromised": (
                self.last_employee_compromised.isoformat() if self.last_employee_compromised else None
            ),
            "last_user_compromised": (
                self.last_user_compromised.isoformat() if self.last_user_compromised else None
            ),
            "stealer_families": self.stealer_families,
            "employee_password_strength": self.employee_password_strength,
            "url_count": len(self.urls),
            "top_employee_urls": [
                {"url": u.url, "occurrence": u.occurrence}
                for u in top if u.audience == AUDIENCE_EMPLOYEE
            ][:10],
        }


@dataclass
class EmailInfection:
    date_compromised: Optional[datetime]
    corporate_services: int
    user_services: int


def _audience(raw: Any, default: str) -> str:
    text = str(raw or "").lower()
    if text.startswith("employee"):
        return AUDIENCE_EMPLOYEE
    if text.startswith("user") or text.startswith("client"):
        return AUDIENCE_USER
    return default


def parse_domain_response(domain: str, data: Dict[str, Any]) -> DomainStealerResult:
    data = data or {}
    result = DomainStealerResult(
        domain=domain,
        total=int(data.get("total") or 0),
        employees=int(data.get("employees") or 0),
        users=int(data.get("users") or 0),
        third_parties=int(data.get("third_parties") or 0),
        last_employee_compromised=_parse_dt(data.get("last_employee_compromised")),
        last_user_compromised=_parse_dt(data.get("last_user_compromised")),
    )
    families = data.get("stealerFamilies") or {}
    result.stealer_families = {
        k: int(v) for k, v in families.items() if k != "total" and isinstance(v, (int, float))
    }
    strength = data.get("employeePasswords") or {}
    result.employee_password_strength = {
        k: (v.get("perc") if isinstance(v, dict) else v)
        for k, v in strength.items()
    }

    urls = (data.get("data") or {})
    seen: set[tuple[str, str]] = set()
    for key, default in (("employees_urls", AUDIENCE_EMPLOYEE), ("clients_urls", AUDIENCE_USER)):
        for row in urls.get(key) or []:
            url = str(row.get("url") or "").strip()
            if not url or "*" in url:  # skip masked entries
                continue
            audience = _audience(row.get("type"), default)
            if (url, audience) in seen:
                continue
            seen.add((url, audience))
            try:
                host = (urlsplit(url).hostname or "").lower() or None
            except ValueError:
                host = None
            result.urls.append(StealerUrl(
                url=url[:2000], host=host, audience=audience,
                occurrence=int(row.get("occurrence") or 0),
            ))
    return result


def parse_email_response(data: Dict[str, Any]) -> List[EmailInfection]:
    infections = []
    for row in (data or {}).get("stealers") or []:
        if not isinstance(row, dict):
            continue
        infections.append(EmailInfection(
            date_compromised=_parse_dt(row.get("date_compromised")),
            corporate_services=int(row.get("total_corporate_services") or 0),
            user_services=int(row.get("total_user_services") or 0),
        ))
    return infections


class HudsonRockClient:
    def __init__(self, client: Optional[httpx.AsyncClient] = None, max_concurrent: int = 2):
        self._client = client
        self._sem = asyncio.Semaphore(max_concurrent)

    async def _get(self, path: str, params: Dict[str, str]) -> Dict[str, Any]:
        async with self._sem:
            owns = self._client is None
            client = self._client or httpx.AsyncClient(timeout=_TIMEOUT)
            try:
                resp = await client.get(f"{_BASE}/{path}", params=params)
            finally:
                if owns:
                    await client.aclose()
            await asyncio.sleep(0.3)
        if resp.status_code == 404:
            return {}
        if resp.status_code == 429:
            raise HudsonRockError("Hudson Rock rate limit reached (HTTP 429)")
        if resp.status_code != 200:
            raise HudsonRockError(f"Hudson Rock returned HTTP {resp.status_code}")
        return resp.json() or {}

    async def search_by_domain(self, domain: str) -> DomainStealerResult:
        domain = domain.strip().lower().lstrip("@")
        return parse_domain_response(domain, await self._get("search-by-domain", {"domain": domain}))

    async def search_by_email(self, email: str) -> List[EmailInfection]:
        return parse_email_response(await self._get("search-by-email", {"email": email.strip().lower()}))
