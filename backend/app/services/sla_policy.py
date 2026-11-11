"""SLA policy: remediation window by tier (urgent → info) and exposure.

The table lives in per-organization settings (``sla_policy`` module) so the
security team can retune it without code changes. Defaults are the proposed
remediation windows:

    tier       internet-accessible   non-internet-accessible
    urgent           2 days               10 days
    critical        14 days               30 days
    high            30 days               60 days
    medium          60 days               90 days
    low             90 days              180 days
    info             none                 none
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from app.models.project_settings import (
    MODULE_SLA_POLICY,
    ProjectSettings,
    default_sla_policy_config,
)

TIERS = ("urgent", "critical", "high", "medium", "low", "info")
EXPOSURES = ("internet_accessible", "non_internet_accessible")
_RISK_LEVEL_TO_TIER = {"informational": "info", "info": "info"}


class PolicyError(ValueError):
    """Raised for an invalid SLA policy update."""


def load_policy(db, organization_id: int) -> Dict[str, Any]:
    """The org's policy, with every missing key filled from the defaults."""
    defaults = default_sla_policy_config()
    stored = ProjectSettings.get_config(db, organization_id, MODULE_SLA_POLICY) or {}
    return merge_policy(defaults, stored)


def merge_policy(base: Dict[str, Any], update: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    for key, value in (update or {}).items():
        if key in EXPOSURES and isinstance(value, dict):
            merged[key] = {**(base.get(key) or {}), **value}
        else:
            merged[key] = value
    return merged


def validate_policy(policy: Dict[str, Any]) -> Dict[str, Any]:
    """Check an update before storing it; returns the normalized policy."""
    out = dict(policy)
    for exposure in EXPOSURES:
        table = out.get(exposure) or {}
        if not isinstance(table, dict):
            raise PolicyError(f"{exposure} must map tier → days")
        clean = {}
        for tier, days in table.items():
            if tier not in TIERS:
                raise PolicyError(f"Unknown tier {tier!r}; expected one of {', '.join(TIERS)}")
            if days is not None and (not isinstance(days, int) or isinstance(days, bool) or not 0 < days <= 3650):
                raise PolicyError(f"{exposure}.{tier} must be a whole number of days (1-3650) or null")
            clean[tier] = days
        out[exposure] = clean
    if out.get("tier_source") not in ("severity", "risk_level"):
        raise PolicyError("tier_source must be 'severity' or 'risk_level'")
    if out.get("default_exposure") not in EXPOSURES:
        raise PolicyError(f"default_exposure must be one of {', '.join(EXPOSURES)}")
    if out.get("clock_starts") not in ("triage", "detected"):
        raise PolicyError("clock_starts must be 'triage' or 'detected'")
    thresholds = out.get("reminder_thresholds") or []
    if not isinstance(thresholds, list) or not all(
        isinstance(t, (int, float)) and not isinstance(t, bool) and 0 < t < 1 for t in thresholds
    ):
        raise PolicyError("reminder_thresholds must be fractions between 0 and 1, e.g. [0.5, 0.9]")
    out["reminder_thresholds"] = sorted(set(float(t) for t in thresholds))
    return out


def is_known_exploited(vuln: Any) -> bool:
    """True when the stored evidence says the CVE is in a KEV list."""
    meta = vuln.metadata_ or {}
    if meta.get("kev") is True or meta.get("in_kev") is True or meta.get("known_exploited") is True:
        return True
    if any(str(t).lower() in ("kev", "cisa_kev", "known_exploited") for t in (vuln.tags or [])):
        return True
    awareness = (((meta.get("severity_eval") or {}).get("factors") or {}).get("awareness") or {})
    return "KEV" in str(awareness.get("reason") or "")


def default_tier(vuln: Any, policy: Dict[str, Any]) -> str:
    """Tier the policy proposes for a finding before analyst overrides."""
    tier = None
    if policy.get("tier_source") == "risk_level" and getattr(vuln, "sev_level", None):
        level = str(vuln.sev_level).lower()
        tier = _RISK_LEVEL_TO_TIER.get(level, level)
    if tier not in TIERS:
        severity = getattr(vuln.severity, "value", vuln.severity)
        tier = str(severity or "info").lower()
    if tier not in TIERS:
        tier = "info"
    if tier == "critical" and policy.get("urgent_if_kev_critical") and is_known_exploited(vuln):
        tier = "urgent"
    return tier


def default_internet_accessible(vuln: Any, policy: Dict[str, Any]) -> bool:
    asset = getattr(vuln, "asset", None)
    is_public = getattr(asset, "is_public", None) if asset is not None else None
    if is_public is not None:
        return bool(is_public)
    return policy.get("default_exposure", "internet_accessible") == "internet_accessible"


@dataclass
class SlaResult:
    tier: str
    internet_accessible: bool
    days: Optional[int]
    started_at: datetime
    due_at: Optional[datetime]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "tier": self.tier,
            "internet_accessible": self.internet_accessible,
            "exposure": "internet_accessible" if self.internet_accessible else "non_internet_accessible",
            "days": self.days,
            "started_at": self.started_at.isoformat(),
            "due_at": self.due_at.isoformat() if self.due_at else None,
        }


def compute_sla(
    vuln: Any,
    policy: Dict[str, Any],
    *,
    tier: Optional[str] = None,
    internet_accessible: Optional[bool] = None,
    now: Optional[datetime] = None,
) -> SlaResult:
    """Remediation window for a finding; explicit tier/exposure win over defaults."""
    tier = tier or default_tier(vuln, policy)
    if tier not in TIERS:
        raise PolicyError(f"Unknown tier {tier!r}")
    if internet_accessible is None:
        internet_accessible = default_internet_accessible(vuln, policy)
    exposure = "internet_accessible" if internet_accessible else "non_internet_accessible"
    days = (policy.get(exposure) or {}).get(tier)
    now = now or datetime.utcnow()
    if policy.get("clock_starts") == "detected" and getattr(vuln, "first_detected", None):
        started = vuln.first_detected
    else:
        started = now
    due = started + timedelta(days=int(days)) if days else None
    return SlaResult(tier=tier, internet_accessible=bool(internet_accessible),
                     days=int(days) if days else None, started_at=started, due_at=due)
