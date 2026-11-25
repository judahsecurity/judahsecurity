"""Risk scoring for identities and leaked-credential exposures.

Pure functions: no database or network access, so the weights are easy to test
and to tune. Phase 1 scores from ServiceNow attributes (title, department,
groups, VIP, active). Entitlement data from SailPoint should outrank title
keywords once it exists, because titles are noisy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable, Optional

from app.models.identity import (
    CREDENTIAL_EMAIL_ONLY,
    CREDENTIAL_PASSWORD,
    CREDENTIAL_PASSWORD_HASH,
    CREDENTIAL_PASSWORD_PLAINTEXT,
    CREDENTIAL_SESSION_COOKIE,
    CREDENTIAL_TOKEN,
)


def _rx(words: Iterable[str]) -> re.Pattern[str]:
    return re.compile(r"\b(?:" + "|".join(words) + r")\b", re.IGNORECASE)


# Group names that indicate privileged access.
PRIVILEGED_GROUP_RX = _rx([
    r"domain admins?", r"enterprise admins?", r"schema admins?", r"global admins?",
    r"administrators?", r"admins?", r"root", r"sudoers?", r"privileged", r"pam",
    r"cyberark", r"break[- ]?glass", r"tier[- ]?0", r"security_admin", r"sys_?admin",
    r"aws[- _]?admin", r"azure[- _]?admin", r"gcp[- _]?admin",
])

EXECUTIVE_TITLE_RX = _rx([
    r"chief", r"ceo", r"cfo", r"cto", r"cio", r"ciso", r"coo", r"cro", r"president",
    r"vp", r"svp", r"evp", r"vice president", r"general counsel", r"board",
    r"director", r"head of",
])

SENSITIVE_FUNCTION_RX = _rx([
    r"finance", r"financial", r"treasury", r"payroll", r"accounts payable", r"ap",
    r"accounting", r"controller", r"human resources", r"hr", r"people ops",
    r"legal", r"help ?desk", r"service ?desk", r"it support", r"procurement",
])

TECHNICAL_TITLE_RX = _rx([
    r"admin", r"administrator", r"sysadmin", r"engineer", r"devops", r"sre",
    r"developer", r"architect", r"security", r"dba", r"database", r"network",
    r"cloud", r"infrastructure",
])

SERVICE_ACCOUNT_RX = re.compile(r"^(?:svc|sa|srv|service)[._-]|[._-](?:svc|service)$", re.I)


@dataclass(frozen=True)
class ScoreFactor:
    key: str
    points: int
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"key": self.key, "points": self.points, "detail": self.detail}


def privileged_groups(groups: Iterable[str]) -> list[str]:
    return [g for g in groups if g and PRIVILEGED_GROUP_RX.search(g)]


def score_identity(
    *,
    title: Optional[str],
    department: Optional[str],
    groups: Iterable[str],
    is_vip: bool,
    is_active: bool,
    username: Optional[str] = None,
    worker_type: Optional[str] = None,
) -> tuple[int, list[ScoreFactor], bool]:
    """Return (score 0-100, factors, is_privileged)."""
    factors: list[ScoreFactor] = []
    title = title or ""
    department = department or ""
    groups = list(groups or [])

    priv = privileged_groups(groups)
    if priv:
        factors.append(ScoreFactor(
            "privileged_group", 45, f"Member of privileged group(s): {', '.join(priv[:5])}"
        ))

    if EXECUTIVE_TITLE_RX.search(title):
        factors.append(ScoreFactor("executive_title", 25, f"Executive or senior title: {title}"))

    fn_match = SENSITIVE_FUNCTION_RX.search(title) or SENSITIVE_FUNCTION_RX.search(department)
    if fn_match:
        factors.append(ScoreFactor(
            "sensitive_function", 20, f"Sensitive business function: {fn_match.group(0)}"
        ))

    # Title keywords only count when there is no group evidence of privilege.
    if not priv and TECHNICAL_TITLE_RX.search(title):
        factors.append(ScoreFactor("technical_title", 15, f"Technical or admin title: {title}"))

    if is_vip:
        factors.append(ScoreFactor("vip", 15, "Flagged VIP in the identity source"))

    if (worker_type or "").lower() == "contractor":
        factors.append(ScoreFactor("contractor", 10, "Contractor or vendor account"))

    if username and SERVICE_ACCOUNT_RX.search(username):
        factors.append(ScoreFactor(
            "service_account", 20, "Looks like a service account (often exempt from MFA)"
        ))

    score = min(100, sum(f.points for f in factors))

    if not is_active:
        # A disabled source record lowers risk, but the downstream directory
        # account may still be live; Phase 3 checks that separately.
        score = score // 2
        factors.append(ScoreFactor(
            "inactive_in_source", 0, "Inactive in the identity source (score halved)"
        ))

    return score, factors, bool(priv)


CREDENTIAL_POINTS = {
    CREDENTIAL_SESSION_COOKIE: 40,
    CREDENTIAL_TOKEN: 40,
    CREDENTIAL_PASSWORD_PLAINTEXT: 35,
    CREDENTIAL_PASSWORD: 25,
    CREDENTIAL_PASSWORD_HASH: 20,
    CREDENTIAL_EMAIL_ONLY: 5,
}


def recency_points(leak_date: Optional[datetime], now: Optional[datetime] = None) -> tuple[int, str]:
    if leak_date is None:
        return 5, "Leak date unknown"
    now = now or datetime.utcnow()
    days = max(0, (now - leak_date).days)
    if days <= 30:
        return 30, f"Leaked {days} days ago"
    if days <= 180:
        return 20, f"Leaked {days} days ago"
    if days <= 365:
        return 12, f"Leaked {days} days ago"
    if days <= 3 * 365:
        return 6, f"Leaked about {days // 365} year(s) ago"
    return 0, f"Leaked about {days // 365} years ago"


def severity_for(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 35:
        return "medium"
    if score >= 15:
        return "low"
    return "info"


def score_exposure(
    *,
    credential_type: str,
    leak_date: Optional[datetime],
    identity_score: Optional[int],
    identity_privileged: bool = False,
    asset_matched: bool = False,
    now: Optional[datetime] = None,
) -> tuple[int, str, list[ScoreFactor]]:
    """Return (priority 0-100, severity, factors)."""
    factors: list[ScoreFactor] = []

    cred = CREDENTIAL_POINTS.get(credential_type, 5)
    factors.append(ScoreFactor("credential_type", cred, f"Credential type: {credential_type}"))

    rec, rec_detail = recency_points(leak_date, now)
    factors.append(ScoreFactor("recency", rec, rec_detail))

    if identity_score is None:
        factors.append(ScoreFactor(
            "identity_unmatched", 0, "No matching identity in the system of record"
        ))
    else:
        pts = round(identity_score * 0.35)
        factors.append(ScoreFactor("identity_risk", pts, f"Identity risk score {identity_score}/100"))
        if identity_privileged and credential_type != CREDENTIAL_EMAIL_ONLY:
            factors.append(ScoreFactor(
                "privileged_credential", 10, "Usable credential for a privileged identity"
            ))

    if asset_matched:
        factors.append(ScoreFactor(
            "asset_match", 10, "Credential was captured for one of the organization's assets"
        ))

    score = min(100, sum(f.points for f in factors))
    return score, severity_for(score), factors


# ── Infostealer login URLs ───────────────────────────────────────────────────

# Ordered: first match wins. Each entry is (category, points, host/path regex).
LOGIN_CATEGORIES: tuple[tuple[str, int, re.Pattern[str]], ...] = (
    ("mfa", 35, re.compile(r"mfa|2fa|otp|duo|authenticator|mfaportal", re.I)),
    ("sso", 35, re.compile(
        r"adfs|/saml|/oauth2?|/idp|^idp\.|^sso\.|^fs\.|okta|ping(one|fed|identity)|"
        r"login\.microsoftonline|/auth/realms|shibboleth|/cas/login", re.I)),
    ("remote_access", 35, re.compile(
        r"vpn|citrix|netscaler|/remote/|globalprotect|anyconnect|pulse|rdweb|"
        r"/rdp|^remote\.|^gateway\.|^portal\.|/owa|/ecp|horizon|workspace", re.I)),
    ("admin", 30, re.compile(r"admin|manage|console|cpanel|plesk|jenkins|grafana|kibana", re.I)),
    ("file_transfer", 25, re.compile(r"^s?ftps?://|^ftp\.|sharefile|filetransfer|moveit|sftp", re.I)),
    ("password_reset", 15, re.compile(r"reset[-_]?password|updatepassword|forgot|recover", re.I)),
    ("login", 15, re.compile(r"login|signin|sign-in|logon|/auth", re.I)),
)


def classify_login_url(url: str) -> tuple[str, int]:
    # Host-anchored patterns (^idp.) need the scheme stripped; ^ftp:// needs it kept.
    bare = url.split("://", 1)[-1]
    for category, points, pattern in LOGIN_CATEGORIES:
        if pattern.search(bare) or pattern.search(url):
            return category, points
    return "other", 5


def volume_points(occurrence: int) -> int:
    if occurrence >= 1000:
        return 15
    if occurrence >= 100:
        return 10
    if occurrence >= 10:
        return 6
    if occurrence >= 1:
        return 2
    return 0


def score_stealer_url(
    *,
    url: str,
    audience: str,
    occurrence: int,
    last_compromised: Optional[datetime],
    asset_matched: bool,
    now: Optional[datetime] = None,
) -> tuple[int, str, str, list[ScoreFactor]]:
    """Return (priority 0-100, severity, login category, factors)."""
    factors: list[ScoreFactor] = []
    category, cat_points = classify_login_url(url)
    factors.append(ScoreFactor("login_category", cat_points, f"Login type: {category}"))

    if audience == "employee":
        factors.append(ScoreFactor("employee_credentials", 20, "Credentials saved by employees"))
    else:
        factors.append(ScoreFactor("customer_credentials", 5, "Credentials saved by customers"))

    vol = volume_points(occurrence)
    factors.append(ScoreFactor("volume", vol, f"{occurrence} infected machine(s) saved this login"))

    rec, rec_detail = recency_points(last_compromised, now)
    rec = rec // 2  # domain-wide date, not specific to this URL
    factors.append(ScoreFactor("recency", rec, f"Latest infection for this audience: {rec_detail.lower()}"))

    if asset_matched:
        factors.append(ScoreFactor("asset_match", 10, "Host is in the organization's inventory"))

    score = min(100, sum(f.points for f in factors))
    return score, severity_for(score), category, factors
