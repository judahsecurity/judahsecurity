"""Unauth OpenAPI account lookup (CWE-204 / CWE-200 / CWE-862).

Schema and status differences are discovery leads; execution-backed impact
is required before confirmation. One canary email. Do not invent
a 200 UserAccount body. ACAO ``*`` is extra, not cors_credentials.
"""

from __future__ import annotations

import re
from app.services.agent.proof_policy import PROOF_GUIDANCE
from typing import Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

CANARY_EMAIL = "aegis-enum-canary@example.invalid"

ACCOUNT_PATH_RE = re.compile(r"(?i)/(?:api/)?auth/account/?$")
URL_RE = re.compile(r"https?://[^\s\"'<>]+")

_FINDING_HINTS = (
    "/api/auth/account",
    "account lookup",
    "user enumeration",
    "user account statistics",
    "account statistics without",
    "cwe-204",
    "cwe 204",
    "unauth_account_lookup",
)

WRITEUP_RULES = PROOF_GUIDANCE + "\nAccount lookup: schema hints and 401-vs-404/500 are candidates only. Use controlled test accounts; do not spray real user emails. Do not infer role bytes or Critical severity."

REVIEW_RULES = PROOF_GUIDANCE + "\nAccount lookup: schema hints and 401-vs-404/500 are candidates only. Use controlled test accounts; do not spray real user emails. Do not infer role bytes or Critical severity."

VERIFIER_ADDENDUM = f"Use the controlled canary {CANARY_EMAIL}. A single response is not an existence oracle. " + PROOF_GUIDANCE + "\nAccount lookup: schema hints and 401-vs-404/500 are candidates only. Use controlled test accounts; do not spray real user emails. Do not infer role bytes or Critical severity."

HUNTER_RULES = PROOF_GUIDANCE + "\nAccount lookup: schema hints and 401-vs-404/500 are candidates only. Use controlled test accounts; do not spray real user emails. Do not infer role bytes or Critical severity."


def is_account_lookup_path(url: str) -> bool:
    if not url:
        return False
    path = urlparse(url).path.rstrip("/") + "/"
    return bool(ACCOUNT_PATH_RE.search(path) or re.search(r"(?i)/auth/account/?", path))


def lookup_email(url: str) -> Optional[str]:
    if not url:
        return None
    qs = parse_qs(urlparse(url).query, keep_blank_values=True)
    for key, values in qs.items():
        if key.lower() == "email" and values:
            return str(values[0] or "").strip()
    return None


def spray_violation(url: str) -> Optional[str]:
    """Error if this is an account-lookup email probe that is not the canary."""
    if not is_account_lookup_path(url):
        return None
    email = lookup_email(url)
    if not email:
        return None
    if email.lower() == CANARY_EMAIL.lower():
        return None
    return (
        f"Blocked: /api/auth/account/ email spray. Use only {CANARY_EMAIL} "
        f"(got {email}). One canary; do not spray employee inboxes or probe admin@."
    )


def rewrite_lookup_url(url: str) -> Tuple[str, Optional[str]]:
    """Force the canary email on account-lookup URLs. Returns (url, note)."""
    violation = spray_violation(url)
    if not violation:
        return url, None
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    original = lookup_email(url) or ""
    qs["email"] = [CANARY_EMAIL]
    new_query = urlencode(qs, doseq=True)
    new_url = urlunparse(parsed._replace(query=new_query))
    note = f"rewrote email={original} → {CANARY_EMAIL} (one canary; do not spray)"
    return new_url, note


def spray_violation_in_text(text: str) -> Optional[str]:
    for match in URL_RE.findall(text or ""):
        msg = spray_violation(match)
        if msg:
            return msg
    return None


def rewrite_cli_args(args: str) -> Tuple[str, Optional[str]]:
    notes = []

    def _sub(match: re.Match[str]) -> str:
        new, note = rewrite_lookup_url(match.group(0))
        if note:
            notes.append(note)
        return new

    out = URL_RE.sub(_sub, args or "")
    return out, ("; ".join(notes) if notes else None)


def is_account_lookup_finding(text: str) -> bool:
    blob = (text or "").lower()
    return any(h in blob for h in _FINDING_HINTS)


def has_account_lookup_proof(text: str) -> bool:
    """Narrative/schema matching cannot establish a live account lookup proof.

    Confirmation uses execution artifacts and proof_policy instead.
    """
    return False


def allows_critical_ra(text: str) -> bool:
    """Account-lookup keywords do not override the standard impact assessment."""
    return False


def inferred_role_payload(text: str) -> bool:
    """True when the writeup claims a 200 UserAccount body it did not quote."""
    blob = (text or "").lower()
    if not is_account_lookup_finding(blob):
        return False
    claims_payload = any(
        phrase in blob
        for phrase in (
            "full useraccount",
            "full user account",
            "registered email returns http 200",
            "returns http 200 with the full",
            "200 with the full useraccount",
            "when db is available, it returns",
        )
    )
    has_body = any(
        token in blob
        for token in (
            '"is_staff"',
            '"role"',
            "is_staff: true",
            "is_staff: false",
            "'is_staff'",
            "role\": \"admin",
            "role\": \"viewer",
            "role\": \"maintainer",
        )
    )
    return claims_payload and not has_body
