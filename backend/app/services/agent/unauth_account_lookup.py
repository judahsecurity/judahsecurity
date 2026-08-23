"""Unauth OpenAPI account lookup (CWE-204 / CWE-200 / CWE-862).

Gold bar: schema ``security: {}`` plus ``is_staff``/``role``, and/or sibling
401 vs lookup 200 / 404 / 500. File Critical. One canary email. Do not invent
a 200 UserAccount body. ACAO ``*`` is extra, not cors_credentials.
"""

from __future__ import annotations

import re
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

WRITEUP_RULES = (
    "Unauth OpenAPI account lookup (CWE-204 / CWE-200 / CWE-862): GET "
    "/api/auth/account/?email= documented with security: {} ('without "
    "authentication') returning email, is_active, valid_through, is_staff, role. "
    "Schema-unauth + privilege fields is SUBMIT Critical. Unauth lookup that is "
    "200, 404 ('User does not exist!'), or 500 while /api/auth/profile/ and "
    "/users/me/ are 401 also SUBMIT — a down database is not an auth rejection; "
    "404 is an existence oracle, not a kill. One canary email "
    f"({CANARY_EMAIL}); do not spray employee inboxes; do not dump ICS users. "
    "Do not claim a 200 UserAccount payload (is_staff/role bytes) unless that "
    "body is in demonstrated_chain stdout — schema + 401-vs-404/500 is enough. "
    "Detection step claims must match tool stdout. ACAO * is extra, not the "
    "CORS-credentials finding. File Critical (not Open High). Kill only if the "
    "lookup 401/403 like siblings, the schema requires JWT, or the body is a "
    "non-enumerating boolean. Remediation: require JWT; if a pre-login check is "
    "needed, boolean is_active only + rate limit; do not confirm account existence."
)

REVIEW_RULES = (
    "Unauth /api/auth/account/ (Ask Marcus): keep Demonstrated. Raise High→Critical "
    "when schema security: {} quotes is_staff/role OR sibling 401 vs lookup "
    "200/404/500 is in the packet. Do not drop because the 200 UserAccount body "
    "was not captured. Do not treat 404 'User does not exist!' as a kill — that "
    "is the existence oracle. Do not mix ACAO * into cors_credentials (ACAC is "
    "absent). why_not_higher: no RCE, no ATO, no sprayed ICS users, no inferred "
    "role bytes. Retest bar: unauth lookup returns 401 like /api/auth/profile/. "
    "Do not re-query live emails; do not spray."
)

VERIFIER_ADDENDUM = (
    "This is an unauth account-lookup candidate. Re-derive ONLY:\n"
    "1) GET /api/schema/ (or swagger) and quote security: {} / 'without "
    "authentication' plus UserAccount is_staff/role/valid_through if present.\n"
    "2) compare_requests unauth GET /api/auth/profile/ (expect 401) vs GET "
    f"/api/auth/account/?email={CANARY_EMAIL} (use_auth_session=false).\n"
    "confirmed if lookup is 200 with those fields, OR 404 'User does not exist!' "
    "/ existence oracle, OR 500/OperationalError — while the sibling is 401. "
    "A down database is confirmed, not refuted. An unregistered canary is "
    "confirmed, not refuted. refuted only if the lookup 401/403s like siblings "
    "or the schema requires JWT and the body is a non-enumerating boolean.\n"
    f"Use ONLY {CANARY_EMAIL}. Do not spray admin@ / employee inboxes. Do not "
    "hunt a registered email to capture is_staff/role. Do not claim a 200 "
    "UserAccount payload unless YOUR stdout contains those bytes. ACAO * is extra."
)

HUNTER_RULES = (
    "Unauth account/email lookup: hunt schema security: {} on /api/auth/account/ "
    "(or similar). Quote UserAccount fields is_staff/role/valid_through. "
    "compare_requests unauth GET /api/auth/profile/ (401) vs "
    f"/api/auth/account/?email={CANARY_EMAIL} (200 with those fields OR 404 "
    "existence oracle OR 500). One canary only — do not spray employee inboxes; "
    "do not dump ICS users. 404/500 vs sibling 401 is SUBMIT Critical. Do not "
    "claim a 200 role body unless stdout has it. ACAO * is extra. "
    "queue_finding_followups(vuln_type='unauth_account_lookup'). Kill only lookup "
    "401/403 or JWT-required generic boolean."
)


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
    blob = (text or "").lower()
    schema_proof = any(
        token in blob
        for token in (
            "security: {}",
            "security:{}",
            "without authentication",
            "is_staff",
            "valid_through",
        )
    )
    jwt_skip = "401" in blob and any(
        token in blob
        for token in (
            "500",
            "404",
            "200",
            "user does not exist",
            "operationalerror",
            "bypasses jwt",
            "bypasses the jwt",
            "jwt authentication middleware",
            "vs 401",
            "versus 401",
            "401 vs",
        )
    )
    return schema_proof or jwt_skip


def allows_critical_ra(text: str) -> bool:
    """Schema-unauth + privilege fields, or sibling 401 vs 200/404/500, is Critical."""
    if not is_account_lookup_finding(text):
        return False
    return has_account_lookup_proof(text)


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
