"""Auth middleware fails open when Authorization is absent (CWE-287 / CWE-306).

Two variants, both ``use_auth_session=false`` on the SAME path:

1. Middleware skip: no Authorization header returns 200/400 (controller ran)
   AND Authorization: Bearer aegis-invalid returns 401. 400 missing-params is
   a bypass — the middleware never ran.
2. Trusted identity header (CWE-290): no Authorization returns 401/403, but no
   Authorization plus a client-supplied identity header (X-User-Id,
   X-Forwarded-User, X-MS-CLIENT-PRINCIPAL-NAME, ...) set to a canary returns
   2xx. The server falls back to the header as the authenticated identity, so
   anyone can impersonate any user. Echo of the canary in the body is the
   strongest proof. Use the canary, never a real user's identity.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

INVALID_BEARER = "Bearer aegis-invalid"

# Fabricated identity for the spoof variant. Proves the header is trusted
# without reading a real user's data.
CANARY_IDENTITY = "aegis-spoof-canary@invalid.example"

# Headers apps (or their reverse proxies / platform auth) treat as an asserted
# identity. Trusting one from an external client is impersonation.
IDENTITY_HEADERS = (
    "x-user-id",
    "x-userid",
    "x-user",
    "x-user-email",
    "x-user-name",
    "x-email",
    "x-forwarded-user",
    "x-forwarded-email",
    "x-forwarded-preferred-username",
    "x-remote-user",
    "remote-user",
    "x-auth-user",
    "x-authenticated-user",
    "x-auth-request-user",
    "x-auth-request-email",
    "x-principal-id",
    "x-ms-client-principal-name",
    "x-ms-client-principal-id",
    "x-goog-authenticated-user-email",
    "x-amzn-oidc-identity",
)

_SKIP_HINTS = (
    "bypassauthorization",
    "bypass authorization",
    "missing authorization header",
    "no authorization header",
    "without an authorization header",
    "auth middleware",
    "middleware bypass",
    "auth_header_bypass",
    "aegis-invalid",
)

_IDENTITY_HINTS = (
    "identity header",
    "identity_header",
    "x-user-id",
    "x-forwarded-user",
    "x-remote-user",
    "x-ms-client-principal",
    "aegis-spoof-canary",
)

_FINDING_HINTS = _SKIP_HINTS + _IDENTITY_HINTS

WRITEUP_RULES = (
    "Auth middleware skip when Authorization is absent (CWE-287 / CWE-306): compare "
    f"no-header vs {INVALID_BEARER}. No-header 200/400 (controller ran) AND "
    "invalid-bearer 401 is SUBMIT High. 400 missing required params is a bypass — "
    "the middleware never ran. Do not dump. If missing header is 401/403, do not "
    "kill yet: resend with no Authorization plus an identity header (X-User-Id, "
    f"X-Forwarded-User, X-MS-CLIENT-PRINCIPAL-NAME) = {CANARY_IDENTITY}. "
    "No-header 401 AND identity-header 2xx (canary echoed) is SUBMIT High "
    "(CWE-290 impersonation). compare_requests use_auth_session=false. "
    "Remediation: disable ByPassAuthorization; fail closed when the header is "
    "missing; never trust client-supplied identity headers — validate a signed "
    "token and strip identity headers at the edge."
)

REVIEW_RULES = (
    "Auth-header bypass (Ask Leo): keep Demonstrated High. Do not drop because "
    "no-header is 400 — that is the controller running. Do not raise to Critical "
    "on 400 alone (no dump, no write). Identity-header spoof (no-header 401, "
    "X-User-Id canary 2xx) is also Demonstrated High; do not drop because the "
    "canary user has no data. Retest bar: missing Authorization returns 401 like "
    "invalid Bearer, with or without identity headers. Do not dump records."
)

VERIFIER_ADDENDUM = (
    "This is an auth-header-bypass candidate. Re-derive ONLY:\n"
    "1) compare_requests use_auth_session=false on the SAME path:\n"
    "   baseline: no Authorization header.\n"
    f"   mutant: Authorization: {INVALID_BEARER}.\n"
    "confirmed if no-header is 200 OR 400 (controller ran) AND invalid-bearer is "
    "401. 400 missing-params is confirmed, not refuted. refuted only if missing "
    "header is 401/403 like invalid Bearer AND step 2 also fails.\n"
    "2) Identity-header variant: baseline no Authorization (expect 401/403);\n"
    "   mutant: no Authorization + X-User-Id (or the claimed header): "
    f"{CANARY_IDENTITY}.\n"
    "confirmed if mutant is 2xx (canary echoed is strongest). Use the canary, "
    "never a real user's identity.\n"
    "Probe 2–4 mapped routes. Do not dump. Empty/canary body on writes."
)

HUNTER_RULES = (
    "Auth header bypass: compare_requests use_auth_session=false. Same URL: "
    f"no Authorization vs {INVALID_BEARER}. SUBMIT if no-header is 200/400 AND "
    "invalid-bearer is 401. 400 missing-params is a bypass. Probe 2–4 mapped "
    "routes. Do not dump. queue_finding_followups(vuln_type='auth_header_bypass')."
)


def _auth_value(headers: Optional[Dict[str, Any]]) -> str:
    if not isinstance(headers, dict):
        return ""
    for key, value in headers.items():
        if str(key).lower() == "authorization":
            return str(value or "").strip()
    return ""


def is_invalid_bearer(headers: Optional[Dict[str, Any]]) -> bool:
    value = _auth_value(headers).lower()
    return "aegis-invalid" in value or value == "bearer aegis-invalid"


def identity_header_names(headers: Optional[Dict[str, Any]]) -> List[str]:
    """Identity-assertion headers present with a non-empty value."""
    if not isinstance(headers, dict):
        return []
    return [
        str(k).lower()
        for k, v in headers.items()
        if str(k).lower() in IDENTITY_HEADERS and str(v or "").strip()
    ]


def _identity_value(headers: Optional[Dict[str, Any]]) -> str:
    if not isinstance(headers, dict):
        return ""
    for key, value in headers.items():
        if str(key).lower() in IDENTITY_HEADERS and str(value or "").strip():
            return str(value).strip()
    return ""


def is_identity_spoof_pair(
    baseline_headers: Optional[Dict[str, Any]],
    mutant_headers: Optional[Dict[str, Any]],
) -> bool:
    """Neither side sends Authorization; exactly one side adds an identity header."""
    if _auth_value(baseline_headers) or _auth_value(mutant_headers):
        return False
    b = bool(identity_header_names(baseline_headers))
    m = bool(identity_header_names(mutant_headers))
    return b != m


def is_auth_header_pair(
    baseline_headers: Optional[Dict[str, Any]],
    mutant_headers: Optional[Dict[str, Any]],
) -> bool:
    b, m = _auth_value(baseline_headers), _auth_value(mutant_headers)
    if (not b) and is_invalid_bearer(mutant_headers):
        return True
    if (not m) and is_invalid_bearer(baseline_headers):
        return True
    return False


def should_force_unauth_session(
    baseline_url: str,
    mutant_url: str,
    baseline_headers: Optional[Dict[str, Any]] = None,
    mutant_headers: Optional[Dict[str, Any]] = None,
) -> bool:
    return is_auth_header_pair(baseline_headers, mutant_headers) or is_identity_spoof_pair(
        baseline_headers, mutant_headers
    )


def is_auth_header_finding(text: str) -> bool:
    blob = (text or "").lower()
    return any(h in blob for h in _FINDING_HINTS)


def has_auth_header_proof(text: str) -> bool:
    blob = (text or "").lower()
    deny = "401" in blob or "403" in blob
    controller = (
        "400" in blob
        or "200" in blob
        or "201" in blob
        or "204" in blob
        or "controller ran" in blob
        or "missing params" in blob
        or "auth_header_skip" in blob
    )
    pair = (
        "aegis-invalid" in blob
        or "invalid bearer" in blob
        or "no-header" in blob
        or "no header" in blob
        or "no authorization" in blob
        or "identity header" in blob
        or "aegis-spoof-canary" in blob
        or any(h in blob for h in IDENTITY_HEADERS)
    )
    return deny and controller and pair


def caps_critical_as_high(text: str) -> bool:
    """Middleware skip on 200/400 alone stays High.

    Identity-header spoof is not capped here: impersonating a privileged user
    on production can be Critical and is judged on the demonstrated impact.
    """
    blob = (text or "").lower()
    if any(h in blob for h in _IDENTITY_HINTS):
        return False
    return any(h in blob for h in _SKIP_HINTS)


def annotate_compare_proof(
    *,
    baseline_headers: Optional[Dict[str, Any]],
    mutant_headers: Optional[Dict[str, Any]],
    baseline_status: int,
    mutant_status: int,
    baseline_body: str = "",
    mutant_body: str = "",
) -> Tuple[List[str], Optional[Dict[str, Any]], Optional[str]]:
    if is_identity_spoof_pair(baseline_headers, mutant_headers):
        if identity_header_names(mutant_headers):
            spoof_headers, spoof_status, spoof_body = mutant_headers, mutant_status, mutant_body
            plain_status = baseline_status
        else:
            spoof_headers, spoof_status, spoof_body = baseline_headers, baseline_status, baseline_body
            plain_status = mutant_status
        if plain_status in (401, 403) and 200 <= spoof_status < 300:
            names = identity_header_names(spoof_headers)
            value = _identity_value(spoof_headers)
            echoed = bool(value) and value.lower() in (spoof_body or "").lower()
            signals = ["identity_header_trusted"]
            if echoed:
                signals.append("identity_echoed")
            proof = {
                "lane": "auth_header_bypass",
                "variant": "identity_header_spoof",
                "demonstrated": True,
                "no_header_status": plain_status,
                "identity_header": names[0] if names else "",
                "identity_header_status": spoof_status,
                "identity_echoed": echoed,
                "canary_identity": value == CANARY_IDENTITY,
                "submit": (
                    f"High — no Authorization is {plain_status} but "
                    f"{names[0] if names else 'identity header'} alone is "
                    f"{spoof_status}{' and the asserted identity is echoed' if echoed else ''}"
                    " (server trusts a client-supplied identity)"
                ),
            }
            return signals, proof, "MUTANT_BYPASS_CANDIDATE"
        return [], None, None
    if not is_auth_header_pair(baseline_headers, mutant_headers):
        return [], None, None
    if is_invalid_bearer(mutant_headers) and not _auth_value(baseline_headers):
        no_header, bearer = baseline_status, mutant_status
    else:
        no_header, bearer = mutant_status, baseline_status
    if no_header in (200, 400) and bearer == 401:
        proof = {
            "lane": "auth_header_bypass",
            "demonstrated": True,
            "no_header_status": no_header,
            "invalid_bearer_status": bearer,
            "submit": (
                "High — no Authorization reached the controller "
                f"({no_header}) while {INVALID_BEARER} is 401"
            ),
        }
        return ["auth_header_skip"], proof, "MUTANT_BYPASS_CANDIDATE"
    return [], None, None
