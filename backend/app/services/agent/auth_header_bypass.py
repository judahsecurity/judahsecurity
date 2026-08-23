"""Auth middleware skipped when Authorization is absent (CWE-287 / CWE-306).

Gold bar: SAME path, no Authorization header returns 200/400 (controller ran)
AND Authorization: Bearer aegis-invalid returns 401. 400 missing-params is a
bypass — the middleware never ran. ``use_auth_session=false``.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

INVALID_BEARER = "Bearer aegis-invalid"

_FINDING_HINTS = (
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

WRITEUP_RULES = (
    "Auth middleware skip when Authorization is absent (CWE-287 / CWE-306): compare "
    f"no-header vs {INVALID_BEARER}. No-header 200/400 (controller ran) AND "
    "invalid-bearer 401 is SUBMIT High. 400 missing required params is a bypass — "
    "the middleware never ran. Do not dump. Kill only if missing header is 401/403. "
    "compare_requests use_auth_session=false. Remediation: disable "
    "ByPassAuthorization; fail closed when the header is missing."
)

REVIEW_RULES = (
    "Auth-header bypass (Ask Marcus): keep Demonstrated High. Do not drop because "
    "no-header is 400 — that is the controller running. Do not raise to Critical "
    "on 400 alone (no dump, no write). Retest bar: missing Authorization returns "
    "401 like invalid Bearer. Do not dump records."
)

VERIFIER_ADDENDUM = (
    "This is an auth-header-bypass candidate. Re-derive ONLY:\n"
    "1) compare_requests use_auth_session=false on the SAME path:\n"
    "   baseline: no Authorization header.\n"
    f"   mutant: Authorization: {INVALID_BEARER}.\n"
    "confirmed if no-header is 200 OR 400 (controller ran) AND invalid-bearer is "
    "401. 400 missing-params is confirmed, not refuted. refuted only if missing "
    "header is 401/403 like invalid Bearer.\n"
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
    return is_auth_header_pair(baseline_headers, mutant_headers)


def is_auth_header_finding(text: str) -> bool:
    blob = (text or "").lower()
    return any(h in blob for h in _FINDING_HINTS)


def has_auth_header_proof(text: str) -> bool:
    blob = (text or "").lower()
    deny = "401" in blob or "403" in blob
    controller = (
        "400" in blob
        or "200" in blob
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
    )
    return deny and controller and pair


def caps_critical_as_high(text: str) -> bool:
    return is_auth_header_finding(text)


def annotate_compare_proof(
    *,
    baseline_headers: Optional[Dict[str, Any]],
    mutant_headers: Optional[Dict[str, Any]],
    baseline_status: int,
    mutant_status: int,
) -> Tuple[List[str], Optional[Dict[str, Any]], Optional[str]]:
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
