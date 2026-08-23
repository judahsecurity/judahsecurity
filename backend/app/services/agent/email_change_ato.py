"""Unauth email-change ATO (djoser reset_email, CWE-306 / CWE-640).

Gold bar: unauth POST set_password 401 vs unauth POST reset_email 204/200
with the canary address. Confirm uid=MQ + garbage token enumerates users.
One canary. Do not complete ATO on a real mailbox. Do not spray.
``use_auth_session=false`` — crawl cookies hide the 401 sibling.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

CANARY_EMAIL = "aegis-ato-canary@example.invalid"
GARBAGE_TOKEN = "aegis-invalid-token"
CONFIRM_UID = "MQ"  # base64 of user id 1

RESET_EMAIL_RE = re.compile(r"(?i)/api/auth/users/reset_email/?$")
RESET_CONFIRM_RE = re.compile(r"(?i)/api/auth/users/reset_email_confirm/?$")
SET_PASSWORD_RE = re.compile(r"(?i)/api/auth/users/set_password/?$")
EMAIL_CHANGE_RE = re.compile(
    r"(?i)reset_email|reset_email_confirm|change_email|update_email|"
    r"/email/change|/users/set_email"
)
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_EMAIL_JSON_RE = re.compile(
    r'"(email|new_email)"\s*:\s*"([^"]+)"',
    re.I,
)

_FINDING_HINTS = (
    "reset_email",
    "reset-email",
    "email change",
    "change email",
    "email-change",
    "djoser",
    "reset_email_confirm",
    "email_change_ato",
)

WRITEUP_RULES = (
    "Unauth email-change ATO (djoser reset_email, CWE-306 / CWE-640): unauth POST "
    "/api/auth/users/reset_email/ 204 while set_password 401 is SUBMIT High. Confirm "
    f"with uid={CONFIRM_UID} (user 1) + garbage token enumerating 'Invalid token for "
    "given user' vs 'Invalid user id' is extra. One canary email "
    f"({CANARY_EMAIL}); do not complete ATO on a real mailbox; do not spray. "
    "OPTIONS 401 or schema jwtAuth is NOT a kill. compare_requests "
    "use_auth_session=false. Remediation: IsAuthenticated on both views; bind the "
    "change to the session user; consistent errors; rate limit."
)

REVIEW_RULES = (
    "Unauth reset_email (Ask Marcus): keep Demonstrated High. Do not raise to "
    "Critical unless a live mailbox takeover was demonstrated — and hunters must "
    "not complete ATO on production. Do not drop because OPTIONS is 401 or the "
    "schema claims jwtAuth. why_not_higher: no write/RCE, canary only, token not "
    "redeemed. Retest bar: unauth reset_email returns 401 like set_password. "
    "Do not re-POST a real new_email."
)

VERIFIER_ADDENDUM = (
    "This is an unauth email-change candidate. Re-derive ONLY:\n"
    "1) compare_requests use_auth_session=false: unauth POST "
    "/api/auth/users/set_password/ — expect 401.\n"
    f"2) unauth POST /api/auth/users/reset_email/ json={{\"email\":\"{CANARY_EMAIL}\"}} "
    "— expect 204/200.\n"
    f"3) Optional: unauth POST reset_email_confirm uid={CONFIRM_UID} "
    f"token={GARBAGE_TOKEN} new_email={CANARY_EMAIL}. 'Invalid token for given "
    "user' vs 'Invalid user id' enumerates. 2–4 uids max.\n"
    "confirmed if sibling is 401/403 AND reset_email is 200/204. OPTIONS 401 is "
    "not a refute. refuted only if reset_email 401/403s like set_password.\n"
    f"Use ONLY {CANARY_EMAIL}. Do not complete ATO on a real mailbox. Do not spray."
)

HUNTER_RULES = (
    "Unauth email-change (djoser reset_email): compare_requests "
    "use_auth_session=false. Baseline: unauth POST set_password (401). Mutant: "
    f"unauth POST reset_email email={CANARY_EMAIL} (204/200). That pair is SUBMIT "
    f"High. Confirm uid={CONFIRM_UID} + {GARBAGE_TOKEN} for user enum. One canary; "
    "do not complete ATO on a real mailbox; do not spray. OPTIONS 401 / schema "
    "jwtAuth is not a kill. queue_finding_followups(vuln_type='email_change_ato')."
)


def _path(url: str) -> str:
    if not url:
        return ""
    return urlparse(url).path or url


def is_reset_email_path(url: str) -> bool:
    return bool(RESET_EMAIL_RE.search(_path(url)))


def is_confirm_path(url: str) -> bool:
    return bool(RESET_CONFIRM_RE.search(_path(url)))


def is_set_password_path(url: str) -> bool:
    return bool(SET_PASSWORD_RE.search(_path(url)))


def is_email_change_path(url: str) -> bool:
    path = _path(url)
    return bool(
        RESET_EMAIL_RE.search(path)
        or RESET_CONFIRM_RE.search(path)
        or EMAIL_CHANGE_RE.search(path)
    )


def _has_authorization(headers: Optional[Dict[str, Any]]) -> bool:
    if not isinstance(headers, dict):
        return False
    for key, value in headers.items():
        if str(key).lower() == "authorization" and str(value or "").strip():
            return True
    return False


def should_force_unauth_session(
    baseline_url: str,
    mutant_url: str,
    baseline_headers: Optional[Dict[str, Any]] = None,
    mutant_headers: Optional[Dict[str, Any]] = None,
) -> bool:
    if not (
        is_email_change_path(baseline_url)
        or is_email_change_path(mutant_url)
        or is_set_password_path(baseline_url)
        or is_set_password_path(mutant_url)
    ):
        return False
    if _has_authorization(baseline_headers) or _has_authorization(mutant_headers):
        return False
    return True


def _rewrite_email_obj(data: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    notes: List[str] = []
    out = dict(data)
    for key in list(out.keys()):
        if str(key).lower() not in ("email", "new_email"):
            continue
        value = str(out[key] or "").strip()
        if value.lower() != CANARY_EMAIL.lower():
            notes.append(f"rewrote {key}={value!r} → {CANARY_EMAIL}")
            out[key] = CANARY_EMAIL
    if not any(str(k).lower() in ("email", "new_email") for k in out):
        out["email"] = CANARY_EMAIL
        notes.append(f"injected email={CANARY_EMAIL}")
    return out, notes


def sanitize_email_change_body(
    url: str,
    method: str,
    body: Optional[str],
) -> Tuple[Optional[str], Optional[str]]:
    if not is_email_change_path(url):
        return body, None
    if (method or "GET").upper() not in ("POST", "PUT", "PATCH"):
        return body, None

    notes: List[str] = []
    raw = (body or "").strip()
    if not raw:
        payload: Dict[str, Any] = {"email": CANARY_EMAIL}
        if is_confirm_path(url):
            payload = {
                "uid": CONFIRM_UID,
                "token": GARBAGE_TOKEN,
                "new_email": CANARY_EMAIL,
            }
        return json.dumps(payload, separators=(",", ":")), (
            f"injected canary body ({CANARY_EMAIL})"
        )

    try:
        data = json.loads(raw)
    except Exception:
        payload = {"email": CANARY_EMAIL}
        if is_confirm_path(url):
            payload = {
                "uid": CONFIRM_UID,
                "token": GARBAGE_TOKEN,
                "new_email": CANARY_EMAIL,
            }
        return json.dumps(payload, separators=(",", ":")), (
            "replaced non-JSON email-change body with canary"
        )

    if not isinstance(data, dict):
        return json.dumps({"email": CANARY_EMAIL}, separators=(",", ":")), (
            "replaced non-object email-change body with canary"
        )

    data, extra = _rewrite_email_obj(data)
    notes.extend(extra)
    if is_confirm_path(url):
        token = str(data.get("token") or data.get("Token") or "").strip()
        if token and token != GARBAGE_TOKEN and len(token) >= 16:
            data["token"] = GARBAGE_TOKEN
            notes.append("replaced live token with garbage (do not complete ATO)")
        if not data.get("uid") and not data.get("Uid"):
            data["uid"] = CONFIRM_UID
            notes.append(f"injected uid={CONFIRM_UID}")
        if "token" not in {str(k).lower() for k in data}:
            data["token"] = GARBAGE_TOKEN
            notes.append("injected garbage token")
    encoded = json.dumps(data, separators=(",", ":"))
    return encoded, ("; ".join(notes) if notes else None)


def sanitize_email_change(
    url: str,
    method: str,
    body: Optional[str],
    headers: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[str], Dict[str, Any], Optional[str]]:
    hdrs = {str(k): str(v) for k, v in dict(headers or {}).items()}
    new_body, note = sanitize_email_change_body(url, method, body)
    if new_body and new_body != (body or ""):
        if not any(k.lower() == "content-type" for k in hdrs):
            hdrs["Content-Type"] = "application/json"
    return new_body, hdrs, note


def spray_violation(url: str, body: Optional[str] = None) -> Optional[str]:
    blob = f"{url or ''} {body or ''}"
    if not is_email_change_path(url) and not EMAIL_CHANGE_RE.search(blob):
        return None
    for match in _EMAIL_JSON_RE.finditer(body or ""):
        email = match.group(2).strip()
        if email.lower() != CANARY_EMAIL.lower() and "@" in email:
            return (
                f"Blocked: email-change spray. Use only {CANARY_EMAIL} "
                f"(got {email}). Do not complete ATO on a real mailbox."
            )
    return None


def rewrite_cli_args(args: str) -> Tuple[str, Optional[str]]:
    notes: List[str] = []

    def _sub_url(match: re.Match[str]) -> str:
        return match.group(0)

    out = URL_RE.sub(_sub_url, args or "")

    def _sub_email(match: re.Match[str]) -> str:
        field, email = match.group(1), match.group(2)
        if email.lower() == CANARY_EMAIL.lower():
            return match.group(0)
        if not EMAIL_CHANGE_RE.search(out) and "reset_email" not in out.lower():
            return match.group(0)
        notes.append(f"rewrote {field}={email} → {CANARY_EMAIL}")
        return f'"{field}": "{CANARY_EMAIL}"'

    if EMAIL_CHANGE_RE.search(out) or "reset_email" in out.lower():
        out = _EMAIL_JSON_RE.sub(_sub_email, out)
    return out, ("; ".join(notes) if notes else None)


def spray_violation_in_text(text: str) -> Optional[str]:
    blob = text or ""
    if not EMAIL_CHANGE_RE.search(blob) and "reset_email" not in blob.lower():
        return None
    for match in _EMAIL_JSON_RE.finditer(blob):
        email = match.group(2).strip()
        if email.lower() != CANARY_EMAIL.lower() and "@" in email:
            if email.endswith(".invalid"):
                continue
            return (
                f"Blocked: email-change spray. Use only {CANARY_EMAIL} "
                f"(got {email}). Do not complete ATO on a real mailbox."
            )
    return None


def is_email_change_finding(text: str) -> bool:
    blob = (text or "").lower()
    return any(h in blob for h in _FINDING_HINTS)


def has_email_change_proof(text: str) -> bool:
    blob = (text or "").lower()
    sibling_deny = "401" in blob or "403" in blob
    accepted = any(s in blob for s in ("204", "200", "email_change_unauth"))
    pair = "set_password" in blob or "sibling" in blob or "401" in blob
    canary = CANARY_EMAIL.lower() in blob or "aegis-ato-canary" in blob
    enum = "invalid token for given user" in blob or "uid=mq" in blob or "uid=mq" in blob.replace(" ", "")
    return (sibling_deny and accepted and (pair or canary)) or (
        enum and sibling_deny
    )


def caps_critical_as_high(text: str) -> bool:
    """ATO not completed on a real mailbox → High, not Critical."""
    if not is_email_change_finding(text):
        return False
    blob = (text or "").lower()
    completed = any(
        t in blob
        for t in (
            "mailbox takeover",
            "confirmed new_email",
            "session as victim",
            "logged in as",
        )
    )
    return not completed


def annotate_compare_proof(
    *,
    baseline_url: str,
    mutant_url: str,
    baseline_status: int,
    mutant_status: int,
    mutant_body: str = "",
) -> Tuple[List[str], Optional[Dict[str, Any]], Optional[str]]:
    reset = is_reset_email_path(mutant_url) or is_email_change_path(mutant_url)
    sibling = is_set_password_path(baseline_url) or is_set_password_path(mutant_url)
    if not (reset or sibling):
        return [], None, None
    deny, accept = baseline_status, mutant_status
    if is_reset_email_path(baseline_url) and is_set_password_path(mutant_url):
        deny, accept = mutant_status, baseline_status
    if deny in (401, 403) and accept in (200, 204):
        proof = {
            "lane": "email_change_ato",
            "demonstrated": True,
            "baseline_status": baseline_status,
            "mutant_status": mutant_status,
            "canary": CANARY_EMAIL,
            "submit": (
                "High — unauth reset_email accepted while set_password 401. "
                "One canary; do not complete ATO."
            ),
        }
        return ["email_change_unauth"], proof, "MUTANT_BYPASS_CANDIDATE"
    if "invalid token for given user" in (mutant_body or "").lower():
        return ["email_change_uid_enum"], {
            "lane": "email_change_ato",
            "demonstrated": True,
            "submit": "High — confirm located a user without a session",
        }, "MUTANT_BYPASS_CANDIDATE"
    return [], None, None
