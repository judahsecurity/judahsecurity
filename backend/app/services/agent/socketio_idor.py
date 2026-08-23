"""Unauth Socket.IO get_stream IDOR (CWE-639 / CWE-306).

Gold bar: anonymous Engine.IO polling + 42["get_stream", fabricated siteId]
returns url_key. Do not fetch the video stream. Do not send null crash loops
against ICS. Video-not-downloaded is NOT a kill.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

FABRICATED_SITE = "site_AEGIS_PROOF"
FABRICATED_EVENT = {
    "siteId": FABRICATED_SITE,
    "userId": "ATTACKER_NO_CREDENTIALS",
    "userType": "Anonymous",
}

SOCKETIO_RE = re.compile(r"(?i)socket\.io|/socket\.io/|get_stream|url_key")
NULL_CRASH_RE = re.compile(
    r'(?i)42\s*\[\s*"get_stream"\s*,\s*null\s*\]'
    r'|\[\s*"get_stream"\s*,\s*null\s*\]'
    r'|get_stream["\']?\s*,\s*null',
)
URL_KEY_RE = re.compile(r'(?i)["\']?url_key["\']?\s*[:=]\s*["\']?(/?[0-9A-Za-z_-]+)')

_FINDING_HINTS = (
    "get_stream",
    "url_key",
    "socketio_idor",
    "socket.io idor",
    "camera stream",
)

WRITEUP_RULES = (
    "Socket.IO get_stream IDOR (CWE-639 / CWE-306): anonymous Engine.IO polling + "
    f'42["get_stream", {FABRICATED_EVENT}] returning url_key is SUBMIT High. Do not '
    "fetch the video stream. Do not send null/malformed crash loops against ICS. "
    "Video not downloaded is NOT a kill. CORS on /socket.io/ is the sibling "
    "cors_credentials card; hardcoded siteId/userType=Admin is js_secrets."
)

REVIEW_RULES = (
    "Socket.IO get_stream (Ask Marcus): keep Demonstrated High. Do not drop because "
    "video was not downloaded. Do not ask hunters to send null crash loops. Retest "
    "bar: anonymous get_stream 401/403 or no url_key. Do not re-fetch footage."
)

VERIFIER_ADDENDUM = (
    "This is a Socket.IO get_stream IDOR candidate. Re-derive ONLY:\n"
    "1) GET /socket.io/?EIO=3&transport=polling (sid).\n"
    f'2) POST 42["get_stream", {json.dumps(FABRICATED_EVENT, separators=(",", ":"))}].\n'
    "confirmed if a url_key / namespace is returned without a session.\n"
    "Do not GET the video stream. Do not send null or 42[\"get_stream\",null] — "
    "that crashes ICS Node processes. Unreachable video URL is not a refute.\n"
    "refuted only if get_stream 401/403s or no url_key."
)

HUNTER_RULES = (
    "Socket.IO get_stream IDOR: Engine.IO polling then fabricated siteId "
    f"({FABRICATED_SITE}). SUBMIT on url_key. Do not fetch video. Do not send "
    "null crash loops. queue_finding_followups(vuln_type='socketio_idor')."
)


def is_socketio_path(url: str) -> bool:
    if not url:
        return False
    blob = f"{url} {urlparse(url).path}"
    return bool(SOCKETIO_RE.search(blob))


def crash_violation(text: str) -> Optional[str]:
    if NULL_CRASH_RE.search(text or ""):
        return (
            "Blocked: Socket.IO null get_stream crashes the Node process (ICS "
            "availability). Send a fabricated siteId object instead of null. "
            f"Use {FABRICATED_SITE}."
        )
    return None


def rewrite_null_payload(text: str) -> Tuple[str, Optional[str]]:
    if not NULL_CRASH_RE.search(text or ""):
        return text or "", None
    payload = json.dumps(FABRICATED_EVENT, separators=(",", ":"))
    out = NULL_CRASH_RE.sub(f'42["get_stream",{payload}]', text or "", count=1)
    return out, f"rewrote null get_stream → fabricated {FABRICATED_SITE} (no crash loops)"


def is_socketio_finding(text: str) -> bool:
    blob = (text or "").lower()
    if "cors" in blob and "origin" in blob and "get_stream" not in blob:
        return False
    if any(h in blob for h in _FINDING_HINTS):
        return True
    return ("socket.io" in blob or "socketio" in blob) and any(
        t in blob for t in ("idor", "unauth", "siteid", "camera")
    )


def has_socketio_proof(text: str) -> bool:
    blob = (text or "").lower()
    return bool(
        URL_KEY_RE.search(text or "")
        or "url_key" in blob
        or "socketio_url_key" in blob
        or ("get_stream" in blob and "fabricated" in blob)
    )


def caps_critical_as_high(text: str) -> bool:
    return is_socketio_finding(text)


def annotate_compare_proof(
    *,
    baseline_url: str,
    mutant_url: str,
    mutant_body: str,
    baseline_body: str = "",
) -> Tuple[List[str], Optional[Dict[str, Any]], Optional[str]]:
    blob = f"{baseline_url} {mutant_url} {mutant_body} {baseline_body}"
    if not SOCKETIO_RE.search(blob):
        return [], None, None
    match = URL_KEY_RE.search(mutant_body or "") or URL_KEY_RE.search(baseline_body or "")
    if match:
        proof = {
            "lane": "socketio_idor",
            "demonstrated": True,
            "url_key": match.group(1),
            "submit": (
                "High — anonymous get_stream returned url_key for a fabricated "
                "siteId. Do not fetch video."
            ),
        }
        return ["socketio_url_key"], proof, "MUTANT_BYPASS_CANDIDATE"
    return [], None, None
