"""Unauthenticated ASP.NET / API settings write (CWE-306 / CWE-862).

Gold bar: sibling write 401 vs unauth POST SaveSettings 200 void
(Content-Length: 0). File High. One canary key. Do not replace production
settings or flip enableNotifications / createPlannerTasks / powerBIReportId.
GET GetSettings 500 is not a kill. Proof must run with
``use_auth_session=false``.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

CANARY_KEY = "aegis-verify-key"
CANARY_VALUE = "aegis-verify-ok"
CANARY_KEY_PREFIX = "aegis-verify-"

PRODUCTION_FLAGS = (
    "enableNotifications",
    "createPlannerTasks",
    "powerBIReportId",
)
_PRODUCTION_FLAG_LC = {f.lower(): f for f in PRODUCTION_FLAGS}

# Save*/Write*/Update* on a Settings controller — not GetSettings.
SETTINGS_WRITE_PATH_RE = re.compile(
    r"(?i)"
    r"(?:/api/[^/?#]*settings[^/?#]*/(?:save|write|update)[^/?#]*)"
    r"|(?:/(?:save|write|update)settings(?:/|$))"
    r"|(?:/api/settings/?$)"
)

URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_FLAG_VALUE_RE = re.compile(
    r'"(enableNotifications|createPlannerTasks|powerBIReportId)"\s*:\s*'
    r'(true|false|"[^"]*")',
    re.I,
)

_FINDING_HINTS = (
    "/api/settings/savesettings",
    "/api/settings",
    "savesettings",
    "save settings",
    "unauth_settings_write",
    "unauthenticated settings write",
    "application settings write",
    "doccentrumappsettings",
)

WRITEUP_RULES = (
    "Unauthenticated ASP.NET / API settings write (CWE-306 / CWE-862): paired "
    "proof is the finding. POST a sibling write that enforces auth (e.g. "
    "/api/TaskAdmin/UpdateTask) with no Authorization header — expect 401. Then "
    "POST /api/Settings/SaveSettings (or mapped Save*/Write* config endpoint) "
    "with no Authorization and a JSON body matching the settings schema. HTTP "
    "200 with Content-Length: 0 is the standard ASP.NET Core void-action "
    "success — the write was accepted. That 401-vs-200 differential is SUBMIT "
    f"(High). GET /GetSettings returning 500 / NullReferenceException is NOT a "
    f"kill (no read-back). One canary key only ({CANARY_KEY_PREFIX}<rand>); do "
    "not replace the full settings collection; do not flip production flags "
    "(enableNotifications, createPlannerTasks, powerBIReportId) unless already "
    "known. Do not claim persistence unless GetSettings round-trips the canary. "
    "Hosting on *.azurewebsites.net is App Service, not an Azure Function env "
    "dump. Remediation: [Authorize] on the controller (or a global "
    "FallbackPolicy so missing attributes deny) plus "
    '[Authorize(Roles="Admin")] on SaveSettings. Follow-up other controllers '
    "that process without 401 (LogQuery, Audit, ReadTasks, OpenDocument) as a "
    "sibling missing-auth card — empty-array 200s and Graph-downstream 500s "
    "are not this High write."
)

REVIEW_RULES = (
    "Unauth SaveSettings (Ask Marcus): keep Demonstrated High. Do not raise to "
    "Critical on void 200 alone — Critical needs GetSettings round-trip of the "
    "canary AND a demonstrated security-control change. Do not drop because "
    "GetSettings is 500 / NRE (no read-back). Do not mix *.azurewebsites.net "
    "App Service with an Azure Function env dump. why_not_higher: no proven "
    "persistence, no flag flip, no BFLA with a low-priv session. Retest bar: "
    "unauth POST SaveSettings returns 401 like UpdateTask. Do not re-POST a "
    "replacement settings collection; do not flip production flags."
)

VERIFIER_ADDENDUM = (
    "This is an unauth settings-write candidate. Re-derive ONLY:\n"
    "1) compare_requests with use_auth_session=false: unauth POST a sibling "
    "write that enforces auth (e.g. /api/TaskAdmin/UpdateTask) — expect 401.\n"
    "2) unauth POST /api/Settings/SaveSettings (or mapped Save*/Write*) with "
    f'json={{"settings":[{{"key":"{CANARY_KEY}","value":"{CANARY_VALUE}"}}]}}.\n'
    "confirmed if sibling is 401/403 AND SaveSettings is 200/204 with "
    "Content-Length: 0 (ASP.NET Core void success). GET GetSettings 500 / "
    "NullReferenceException is confirmed, not refuted — there is no read-back. "
    "refuted only if SaveSettings 401/403s like the sibling.\n"
    f"Use ONLY one {CANARY_KEY_PREFIX}* key. Do not send a replacement "
    "settings array. Do not set enableNotifications / createPlannerTasks / "
    "powerBIReportId to true/false. Do not claim the canary persisted unless "
    "YOUR GetSettings stdout contains those bytes."
)

HUNTER_RULES = (
    "Unauth ASP.NET / API settings write: compare_requests use_auth_session="
    "false. Baseline: unauth POST a 401 sibling write (TaskAdmin/UpdateTask). "
    f"Mutant: unauth POST SaveSettings with json settings key {CANARY_KEY}="
    f"{CANARY_VALUE}. 401 vs 200 Content-Length: 0 is SUBMIT High. GET "
    "GetSettings 500 is not a kill. One canary key — do not replace production "
    "settings; do not flip enableNotifications/createPlannerTasks/"
    "powerBIReportId. Crawl cookies hide the 401 sibling — never leave "
    "use_auth_session true. queue_finding_followups(vuln_type="
    "'unauth_settings_write'). Kill only SaveSettings 401/403 like siblings. "
    "*.azurewebsites.net is App Service, not a Function env dump."
)


def canary_body() -> Dict[str, Any]:
    return {"settings": [{"key": CANARY_KEY, "value": CANARY_VALUE}]}


def is_settings_write_path(url: str) -> bool:
    if not url:
        return False
    path = urlparse(url).path or url
    return bool(SETTINGS_WRITE_PATH_RE.search(path))


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
    """Cookie-less probes for missing-[Authorize] writes.

    A crawl session would turn the 401 sibling into 200 and hide the bug.
    Keep the session when a Bearer is already set (authenticated BFLA probe).
    """
    if not (is_settings_write_path(baseline_url) or is_settings_write_path(mutant_url)):
        return False
    if _has_authorization(baseline_headers) or _has_authorization(mutant_headers):
        return False
    return True


def _is_canary_key(key: Any) -> bool:
    return str(key or "").lower().startswith(CANARY_KEY_PREFIX)


def _null_production_flags(obj: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    notes: List[str] = []
    out = dict(obj)
    for key in list(out.keys()):
        canonical = _PRODUCTION_FLAG_LC.get(str(key).lower())
        if not canonical:
            continue
        value = out[key]
        if value is not None and value != "":
            out[key] = None
            notes.append(f"nulled {key}={value!r} (do not flip production flags)")
    return out, notes


def _sanitize_settings_items(items: List[Any]) -> Tuple[List[Dict[str, Any]], List[str]]:
    notes: List[str] = []
    kept: List[Dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        key = item.get("key", item.get("Key", ""))
        if not _is_canary_key(key):
            notes.append(f"dropped non-canary settings key {key!r}")
            continue
        value = item.get("value", item.get("Value", CANARY_VALUE))
        kept.append({"key": str(key), "value": value})
    if not kept:
        kept = [{"key": CANARY_KEY, "value": CANARY_VALUE}]
        notes.append(f"injected {CANARY_KEY} canary (one key only)")
    elif len(kept) > 1:
        kept = kept[:1]
        notes.append("kept one canary key only")
    return kept, notes


def sanitize_settings_body(
    url: str,
    method: str,
    body: Optional[str],
) -> Tuple[Optional[str], Optional[str]]:
    """Force a one-key canary body on settings-write POSTs. Returns (body, note)."""
    if not is_settings_write_path(url):
        return body, None
    if (method or "GET").upper() not in ("POST", "PUT", "PATCH"):
        return body, None

    notes: List[str] = []
    raw = (body or "").strip()
    if not raw:
        return json.dumps(canary_body(), separators=(",", ":")), (
            f"injected canary body ({CANARY_KEY})"
        )

    try:
        data = json.loads(raw)
    except Exception:
        return json.dumps(canary_body(), separators=(",", ":")), (
            "replaced non-JSON SaveSettings body with one canary key"
        )

    if isinstance(data, list):
        kept, extra = _sanitize_settings_items(data)
        notes.extend(extra)
        return json.dumps(kept, separators=(",", ":")), (
            "; ".join(notes) if notes else None
        )

    if not isinstance(data, dict):
        return json.dumps(canary_body(), separators=(",", ":")), (
            "replaced non-object SaveSettings body with one canary key"
        )

    data, extra = _null_production_flags(data)
    notes.extend(extra)

    settings_key = next(
        (k for k in data if str(k).lower() == "settings"),
        None,
    )
    if settings_key is not None and isinstance(data[settings_key], list):
        kept, extra = _sanitize_settings_items(data[settings_key])
        notes.extend(extra)
        data[settings_key] = kept
    else:
        key = data.get("key", data.get("Key"))
        if key is not None:
            if not _is_canary_key(key):
                data["key"] = CANARY_KEY
                data["value"] = CANARY_VALUE
                notes.append("rewrote single setting to canary")
        else:
            data["settings"] = canary_body()["settings"]
            notes.append("injected settings canary array")

    encoded = json.dumps(data, separators=(",", ":"))
    return encoded, ("; ".join(notes) if notes else None)


def sanitize_settings_write(
    url: str,
    method: str,
    body: Optional[str],
    headers: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[str], Dict[str, Any], Optional[str]]:
    hdrs = {str(k): str(v) for k, v in dict(headers or {}).items()}
    new_body, note = sanitize_settings_body(url, method, body)
    if new_body and new_body != (body or ""):
        if not any(k.lower() == "content-type" for k in hdrs):
            hdrs["Content-Type"] = "application/json"
    return new_body, hdrs, note


def destructive_settings_payload(text: str) -> bool:
    """True when a body still flips production flags or replaces the collection."""
    blob = text or ""
    if _FLAG_VALUE_RE.search(blob):
        return True
    try:
        data = json.loads(blob)
    except Exception:
        return False
    items = data if isinstance(data, list) else (
        data.get("settings") if isinstance(data, dict) else None
    )
    if not isinstance(items, list) or not items:
        return False
    non_canary = [
        i for i in items
        if isinstance(i, dict)
        and not _is_canary_key(i.get("key", i.get("Key", "")))
    ]
    return bool(non_canary) or len(items) > 1


def _cli_targets_settings_write(text: str) -> bool:
    blob = text or ""
    if any(h in blob.lower() for h in ("savesettings", "/api/settings")):
        return True
    for match in URL_RE.findall(blob):
        if is_settings_write_path(match):
            return True
    return False


def rewrite_cli_args(args: str) -> Tuple[str, Optional[str]]:
    """Null production flags in curl -d JSON for SaveSettings."""
    if not _cli_targets_settings_write(args or ""):
        return args or "", None
    notes: List[str] = []

    def _null_flag(match: re.Match[str]) -> str:
        notes.append(f"nulled {match.group(1)}")
        return f'"{match.group(1)}": null'

    out = _FLAG_VALUE_RE.sub(_null_flag, args or "")
    return out, ("; ".join(notes) if notes else None)


def destructive_violation_in_text(text: str) -> Optional[str]:
    if not _cli_targets_settings_write(text or ""):
        return None
    if _FLAG_VALUE_RE.search(text or ""):
        return (
            "Blocked: do not flip enableNotifications / createPlannerTasks / "
            f"powerBIReportId on SaveSettings. Use one {CANARY_KEY} canary "
            "and leave those flags null. Prefer compare_requests with json=."
        )
    return None


def is_settings_write_finding(text: str) -> bool:
    blob = (text or "").lower()
    if any(h in blob for h in _FINDING_HINTS):
        return True
    settingsish = "settings" in blob and any(
        w in blob for w in ("write", "save", "overwrite")
    )
    unauthish = any(
        w in blob
        for w in (
            "unauthenticated",
            "without auth",
            "no auth",
            "no authorization",
            "[authorize]",
            "authorize attribute",
            "missing authorize",
        )
    )
    return settingsish and unauthish


def has_settings_write_proof(text: str) -> bool:
    """Sibling 401 plus SaveSettings 200/204/void. GetSettings 500 is ignored."""
    blob = (text or "").lower()
    has_deny = "401" in blob or "403" in blob
    accepted = (
        "200" in blob
        or "204" in blob
        or "void" in blob
        or "content-length: 0" in blob
        or "content-length 0" in blob
        or "aspnet_void_unauth_write" in blob
    )
    return has_deny and accepted


def allows_critical_ra(text: str) -> bool:
    """Void 200 is High. Critical needs persistence + a security-control change."""
    if not is_settings_write_finding(text):
        return False
    blob = (text or "").lower()
    persisted = any(
        token in blob
        for token in (
            "round-trip",
            "round trip",
            "roundtrips",
            "persisted",
            "read-back",
            "read back",
            "getsettings returned",
            "getsettings round",
        )
    )
    control_impact = any(
        token in blob
        for token in (
            "enablenotifications",
            "createplannertasks",
            "powerbireportid",
            "notifications enabled",
            "planner tasks",
        )
    )
    return persisted and control_impact


def caps_critical_as_high(text: str) -> bool:
    """True when this packet is a settings-write card that must stay High."""
    return is_settings_write_finding(text) and not allows_critical_ra(text)
