"""
Detect client-side HMAC signing keys and ICS credentials hidden in JS bundles.

Gitleaks and string-regex scanners miss this class: the secret never appears as a
literal. Angular/iLens-style bundles assign an object whose *property names* are
the key material, then reconstruct it at runtime with Object.keys(obj).join("")
or for-in concatenation, and immediately feed it to crypto-js HmacSHA256 (HS256
JWTs) or MQTT/RFID login fields.

CWE-321 / CWE-798 / CWE-312. Presence in a public bundle is the finding —
backend timeout does not reduce exposure.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

# Empty-string fragment objects: this.waste={k:"",li:"",Lens:""}
_EMPTY_OBJ_RE = re.compile(
    r"(?:(?P<qual>this|window|self|[A-Za-z_$][\w$]*)\.)?(?P<name>[A-Za-z_$][\w$]*)"
    r"\s*=\s*\{(?P<body>(?:\s*[A-Za-z0-9_$\"']+\s*:\s*(?:\"\"|'')\s*,?){2,}\s*)\}",
)

_PROP_KEY_RE = re.compile(r"([A-Za-z0-9_$]+)\s*:\s*(?:\"\"|'')")

# Object.keys(this.waste).join("")  — empty separator only
_JOIN_RE = re.compile(
    r"Object\.keys\(\s*(?P<ref>(?:this|window|self|[A-Za-z_$][\w$]*)"
    r"(?:\.[A-Za-z_$][\w$]*)?)\s*\)\s*\.join\(\s*['\"]{2}\s*\)"
)

# for(const t in this.waste)e+=t
_FORIN_RE = re.compile(
    r"for\s*\(\s*(?:const|let|var)\s+(?P<iter>[A-Za-z_$][\w$]*)\s+in\s+"
    r"(?P<ref>(?:this|window|self|[A-Za-z_$][\w$]*)(?:\.[A-Za-z_$][\w$]*)?)\s*\)"
    r"\s*(?P<acc>[A-Za-z_$][\w$]*)\s*\+=\s*(?P=iter)"
)

_HMAC_RE = re.compile(
    r"HmacSHA256|HmacSHA1|HmacSHA512|"
    r"createHmac\s*\(\s*['\"]sha(?:256|1|512)|"
    r"alg\s*:\s*['\"]HS256['\"]|"
    r"typ\s*:\s*['\"]JWT['\"]|"
    r"getSessionKey|returnK\s*\(",
    re.I,
)

_MQTT_RE = re.compile(
    r"mqttPath|mqttUrl|mqttHost|useSSL|wss://|mqtt://|"
    r"userName\s*:|password\s*:|"
    r"hmi/live_tags|SCADA|iLens|digital.?twin|\bOEE\b|\bDAHS\b",
    re.I,
)

_RFID_RE = re.compile(
    r"(?P<field>rfid(?:UserName|Username|Password|_user|_pass|_password|User|_pwd))"
    r"\s*:\s*['\"](?P<value>[^'\"]+)['\"]",
    re.I,
)

_ICS_HINT_RE = re.compile(
    r"hmi/live_tags|SCADA|iLens|ilens_api|digital.?twin|"
    r"\bOEE\b|\bDAHS\b|mqttPath|rfidPassword|rfidUserName",
    re.I,
)

# Skip empty init objects whose keys are ordinary config words.
_COMMON_KEYS = {
    "id", "name", "type", "value", "data", "error", "success", "message", "status",
    "enabled", "disabled", "url", "path", "host", "port", "timeout", "retry",
    "debug", "mode", "token", "user", "password", "username", "email",
    "secret", "config", "options", "headers", "method", "body", "params",
    "true", "false", "null", "undefined", "length", "index", "count", "total",
    "start", "end", "min", "max", "default", "title", "label", "description",
    "width", "height", "color", "style", "class", "children", "props",
}

_CRED_JOIN_PREFIX_RE = re.compile(
    r"(userName|password|username|user|pass)\s*:\s*$",
    re.I,
)

_PLACEHOLDER_VALUES = {
    "", "changeme", "password", "secret", "todo", "placeholder", "your_password",
    "xxx", "test", "null", "undefined", "n/a", "na",
}

_CONTEXT_WINDOW = 12_000
_SNIPPET_RADIUS = 160
_MAX_KEYS = 32
_MIN_SECRET_LEN = 6


def _redact(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return value[:2] + "***"
    return f"{value[:4]}***{value[-4:]}"


def _snippet(text: str, pos: int, secret: str = "") -> str:
    start = max(0, pos - _SNIPPET_RADIUS)
    end = min(len(text), pos + _SNIPPET_RADIUS)
    blob = text[start:end]
    if secret:
        blob = blob.replace(secret, _redact(secret))
    return blob.replace("\n", " ")


def _normalize_ref(ref: str) -> str:
    return (ref or "").strip()


def _ref_name(ref: str) -> str:
    ref = _normalize_ref(ref)
    if "." in ref:
        return ref.rsplit(".", 1)[-1]
    return ref


def _parse_empty_object(body: str) -> Optional[List[str]]:
    keys = _PROP_KEY_RE.findall(body)
    if len(keys) < 2 or len(keys) > _MAX_KEYS:
        return None
    # Reject objects that also contain non-empty string values.
    if re.search(r":\s*['\"][^'\"]+['\"]", body):
        return None
    if all(k.lower() in _COMMON_KEYS for k in keys):
        return None
    return keys


def _nearby(text: str, pos: int, regex: re.Pattern, window: int = _CONTEXT_WINDOW) -> bool:
    lo = max(0, pos - window)
    hi = min(len(text), pos + window)
    return bool(regex.search(text[lo:hi]))


def _nearby_hits(text: str, pos: int, regex: re.Pattern, window: int = _CONTEXT_WINDOW) -> List[str]:
    lo = max(0, pos - window)
    hi = min(len(text), pos + window)
    return [m.group(0)[:80] for m in regex.finditer(text[lo:hi])][:8]


def _index_objects(text: str) -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []
    for m in _EMPTY_OBJ_RE.finditer(text):
        keys = _parse_empty_object(m.group("body") or "")
        if not keys:
            continue
        reconstructed = "".join(keys)
        if len(reconstructed) < _MIN_SECRET_LEN:
            continue
        qual = m.group("qual") or ""
        name = m.group("name") or ""
        refs = [name]
        if qual:
            refs.append(f"{qual}.{name}")
        found.append(
            {
                "name": name,
                "qual": qual,
                "refs": refs,
                "keys": keys,
                "reconstructed": reconstructed,
                "offset": m.start(),
            }
        )
    return found


def _index_reconstructions(text: str) -> List[Tuple[str, str, int]]:
    """Return (ref, method, offset) for Object.keys join and for-in concat."""
    out: List[Tuple[str, str, int]] = []
    for m in _JOIN_RE.finditer(text):
        out.append((_normalize_ref(m.group("ref")), 'Object.keys().join("")', m.start()))
    for m in _FORIN_RE.finditer(text):
        out.append((_normalize_ref(m.group("ref")), "for-in concatenation", m.start()))
    return out


def _match_obj(objs: Sequence[Dict[str, Any]], ref: str) -> Optional[Dict[str, Any]]:
    ref_n = _normalize_ref(ref)
    name = _ref_name(ref_n)
    for obj in objs:
        if ref_n in obj["refs"] or name == obj["name"]:
            return obj
    return None


def _join_site_role(text: str, pos: int) -> str:
    prefix = text[max(0, pos - 48) : pos]
    if _CRED_JOIN_PREFIX_RE.search(prefix):
        return "credential"
    window = text[max(0, pos - 500) : min(len(text), pos + 500)]
    if _HMAC_RE.search(window):
        return "hmac"
    return "unknown"


def _role_for(name: str, usage: Sequence[str], site_roles: Sequence[str]) -> str:
    if "credential" in site_roles:
        n = (name or "").lower()
        if "pass" in n:
            return "mqtt_or_gateway_password"
        return "mqtt_or_gateway_username"
    if "hmac" in site_roles:
        return "hmac_signing_key"
    n = (name or "").lower()
    blob = " ".join(usage).lower() + " " + n
    if "hmac" in blob or "hs256" in blob or "jwt" in blob or n in {"waste", "sessionkey"}:
        return "hmac_signing_key"
    if "pass" in n or "password" in blob:
        return "mqtt_or_gateway_password"
    if "name" in n or "user" in blob or "username" in blob:
        return "mqtt_or_gateway_username"
    return "obfuscated_secret"


def analyze_js_client_secrets(text: str, source_url: str = "") -> List[Dict[str, Any]]:
    """Return structured findings for obfuscated HMAC / MQTT / RFID secrets in JS."""
    if not text:
        return []

    objs = _index_objects(text)
    ics_signals = sorted({m.group(0) for m in _ICS_HINT_RE.finditer(text)})[:12]
    reconstructions = _index_reconstructions(text)
    findings: List[Dict[str, Any]] = []
    seen = set()

    joined_refs = {ref for ref, _method, _pos in reconstructions}

    for obj in objs:
        used_by = [
            (ref, method, pos)
            for ref, method, pos in reconstructions
            if _match_obj([obj], ref) is obj
        ]
        site_roles = [_join_site_role(text, pos) for _ref, _method, pos in used_by]
        hmac_near = _nearby(text, obj["offset"], _HMAC_RE)
        mqtt_near = _nearby(text, obj["offset"], _MQTT_RE, window=4000)
        if not used_by and not hmac_near and not mqtt_near:
            continue

        usage: List[str] = []
        usage.extend(_nearby_hits(text, obj["offset"], _HMAC_RE))
        usage.extend(_nearby_hits(text, obj["offset"], _MQTT_RE, window=4000))
        for _ref, method, _pos in used_by:
            usage.append(method)

        cred_join = "credential" in site_roles
        hmac_join = "hmac" in site_roles or (
            not cred_join and hmac_near and used_by
        )
        role = _role_for(obj["name"], usage, site_roles)
        if hmac_join and not cred_join:
            kind = "hmac_signing_key"
            cwe = "CWE-321"
            severity = "critical"
        elif cred_join or (mqtt_near and used_by):
            kind = "obfuscated_credential"
            cwe = "CWE-798"
            severity = "critical"
        elif hmac_near:
            kind = "hmac_signing_key"
            cwe = "CWE-321"
            severity = "critical"
        else:
            kind = "obfuscated_secret"
            cwe = "CWE-312"
            severity = "high"

        key = (kind, obj["name"], obj["reconstructed"])
        if key in seen:
            continue
        seen.add(key)

        findings.append(
            {
                "kind": kind,
                "role": role,
                "severity": severity,
                "cwe": cwe,
                "source_url": source_url,
                "object_name": obj["name"],
                "object_ref": (f"{obj['qual']}.{obj['name']}" if obj["qual"] else obj["name"]),
                "property_keys": obj["keys"],
                "reconstruction": used_by[0][1] if used_by else "Object.keys property-name concat",
                "reconstructed": obj["reconstructed"],
                "redacted": _redact(obj["reconstructed"]),
                "usage": list(dict.fromkeys(usage))[:10],
                "offset": obj["offset"],
                "joined_in_bundle": bool(used_by) or obj["name"] in {_ref_name(r) for r in joined_refs},
                "ics_signals": ics_signals,
                "snippet": _snippet(text, obj["offset"], obj["reconstructed"]),
                "note": (
                    "Secret is the concatenation of object property names, not a string "
                    "literal. Gitleaks will miss this. Public bundle exposure is sufficient "
                    "for CWE-321/CWE-798; a live API/MQTT accept is optional extra proof. "
                    "Backend timeout is not a kill."
                ),
            }
        )

    for m in _RFID_RE.finditer(text):
        field = m.group("field") or "rfid"
        value = m.group("value") or ""
        if value.strip().lower() in _PLACEHOLDER_VALUES:
            continue
        if len(value) < 3:
            continue
        key = ("plaintext_ics_credential", field.lower(), value)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            {
                "kind": "plaintext_ics_credential",
                "role": "rfid_password" if "pass" in field.lower() else "rfid_username",
                "severity": "critical" if "pass" in field.lower() else "high",
                "cwe": "CWE-798",
                "source_url": source_url,
                "object_name": field,
                "object_ref": field,
                "property_keys": [],
                "reconstruction": "plaintext",
                "reconstructed": value,
                "redacted": _redact(value),
                "usage": _nearby_hits(text, m.start(), _MQTT_RE, window=4000) or [field],
                "offset": m.start(),
                "joined_in_bundle": False,
                "ics_signals": ics_signals,
                "snippet": _snippet(text, m.start(), value),
                "note": (
                    "ICS/RFID credential in a public JavaScript bundle. Rotate and "
                    "remove from the client. Live broker login is optional extra proof."
                ),
            }
        )

    # Join sites whose object we failed to parse still matter if HMAC is adjacent.
    for ref, method, pos in reconstructions:
        if _match_obj(objs, ref):
            continue
        if not (_nearby(text, pos, _HMAC_RE) or _nearby(text, pos, _MQTT_RE, window=4000)):
            continue
        key = ("unresolved_reconstruction", ref, method)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            {
                "kind": "unresolved_key_reconstruction",
                "role": "hmac_signing_key" if _nearby(text, pos, _HMAC_RE) else "obfuscated_credential",
                "severity": "high",
                "cwe": "CWE-321" if _nearby(text, pos, _HMAC_RE) else "CWE-798",
                "source_url": source_url,
                "object_name": _ref_name(ref),
                "object_ref": ref,
                "property_keys": [],
                "reconstruction": method,
                "reconstructed": "",
                "redacted": "",
                "usage": _nearby_hits(text, pos, _HMAC_RE) + _nearby_hits(text, pos, _MQTT_RE, window=4000),
                "offset": pos,
                "joined_in_bundle": True,
                "ics_signals": ics_signals,
                "snippet": _snippet(text, pos),
                "note": (
                    "Bundle reconstructs a secret via Object.keys/for-in next to HMAC or "
                    "MQTT usage, but the empty-string object was not parsed. Inspect the snippet."
                ),
            }
        )

    return findings


def summarize_client_signing_findings(findings: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Compact agent-facing summary: counts, kinds, and whether CWE-321 is demonstrated."""
    kinds = sorted({str(f.get("kind") or "") for f in findings if f.get("kind")})
    demonstrated = any(
        f.get("kind") == "hmac_signing_key" and f.get("reconstructed") and f.get("joined_in_bundle")
        for f in findings
    ) or any(
        f.get("kind") == "hmac_signing_key" and f.get("reconstructed")
        for f in findings
    )
    creds_demonstrated = any(
        f.get("kind") in {"obfuscated_credential", "plaintext_ics_credential"} and f.get("reconstructed")
        for f in findings
    )
    return {
        "count": len(findings),
        "kinds": kinds,
        "hmac_key_demonstrated": demonstrated,
        "ics_creds_demonstrated": creds_demonstrated,
        "submit_without_live_api": demonstrated or creds_demonstrated,
        "cwe": "CWE-321" if demonstrated else ("CWE-798" if creds_demonstrated else None),
    }
