"""Safe handling helpers for credentials discovered during assessments.

Scanners need the original value briefly for verification and deterministic
deduplication, but API responses, logs, scan summaries, and vulnerability rows
must never become a second secret store.  These helpers provide a stable
fingerprint and an intentionally non-reversible display value.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit


def secret_fingerprint(value: Any) -> str:
    """Return a stable, non-reversible identifier for a secret candidate."""
    raw = str(value or "").encode("utf-8", errors="replace")
    return f"sha256:{hashlib.sha256(raw).hexdigest()[:16]}"


def redact_secret(value: Any) -> str:
    """Return a display-safe marker that exposes no part of the value."""
    raw = str(value or "")
    return f"[REDACTED {secret_fingerprint(raw)} len={len(raw)}]"


def secret_descriptor(value: Any) -> dict[str, Any]:
    """Structured representation safe to persist or return to an operator."""
    raw = str(value or "")
    return {
        "redacted": redact_secret(raw),
        "fingerprint": secret_fingerprint(raw),
        "length": len(raw),
    }


def extract_secret_candidate(data: Mapping[str, Any] | None) -> str:
    """Extract the value field used by common scanner result formats."""
    if not isinstance(data, Mapping):
        return ""
    for key in ("match", "secret", "raw", "value", "key", "token", "password"):
        value = data.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def safe_secret_metadata(
    data: Mapping[str, Any] | None,
    *,
    source: str = "",
    kind: str = "",
) -> dict[str, Any]:
    """Create persistence-safe metadata without copying arbitrary raw fields."""
    candidate = extract_secret_candidate(data)
    result: dict[str, Any] = {
        "kind": kind or str((data or {}).get("kind") or "secret"),
        "source": source,
        **secret_descriptor(candidate),
    }
    for key in ("rule", "rule_id", "detector", "line", "column", "verified"):
        value = (data or {}).get(key)
        if value is not None:
            result[key] = value
    return result


def redact_secret_context(context: Any, secret: Any) -> str:
    """Remove the candidate from a surrounding source-code excerpt."""
    text = str(context or "")
    raw = str(secret or "")
    return text.replace(raw, redact_secret(raw)) if raw else text


def safe_source_url(value: Any) -> str:
    """Strip credentials, query parameters, and fragments from evidence URLs."""
    raw = str(value or "")
    try:
        parsed = urlsplit(raw)
        if not parsed.scheme or not parsed.hostname:
            return raw.split("?", 1)[0].split("#", 1)[0]
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        netloc = f"{host}:{parsed.port}" if parsed.port else host
        return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))
    except Exception:
        return raw.split("?", 1)[0].split("#", 1)[0]
