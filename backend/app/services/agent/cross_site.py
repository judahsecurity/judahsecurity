"""What a browser sends when a foreign page submits a request to the target.

Used for CSRF proof. A replay that keeps every session cookie and custom
header shows nothing about cross-site exploitability: modern browsers treat a
cookie without a SameSite attribute as Lax, never attach Lax or Strict cookies
to a cross-site POST, and cannot add non-safelisted headers without a CORS
preflight the target would have to allow.
"""

from __future__ import annotations

from typing import Any, Iterable

FOREIGN_ORIGIN = "https://aegis-csrf.invalid"

# CORS-safelisted request headers a page can set without a preflight, plus the
# headers the browser itself supplies.
_SAFELISTED = frozenset({
    "accept", "accept-language", "content-language", "content-type",
    "origin", "referer", "user-agent",
})
SIMPLE_CONTENT_TYPES = frozenset({
    "application/x-www-form-urlencoded", "multipart/form-data", "text/plain",
})


def same_site_of(cookie: Any) -> str:
    """Normalized SameSite value of a stored dict or an http.cookiejar Cookie."""
    if isinstance(cookie, dict):
        raw = cookie.get("sameSite") or cookie.get("samesite") or cookie.get("same_site")
    else:
        rest = getattr(cookie, "_rest", None) or {}
        raw = next((value for key, value in rest.items()
                    if str(key).lower() == "samesite"), None)
    value = str(raw or "").strip().lower()
    return value if value in {"none", "lax", "strict"} else ""


def cross_site_cookies(stored: Iterable[Any], method: str) -> list[dict]:
    """Cookies a browser attaches to a cross-site request.

    Browsers reject SameSite=None without Secure outright. A missing attribute
    counts as Lax, which a browser sends only on a top-level GET navigation.
    """
    method = (method or "GET").upper()
    kept = []
    for cookie in stored or []:
        if not isinstance(cookie, dict) or not cookie.get("name"):
            continue
        same_site = same_site_of(cookie) or "lax"
        if same_site == "none" and not cookie.get("secure"):
            continue
        if same_site == "none" or (method == "GET" and same_site == "lax"):
            kept.append(cookie)
    return kept


def cross_site_headers(headers: dict | None) -> dict:
    """Keep only safelisted headers and present a foreign Origin and Referer."""
    blocked = sorted(name for name in (headers or {})
                     if str(name).lower() not in _SAFELISTED)
    if blocked:
        raise ValueError(
            "A cross-site page cannot send these headers without a CORS preflight: "
            + ", ".join(blocked)
        )
    kept = {name: value for name, value in (headers or {}).items()
            if str(name).lower() not in {"origin", "referer"}}
    kept["Origin"] = FOREIGN_ORIGIN
    kept["Referer"] = FOREIGN_ORIGIN + "/"
    return kept


def simple_request(method: str, headers: dict | None) -> bool:
    """True when a browser would send this request cross-site without a preflight."""
    if (method or "").upper() not in {"GET", "POST"}:
        return False
    lowered = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    if any(name not in _SAFELISTED and name not in _BROWSER_SUPPLIED for name in lowered):
        return False
    content_type = lowered.get("content-type", "").split(";", 1)[0].strip().lower()
    return not content_type or content_type in SIMPLE_CONTENT_TYPES


# Headers the HTTP client adds on its own; a browser sends equivalents.
_BROWSER_SUPPLIED = frozenset({
    "host", "cookie", "content-length", "accept-encoding", "connection",
    "transfer-encoding",
})
