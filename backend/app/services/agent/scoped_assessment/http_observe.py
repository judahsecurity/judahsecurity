"""Read-only, scoped HTTP observations for API discovery and identity comparison."""

from __future__ import annotations

import hashlib
import json
import re
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .browser import assert_in_scope


MAX_BODY = 64 * 1024
STATIC_RESOURCE_TYPES = {"script", "stylesheet", "image", "font", "media"}


def observed_parent_directories(requests: list[dict], expected_origin: str, limit: int = 8) -> list[str]:
    """Suggest shallow, in-origin directories from resources the browser actually loaded."""
    candidates: set[str] = set()
    for row in requests:
        if row.get("method") != "GET" or row.get("resource_type") not in STATIC_RESOURCE_TYPES:
            continue
        path = row.get("path")
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or "\\" in path:
            continue
        segments = path.split("/")[1:]
        if any(part in ("", ".", "..") or "%2f" in part.lower() for part in segments[:-1]):
            continue
        for depth in range(1, min(len(segments) - 1, 4) + 1):
            candidates.add("/" + "/".join(segments[:depth]) + "/")
    return [expected_origin + path for path in sorted(candidates, key=lambda p: (p.count("/"), p))[:limit]]


def _directory_index_detected(data: bytes, content_type: str) -> bool:
    """Recognize common autoindex pages without returning HTML or filenames to the agent."""
    if content_type != "text/html":
        return False
    apache_or_nginx = re.search(rb"<title>\s*Index of /", data, re.IGNORECASE)
    python_index = re.search(rb"<title>\s*Directory listing for /", data, re.IGNORECASE)
    marker = b"?C=N;O=" in data or b"Parent Directory" in data or re.search(
        rb"<h1>\s*(?:Index of|Directory listing for) /", data, re.IGNORECASE,
    )
    return bool((apache_or_nginx or python_index) and marker)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _cookie_header(storage_state: dict | None, url: str) -> str:
    """Use only cookies valid for the requested host, path, scheme, and time."""
    if not storage_state:
        return ""
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    selected = []
    for cookie in storage_state.get("cookies", []):
        raw_domain = str(cookie.get("domain", "")).lower()
        domain = raw_domain.lstrip(".")
        cookie_path = str(cookie.get("path") or "/")
        name = str(cookie.get("name") or "")
        value = str(cookie.get("value") or "")
        expires = cookie.get("expires", -1)
        domain_matches = host == domain or (raw_domain.startswith(".") and host.endswith("." + domain))
        if not domain or not domain_matches:
            continue
        if not path.startswith(cookie_path.rstrip("/") + "/") and path != cookie_path.rstrip("/"):
            if cookie_path != "/":
                continue
        if cookie.get("secure") and parsed.scheme != "https":
            continue
        if isinstance(expires, (int, float)) and expires > 0 and expires < time.time():
            continue
        if not name or any(char in name + value for char in "\r\n;"):
            continue
        selected.append(f"{name}={value}")
    return "; ".join(selected)


def observe_get(url: str, allowed_origins: list[str], storage_state: dict | None = None) -> dict:
    """GET one in-scope URL without redirects; return bounded response metadata."""
    assert_in_scope(url, allowed_origins)
    headers = {"Accept": "application/json, text/html;q=0.9, */*;q=0.8"}
    cookies = _cookie_header(storage_state, url)
    if cookies:
        headers["Cookie"] = cookies
    request = Request(url, headers=headers, method="GET")
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    try:
        response = opener.open(request, timeout=15)
    except HTTPError as error:
        response = error
    with response:
        data = response.read(MAX_BODY + 1)
        truncated = len(data) > MAX_BODY
        data = data[:MAX_BODY]
        content_type = response.headers.get("Content-Type", "").split(";", 1)[0].lower()[:100]
        location = response.headers.get("Location", "")
        shape: dict = {}
        if content_type == "application/json" and not truncated:
            try:
                parsed = json.loads(data)
                if isinstance(parsed, dict):
                    shape = {"type": "object", "keys": sorted(str(key)[:100] for key in parsed)[:50]}
                elif isinstance(parsed, list):
                    shape = {"type": "array", "items": min(len(parsed), 1000)}
            except (UnicodeDecodeError, ValueError):
                pass
        return {
            "operation": "http_get",
            "target_template": url,
            "method": "GET",
            "status": response.status,
            "content_type": content_type,
            "bytes_captured": len(data),
            "truncated": truncated,
            "body_sha256": hashlib.sha256(data).hexdigest(),
            "json_shape": shape,
            "directory_index": _directory_index_detected(data, content_type),
            "redirected": bool(location),
        }
