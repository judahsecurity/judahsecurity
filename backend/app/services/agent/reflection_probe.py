"""Bounded, same-origin GET canaries for inputs observed during browser recon.

A reflected marker is a lead for an XSS specialist, never execution proof.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import time
from urllib.parse import urlencode, urlsplit

_UNSAFE_PATH = re.compile(
    r"(?:^|/)(?:logout|signout|delete|remove|purchase|checkout|pay|transfer|"
    r"unsubscribe|reset|confirm|activate|disable)(?:/|$)", re.I,
)
_PREFERRED = re.compile(r"search|query|term|category|filter|name|title|comment", re.I)
_MAX_BODY = 1_000_000


def reflection_candidates(target: str, inventory: list[dict], limit: int = 8) -> list[dict]:
    """Select observed, testable GET inputs on the exact target origin."""
    parts = urlsplit(target)
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
        return []
    origin = f"{parts.scheme}://{parts.netloc}"
    candidates = []
    seen = set()
    for row in inventory:
        if not isinstance(row, dict) or row.get("method") != "GET" or row.get("location") != "query":
            continue
        if not row.get("testable") or row.get("source") not in {
            "observed_form", "page_url", "captured_api", "api_endpoint",
        }:
            continue
        path, name = row.get("path"), row.get("name")
        if (not isinstance(path, str) or not path.startswith("/") or path.startswith("//")
                or not isinstance(name, str) or not name or _UNSAFE_PATH.search(path)):
            continue
        if row.get("host") != parts.netloc:
            continue
        key = (path, name)
        if key in seen:
            continue
        seen.add(key)
        candidates.append({"origin": origin, "path": path, "parameter": name,
                           "source": row["source"]})
    candidates.sort(key=lambda row: (
        not bool(_PREFERRED.search(row["parameter"])),
        not bool(_PREFERRED.search(row["path"])),
        row["path"], row["parameter"],
    ))
    return candidates[:max(0, min(limit, 20))]


async def probe_reflections(context, target: str, inventory: list[dict], *,
                            deadline: float, limit: int = 8) -> list[dict]:
    """Make at most ``limit`` safe GETs. No redirects, payloads, or browser JS."""
    observations = []
    for row in reflection_candidates(target, inventory, limit):
        if time.monotonic() >= deadline - 2:
            break
        marker = "aegis" + secrets.token_hex(7)
        url = row["origin"] + row["path"] + "?" + urlencode({row["parameter"]: marker})
        try:
            response = await context.request.get(
                url, timeout=min(8000, max(1000, int((deadline - time.monotonic()) * 1000))),
                max_redirects=0,
            )
            content_type = str(response.headers.get("content-type") or "").lower()
            size = int(response.headers.get("content-length") or 0)
            if response.status >= 300 or "text/html" not in content_type or size > _MAX_BODY:
                continue
            body = await response.body()
            if len(body) > _MAX_BODY:
                continue
            reflected = marker.encode() in body
            observations.append({
                "path": row["path"], "parameter": row["parameter"],
                "source": row["source"], "method": "GET", "status": response.status,
                "marker": marker, "reflected": reflected,
                "reflection_location": "html_response_source" if reflected else "none",
                "response_sha256": hashlib.sha256(body).hexdigest(),
                "browser_execution_verified": False,
            })
        except Exception:
            # A failed canary must not fail the otherwise useful crawl.
            continue
    return observations
