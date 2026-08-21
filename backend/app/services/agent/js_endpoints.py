"""Extract and triage API paths/URLs from JavaScript (js-analysis skill).

Network only to fetch in-scope .js; analysis is local. Groups leads for
IDOR / SSRF / open-redirect — not a secret scanner.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Set
from urllib.parse import urlparse

import httpx

from app.services.js_recon_service import ENDPOINT_PATTERN

_STATIC_NOISE = (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2",
                 ".map", ".ico", ".ttf", ".eot")
_IDOR_KEYS = re.compile(r"(?:[?&]|['\"])(id|user_id|uid|account|org|tenant|uuid|token)=")
_SSRF_KEYS = re.compile(
    r"(?:[?&]|['\"])(url|uri|redirect|next|callback|dest|target|webhook|proxy|requestUrl|datasource)=",
    re.I,
)
_FETCH_HINT = re.compile(
    r"""(?:fetch|\.get|\.post|\.ajax|\.load|axios)\s*\(\s*['"`]([^'"`]+)['"`]""",
    re.I,
)
# Portable port of extract_endpoints.sh (Perl): split minified JS, then
# https URLs / quoted /paths / fetch|.get|.post|.ajax|.load targets.
_EXTRACT = re.compile(
    r"""(https?://[^"'` >]{4,})|(?:["'`](/{1,2}[a-zA-Z0-9_?&=/\-#.]{3,}))|(?:(?:\.(?:get|post|ajax|load)|fetch)\s*\(\s*["'`]((?:https?://)?/?[^"'`> ]{3,}))""",
    re.I,
)
_BASE_URL = re.compile(
    r"""(?:API_BASE|baseURL|BASE_URL|apiUrl|API_URL)\s*[:=]\s*['"`]([^'"`]+)['"`]""",
    re.I,
)
MAX_URLS = 20
MAX_BYTES = 1_500_000


def triage_endpoints(
    endpoints: Iterable[str],
    *,
    origin_host: str = "",
) -> Dict[str, List[str]]:
    api: List[str] = []
    absolute: List[str] = []
    fetch_like: List[str] = []
    idor: List[str] = []
    ssrf: List[str] = []
    seen: Set[str] = set()
    origin_host = (origin_host or "").lower()

    for raw in endpoints:
        v = (raw or "").strip()
        if not v or v in seen:
            continue
        low = v.lower().split("?")[0]
        if any(low.endswith(ext) for ext in _STATIC_NOISE):
            continue
        if v.startswith("http"):
            host = (urlparse(v).hostname or "").lower()
            if origin_host and host and host != origin_host and not host.endswith("." + origin_host):
                # Keep as absolute (SSRF/redirect candidate) if it looks like a URL param sink
                if _SSRF_KEYS.search(v):
                    ssrf.append(v[:300])
                continue
            absolute.append(v[:300])
        elif "/api/" in v or v.startswith("/graphql") or v.startswith("/v1/") or v.startswith("/v2/"):
            api.append(v[:300])
        else:
            fetch_like.append(v[:300])
        if _IDOR_KEYS.search(v):
            idor.append(v[:300])
        if _SSRF_KEYS.search(v) or "url=" in v.lower():
            ssrf.append(v[:300])
        seen.add(v)
        if len(seen) >= 400:
            break
    return {
        "api_routes": api[:80],
        "absolute_urls": absolute[:40],
        "fetch_targets": fetch_like[:80],
        "idor_candidates": idor[:40],
        "ssrf_redirect_candidates": ssrf[:40],
    }


def extract_from_body(body: str) -> List[str]:
    found: List[str] = []
    seen: Set[str] = set()

    def add(v: str) -> None:
        v = (v or "").strip()
        if v and v not in seen:
            seen.add(v)
            found.append(v)

    split = re.sub(r"[;})>]", "\n", body or "")
    for m in _EXTRACT.finditer(split):
        add(m.group(1) or m.group(2) or m.group(3) or "")
    for m in ENDPOINT_PATTERN.finditer(body or ""):
        add(m.group(1) or "")
    for m in _FETCH_HINT.finditer(body or ""):
        add(m.group(1) or "")
    for m in _BASE_URL.finditer(body or ""):
        add(m.group(1) or "")
    return found


async def extract_js_endpoints(
    urls: Iterable[str],
    *,
    origin_host: str = "",
    timeout: float = 12.0,
) -> Dict[str, Any]:
    urls = [u.strip() for u in urls if str(u).strip().startswith("http")][:MAX_URLS]
    if not urls:
        return {"ok": False, "error": "no https URLs"}
    origin_host = origin_host or (urlparse(urls[0]).hostname or "")
    all_eps: List[str] = []
    analyzed = 0
    errors: List[str] = []
    async with httpx.AsyncClient(follow_redirects=True, verify=False, timeout=timeout) as client:
        for url in urls:
            try:
                r = await client.get(url)
                body = (r.text or "")[:MAX_BYTES]
                all_eps.extend(extract_from_body(body))
                analyzed += 1
            except Exception as exc:
                errors.append(f"{url}: {exc}"[:180])
    groups = triage_endpoints(all_eps, origin_host=origin_host)
    flat: List[str] = []
    seen: Set[str] = set()
    for key in ("ssrf_redirect_candidates", "idor_candidates", "api_routes", "absolute_urls", "fetch_targets"):
        for item in groups[key]:
            if item not in seen:
                seen.add(item)
                flat.append(item)
    return {
        "ok": True,
        "js_analyzed": analyzed,
        "endpoint_count": len(flat),
        "endpoints": flat[:200],
        "triage": groups,
        "errors": errors[:8],
        "next": (
            "ingest_urls_into_map the in-scope paths, then mutate_captured_request / "
            "discover_parameters on IDOR/SSRF candidates"
        ),
    }
