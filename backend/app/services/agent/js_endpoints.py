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
# JShero / jsluice: method + URL from XHR and axios/jQuery verbs.
_XHR_OPEN = re.compile(
    r"""\.open\s*\(\s*['"`](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['"`]\s*,\s*['"`]([^'"`]{1,600})['"`]""",
    re.I,
)
_VERB_CALL = re.compile(
    r"""\b(?:axios\.(get|post|put|delete|patch)|\$\.(get|post)|jQuery\.(get|post))\s*\(\s*['"`]([^'"`]{1,600})['"`]""",
    re.I,
)
_ASSIGN_SINK = re.compile(
    r"""(?:\blocation\b(?:\.(?:href|assign|replace))?|[\w$.]+\.(?:href|src)|this\.(?:url|_url|baseUrl))\s*=\s*['"`]([^'"`]{1,600})['"`]""",
    re.I,
)
_TEMPLATE = re.compile(r"`([^`]{1,1000})`")
_TEMPLATE_EXPR = re.compile(r"\$\{[^}]{0,200}\}")
_PARAM_OBJ = re.compile(
    r"""\b(?:data|params|body|query|form|json)\s*:\s*\{([^{}]{0,2000})\}""",
    re.I,
)
_OBJ_KEY = re.compile(r"""['"]?([A-Za-z_$][\w$\-]{0,60})['"]?\s*:""")
_PARAM_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-]{2,99}$")
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


def _normalize_template(s: str) -> str:
    return _TEMPLATE_EXPR.sub("EXPR", s or "")


def extract_methods_and_params(body: str) -> Dict[str, Any]:
    """JShero/jsluice extras: HTTP methods, config-object params, template routes."""
    text = body or ""
    methods: List[Dict[str, str]] = []
    params: Set[str] = set()
    extra: List[str] = []
    for m in _XHR_OPEN.finditer(text):
        url = (m.group(2) or "").strip()
        if url:
            extra.append(url)
            methods.append({"method": m.group(1).upper(), "url": url[:300]})
    for m in _VERB_CALL.finditer(text):
        verb = (m.group(1) or m.group(2) or m.group(3) or "").upper()
        url = (m.group(4) or "").strip()
        if url:
            extra.append(url)
            methods.append({"method": verb, "url": url[:300]})
    for m in _ASSIGN_SINK.finditer(text):
        extra.append((m.group(1) or "").strip())
    for m in _TEMPLATE.finditer(text):
        cand = _normalize_template(m.group(1)).strip()
        if cand and "EXPR" in cand and cand.replace("EXPR", "").replace("/", "").strip():
            extra.append(cand)
    for m in _PARAM_OBJ.finditer(text):
        for km in _OBJ_KEY.finditer(m.group(1) or ""):
            key = km.group(1)
            if _PARAM_NAME.match(key) and key != "EXPR":
                params.add(key)
    return {"extra_urls": [u for u in extra if u], "methods": methods[:80], "params": sorted(params)[:80]}


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
    for u in extract_methods_and_params(body).get("extra_urls") or []:
        add(u)
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
    methods: List[Dict[str, str]] = []
    params: Set[str] = set()
    analyzed = 0
    errors: List[str] = []
    async with httpx.AsyncClient(follow_redirects=True, verify=False, timeout=timeout) as client:
        for url in urls:
            try:
                r = await client.get(url)
                body = (r.text or "")[:MAX_BYTES]
                all_eps.extend(extract_from_body(body))
                extra = extract_methods_and_params(body)
                methods.extend(extra.get("methods") or [])
                params.update(extra.get("params") or [])
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
    reseed = [u for u in flat if u.startswith("http") or u.startswith("/")][:80]
    return {
        "ok": True,
        "js_analyzed": analyzed,
        "endpoint_count": len(flat),
        "endpoints": flat[:200],
        "triage": groups,
        "methods": methods[:80],
        "params": sorted(params)[:80],
        "reseed_urls": reseed,
        "errors": errors[:8],
        "next": (
            "ingest_urls_into_map the in-scope paths (reseed), then mutate_captured_request / "
            "discover_parameters on IDOR/SSRF candidates. scan_js_sinks on the same bundles."
        ),
    }
