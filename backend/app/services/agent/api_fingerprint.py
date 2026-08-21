"""Fingerprint APIs from captured Interceptor/crawl traffic.

Port of api-fingerprint-caido (collect_caido_api_traffic.py + HTTP fingerprinting
checklist) without Caido GraphQL, Codex, or external corroboration. Passive on
capability_map samples. Active probes are a plan only unless the operator
already authorized them.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

API_PATH_HINTS = re.compile(
    r"(^|/)(api|graphql|rest|rpc|v[0-9]+|oauth|auth|session|users?|admin|actions|datasources)(/|$)",
    re.I,
)
STATIC_EXTENSIONS = {
    ".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm",
}
TECH_HEADERS = {
    "server", "x-powered-by", "x-powered-cms", "via", "x-drupal-cache",
    "x-shopify-stage", "x-varnish", "x-amz-cf-id", "x-cache", "cf-ray",
    "cf-cache-status", "x-aspnet-version", "x-aspnetmvc-version", "x-generator",
    "x-runtime", "x-request-id", "x-amzn-requestid", "x-amz-apigw-id",
    "x-envoy-upstream-service-time", "x-kong-upstream-latency", "x-served-by",
}
COOKIE_TECH = {
    "phpsessid": "PHP",
    "jsessionid": "Java/Jakarta servlet stack",
    "asp.net_sessionid": "ASP.NET",
    "cftoken": "Adobe ColdFusion",
    "cfid": "Adobe ColdFusion",
}
EXTENSION_TECH = {
    ".php": "PHP",
    ".jsp": "Java/JSP",
    ".jspx": "Java/JSP",
    ".do": "Java Struts/Spring-style routing",
    ".action": "Java Struts/Spring-style routing",
    ".aspx": "ASP.NET Web Forms",
    ".ashx": "ASP.NET handler",
    ".asmx": "ASP.NET web service",
    ".cfm": "Adobe ColdFusion",
}
DEFAULT_FILE_PATTERNS = {
    "/favicon.ico": "favicon",
    "/package.json": "Node package metadata",
    "/swagger.json": "OpenAPI/Swagger",
    "/openapi.json": "OpenAPI",
    "/api-docs": "API documentation",
    "/graphql": "GraphQL",
}
DEFAULT_ERROR_SIGNATURES = [
    ("Apache Tomcat", re.compile(r"Apache Tomcat|HTTP Status 404|type Status report", re.I)),
    ("Spring Boot", re.compile(r'"timestamp"\s*:.*"status"\s*:|Whitelabel Error Page', re.I | re.S)),
    ("IIS/ASP.NET", re.compile(r"Microsoft-IIS|ASP\.NET|Server Error in '/", re.I)),
    ("Nginx", re.compile(r"<center>nginx</center>|nginx/", re.I)),
    ("Apache httpd", re.compile(r"Apache/\d|<address>Apache", re.I)),
    ("Express/Node", re.compile(r"Cannot (GET|POST|PUT|DELETE|PATCH) /|X-Powered-By:\s*Express", re.I)),
    ("Django", re.compile(r"DisallowedHost|CSRF verification failed", re.I)),
    ("Rails", re.compile(r"Ruby on Rails|ActionController", re.I)),
    ("Cloudflare", re.compile(r"cf-error-code|Sorry, you have been blocked", re.I)),
    ("AWS API Gateway", re.compile(r"Missing Authentication Token|x-amzn-ErrorType", re.I)),
    ("Appsmith", re.compile(r"/api/v1/actions|/api/v1/datasources", re.I)),
]
COMMON_SECOND_LEVEL_SUFFIXES = {
    "ac.uk", "co.jp", "co.uk", "com.au", "com.br", "com.mx", "org.uk",
}
DEFAULT_PROBE_FILES = [
    "/favicon.ico", "/package.json", "/swagger.json", "/openapi.json",
    "/api-docs", "/graphql",
]
TECHNIQUES = (
    "api_host_discovery",
    "response_header_analysis",
    "banner_proxy_identification",
    "header_order",
    "default_error_pages",
    "malformed_http_requests",
    "default_files_directories",
    "cookie_parameters",
    "external_corroboration",
)


def related_search_domain(host: str) -> str:
    host = (host or "").lower().strip("[]")
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host) or host in {"localhost", ""}:
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    suffix = ".".join(labels[-2:])
    if suffix in COMMON_SECOND_LEVEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _host_from_url(url: str) -> str:
    parsed = urlparse(url if "://" in (url or "") else f"https://placeholder{url or ''}")
    return (parsed.hostname or "").lower()


def _headers_dict(raw: Any) -> Dict[str, str]:
    if isinstance(raw, dict):
        return {str(k).lower(): str(v) for k, v in raw.items() if v is not None}
    if isinstance(raw, list):
        out: Dict[str, str] = {}
        for item in raw:
            if isinstance(item, dict) and item.get("name"):
                out[str(item["name"]).lower()] = str(item.get("value") or "")
        return out
    return {}


def _cookie_names(*blobs: str) -> List[str]:
    names: List[str] = []
    for blob in blobs:
        for part in (blob or "").split(";"):
            if "=" in part:
                names.append(part.split("=", 1)[0].strip())
    return sorted(set(n for n in names if n and n.lower() not in {"authorization", "bearer"}))


def _cookie_technologies(names: Iterable[str]) -> List[Dict[str, str]]:
    out = []
    for name in names:
        tech = COOKIE_TECH.get(name.lower())
        if tech:
            out.append({"cookie": name, "technology": tech, "confidence": "high"})
    return out


def _is_api_candidate(path: str, method: str, content_type: str) -> bool:
    suffix = Path(path or "").suffix.lower()
    if suffix in STATIC_EXTENSIONS:
        return False
    if API_PATH_HINTS.search(path or ""):
        return True
    if method and method.upper() not in {"GET", "HEAD", "OPTIONS"}:
        return True
    return any(m in (content_type or "").lower() for m in ("json", "graphql", "grpc", "protobuf"))


def _path_signals(path: str) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    lower = (path or "").lower()
    suffix = Path(lower).suffix
    if suffix in EXTENSION_TECH:
        findings.append({"kind": "extension", "value": suffix, "meaning": EXTENSION_TECH[suffix]})
    for pattern, meaning in DEFAULT_FILE_PATTERNS.items():
        if lower == pattern or lower.endswith(pattern):
            findings.append({"kind": "default-file", "value": pattern, "meaning": meaning})
    for part in [p for p in lower.split("/") if p]:
        if part in {"wp-admin", "wp-content", "wp-json"}:
            findings.append({"kind": "directory", "value": part, "meaning": "WordPress"})
        elif re.fullmatch(r"v[0-9]+", part):
            findings.append({"kind": "api-version", "value": part, "meaning": "versioned API path"})
    return findings


def _error_signatures(status: Optional[int], body: str, header_blob: str) -> List[Dict[str, str]]:
    haystack = f"{header_blob}\n{body}"
    if not haystack.strip():
        return []
    if status not in {400, 401, 403, 404, 405, 406, 415, 429, 500, 502, 503, 504}:
        # Still allow distinctive body/header banners on 2xx
        interesting = ("Whitelabel", "X-Powered-By", "Missing Authentication Token")
        if not any(s.lower() in haystack.lower() for s in interesting):
            return []
    findings = []
    for tech, pat in DEFAULT_ERROR_SIGNATURES:
        if tech == "Appsmith":
            continue
        m = pat.search(haystack)
        if m:
            findings.append({"technology": tech, "evidence": m.group(0)[:120]})
    return findings


def _normalize_sample(sample: Dict[str, Any], fallback_host: str = "") -> Optional[Dict[str, Any]]:
    if not isinstance(sample, dict):
        return None
    url = str(sample.get("url") or sample.get("path") or "")
    parsed = urlparse(url if "://" in url else f"https://{fallback_host}{url}")
    host = (parsed.hostname or fallback_host or "").lower()
    path = parsed.path or url
    method = str(sample.get("method") or "GET").upper()
    req_h = _headers_dict(sample.get("headers"))
    resp_h = _headers_dict(sample.get("response_headers") or sample.get("resp_headers"))
    ct = resp_h.get("content-type") or req_h.get("content-type") or ""
    status = sample.get("status") or sample.get("statusCode") or sample.get("status_code")
    try:
        status_i = int(status) if status is not None else None
    except (TypeError, ValueError):
        status_i = None
    body = str(sample.get("response_body") or sample.get("body") or "")[:500]
    cookies = _cookie_names(
        req_h.get("cookie", ""),
        resp_h.get("set-cookie", ""),
        str(sample.get("set_cookie") or ""),
    )
    tech_headers = [
        {"name": k, "value": (v[:80] if k != "authorization" else "[redacted]")}
        for k, v in {**req_h, **resp_h}.items()
        if k in TECH_HEADERS or k.startswith("x-")
    ]
    return {
        "host": host,
        "method": method,
        "path": path,
        "url": url[:300],
        "status": status_i,
        "content_type": ct,
        "api_candidate": _is_api_candidate(path, method, ct),
        "path_signals": _path_signals(path),
        "tech_headers": tech_headers,
        "cookie_names": cookies,
        "cookie_technologies": _cookie_technologies(cookies),
        "header_order": list(resp_h.keys())[:12],
        "error_signatures": _error_signatures(status_i, body, " ".join(f"{k}:{v}" for k, v in resp_h.items())),
        "body_sample": body[:200],
    }


def _api_score(host: str, records: List[Dict[str, Any]]) -> Tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []
    labels = host.split(".")
    if any(label in {"api", "graphql", "rest", "gateway", "edge-api"} for label in labels):
        score += 5
        reasons.append("API-like hostname label")
    elif "api" in host:
        score += 3
        reasons.append("API-like hostname substring")
    api_records = [r for r in records if r.get("api_candidate")]
    if api_records:
        score += min(5, len(api_records))
        reasons.append(f"{len(api_records)} API-like request(s)")
    cts = [
        (r.get("content_type") or "").split(";")[0].lower()
        for r in records if r.get("content_type")
    ]
    api_ct = [c for c in cts if any(m in c for m in ("json", "graphql", "grpc", "protobuf", "xml"))]
    if api_ct:
        score += 2
        reasons.append("API content type(s): " + ", ".join(sorted(set(api_ct))[:4]))
    methods = {r.get("method", "") for r in records}
    non_page = sorted(methods - {"", "GET", "HEAD", "OPTIONS"})
    if non_page:
        score += 2
        reasons.append("Non-page HTTP methods: " + ", ".join(non_page))
    api_paths = sorted({r.get("path") for r in records if r.get("api_candidate") and r.get("path")})
    if api_paths:
        score += 2
        reasons.append("API path patterns: " + ", ".join(list(api_paths)[:5]))
    if not records:
        reasons.append("No captured traffic for literal target host")
    return score, reasons


def plan_http_fingerprint_probes(target: str) -> Dict[str, Any]:
    """Low-volume probe plan — do not execute unless the operator authorized active testing."""
    url = target if "://" in (target or "") else f"https://{target or 'example.com'}"
    return {
        "requires_user_authorization": True,
        "executed": False,
        "probes": [
            {"technique": "banner-grabbing GET", "tool": "execute_curl", "url": url},
            {
                "technique": "default error page",
                "tool": "execute_curl",
                "url": url.rstrip("/") + "/__judah_fingerprint_404__",
            },
            {
                "technique": "default files",
                "tool": "execute_curl -I",
                "urls": [url.rstrip("/") + p for p in DEFAULT_PROBE_FILES],
            },
            {
                "technique": "malformed HTTP",
                "note": "Invalid version / XGET — not run by default. Mark coverage not-covered.",
            },
        ],
    }


def _coverage(records: List[Dict[str, Any]], *, active: bool) -> Dict[str, str]:
    has = bool(records)
    headers = any(r.get("tech_headers") for r in records)
    cookies = any(r.get("cookie_names") for r in records)
    errors = any(r.get("error_signatures") or (r.get("status") or 0) >= 400 for r in records)
    files = any(s.get("kind") == "default-file" for r in records for s in r.get("path_signals") or [])
    order = any(r.get("header_order") for r in records)
    return {
        "api_host_discovery": "covered" if has else "not-covered (no captured traffic)",
        "response_header_analysis": "covered" if headers else "not-covered (no Server/X-* on samples)",
        "banner_proxy_identification": "covered" if headers else "not-covered",
        "header_order": "covered-low-confidence" if order else "not-covered (Playwright samples rarely keep order)",
        "default_error_pages": "covered" if errors else "not-covered (no 4xx/5xx bodies in samples)",
        "malformed_http_requests": "not-covered (active-only; not authorized by default)",
        "default_files_directories": "covered" if files else "not-covered (not seen in captured paths)",
        "cookie_parameters": "covered" if cookies else "not-covered",
        "external_corroboration": "out-of-scope (no WhatWeb/Wappalyzer/Shodan in this skill)",
        "active_probes": "executed" if active else "not-covered (plan only)",
    }


def fingerprint_from_samples(
    samples: List[Dict[str, Any]],
    *,
    target: str = "",
    extra_urls: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    parsed = urlparse(target if "://" in (target or "") else f"https://{target or ''}")
    target_host = (parsed.hostname or "").lower()
    records: List[Dict[str, Any]] = []
    for s in samples or []:
        rec = _normalize_sample(s, fallback_host=target_host)
        if rec and rec.get("host"):
            records.append(rec)
    for u in extra_urls or []:
        rec = _normalize_sample({"method": "GET", "url": str(u)}, fallback_host=target_host)
        if rec and rec.get("host") and not any(
            r.get("host") == rec["host"] and r.get("path") == rec.get("path") for r in records
        ):
            records.append(rec)

    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for rec in records:
        if rec.get("host"):
            grouped[rec["host"]].append(rec)
    if target_host and target_host not in grouped:
        grouped[target_host] = []

    fingerprints = []
    indicators: List[Dict[str, str]] = []
    seen_ind: set = set()
    for host, host_records in sorted(grouped.items(), key=lambda kv: (kv[0] != target_host, kv[0])):
        score, reasons = _api_score(host, host_records)
        fingerprints.append({
            "host": host,
            "is_original_target_host": host == target_host,
            "request_count": len(host_records),
            "api_score": score,
            "api_reasons": reasons,
            "is_api_candidate": score >= 3 or host == target_host,
        })
        for rec in host_records:
            for th in rec.get("tech_headers") or []:
                key = f"hdr:{th['name']}:{th['value']}"
                if key not in seen_ind:
                    seen_ind.add(key)
                    indicators.append({
                        "tech": th["name"],
                        "confidence": "high" if th["name"] in {"server", "x-powered-by"} else "medium",
                        "evidence": f"{th['name']}: {th['value']}"[:100],
                    })
            for ck in rec.get("cookie_technologies") or []:
                key = f"ck:{ck['cookie']}"
                if key not in seen_ind:
                    seen_ind.add(key)
                    indicators.append({
                        "tech": ck["technology"],
                        "confidence": "high",
                        "evidence": ck["cookie"],
                    })
            for sig in rec.get("error_signatures") or []:
                key = f"err:{sig['technology']}"
                if key not in seen_ind:
                    seen_ind.add(key)
                    indicators.append({
                        "tech": sig["technology"],
                        "confidence": "high",
                        "evidence": sig["evidence"],
                    })
            blob = rec.get("path") or ""
            if "/api/v1/actions" in blob and "appsmith" not in seen_ind:
                seen_ind.add("appsmith")
                indicators.append({
                    "tech": "appsmith",
                    "confidence": "high",
                    "evidence": blob[:80],
                })
            if "/graphql" in blob.lower() and "graphql" not in seen_ind:
                seen_ind.add("graphql")
                indicators.append({"tech": "graphql", "confidence": "high", "evidence": blob[:80]})
            if "/_next/" in blob and "nextjs" not in seen_ind:
                seen_ind.add("nextjs")
                indicators.append({"tech": "nextjs", "confidence": "medium", "evidence": blob[:80]})

    candidates = sorted(
        [f for f in fingerprints if f["is_api_candidate"]],
        key=lambda x: (not x["is_original_target_host"], -x["api_score"], x["host"]),
    )
    paths = [f"{r['method']} {r['path']}"[:160] for r in records if r.get("path")]
    methods = Counter(r.get("method") or "GET" for r in records)
    blocked = not any(r.get("path") for r in records)
    report = {
        "ok": True,
        "blocked": blocked,
        "target": target,
        "search_domain": related_search_domain(target_host) if target_host else "",
        "source": "captured_traffic",
        "sample_count": len(samples or []),
        "api_host_candidates": [
            {"host": c["host"], "score": c["api_score"], "reasons": c["api_reasons"]}
            for c in candidates[:12]
        ],
        "host_fingerprints": fingerprints[:16],
        "methods": dict(methods),
        "surface_preview": paths[:20],
        "technology_indicators": indicators[:20],
        "coverage": _coverage(records, active=False),
        "recommended_active_probes": plan_http_fingerprint_probes(target or "https://example.com"),
        "next_checks": _next_checks(indicators, paths),
        "note": (
            "Passive on Interceptor/crawl samples (not Caido). "
            "Browse first if blocked. External WhatWeb/Wappalyzer is out of scope here."
        ),
    }
    if blocked:
        report["note"] = (
            "No captured traffic. execute_interceptor / execute_deep_crawl first. "
            "Judah fingerprints from the capability map — Caido is optional, not required."
        )
    return report


def fingerprint_from_map(cmap: Dict[str, Any], *, target: str = "") -> Dict[str, Any]:
    from app.services.agent.request_mutate import samples_from_map

    samples = samples_from_map(cmap if isinstance(cmap, dict) else {})
    extra: List[str] = []
    if isinstance(cmap, dict):
        extra.extend(str(u) for u in (cmap.get("js_files") or [])[:20])
        extra.extend(str(u) for u in (cmap.get("pages_visited") or [])[:20])
        target = target or str(cmap.get("target") or "")
    return fingerprint_from_samples(samples, target=target, extra_urls=extra)


def _next_checks(indicators: List[Dict[str, str]], paths: List[str]) -> List[str]:
    names = {str(i.get("tech") or "").lower() for i in indicators}
    out: List[str] = []
    if "appsmith" in names or any("actions" in p.lower() for p in paths):
        out.append("injection: mutate_captured_request url/datasource/requestUrl → Interactsh")
    if "graphql" in names:
        out.append("graphql_api: introspection + compare_requests on mutations")
    if any("swagger" in n or "openapi" in n for n in names) or any("swagger" in p.lower() for p in paths):
        out.append("api_authz: schema mass-assignment + unauth operations")
    if "nextjs" in names:
        out.append("js_secrets: fetch_lazy_chunks on /_next/static/chunks then extract_js_endpoints")
    if any("php" in n for n in names):
        out.append("content_api: WordPress/PHP paths — mutate_list then authz")
    if not out:
        out.append("content_api: mutate_list paths/params; list_captured_requests → mutate one field")
    out.append("Do not run recommended_active_probes unless the operator authorized active testing")
    return out[:7]
