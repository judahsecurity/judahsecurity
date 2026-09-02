"""
Passive HTTP fingerprinting → hunter targeting.

Higher success rate comes from spending the budget where the stack is weak. This
infers the technology stack from traffic ALREADY captured in the session store
(headers, cookie names, error shapes, gateway/CDN clues) — passive, no new
requests — then maps each detected stack to the vulnerability classes worth
prioritising, so hunters aim instead of spray.

Heuristics distilled from the YesWeHack "HTTP fingerprinting" recon series and
the api-fingerprint-caido skill's technique matrix, ported to run over any
captured responses (not just Caido).
"""

import logging
import re
from collections import OrderedDict
from typing import Dict, List, Optional

logger = logging.getLogger("agent.fingerprint")

# cookie name (lowercased) → (tech, category)
_COOKIE_TECH = {
    "phpsessid": ("PHP", "language"),
    "ci_session": ("CodeIgniter (PHP)", "framework"),
    "laravel_session": ("Laravel (PHP)", "framework"),
    "jsessionid": ("Java servlet", "language"),
    "asp.net_sessionid": ("ASP.NET", "framework"),
    ".aspnetcore.session": ("ASP.NET Core", "framework"),
    "cfid": ("Adobe ColdFusion", "framework"),
    "cftoken": ("Adobe ColdFusion", "framework"),
    "connect.sid": ("Express (Node.js)", "framework"),
    "_rails_session": ("Ruby on Rails", "framework"),
    "csrftoken": ("Django", "framework"),
    "sessionid": ("Django", "framework"),
}

# header name (lowercased) → category label; value is inspected for the product
_HEADER_TECH_NAMES = {
    "x-powered-by": "framework",
    "x-powered-cms": "framework",
    "x-aspnet-version": "framework",
    "x-aspnetmvc-version": "framework",
    "x-drupal-cache": "cms",
    "x-generator": "cms",
    "x-shopify-stage": "saas",
    "x-varnish": "proxy",
    "via": "proxy",
    "x-amzn-requestid": "api_gateway",
    "x-amz-apigw-id": "api_gateway",
    "x-kong-upstream-latency": "api_gateway",
    "x-envoy-upstream-service-time": "proxy",
    "cf-ray": "cdn",
    "cf-cache-status": "cdn",
    "x-served-by": "cdn",
}

_SERVER_HINTS = [
    (re.compile(r"nginx", re.I), "nginx", "server"),
    (re.compile(r"apache", re.I), "Apache", "server"),
    (re.compile(r"microsoft-iis|iis/", re.I), "IIS", "server"),
    (re.compile(r"tomcat|coyote", re.I), "Apache Tomcat", "server"),
    (re.compile(r"cloudflare", re.I), "Cloudflare", "cdn"),
    (re.compile(r"awselb|elasticbeanstalk", re.I), "AWS ELB", "infra"),
    (re.compile(r"gunicorn", re.I), "Gunicorn (Python)", "server"),
    (re.compile(r"express", re.I), "Express (Node.js)", "framework"),
    (re.compile(r"kestrel", re.I), "ASP.NET Core (Kestrel)", "framework"),
]

# body error-shape signatures → (tech, category)
_ERROR_SIGNATURES = [
    (re.compile(r'"timestamp".{0,40}"status".{0,40}"error".{0,40}"path"', re.S), "Spring Boot", "framework"),
    (re.compile(r"application/problem\+json|\"type\".{0,40}\"title\".{0,40}\"status\"", re.S), "RFC7807 API", "api"),
    (re.compile(r"Traceback \(most recent call last\)|Django Version", re.I), "Django (debug)", "framework"),
    (re.compile(r"Action Controller: Exception|rails\.version", re.I), "Ruby on Rails (debug)", "framework"),
    (re.compile(r"Cannot (GET|POST) /|<pre>Error: ", re.I), "Express (Node.js)", "framework"),
    (re.compile(r"Whoops, looks like something went wrong|laravel", re.I), "Laravel (PHP)", "framework"),
    (re.compile(r"Warning:.*on line \d+ in|<b>Fatal error</b>", re.I), "PHP", "language"),
]

# detected tech (matched by substring, case-insensitive) → vuln classes to prioritise
_FOCUS = [
    ("php", ["lfi/rfi", "php deserialization (phar)", "type juggling"], "injection"),
    ("coldfusion", ["known-CVE LFI/RCE", "path traversal"], "injection"),
    ("spring", ["SSRF via actuator", "actuator exposure", "java deserialization"], "ssrf"),
    ("java", ["deserialization", "SSRF", "XXE"], "ssrf"),
    ("tomcat", ["manager/host-manager exposure", "path normalization"], "authz"),
    ("express", ["prototype pollution", "NoSQL injection", "SSRF"], "injection"),
    ("node", ["prototype pollution", "SSRF", "NoSQL injection"], "injection"),
    ("django", ["SSTI", "SQLi via extra()/raw()", "open redirect"], "injection"),
    ("rails", ["mass assignment", "Marshal deserialization", "SSTI"], "authz"),
    ("asp.net", ["ViewState deserialization", "path traversal"], "injection"),
    ("drupal", ["known-CVE RCE (Drupalgeddon)", "access bypass"], "injection"),
    ("shopify", ["app-proxy SSRF", "OAuth/scope abuse"], "authz"),
    ("api_gateway", ["authorization bypass", "route/verb tampering", "mass assignment"], "authz"),
]


def _match_focus(techs: List[str]) -> List[dict]:
    text = " ".join(techs).lower()
    focus = []
    for needle, classes, hunter in _FOCUS:
        if needle in text:
            focus.append({"stack": needle, "prioritize": classes, "hunter": hunter})
    return focus


def _headers_lower(headers: Dict[str, str]) -> "OrderedDict[str, str]":
    out: "OrderedDict[str, str]" = OrderedDict()
    for k, v in (headers or {}).items():
        out[str(k).lower()] = str(v)
    return out


def fingerprint_response(status: int, headers: Dict[str, str], body: str = "",
                         set_cookie: str = "") -> List[dict]:
    """Return technology signals from one response: {tech, category, confidence,
    evidence, source}."""
    signals: List[dict] = []
    h = _headers_lower(headers)

    def add(tech, category, confidence, evidence, source):
        signals.append({"tech": tech, "category": category, "confidence": confidence,
                        "evidence": str(evidence)[:160], "source": source})

    # Direct technology headers
    for name, category in _HEADER_TECH_NAMES.items():
        if name in h:
            val = h[name]
            has_version = bool(re.search(r"\d", val))
            add(val or name, category, "high" if has_version else "medium",
                f"{name}: {val}", "header")

    # Server banner
    server = h.get("server", "")
    for rx, tech, cat in _SERVER_HINTS:
        if server and rx.search(server):
            add(tech, cat, "high" if re.search(r"\d", server) else "medium",
                f"Server: {server}", "header")

    # Cookies (from headers dict or explicit set_cookie blob)
    cookie_blob = " ".join(filter(None, [h.get("set-cookie", ""), set_cookie, h.get("cookie", "")]))
    for cname, (tech, cat) in _COOKIE_TECH.items():
        if re.search(rf"\b{re.escape(cname)}\b", cookie_blob, re.I):
            add(tech, cat, "high", f"cookie {cname}", "cookie")

    # Error-shape body signatures
    if body:
        for rx, tech, cat in _ERROR_SIGNATURES:
            if rx.search(body):
                add(tech, cat, "high", f"error-shape match: {tech}", "error_body")

    return signals


def fingerprint_transactions(transactions) -> dict:
    """Aggregate signals across captured transactions and recommend targeting.

    `transactions` is an iterable of objects with `.response` (HttpResponse) and
    `.request` (HttpRequest) — i.e. SessionStore transactions.
    """
    all_signals: List[dict] = []
    hosts = set()
    for t in transactions or []:
        resp = getattr(t, "response", None)
        req = getattr(t, "request", None)
        if resp is None:
            continue
        if req is not None:
            m = re.search(r"https?://([^/]+)", getattr(req, "url", "") or "")
            if m:
                hosts.add(m.group(1))
        all_signals.extend(fingerprint_response(
            getattr(resp, "status", 0), getattr(resp, "headers", {}) or {},
            getattr(resp, "body", "") or ""))

    # dedupe by (tech, source), keep highest confidence
    order = {"high": 3, "medium": 2, "low": 1}
    best: Dict[tuple, dict] = {}
    for s in all_signals:
        key = (s["tech"], s["source"])
        if key not in best or order[s["confidence"]] > order[best[key]["confidence"]]:
            best[key] = s
    techs = sorted({s["tech"] for s in best.values()})
    focus = _match_focus([s["tech"] for s in best.values()])

    return {
        "hosts": sorted(hosts),
        "technologies": list(best.values()),
        "detected": techs,
        "recommended_focus": focus,
        "summary": (f"{len(techs)} technology signal(s); "
                    f"{len(focus)} targeted focus area(s). Prioritise the named "
                    f"vuln classes for the detected stack."),
    }
