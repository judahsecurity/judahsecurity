"""Bounded, passive leads from JavaScript loaded by the scoped browser.

These signals are discovery hints. None is an independently verified finding.
"""

from __future__ import annotations

import re
from itertools import islice
from urllib.parse import parse_qsl, urljoin, urlsplit

from .browser import origin


MAX_SOURCE_BYTES = 1_000_000
MAX_SOURCES = 20
_LITERAL = re.compile(r"[\"'`]([^\"'`\r\n]{1,300})[\"'`]")
_CALL = re.compile(
    r"\b(fetch|axios\.(?:get|post|put|patch|delete)|\$\.(?:get|post)|jQuery\.(?:get|post))\s*\(\s*[\"'`]([^\"'`]{1,300})[\"'`]",
    re.I,
)
_XHR = re.compile(
    r"\.open\s*\(\s*[\"'`](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[\"'`]\s*,\s*[\"'`]([^\"'`]{1,300})[\"'`]",
    re.I,
)
_SINKS = {
    "html_assignment": re.compile(r"\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\s*\(|document\.write\s*\("),
    "dynamic_code": re.compile(r"\beval\s*\(|new\s+Function\s*\("),
    "message_listener": re.compile(r"addEventListener\s*\(\s*[\"']message[\"']|\.onmessage\s*="),
    "navigation": re.compile(r"(?:window\.)?location\.(?:href|assign|replace)\s*[=(]|window\.open\s*\("),
}
_DOM_SOURCES = {
    "fragment": re.compile(r"(?:window\.)?location\.hash\b"),
    "query": re.compile(r"(?:window\.)?location\.search\b|\bURLSearchParams\s*\("),
}
_TRANSFORMS = {
    "uri_decode": re.compile(r"\bdecodeURI(?:Component)?\s*\("),
    "base64_decode": re.compile(r"\batob\s*\("),
    "html_parse": re.compile(r"\bDOMParser\s*\(|\.parseFromString\s*\("),
}
_CLIENT_SINKS = {
    "dom_open_redirect": re.compile(r"(?:window\.)?location\.(?:href\s*=|assign\s*\(|replace\s*\()|window\.open\s*\("),
    "dom_link_manipulation": re.compile(r"\.href\s*=|\.setAttribute\s*\(\s*['\"]href['\"]\s*,"),
    "dom_data_manipulation": re.compile(r"\.(?:textContent|innerText|value)\s*=|\.setAttribute\s*\("),
    "request_url_override": re.compile(r"\bfetch\s*\(\s*(?!['\"`])|\.open\s*\(\s*['\"](?:GET|POST)['\"]\s*,\s*(?!['\"`])", re.I),
    "client_template_injection": re.compile(r"\b(?:Handlebars\.compile|_\.template|\$compile|angular\.bootstrap)\s*\("),
    "prototype_pollution": re.compile(r"\b(?:Object\.assign|(?:\$|jQuery)\.extend|_\.merge|lodash\.merge|deparam)\s*\("),
}
_MAP = re.compile(r"[#@]\s*sourceMappingURL=([^\s*]+)")
_NOISE = (".js", ".mjs", ".css", ".png", ".jpg", ".svg", ".woff", ".map")


def _route(value: str, script_url: str, expected_origin: str, *, source_map: bool = False) -> str | None:
    if not source_map and not value.startswith(("/", "http://", "https://")):
        return None
    if any(char in value for char in ("{", "}", "<", ">", "\\", " ")):
        return None
    try:
        resolved = urljoin(script_url, value)
        if origin(resolved) != expected_origin:
            return None
        path = urlsplit(resolved).path or "/"
    except ValueError:
        return None
    if not path.startswith("/") or len(path) > 300 or (not source_map and path.lower().endswith(_NOISE)):
        return None
    # Avoid emitting values that resemble a credential embedded in a path.
    if any(len(part) >= 32 and re.fullmatch(r"[A-Za-z0-9_=-]+", part) for part in path.split("/")):
        return None
    return path


def analyze_javascript(data: bytes, *, source_url: str, expected_origin: str) -> dict:
    """Return route and sink locations without exposing source or secret values."""
    if len(data) > MAX_SOURCE_BYTES:
        raise ValueError("JavaScript source exceeds byte budget")
    text = data.decode("utf-8", errors="replace")
    routes: dict[str, set[str]] = {}
    query_leads: dict[tuple[str, str], set[str]] = {}

    def add_query_leads(value: str, path: str, method: str) -> None:
        try:
            pairs = parse_qsl(urlsplit(value).query, keep_blank_values=True, max_num_fields=40)
        except ValueError:
            return
        names = {name for name, _ in pairs if 0 < len(name) <= 80}
        if names:
            query_leads.setdefault((path, method), set()).update(names)

    for match in _CALL.finditer(text):
        method = match.group(1).rsplit(".", 1)[-1].upper()
        method = "GET?" if method == "FETCH" else method
        route = _route(match.group(2), source_url, expected_origin)
        if route:
            routes.setdefault(route, set()).add(method)
            add_query_leads(match.group(2), route, method)
    for match in _XHR.finditer(text):
        route = _route(match.group(2), source_url, expected_origin)
        if route:
            routes.setdefault(route, set()).add(match.group(1).upper())
            add_query_leads(match.group(2), route, match.group(1).upper())
    for match in _LITERAL.finditer(text):
        value = match.group(1)
        if not value.startswith(("/api/", "/graphql", "/rest/", "/v1/", "/v2/")):
            continue
        route = _route(value, source_url, expected_origin)
        if route:
            already_known = route in routes
            routes.setdefault(route, set())
            if not already_known:
                add_query_leads(value, route, "UNKNOWN")
    sinks = []
    for kind, pattern in _SINKS.items():
        for match in islice(pattern.finditer(text), 5):
            sinks.append({"kind": kind, "line": text.count("\n", 0, match.start()) + 1})
    sources = []
    for kind, pattern in _DOM_SOURCES.items():
        for match in islice(pattern.finditer(text), 5):
            sources.append({"kind": kind, "line": text.count("\n", 0, match.start()) + 1})
    transforms = []
    for kind, pattern in _TRANSFORMS.items():
        for match in islice(pattern.finditer(text), 4):
            transforms.append({"kind": kind, "line": text.count("\n", 0, match.start()) + 1})
    # Co-located source and sink patterns are review leads, never data-flow proof.
    client_leads = []
    if sources:
        for kind, pattern in _CLIENT_SINKS.items():
            for match in islice(pattern.finditer(text), 3):
                client_leads.append({"kind": kind, "line": text.count("\n", 0, match.start()) + 1})
    maps = []
    for match in islice(_MAP.finditer(text), 3):
        value = match.group(1)
        if value.startswith("data:"):
            continue
        route = _route(value, source_url, expected_origin, source_map=True)
        if route and route.endswith(".map"):
            maps.append(route)
    return {
        "routes": [{"path": path, "methods": sorted(methods) if methods else ["UNKNOWN"]}
                   for path, methods in sorted(routes.items())[:80]],
        "sink_leads": sinks[:30],
        "source_leads": sources[:10],
        "transform_leads": transforms[:12],
        "client_leads": client_leads[:18],
        "query_leads": [{"path": path, "method": method, "names": sorted(names)[:20]}
                        for (path, method), names in sorted(query_leads.items())[:40]],
        "source_map_paths": sorted(set(maps)),
        "finding": False,
    }
