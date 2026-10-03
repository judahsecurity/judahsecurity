"""A bounded view of browser-observed and JavaScript-derived inputs.

This is discovery context for the current Aegis agent. It does not execute a
probe, assert a vulnerability, or replace the independent finding gate.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from urllib.parse import parse_qsl, urljoin, urlsplit


_POSITIVE_INTEGER = re.compile(r"[1-9][0-9]{0,8}\Z")
_SAFE_NAME = re.compile(r"[A-Za-z0-9_.\[\]/~-]{1,80}\Z")
_SAFE_JSON_PATH = re.compile(r"/[A-Za-z0-9_.\[\]/~*-]{1,119}\Z")
_CREDENTIAL_NAME = re.compile(r"token|secret|password|api[_-]?key|authorization|session|jwt", re.I)
_STATE_PATH = re.compile(r"^(?:delete|remove|logout|signout|purchase|pay|submit|save|send|create|update|reset|confirm)(?:$|[-_])", re.I)


def _valid_path(path: str) -> bool:
    return (path.startswith("/") and not path.startswith("//") and len(path) <= 300
            and not any(len(part) >= 32 and re.fullmatch(r"[A-Za-z0-9_=-]+", part)
                        for part in path.split("/")))


def _safe_replay_path(path: str) -> bool:
    return _valid_path(path) and not any(
        _STATE_PATH.match(part) or _CREDENTIAL_NAME.search(part)
        for part in path.split("/") if part
    )


def _safe_query_names(query: str) -> bool:
    try:
        return all(not _CREDENTIAL_NAME.search(name)
                   for name, _ in parse_qsl(query, keep_blank_values=True, max_num_fields=80))
    except ValueError:
        return False


def _query_fields(query: str) -> list[dict]:
    try:
        pairs = parse_qsl(query, keep_blank_values=True, max_num_fields=80)
    except ValueError:
        return []
    counts = Counter(name for name, _ in pairs)
    fields = []
    for name, value in pairs:
        if not _SAFE_NAME.fullmatch(name) or any(row["name"] == name for row in fields):
            continue
        value_type = ("repeated" if counts[name] > 1 else
                      "positive_integer" if _POSITIVE_INTEGER.fullmatch(value) else
                      "empty" if not value else "string")
        fields.append({"name": name, "value_type": value_type})
        if len(fields) >= 20:
            break
    return fields


def _body_fields(raw: str, content_type: str) -> list[dict]:
    if not isinstance(raw, str) or len(raw) > 4_000:
        return []
    mime = content_type.split(";", 1)[0].lower().strip()
    if mime == "application/json" or mime.endswith("+json"):
        try:
            document = json.loads(raw)
        except ValueError:
            return []
        fields = []

        def visit(value, path: str, depth: int) -> None:
            if len(fields) >= 40 or depth > 5:
                return
            if isinstance(value, dict):
                for key, child in list(value.items())[:40]:
                    if isinstance(key, str) and _SAFE_NAME.fullmatch(key):
                        visit(child, path + "/" + key.replace("~", "~0").replace("/", "~1"), depth + 1)
            elif isinstance(value, list):
                for child in value[:3]:
                    visit(child, path + "/*", depth + 1)
            elif path and not any(row["name"] == path for row in fields):
                kind = "null" if value is None else "boolean" if isinstance(value, bool) else "number" if isinstance(value, (int, float)) else "string"
                fields.append({"name": path, "location": "json", "value_type": kind})

        visit(document, "", 0)
        return fields
    if mime == "application/x-www-form-urlencoded":
        return [{"name": row["name"], "location": "form", "value_type": "string"}
                for row in _query_fields(raw)[:40]]
    return []


def build_application_surface_inventory(crawl) -> dict:
    """Build same-origin leads without returning query or request-body values."""
    target = urlsplit(getattr(crawl, "target", "") or "")
    if target.scheme not in ("http", "https") or not target.netloc:
        return {"endpoints": [], "parameters": [], "test_suggestions": [], "finding": False}
    expected_origin = (target.scheme.lower(), target.netloc.lower())
    endpoints: dict[str, dict] = {}
    parameters: dict[tuple[str, str, str, str], dict] = {}
    suggestions: dict[tuple[str, str], dict] = {}

    def add_endpoint(path: str, method: str, source: str, action_ref: str = "", source_ref: str = "") -> None:
        if not _valid_path(path):
            return
        row = endpoints.setdefault(path, {"path": path, "methods": set(), "sources": set(),
                                          "action_refs": set(), "source_refs": set()})
        row["methods"].add(method)
        row["sources"].add(source)
        if action_ref:
            row["action_refs"].add(action_ref)
        if source_ref:
            row["source_refs"].add(source_ref)

    def add_parameter(path: str, method: str, location: str, name: str, value_type: str,
                      source: str, action_ref: str = "") -> None:
        valid_name = (_SAFE_JSON_PATH.fullmatch(name) if location == "json"
                      else _SAFE_NAME.fullmatch(name))
        if not _valid_path(path) or not valid_name:
            return
        key = (path, method, location, name)
        row = parameters.setdefault(key, {"path": path, "method": method, "location": location,
                                          "name": name, "value_types": set(), "sources": set(),
                                          "action_refs": set()})
        row["value_types"].add(value_type)
        row["sources"].add(source)
        if action_ref:
            row["action_refs"].add(action_ref)

    for sample in (getattr(crawl, "api_samples", []) or [])[:40]:
        if not isinstance(sample, dict):
            continue
        url = sample.get("url") or ""
        parsed = urlsplit(url)
        if (parsed.scheme.lower(), parsed.netloc.lower()) != expected_origin:
            continue
        path, method = parsed.path or "/", str(sample.get("method") or "GET").upper()[:12]
        ref = str(sample.get("action_ref") or "")[:40]
        add_endpoint(path, method, "live_browser", ref)
        query = _query_fields(parsed.query)
        safe_query = _safe_replay_path(path) and _safe_query_names(parsed.query)
        for field in query:
            add_parameter(path, method, "query", field["name"], field["value_type"], "live_browser", ref)
            if method == "GET" and safe_query:
                kind = "numeric_boolean_review" if field["value_type"] == "positive_integer" else "query_input_review"
                suggestions.setdefault((path, field["name"]), {
                    "kind": kind, "path": path, "method": method, "parameter": field["name"],
                    "action_ref": ref, "priority": 1 if kind == "numeric_boolean_review" else 2,
                    "requires_fresh_proof": True, "finding": False,
                })
        content_type = str((sample.get("headers") or {}).get("content-type") or "")
        for field in _body_fields(sample.get("body") or "", content_type):
            add_parameter(path, method, field["location"], field["name"],
                          field["value_type"], "live_browser", ref)

    sources = getattr(crawl, "js_endpoint_sources", {}) or {}
    for value in sorted(getattr(crawl, "endpoints_from_js", set()) or [])[:200]:
        if not isinstance(value, str):
            continue
        parsed = urlsplit(urljoin(crawl.target, value))
        if (parsed.scheme.lower(), parsed.netloc.lower()) != expected_origin:
            continue
        path = parsed.path or "/"
        source_urls = sorted(sources.get(value, set()))[:5]
        source_refs = [parsed_source.path for item in source_urls
                       if (parsed_source := urlsplit(item)).scheme.lower() == target.scheme.lower()
                       and parsed_source.netloc.lower() == target.netloc.lower()
                       and _valid_path(parsed_source.path or "/")]
        for source_ref in source_refs or [""]:
            add_endpoint(path, "UNKNOWN", "javascript_static", source_ref=source_ref)
        for field in _query_fields(parsed.query):
            add_parameter(path, "UNKNOWN", "query", field["name"], "unknown", "javascript_static")

    def public(row: dict) -> dict:
        return {key: sorted(value) if isinstance(value, set) else value for key, value in row.items()}

    return {
        "endpoints": [public(endpoints[path]) for path in sorted(endpoints)[:100]],
        "parameters": [public(parameters[key]) for key in sorted(parameters)[:120]],
        "test_suggestions": sorted(suggestions.values(), key=lambda row: (row["priority"], row["path"], row["parameter"]))[:20],
        "finding": False,
    }


def merge_application_surface_inventories(old: dict, new: dict) -> dict:
    """Keep bounded discovery context when separate crawls are merged."""
    if not old:
        return new or {}
    if not new:
        return old

    endpoints: dict[str, dict] = {}
    parameters: dict[tuple[str, str, str, str], dict] = {}
    for source in (old, new):
        for row in (source.get("endpoints") or [])[:100]:
            path = row.get("path")
            if not isinstance(path, str) or not _valid_path(path):
                continue
            entry = endpoints.setdefault(path, {"path": path, "methods": set(), "sources": set(),
                                                "action_refs": set(), "source_refs": set()})
            for field in ("methods", "sources", "action_refs", "source_refs"):
                entry[field].update(row.get(field) or [])
        for row in (source.get("parameters") or [])[:120]:
            path, method, location, name = (row.get(field) for field in
                                            ("path", "method", "location", "name"))
            if not isinstance(path, str) or not _valid_path(path) or not all(
                isinstance(item, str) for item in (method, location, name)
            ):
                continue
            key = (path, method, location, name)
            entry = parameters.setdefault(key, {"path": path, "method": method,
                                                 "location": location, "name": name,
                                                 "value_types": set(), "sources": set(),
                                                 "action_refs": set()})
            for field in ("value_types", "sources", "action_refs"):
                entry[field].update(row.get(field) or [])

    suggestions = {}
    for row in (old.get("test_suggestions") or [])[:20] + (new.get("test_suggestions") or [])[:20]:
        if isinstance(row, dict) and row.get("finding") is False:
            key = (row.get("path"), row.get("method"), row.get("parameter"))
            suggestions[key] = row

    def public(row: dict) -> dict:
        return {key: sorted(value) if isinstance(value, set) else value for key, value in row.items()}

    return {
        "endpoints": [public(endpoints[key]) for key in sorted(endpoints)[:100]],
        "parameters": [public(parameters[key]) for key in sorted(parameters)[:120]],
        "test_suggestions": sorted(suggestions.values(), key=lambda row: (
            row.get("priority", 99), str(row.get("path")), str(row.get("parameter"))))[:20],
        "finding": False,
    }
