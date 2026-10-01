"""Bounded application surface inventory from browser and JavaScript observations.

Static source matches and prior observations are leads. Only a fresh browser
exchange can supply an artifact ID for an active test suggestion.
"""

from __future__ import annotations

import re

from .browser_actions import allowed_discovery_path


_CREDENTIAL_FIELD = re.compile(r"(?:token|secret|password|api[_-]?key|authorization|session|jwt)", re.I)
MAX_ENDPOINTS = 100
MAX_PARAMETERS = 120
MAX_TEST_SUGGESTIONS = 20


def build_surface_inventory(result: dict, *, body_replay_paths: set[str] | None = None) -> dict:
    origin = result.get("final_origin", "")
    identity = result.get("identity", "anonymous")
    endpoints: dict[str, dict] = {}
    parameters: dict[tuple[str, str, str, str], dict] = {}
    suggestions: dict[tuple[str, str, str, str], dict] = {}
    allowed_bodies = body_replay_paths or set()

    def endpoint(path: str, method: str, source: str, action_ref: str | None = None,
                 artifact_id: str | None = None) -> None:
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or len(path) > 512:
            return
        row = endpoints.setdefault(path, {"path": path, "methods": set(), "sources": set(),
                                         "action_refs": set(), "artifact_ids": set()})
        row["methods"].add(method)
        row["sources"].add(source)
        if action_ref:
            row["action_refs"].add(action_ref)
        if artifact_id:
            row["artifact_ids"].add(artifact_id)

    def parameter(path: str, method: str, location: str, name: str, source: str,
                  value_type: str = "unknown", action_ref: str | None = None,
                  artifact_id: str | None = None) -> None:
        if not isinstance(name, str) or not 0 < len(name) <= 300:
            return
        key = (path, method, location, name)
        row = parameters.setdefault(key, {"path": path, "method": method, "location": location,
                                          "name": name, "value_types": set(), "sources": set(),
                                          "action_refs": set(), "artifact_ids": set()})
        row["value_types"].add(value_type)
        row["sources"].add(source)
        if action_ref:
            row["action_refs"].add(action_ref)
        if artifact_id:
            row["artifact_ids"].add(artifact_id)

    for request in (result.get("requests") or [])[:100]:
        if not isinstance(request, dict) or request.get("resource_type") not in ("xhr", "fetch"):
            continue
        path, method = request.get("path"), request.get("method")
        if not isinstance(path, str) or not isinstance(method, str):
            continue
        endpoint(path, method, "live_browser", request.get("action_ref"))
        for name in request.get("query_keys") or []:
            parameter(path, method, "query", name, "live_browser",
                      action_ref=request.get("action_ref"))

    for script in (result.get("scripts") or [])[:20]:
        if not isinstance(script, dict):
            continue
        artifact_id, action_ref = script.get("artifact_id"), script.get("action_ref")
        analysis = script.get("analysis") or {}
        for route in (analysis.get("routes") or [])[:80]:
            if isinstance(route, dict):
                for method in (route.get("methods") or ["UNKNOWN"])[:8]:
                    endpoint(route.get("path"), method, "javascript_static", action_ref, artifact_id)
        for lead in (analysis.get("query_leads") or [])[:40]:
            if not isinstance(lead, dict):
                continue
            path, method = lead.get("path"), lead.get("method")
            if not isinstance(path, str) or not isinstance(method, str):
                continue
            for name in (lead.get("names") or [])[:20]:
                parameter(path, method, "query", name, "javascript_static",
                          action_ref=action_ref, artifact_id=artifact_id)

    for traffic in (result.get("traffic") or [])[:40]:
        if not isinstance(traffic, dict):
            continue
        path, method = traffic.get("path"), traffic.get("method")
        artifact_id, action_ref = traffic.get("artifact_id"), traffic.get("action_ref")
        if not isinstance(path, str) or not isinstance(method, str):
            continue
        endpoint(path, method, "live_browser", action_ref, artifact_id)
        query_fields = (traffic.get("query_fields") or [])[:20]
        safe_query = (allowed_discovery_path(path) and
                      all(isinstance(field, dict) and isinstance(field.get("name"), str)
                          and not _CREDENTIAL_FIELD.search(field["name"]) for field in query_fields))
        for field in query_fields:
            if not isinstance(field, dict):
                continue
            name, value_type = field.get("name"), field.get("value_type", "unknown")
            parameter(path, method, "query", name, "live_browser", value_type,
                      action_ref, artifact_id)
            if method != "GET" or not artifact_id or not isinstance(name, str) or not safe_query:
                continue
            operation = "http_sqli_boolean" if value_type == "positive_integer" else "http_query_probe"
            priority = 1 if operation == "http_sqli_boolean" else 2
            key = (path, method, "query", name)
            suggestions.setdefault(key, {"operation": operation, "target": origin + path,
                                          "parameter": name, "artifact_id": artifact_id,
                                          "identity": identity, "priority": priority,
                                          "evidence_level": "observed_live_exchange",
                                          "finding": False})
        for field in (traffic.get("body_fields") or [])[:40]:
            if not isinstance(field, dict):
                continue
            name, location = field.get("path"), field.get("location")
            if location not in ("json", "form"):
                continue
            parameter(path, method, location, name, "live_browser",
                      field.get("value_type", "unknown"), action_ref, artifact_id)
            if (method == "POST" and path in allowed_bodies and artifact_id
                    and isinstance(name, str) and not _CREDENTIAL_FIELD.search(name)):
                key = (path, method, location, name)
                suggestions.setdefault(key, {"operation": "http_body_probe", "target": origin + path,
                                              "parameter": name, "artifact_id": artifact_id,
                                              "identity": identity, "priority": 2,
                                              "evidence_level": "observed_live_exchange",
                                              "finding": False})

    def public(row: dict) -> dict:
        return {key: sorted(value) if isinstance(value, set) else value for key, value in row.items()}

    return {
        "endpoints": [public(endpoints[path]) for path in sorted(endpoints)[:MAX_ENDPOINTS]],
        "parameters": [public(parameters[key]) for key in sorted(parameters)[:MAX_PARAMETERS]],
        "test_suggestions": sorted(suggestions.values(), key=lambda row: (row["priority"], row["target"], row["parameter"]))[:MAX_TEST_SUGGESTIONS],
        "finding": False,
    }
