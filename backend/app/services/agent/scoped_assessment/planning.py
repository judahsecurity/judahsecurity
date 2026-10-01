"""Evidence-led assessment work derived from browser observations."""

from __future__ import annotations

from urllib.parse import urlsplit


def routes_from_observation(result: dict) -> list[dict]:
    """Recommend bounded follow-ups; these are leads, never findings."""
    routes: list[dict] = []
    detection = result.get("technology_detection") or {}
    if (detection.get("engine") == "wappalyzer-offline" and detection.get("status") == "ok"):
        matches = detection.get("matches") or []
        if any(row.get("name") == "WordPress" and row.get("confidence", 0) >= 90
               for row in matches if isinstance(row, dict)):
            routes.append({"specialist": "wordpress_assessment", "reason": "observed_wordpress_signature",
                           "status": "recommended"})
    requests = result.get("requests") or []
    if any(row.get("method") == "GET" and row.get("resource_type") in ("fetch", "xhr")
           and isinstance(row.get("path"), str) and (row["path"].startswith("/api/") or
           row["path"].startswith("/graphql")) for row in requests if isinstance(row, dict)):
        routes.append({"specialist": "api_assessment", "reason": "observed_api_request",
                       "status": "recommended"})
    pages = result.get("pages") or []
    paths = [urlsplit(row.get("url", "")).path.lower() for row in pages if isinstance(row, dict)]
    for value in (result.get("target_template"), result.get("final_path")):
        if isinstance(value, str):
            paths.append(urlsplit(value).path.lower())
    if any(any(marker in path for marker in ("/login", "/signin", "/account", "/auth/")) for path in paths):
        routes.append({"specialist": "auth_assessment", "reason": "observed_auth_page",
                       "status": "recommended"})
    return routes


def coverage_from_observation(result: dict) -> list[dict]:
    """Seed concrete checks only from paths the browser observed."""
    rows = []
    for target in (result.get("directory_candidates") or [])[:8]:
        if isinstance(target, str):
            rows.append({"kind": "directory_index", "target": target,
                         "hypothesis": "An observed parent directory may expose an anonymous index",
                         "priority": 2, "expected_operation": "http_get"})
    origin = result.get("final_origin")
    for request in (result.get("requests") or [])[:100]:
        if not isinstance(request, dict) or request.get("method") != "GET":
            continue
        if request.get("resource_type") not in ("fetch", "xhr"):
            continue
        path = request.get("path")
        if isinstance(origin, str) and isinstance(path, str) and path.startswith("/") and not path.startswith("//"):
            rows.append({"kind": "api_observation", "target": origin + path,
                         "hypothesis": "Record the anonymous response shape of this observed API path",
                         "priority": 2, "expected_operation": "http_get"})
    return rows[:20]
