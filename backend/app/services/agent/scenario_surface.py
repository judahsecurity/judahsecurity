"""Small, value-free projection of observed web surface for the scenario map."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

_PARAM_NAME = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_OPAQUE_SEGMENT = re.compile(r"(?<=/)[A-Za-z0-9_-]{32,}(?=/|$)")


def _safe_origin(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = urlsplit(text if "://" in text else f"https://{text}")
        if not parsed.hostname or any(char.isspace() for char in parsed.hostname):
            return ""
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme}://{parsed.hostname.lower()}{port}"
    except ValueError:
        return ""


def _location(value: object, default_origin: str) -> tuple[str, str, list[str]]:
    """Return origin, path and query *names*; never return query values."""
    try:
        parsed = urlsplit(str(value or ""))
        origin = (_safe_origin(f"{parsed.scheme or urlsplit(default_origin).scheme or 'https'}://{parsed.netloc}")
                  if parsed.netloc else default_origin) or default_origin
        path = _OPAQUE_SEGMENT.sub(":id", parsed.path or "/")[:160]
        names = list(dict.fromkeys(
            name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)
            if _PARAM_NAME.fullmatch(name)
        ))[:20]
        return origin, path, names
    except (TypeError, ValueError):
        return default_origin, "/", []


def project_scenario_surface(capability_map: object, engagement_brain: object = None) -> dict:
    """Project persisted observations and declared hypothesis context for the UI.

    Raw request bodies, cookies, URL query values and agent instructions stay out
    of this response. The ledger remains authoritative for hypothesis outcomes.
    """
    cmap = capability_map if isinstance(capability_map, dict) else {}
    brain = engagement_brain if isinstance(engagement_brain, dict) else {}
    default_origin = _safe_origin(cmap.get("target") or brain.get("target"))
    items: list[dict] = []
    seen: set[tuple] = set()

    def add(kind: str, label: str, origin: str, path: str, **extra: str) -> None:
        key = (kind, label, origin, path, extra.get("method", ""))
        if key in seen or len(items) >= 120:
            return
        seen.add(key)
        items.append({"kind": kind, "label": label[:80], "origin": origin,
                      "path": path, **extra})

    pages = list(cmap.get("pages_visited") or []) + [
        row.get("url") for row in (cmap.get("page_inventory") or [])
        if isinstance(row, dict) and row.get("url")
    ]
    for page in pages[:120]:
        origin, path, names = _location(page, default_origin)
        add("directory" if path != "/" and path.endswith("/") else "page",
            path, origin, path)
        for name in names:
            add("parameter", name, origin, path, location="query")

    for row in (cmap.get("api_endpoints") or [])[:100]:
        if not isinstance(row, dict):
            continue
        host = str(row.get("host") or "")
        raw_path = str(row.get("path") or "")
        host_origin = _safe_origin(host)
        if host_origin and default_origin and "://" not in host:
            host_origin = host_origin.replace("https://", f"{urlsplit(default_origin).scheme}://", 1)
        origin, path, names = _location(raw_path, host_origin or default_origin)
        method = str(row.get("method") or "GET").upper()[:8]
        add("endpoint", f"{method} {path}", origin, path, method=method)
        for name in names:
            add("parameter", name, origin, path, location="query")

    for row in (cmap.get("forms") or [])[:80]:
        if not isinstance(row, dict):
            continue
        origin, path, _ = _location(row.get("page") or row.get("action"), default_origin)
        _, action_path, _ = _location(row.get("action") or row.get("page"), origin)
        add("form", str(row.get("method") or "GET").upper()[:8] + " " + action_path,
            origin, path)
        for name in (row.get("inputs") or [])[:40]:
            if isinstance(name, str) and _PARAM_NAME.fullmatch(name):
                add("parameter", name, origin, path, location="form")

    for row in (cmap.get("parameters") or [])[:160]:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "")
        if not _PARAM_NAME.fullmatch(name):
            continue
        origin, path, _ = _location(row.get("page") or row.get("endpoint"), default_origin)
        add("parameter", name, origin, path,
            location=str(row.get("location") or "unknown")[:24])

    contexts: list[dict] = []
    for row in (brain.get("hypotheses") or [])[:300]:
        if not isinstance(row, dict) or not row.get("id"):
            continue
        origin, path, _ = _location(row.get("target"), default_origin)
        evidence = str(row.get("evidence") or "").strip()
        evidence_path = re.sub(r"^(?:GET|POST|PUT|PATCH|DELETE|HEAD)\s+", "", evidence)
        if path == "/" and (evidence_path.startswith("/") or re.fullmatch(r"https?://\S+", evidence_path)):
            evidence_origin, observed_path, _ = _location(evidence_path, origin)
            if any(item["path"] == observed_path and item["origin"] == evidence_origin
                   for item in items):
                origin, path = evidence_origin, observed_path
        parameter = str(row.get("parameter") or "")
        contexts.append({"id": str(row["id"])[:64], "origin": origin,
                         "path": path, "parameter": parameter if _PARAM_NAME.fullmatch(parameter) else ""})

    return {"target": default_origin, "items": items, "contexts": contexts}
