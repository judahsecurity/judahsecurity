"""Value-free parameter inventory for specialist assignment and coverage.

Only names, locations, paths, and evidence references enter the agent map.
Request values, cookies, headers, and bodies are never copied into this ledger.
"""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urljoin, urlsplit

MAX_PARAMETERS = 4000
_NAME = re.compile(r"[A-Za-z_/][A-Za-z0-9_./*\[\]-]{0,79}\Z")
_PROTECTED = re.compile(r"csrf|xsrf|nonce|session|token|secret|api[_-]?key|authorization|jwt|bearer", re.I)
_XSS_HINT = re.compile(r"q|query|search|term|name|title|message|comment|content|text|html|redirect|url", re.I)
_SQL_HINT = re.compile(r"id|key|filter|sort|page|limit|offset|search|query|email|user|order", re.I)
_LOCATIONS = {"query", "form", "body_json", "body_form"}


def _origin(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        return ""
    try:
        port = parts.port
    except ValueError:
        return ""
    default = 443 if parts.scheme == "https" else 80
    return f"{parts.scheme}://{parts.hostname.lower()}" + (f":{port}" if port and port != default else "")


def _base(cmap: dict) -> str:
    for candidate in (cmap.get("scope"), cmap.get("target")):
        if isinstance(candidate, str) and _origin(candidate):
            return _origin(candidate)
    return ""


def _resolved(raw: str, base: str) -> tuple[str, str]:
    if not isinstance(raw, str) or not raw or not base:
        return "", ""
    full = urljoin(base + "/", raw)
    parts = urlsplit(full)
    if _origin(full) != base:
        return "", ""
    return parts.path or "/", parts.query


def collect_parameter_inventory(cmap: dict) -> list[dict]:
    """Merge observed forms, URLs, API samples, and service metadata."""
    base = _base(cmap)
    if not base:
        return []
    rows: dict[tuple[str, str, str, str, str], dict] = {}

    def add(*, method: str, url: str, name: str, location: str,
            source: str, value_type: str = "", identity: str = "",
            artifact_id: str = "") -> None:
        if (not isinstance(name, str) or not _NAME.fullmatch(name)
                or location not in _LOCATIONS):
            return
        path, _ = _resolved(url, base)
        if not path:
            return
        method = str(method or "GET").upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            return
        key = (method, path, location, name, str(identity or "anonymous")[:80])
        row = {
            "method": method, "host": urlsplit(base).netloc, "path": path,
            "name": name, "location": location, "source": str(source)[:40],
            "value_type": str(value_type or "")[:40],
            "identity": key[4], "artifact_id": str(artifact_id or "")[:80],
            "testable": not bool(_PROTECTED.search(name)),
        }
        prior = rows.get(key)
        if prior is None:
            if len(rows) < MAX_PARAMETERS:
                rows[key] = row
        elif artifact_id and not prior.get("artifact_id"):
            rows[key] = row

    def query(url: str, method: str, source: str, identity: str = "",
              artifact_id: str = "") -> None:
        path, raw_query = _resolved(url, base)
        if not path:
            return
        try:
            pairs = parse_qsl(raw_query, keep_blank_values=True, max_num_fields=100)
        except ValueError:
            return
        for name, _ in pairs[:40]:
            add(method=method, url=url, name=name, location="query",
                source=source, identity=identity, artifact_id=artifact_id)

    for page in (cmap.get("pages_visited") or [])[:120]:
        if isinstance(page, str):
            query(page, "GET", "page_url")

    for form in (cmap.get("forms") or [])[:80]:
        if not isinstance(form, dict):
            continue
        method = str(form.get("method") or "GET").upper()
        action = str(form.get("action") or form.get("page") or cmap.get("target") or "")
        if not action:
            continue
        query(action, method, "form_action")
        for field in (form.get("fields") or form.get("inputs") or [])[:60]:
            name = field.get("name") if isinstance(field, dict) else field
            value_type = field.get("control_type", "") if isinstance(field, dict) else ""
            add(method=method, url=action, name=name,
                location="query" if method == "GET" else "form",
                source="observed_form", value_type=value_type)

    for endpoint in (cmap.get("api_endpoints") or [])[:300]:
        if not isinstance(endpoint, dict):
            continue
        path = str(endpoint.get("path") or "")
        host = str(endpoint.get("host") or urlsplit(base).netloc)
        url = path if path.startswith(("http://", "https://")) else f"{urlsplit(base).scheme}://{host}/{path.lstrip('/')}"
        query(url, str(endpoint.get("method") or "GET"), "api_endpoint")
        for name in (endpoint.get("query_keys") or [])[:40]:
            add(method=str(endpoint.get("method") or "GET"), url=url,
                name=name, location="query", source="api_endpoint")

    for sample in (cmap.get("api_samples") or [])[:80]:
        if not isinstance(sample, dict):
            continue
        method = str(sample.get("method") or "GET")
        url = str(sample.get("url") or "")
        query(url, method, "captured_api")
        body = sample.get("body")
        if isinstance(body, str) and len(body) <= 16_000:
            try:
                body = json.loads(body)
            except ValueError:
                content_type = str((sample.get("headers") or {}).get("content-type") or "").lower()
                if "application/x-www-form-urlencoded" in content_type:
                    try:
                        for name, _ in parse_qsl(body, keep_blank_values=True, max_num_fields=100)[:40]:
                            add(method=method, url=url, name=name, location="body_form", source="captured_api")
                    except ValueError:
                        pass
                body = None
        if isinstance(body, dict):
            def walk_json(value: dict, prefix: str = "", depth: int = 0) -> None:
                if depth > 3:
                    return
                for key, child in list(value.items())[:40]:
                    if not isinstance(key, str):
                        continue
                    name = f"{prefix}.{key}" if prefix else key
                    if isinstance(child, dict):
                        walk_json(child, name, depth + 1)
                    else:
                        add(method=method, url=url, name=name, location="body_json", source="captured_api")
            walk_json(body)

    for raw in (cmap.get("parameter_inventory") or [])[:MAX_PARAMETERS]:
        if not isinstance(raw, dict):
            continue
        url = str(raw.get("url") or "") or base + str(raw.get("path") or "")
        add(method=raw.get("method", "GET"), url=url, name=raw.get("name"),
            location=raw.get("location", "query"), source=raw.get("source", "service"),
            value_type=raw.get("value_type", ""), identity=raw.get("identity", ""),
            artifact_id=raw.get("artifact_id", ""))

    return sorted(rows.values(), key=lambda row: (
        row["host"], row["path"], row["method"], row["location"], row["name"], row["identity"],
    ))


def parameters_for_specialist(cmap: dict, specialist: str) -> list[dict]:
    rows = [row for row in collect_parameter_inventory(cmap) if row["testable"]]
    if specialist not in {"xss", "sqli", "injection"}:
        return rows

    def rank(row: dict) -> tuple:
        return (parameter_priority(row, specialist), row["path"], row["name"])

    return sorted(rows, key=rank)


def parameter_priority(row: dict, specialist: str) -> int:
    """Order likely sinks first without removing lower-signal observed inputs."""
    name = str(row.get("name") or "")
    value_type = str(row.get("value_type") or "")
    if specialist == "xss":
        favored = bool(_XSS_HINT.search(name)) or value_type in {"search", "text", "textarea"}
    elif specialist == "sqli":
        favored = bool(_SQL_HINT.search(name)) or value_type in {"positive_integer", "number"}
    else:
        favored = bool(_XSS_HINT.search(name) or _SQL_HINT.search(name))
    observed = row.get("source") in {"observed_form", "captured_api", "browser_traffic"}
    return 0 if favored and observed else 1 if favored else 2
