"""Package browser-observed API exchanges as private, bounded evidence."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections import Counter
from urllib.parse import parse_qsl, urlsplit

from .browser import origin


MAX_EXCHANGES = 120
MAX_BODY_BYTES = 256_000
MAX_URL_LENGTH = 2_048
MAX_BODY_FIELDS = 40
_POSITIVE_INTEGER = re.compile(r"[1-9][0-9]{0,8}\Z")
_GRAPHQL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,79}\Z")


def _replay_headers(headers: dict[str, str] | None, *, expected_origin: str = "") -> dict[str, str]:
    """Keep only fixed, non-credential application headers for a future replay."""
    selected: dict[str, str] = {}
    for name, value in (headers or {}).items():
        key = str(name).lower()
        normalized = str(value).strip()
        if key == "x-requested-with" and normalized.lower() == "xmlhttprequest":
            selected["X-Requested-With"] = "XMLHttpRequest"
        elif key == "accept" and re.fullmatch(r"[A-Za-z0-9/*+.;=, qQ-]{1,160}", normalized):
            selected["Accept"] = normalized
        elif key == "origin" and expected_origin and normalized == expected_origin:
            selected["Origin"] = normalized
        elif key == "referer" and expected_origin and len(normalized) <= MAX_URL_LENGTH:
            try:
                parts = urlsplit(normalized)
                if (origin(normalized) == expected_origin and not parts.fragment
                        and not parts.username and not parts.password):
                    selected["Referer"] = normalized
            except ValueError:
                pass
        elif key in {"apollo-require-preflight", "graphql-require-preflight"} and normalized.lower() == "true":
            selected["Apollo-Require-Preflight" if key.startswith("apollo") else "GraphQL-Require-Preflight"] = "true"
    return selected


def _graphql_shape(data: bytes, mime: str) -> tuple[str, str, str, list[dict]] | None:
    if mime != "application/json" and not mime.endswith("+json"):
        return None
    try:
        document = json.loads(data)
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(document, dict) or not isinstance(document.get("query"), str):
        return None
    query = document["query"].lstrip()
    while query.startswith("#"):
        query = query.partition("\n")[2].lstrip()
    match = re.match(r"(query|mutation|subscription)\b", query)
    operation_type = match.group(1) if match else "query" if query.startswith("{") else "unknown"
    # A document can carry several named operations. Generic replay must not
    # assume the first query is the operation the application actually ran.
    if operation_type == "query" and re.search(r"\b(?:mutation|subscription)\b", query):
        operation_type = "mixed"
    operation_name = document.get("operationName")
    if not isinstance(operation_name, str) or not _GRAPHQL_NAME.fullmatch(operation_name):
        operation_name = ""
    variables = document.get("variables")
    document_hash = hashlib.sha256(document["query"].encode()).hexdigest()
    if not isinstance(variables, dict):
        return operation_type, operation_name, document_hash, []
    _, _, fields = _body_fields(json.dumps({"variables": variables}).encode(), "application/json")
    return operation_type, operation_name, document_hash, fields


def _query_fields(query: str) -> list[dict]:
    """Expose field names and proof-relevant types, never query values."""
    try:
        pairs = parse_qsl(query, keep_blank_values=True, max_num_fields=100)
    except ValueError:
        return []
    counts = Counter(name for name, _ in pairs)
    fields = []
    for name, value in pairs:
        if not 0 < len(name) <= 80 or any(row["name"] == name for row in fields):
            continue
        value_type = ("repeated" if counts[name] > 1 else
                      "positive_integer" if _POSITIVE_INTEGER.fullmatch(value) else
                      "empty" if not value else "string")
        fields.append({"name": name, "value_type": value_type})
        if len(fields) >= 20:
            break
    return fields


def _body_fields(data: bytes, content_type: str) -> tuple[str, str, list[dict]]:
    """Describe input locations and types without returning request values."""
    mime = content_type.split(";", 1)[0].strip().lower()
    if not data:
        return mime, "empty", []
    fields: list[dict] = []
    seen: set[str] = set()
    if mime == "application/json" or mime.endswith("+json"):
        try:
            document = json.loads(data)
        except (UnicodeDecodeError, ValueError):
            return mime, "invalid", []

        def collect(value, path: str, depth: int) -> None:
            if len(fields) >= MAX_BODY_FIELDS or depth > 5:
                return
            if isinstance(value, dict):
                for key, child in list(value.items())[:MAX_BODY_FIELDS]:
                    if not isinstance(key, str) or not 0 < len(key) <= 80:
                        continue
                    segment = key.replace("~", "~0").replace("/", "~1")
                    collect(child, path + "/" + segment, depth + 1)
            elif isinstance(value, list):
                for child in value[:3]:
                    collect(child, path + "/*", depth + 1)
            elif path and path not in seen and len(path) <= 300:
                seen.add(path)
                kind = "null" if value is None else "boolean" if isinstance(value, bool) else "number" if isinstance(value, (int, float)) else "string"
                fields.append({"location": "json", "path": path, "value_type": kind})

        collect(document, "", 0)
        return mime, "parsed", fields
    if mime == "application/x-www-form-urlencoded":
        try:
            pairs = parse_qsl(data.decode("utf-8"), keep_blank_values=True, max_num_fields=100)
        except (UnicodeDecodeError, ValueError):
            return mime, "invalid", []
        for name, _ in pairs:
            if name not in seen and 0 < len(name) <= 80:
                seen.add(name)
                fields.append({"location": "form", "path": name, "value_type": "string"})
                if len(fields) >= MAX_BODY_FIELDS:
                    break
        return mime, "parsed", fields
    return mime, "unsupported", []


def package_exchange(*, url: str, expected_origin: str, action_ref: str,
                     method: str, resource_type: str, status: int,
                     content_type: str, request_body: bytes,
                     response_body: bytes, request_content_type: str = "",
                     page_url: str = "", request_headers: dict[str, str] | None = None) -> tuple[dict, bytes]:
    if origin(url) != expected_origin:
        raise ValueError("Exchange is outside the browser origin")
    if len(url) > MAX_URL_LENGTH:
        raise ValueError("Exchange URL exceeds capture limit")
    if resource_type not in {"xhr", "fetch", "document"}:
        raise ValueError("Only execution-owned browser traffic is captured")
    if len(request_body) > MAX_BODY_BYTES or len(response_body) > MAX_BODY_BYTES:
        raise ValueError("Exchange body exceeds capture limit")
    parts = urlsplit(url)
    if resource_type == "document" and (method.upper() != "GET" or not parts.query):
        raise ValueError("Only input-bearing GET navigations are captured")
    # The rendering page is needed to test XHR responses consumed by a SPA.
    # Keep its query private, just as we do for the captured API URL.
    try:
        valid_page = bool(page_url and len(page_url) <= MAX_URL_LENGTH
                          and origin(page_url) == expected_origin)
    except ValueError:
        valid_page = False
    if not valid_page:
        page_url = ""
    request_mime, body_fields_status, body_fields = _body_fields(request_body, request_content_type)
    graphql = _graphql_shape(request_body, request_mime)
    if graphql is not None:
        body_fields = graphql[3]
    replay_headers = _replay_headers(request_headers, expected_origin=expected_origin)
    public = {
        "action_ref": action_ref,
        "page_path": (urlsplit(page_url).path or "/")[:512] if page_url else "",
        "method": method.upper()[:12],
        "path": (parts.path or "/")[:512],
        "query_keys": sorted({key[:80] for key, _ in parse_qsl(parts.query)})[:20],
        "query_fields": _query_fields(parts.query),
        "request_content_type": request_mime[:80],
        "body_fields_status": body_fields_status,
        "body_fields": body_fields,
        "protocol": "graphql" if graphql is not None else "http",
        "graphql_operation_type": graphql[0] if graphql else "",
        "graphql_operation_name": graphql[1] if graphql else "",
        "graphql_document_sha256": graphql[2] if graphql else "",
        "replay_header_names": sorted(replay_headers),
        "resource_type": resource_type,
        "status": status,
        "content_type": content_type.split(";", 1)[0][:80],
        "request_bytes": len(request_body),
        "response_bytes": len(response_body),
        "request_sha256": hashlib.sha256(request_body).hexdigest(),
        "response_sha256": hashlib.sha256(response_body).hexdigest(),
    }
    # Full URL and bodies stay in the private artifact. No cookie or Authorization
    # header is copied; future replay must draw credentials from a named identity.
    private = json.dumps({
        "url": url,
        "method": method.upper(),
        "resource_type": resource_type,
        "status": status,
        "content_type": content_type,
        "action_ref": action_ref,
        "page_url": page_url,
        "request_body_base64": base64.b64encode(request_body).decode("ascii"),
        "request_content_type": request_mime,
        "replay_headers": replay_headers,
        "graphql_operation_type": graphql[0] if graphql else "",
        "response_body_base64": base64.b64encode(response_body).decode("ascii"),
    }, sort_keys=True).encode()
    return public, private
