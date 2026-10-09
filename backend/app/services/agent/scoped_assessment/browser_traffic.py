"""Package browser-observed API exchanges as private, bounded evidence."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import xml.etree.ElementTree as ElementTree
from collections import Counter
from urllib.parse import parse_qsl, urlsplit

from .browser import origin


MAX_EXCHANGES = 40
MAX_BODY_BYTES = 256_000
MAX_URL_LENGTH = 2_048
MAX_BODY_FIELDS = 40
_POSITIVE_INTEGER = re.compile(r"[1-9][0-9]{0,8}\Z")


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
    if mime in {"application/xml", "text/xml"} or mime.endswith("+xml"):
        # XML is inventoried only. Parsing never authorizes a replay or an XXE claim.
        if re.search(rb"<!\s*(?:DOCTYPE|ENTITY)\b", data, re.I):
            return mime, "unsafe_xml", []
        try:
            document = ElementTree.fromstring(data)
        except ElementTree.ParseError:
            return mime, "invalid", []

        def collect_xml(node: ElementTree.Element, path: str, depth: int) -> None:
            if depth > 5 or len(fields) >= MAX_BODY_FIELDS:
                return
            tag = node.tag.rsplit("}", 1)[-1]
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,79}", tag):
                return
            current = f"{path}/{tag}"
            if len(current) > 300:
                return
            if not list(node) and current not in seen:
                seen.add(current)
                fields.append({"location": "xml", "path": current, "value_type": "string"})
            for child in list(node)[:MAX_BODY_FIELDS]:
                collect_xml(child, current, depth + 1)

        collect_xml(document, "", 0)
        return mime, "parsed", fields
    return mime, "unsupported", []


def package_exchange(*, url: str, expected_origin: str, action_ref: str,
                     method: str, resource_type: str, status: int,
                     content_type: str, request_body: bytes,
                     response_body: bytes, request_content_type: str = "") -> tuple[dict, bytes]:
    if origin(url) != expected_origin:
        raise ValueError("Exchange is outside the browser origin")
    if len(url) > MAX_URL_LENGTH:
        raise ValueError("Exchange URL exceeds capture limit")
    if resource_type not in {"xhr", "fetch"}:
        raise ValueError("Only execution-owned API traffic is captured")
    if len(request_body) > MAX_BODY_BYTES or len(response_body) > MAX_BODY_BYTES:
        raise ValueError("Exchange body exceeds capture limit")
    parts = urlsplit(url)
    request_mime, body_fields_status, body_fields = _body_fields(request_body, request_content_type)
    public = {
        "action_ref": action_ref,
        "method": method.upper()[:12],
        "path": (parts.path or "/")[:512],
        "query_keys": sorted({key[:80] for key, _ in parse_qsl(parts.query)})[:20],
        "query_fields": _query_fields(parts.query),
        "request_content_type": request_mime[:80],
        "body_fields_status": body_fields_status,
        "body_fields": body_fields,
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
        "request_body_base64": base64.b64encode(request_body).decode("ascii"),
        "request_content_type": request_mime,
        "response_body_base64": base64.b64encode(response_body).decode("ascii"),
    }, sort_keys=True).encode()
    return public, private
