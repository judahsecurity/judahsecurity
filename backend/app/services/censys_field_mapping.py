"""Validated, per-workspace field mappings for Censys ASM imports.

Identity, organization ownership, and source attribution are deliberately not
configurable. Extra fields live under metadata.censys_asm.custom so vendor
schema changes do not require a database column for every new Censys field.
"""

from __future__ import annotations

import copy
import re
from datetime import datetime, timezone
from typing import Any

ENTITY_TARGETS: dict[str, dict[str, str]] = {
    "host": {
        "operating_system": "text", "asn": "text", "country": "text",
        "country_code": "text", "city": "text", "hosting_provider": "text",
        "http_title": "text", "http_status": "integer", "http_headers": "object",
        "dns_records": "object", "ssl_info": "object", "last_seen": "datetime",
    },
    "domain": {
        "root_domain": "text", "dns_records": "object", "last_seen": "datetime",
    },
    "subdomain": {
        "root_domain": "text", "dns_records": "object", "last_seen": "datetime",
    },
    "certificate": {"ssl_info": "object", "last_seen": "datetime"},
    "risk": {
        "cve_id": "text", "cvss_score": "number", "cvss_vector": "text",
        "evidence": "text", "remediation": "text", "references": "array",
        "first_detected": "datetime", "last_detected": "datetime",
    },
}

_PATH = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*|\[\d{1,3}\])*$")
_CUSTOM = re.compile(r"^custom\.[A-Za-z][A-Za-z0-9_]{0,63}$")
_MISSING = object()
_TEXT_LIMITS = {
    "operating_system": 200, "asn": 50, "country": 100, "country_code": 10,
    "city": 100, "hosting_provider": 100, "http_title": 500,
    "root_domain": 255, "cve_id": 50, "cvss_vector": 100,
}


def validate_rules(rules: list[dict[str, str]]) -> list[dict[str, str]]:
    """Return normalized rules or reject the entire update before saving it."""
    if len(rules) > 50:
        raise ValueError("At most 50 mapping rules are allowed.")
    normalized = []
    seen = set()
    for rule in rules:
        entity = str(rule.get("entity", "")).strip().lower()
        source = str(rule.get("source_path", "")).strip()
        target = str(rule.get("target", "")).strip()
        if entity not in ENTITY_TARGETS:
            raise ValueError(f"Unsupported Censys entity: {entity}")
        if len(source) > 160 or not _PATH.fullmatch(source) or "__" in source:
            raise ValueError(f"Invalid source path: {source[:80]}")
        if target not in ENTITY_TARGETS[entity] and not _CUSTOM.fullmatch(target):
            raise ValueError(f"Unsupported target for {entity}: {target[:80]}")
        key = (entity, source, target)
        if key in seen:
            raise ValueError("Duplicate mapping rule.")
        seen.add(key)
        normalized.append({"entity": entity, "source_path": source, "target": target})
    return normalized


def extract_path(record: dict, path: str) -> Any:
    """Read a dotted path and optional numeric list indexes without eval."""
    value: Any = record
    for part in re.findall(r"[^.\[\]]+|\[\d+\]", path):
        if part.startswith("["):
            index = int(part[1:-1])
            if not isinstance(value, list) or index >= len(value):
                return _MISSING
            value = value[index]
        elif isinstance(value, dict):
            value = value.get(part, _MISSING)
        else:
            return _MISSING
        if value is _MISSING:
            return _MISSING
    return value


def _coerce(value: Any, kind: str) -> Any:
    if value is None:
        return _MISSING
    try:
        if kind == "text":
            if isinstance(value, (dict, list)):
                return _MISSING
            return str(value)[:500]
        if kind == "integer":
            if isinstance(value, bool):
                return _MISSING
            return int(value)
        if kind == "number":
            if isinstance(value, bool):
                return _MISSING
            number = float(value)
            return number if 0 <= number <= 10 else _MISSING
        if kind == "object":
            return copy.deepcopy(value) if isinstance(value, dict) else _MISSING
        if kind == "array":
            return copy.deepcopy(value) if isinstance(value, list) else _MISSING
        if kind == "datetime":
            if isinstance(value, datetime):
                dt = value
            elif isinstance(value, str):
                dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            else:
                return _MISSING
            return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt
    except (ValueError, TypeError, OverflowError):
        pass
    return _MISSING


def mapped_values(record: dict, entity: str, rules: list[dict[str, str]]) -> tuple[dict, dict]:
    """Return canonical field values and namespaced custom values for one record."""
    fields: dict[str, Any] = {}
    custom: dict[str, Any] = {}
    for rule in rules:
        if rule["entity"] != entity:
            continue
        raw = extract_path(record, rule["source_path"])
        if raw is _MISSING or raw is None:
            continue
        target = rule["target"]
        if target.startswith("custom."):
            # Preserve JSON-compatible scalar/object values. Bound one value to
            # avoid a custom mapping filling the entire asset metadata column.
            if len(str(raw)) <= 8192:
                custom[target.removeprefix("custom.")] = copy.deepcopy(raw)
        else:
            value = _coerce(raw, ENTITY_TARGETS[entity][target])
            if value is not _MISSING:
                if isinstance(value, str) and target in _TEXT_LIMITS:
                    value = value[:_TEXT_LIMITS[target]]
                fields[target] = value
    return fields, custom


def apply_mapped_values(row: Any, fields: dict, custom: dict) -> None:
    for key, value in fields.items():
        setattr(row, key, value)
    if custom:
        metadata = dict(row.metadata_ or {})
        namespace = dict(metadata.get("censys_asm") or {})
        values = dict(namespace.get("custom") or {})
        values.update(custom)
        namespace["custom"] = values
        metadata["censys_asm"] = namespace
        row.metadata_ = metadata


def sample_fields(record: dict, max_fields: int = 120) -> list[dict[str, str]]:
    """Expose bounded field paths and examples for the mapping editor."""
    fields: list[dict[str, str]] = []

    def walk(value: Any, path: str, depth: int) -> None:
        if len(fields) >= max_fields or depth > 5:
            return
        if isinstance(value, dict):
            if path:
                fields.append({"path": path, "type": "object", "example": f"{len(value)} fields"})
            for key, child in value.items():
                if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", key):
                    walk(child, f"{path}.{key}" if path else key, depth + 1)
        elif isinstance(value, list):
            if path:
                fields.append({"path": path, "type": "array", "example": f"{len(value)} items"})
            if value:
                walk(value[0], f"{path}[0]", depth + 1)
        elif path:
            fields.append({"path": path, "type": type(value).__name__, "example": str(value)[:100]})

    walk(record, "", 0)
    return fields
