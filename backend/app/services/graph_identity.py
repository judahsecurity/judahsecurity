"""Stable, tenant-scoped identifiers for the attack-surface knowledge graph."""

from __future__ import annotations

import hashlib
from urllib.parse import urljoin, urlsplit, urlunsplit


def canonical_script_url(value: str, base_url: str | None = None) -> str | None:
    """Keep the resource identity while dropping fragments and sensitive query strings."""
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = urljoin(base_url, value.strip()) if base_url else value.strip()
    try:
        parsed = urlsplit(candidate)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        hostname = parsed.hostname.lower().rstrip(".")
        port = parsed.port
        default_port = 80 if parsed.scheme.lower() == "http" else 443
        host = f"[{hostname}]" if ":" in hostname else hostname
        if port and port != default_port:
            host = f"{host}:{port}"
        return urlunsplit((parsed.scheme.lower(), host, parsed.path or "/", "", ""))
    except ValueError:
        return None


def script_key(organization_id: int, url: str) -> str:
    return hashlib.sha256(f"{organization_id}:{url}".encode()).hexdigest()[:32]


def source_file_key(organization_id: int, repository: str, commit: str, path: str) -> str:
    value = f"{organization_id}:{repository}:{commit}:{path}"
    return hashlib.sha256(value.encode()).hexdigest()[:32]
