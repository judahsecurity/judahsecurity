"""Deterministic network scope checks for assessment-owned HTTP traffic."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit


def _host(value: str) -> str:
    parsed = urlsplit(value if "://" in value else f"https://{value}")
    return (parsed.hostname or "").strip().lower().rstrip(".")


def register_scope(manager, *targets: str) -> set[str]:
    """Add operator/orchestrator supplied targets to this assessment session."""
    scope = manager._assessment_scope
    for target in targets:
        host = _host(str(target or ""))
        if host:
            scope.add(host)
    return set(scope)


def allowed_hosts(manager) -> set[str]:
    from app.services.agent.assessment_sessions import identity_registry
    from app.services.agent.tools import current_seed_target

    hosts = set(getattr(manager, "_assessment_scope", set()) or set())
    for target in (
        current_seed_target.get(),
        getattr(manager, "_fallback_target", ""),
    ):
        host = _host(str(target or ""))
        if host:
            hosts.add(host)
    registry = identity_registry(manager)
    for identity in registry.identities.values():
        host = _host(identity.get("target", ""))
        if host:
            hosts.add(host)
    return hosts


def assert_url_in_scope(manager, url: str) -> str:
    """Reject network destinations not explicitly registered for this assessment."""
    parsed = urlsplit(str(url or ""))
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("An absolute HTTP(S) assessment URL is required")
    if parsed.username or parsed.password:
        raise ValueError("Embedded URL credentials are not allowed")
    host = parsed.hostname.lower().rstrip(".")
    scope = allowed_hosts(manager)
    if not scope:
        raise ValueError("No assessment network scope is registered")
    exact = host in scope
    wildcard = any(
        item.startswith("*.") and host.endswith(item[1:]) and host != item[2:]
        for item in scope
    )
    if not exact and not wildcard:
        raise ValueError(f"Out-of-scope network destination blocked: {host}")
    # Literal special-use addresses are usable only when the operator registered
    # that exact address. This avoids suffix tricks while keeping local labs usable.
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if not exact:
            raise ValueError("IP address destinations require an exact scope entry")
    return host
