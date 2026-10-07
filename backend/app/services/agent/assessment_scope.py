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


def prepare_browser_scope(manager, spec: dict, *, fallback_target: str = "") -> dict:
    """Bind an Agent mode browser call to one registered HTTP origin."""
    if not isinstance(spec, dict) or not isinstance(spec.get("actions"), list):
        raise ValueError("Browser actions require a JSON object with an actions array")
    urls = [action.get("url") for action in spec["actions"]
            if isinstance(action, dict) and action.get("url")]
    login = spec.get("login")
    if isinstance(login, dict) and login.get("url"):
        urls.append(login["url"])
    if not urls and fallback_target:
        urls.append(fallback_target)
    if not urls:
        raise ValueError("Browser actions require an assessment URL")
    origins = set()
    for url in urls:
        assert_url_in_scope(manager, str(url))
        parsed = urlsplit(str(url))
        origins.add((parsed.scheme, parsed.hostname.lower(), parsed.port or
                     (443 if parsed.scheme == "https" else 80)))
    if len(origins) != 1:
        raise ValueError("Browser actions must stay on one origin per call")
    bounded = dict(spec)
    bounded["allowed_origin"] = str(urls[0])
    return bounded
