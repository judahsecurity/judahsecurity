"""
aegis_praetorium.scope — pluggable scope resolver.

Lictor's ``enforce_scope`` pre-hook delegates the "is this target in scope
for this org?" decision to whichever resolver the host application registers.

Two implementations ship in-box:

  - ``AllowAllResolver``  — default; never rejects (used when no host has
                            opted in to scope enforcement)
  - ``HostListResolver``  — accepts hostnames, root domains, or exact
                            ``host:port`` endpoints. Wildcard subdomain
                            matching is built in for portless domain scopes.

The platform agent (`backend/`) registers a SQLAlchemy-backed resolver that
queries its ``Asset`` table by org_id. The Aegis Vanguard agent registers a
``HostListResolver`` from its ``--scope`` CLI flag.

Hosts call ``set_scope_resolver`` once at startup; ``get_scope_resolver`` is
called per-invocation by the Lictor pre-hook.
"""

from __future__ import annotations

from threading import Lock
from typing import Iterable, Optional, Protocol, runtime_checkable
from urllib.parse import urlparse


@runtime_checkable
class ScopeResolver(Protocol):
    """Decide whether a hostname or host:port endpoint is in scope."""

    def is_in_scope(self, hostname: str, *, org_id: Optional[int] = None) -> bool: ...


class AllowAllResolver:
    """Permissive default — useful when no host has wired scope enforcement."""

    def is_in_scope(self, hostname: str, *, org_id: Optional[int] = None) -> bool:
        return True


class HostListResolver:
    """In-memory allowlist with subdomain matching.

    ``HostListResolver(["example.com", "internal.corp.io"])``
        accepts ``foo.example.com``, ``api.example.com``,
        ``deep.internal.corp.io``; rejects ``other-target.com``.
    """

    def __init__(self, allowed: Iterable[str]) -> None:
        self._allowed = set()
        for host in allowed:
            self.add(host)

    @staticmethod
    def _split(value: str) -> tuple[str, Optional[int]]:
        text = (value or "").strip().lower()
        if not text:
            return "", None
        parsed = urlparse(text if "://" in text else f"//{text}")
        try:
            port = parsed.port
        except ValueError:
            return "", None
        if port is None and parsed.scheme == "http":
            port = 80
        elif port is None and parsed.scheme == "https":
            port = 443
        return (parsed.hostname or ""), port

    def add(self, host: str) -> None:
        parsed = self._split(host)
        if parsed[0]:
            self._allowed.add(parsed)

    def is_in_scope(self, hostname: str, *, org_id: Optional[int] = None) -> bool:
        if not hostname:
            return False
        h, port = self._split(hostname)
        if not h:
            return False
        for allowed_host, allowed_port in self._allowed:
            if allowed_port is not None:
                # A port-bearing scope denotes one exact network endpoint.
                if h == allowed_host and port == allowed_port:
                    return True
                continue
            if h == allowed_host or h.endswith(f".{allowed_host}"):
                return True
        return False


_resolver: ScopeResolver = AllowAllResolver()
_resolver_lock = Lock()


def set_scope_resolver(resolver: ScopeResolver) -> None:
    """Install the resolver Lictor will consult. Thread-safe."""
    global _resolver
    with _resolver_lock:
        _resolver = resolver


def get_scope_resolver() -> ScopeResolver:
    """Return the active resolver (defaults to AllowAllResolver)."""
    return _resolver


__all__ = [
    "ScopeResolver",
    "AllowAllResolver",
    "HostListResolver",
    "get_scope_resolver",
    "set_scope_resolver",
]
