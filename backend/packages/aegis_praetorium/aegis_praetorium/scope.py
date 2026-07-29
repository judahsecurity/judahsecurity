"""
aegis_praetorium.scope — pluggable scope resolver.

Lictor's ``enforce_scope`` pre-hook delegates the "is this hostname in scope
for this org?" decision to whichever resolver the host application registers.

Two implementations ship in-box:

  - ``AllowAllResolver``  — default; never rejects (used when no host has
                            opted in to scope enforcement)
  - ``HostListResolver``  — accepts a list of allowed hostnames / root
                            domains. Wildcard subdomain matching is built in:
                            "example.com" matches "foo.example.com".

The platform agent (`backend/`) registers a SQLAlchemy-backed resolver that
queries its ``Asset`` table by org_id. The Aegis Vanguard agent registers a
``HostListResolver`` from its ``--scope`` CLI flag.

Hosts call ``set_scope_resolver`` once at startup; ``get_scope_resolver`` is
called per-invocation by the Lictor pre-hook.
"""

from __future__ import annotations

from threading import Lock
from typing import Iterable, Optional, Protocol, runtime_checkable


@runtime_checkable
class ScopeResolver(Protocol):
    """Decide whether a hostname is in scope for the calling org."""

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
        self._allowed = {h.strip().lower() for h in allowed if h and h.strip()}

    def add(self, host: str) -> None:
        if host and host.strip():
            self._allowed.add(host.strip().lower())

    def is_in_scope(self, hostname: str, *, org_id: Optional[int] = None) -> bool:
        if not hostname:
            return False
        h = hostname.strip().lower()
        if h in self._allowed:
            return True
        # Subdomain match: "foo.bar.example.com" is allowed if "example.com" is.
        parts = h.split(".")
        for i in range(len(parts) - 1):
            if ".".join(parts[i:]) in self._allowed:
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
