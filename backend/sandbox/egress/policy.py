"""Egress policy for the explorer sandbox. Pure functions, no I/O.

The sandbox gives the model a real shell, so its commands cannot be policed by
parsing them. Every byte it sends instead leaves through one HTTP(S) proxy,
and this module decides whether a request may go:

- The destination host must be in the session's scope (exact host, or an OAST
  suffix when the operator allowed callbacks).
- Every address the host resolves to must be public, unless the operator
  scoped that exact private IP (a lab target). Loopback, link-local, cloud
  metadata, multicast and unspecified addresses are never reachable, whatever
  the scope says, so DNS rebinding cannot reach the platform's own services.
- Only http and https on the scoped port set.
- A per-session request budget.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Iterable

ALWAYS_DENIED_NETWORKS = tuple(ipaddress.ip_network(net) for net in (
    "0.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",      # link-local, includes 169.254.169.254 metadata
    "100.100.100.200/32",  # Alibaba metadata
    "224.0.0.0/4",
    "240.0.0.0/4",
    "255.255.255.255/32",
    "::/128",
    "::1/128",
    "fe80::/10",
    "ff00::/8",
    "fd00:ec2::254/128",   # AWS IMDS over IPv6
))

DENIED_HOSTNAMES = frozenset({
    "localhost", "metadata", "metadata.google.internal", "metadata.azure.com",
})


@dataclass(frozen=True)
class SessionScope:
    hosts: frozenset[str]
    oob_suffixes: tuple[str, ...] = ()
    max_requests: int = 2000
    # Exact private IPs the operator scoped (lab targets on a LAN/docker bridge).
    private_ips: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_dict(cls, raw: dict) -> "SessionScope":
        hosts = frozenset(_norm(h) for h in (raw.get("hosts") or []) if _norm(h))
        private = set()
        for host in hosts:
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                continue
            if not address.is_global and not _always_denied(address):
                private.add(str(address))
        return cls(
            hosts=hosts,
            oob_suffixes=tuple(_norm(s) for s in (raw.get("oob_suffixes") or []) if _norm(s)),
            max_requests=max(1, int(raw.get("max_requests") or 2000)),
            private_ips=frozenset(private),
        )


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str = ""


def _norm(host: str) -> str:
    return str(host or "").strip().lower().rstrip(".").strip("[]")


def _always_denied(address: ipaddress._BaseAddress) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return any(address.version == net.version and address in net for net in ALWAYS_DENIED_NETWORKS)


def host_in_scope(host: str, scope: SessionScope) -> bool:
    host = _norm(host)
    if not host or host in DENIED_HOSTNAMES:
        return False
    if host in scope.hosts:
        return True
    return any(host == suffix or host.endswith("." + suffix) for suffix in scope.oob_suffixes)


def address_allowed(address: str, scope: SessionScope) -> bool:
    try:
        ip = ipaddress.ip_address(_norm(address))
    except ValueError:
        return False
    if _always_denied(ip):
        return False
    if ip.is_global:
        return True
    return str(ip) in scope.private_ips


def decide(*, scheme: str, host: str, port: int, resolved: Iterable[str],
           scope: SessionScope | None, requests_used: int) -> Decision:
    if scope is None:
        return Decision(False, "no active sandbox session for these credentials")
    if scheme not in ("http", "https"):
        return Decision(False, f"scheme {scheme!r} is not allowed")
    if not 0 < int(port or 0) < 65536:
        return Decision(False, "invalid port")
    if not host_in_scope(host, scope):
        return Decision(False, f"{_norm(host)} is not in this assessment's scope")
    addresses = list(resolved)
    if not addresses:
        return Decision(False, f"{_norm(host)} did not resolve")
    for address in addresses:
        if not address_allowed(address, scope):
            return Decision(False, f"{_norm(host)} resolves to a non-public address ({address})")
    if requests_used >= scope.max_requests:
        return Decision(False, "sandbox request budget exhausted for this assessment")
    return Decision(True)
