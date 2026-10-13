"""Graph identity for IP observations, including overlapping networks."""

import hashlib
import ipaddress
from dataclasses import dataclass


@dataclass(frozen=True)
class GraphIPIdentity:
    address: str
    key: str
    scope_id: str
    ip_type: str


def graph_ip_identity(address: str, organization_id: int, asset) -> GraphIPIdentity:
    """Use an explicit network, a shared public identity, or a local namespace.

    An explicit network_scope_id takes precedence even for a public address.
    A private address is only shared between assets when they carry the same
    scope. Without one, the owning asset is the scope.
    This also covers ULA, link-local, CGNAT, and other non-global addresses.
    """
    parsed = ipaddress.ip_address(str(address).strip())
    normalized = str(parsed)
    metadata = getattr(asset, "metadata_", None) or {}
    explicit = metadata.get("network_scope_id") if isinstance(metadata, dict) else None
    explicit = str(explicit).strip() if explicit is not None else ""
    if explicit:
        if len(explicit) > 128:
            explicit = "sha256:" + hashlib.sha256(explicit.encode()).hexdigest()
        scope_id = f"org:{organization_id}:network:{explicit}"
    elif parsed.is_global:
        scope_id = "global"
    else:
        scope_id = f"org:{organization_id}:asset:{asset.id}"
    return GraphIPIdentity(
        address=normalized,
        key=f"{scope_id}|{normalized}",
        scope_id=scope_id,
        ip_type=f"ipv{parsed.version}",
    )
