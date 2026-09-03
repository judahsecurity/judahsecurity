"""Fortinet FortiGate integration service.

Read-only import of firewall address objects as assets from the FortiOS REST
API (``/api/v2/cmdb/firewall/address`` and ``/addrgrp``).

FortiGate address objects come in several ``type`` variants:
    ipmask     — a subnet, stored as "10.0.0.0 255.255.255.0" or "10.0.0.0/24"
    iprange    — start-ip / end-ip (the start IP is seeded as an asset)
    fqdn       — a fully-qualified domain name
    geography / dynamic / mac / wildcard — not directly resolvable, skipped

The FortiOS REST API authenticates with a REST API admin token sent as
``Authorization: Bearer <token>``. All calls are read-only GETs; the
integration never writes configuration back to the FortiGate.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetStatus, AssetType
from app.models.fortigate_integration import FortiGateIntegration

logger = logging.getLogger(__name__)

DISCOVERY_SOURCE = "fortigate"
CLOUD_SERVICE_TAG = "fortinet"
SOURCE_TAG = f"source:{DISCOVERY_SOURCE}"

REQUEST_TIMEOUT = httpx.Timeout(45.0, connect=15.0)
RATE_LIMIT_DELAY = 0.1

_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$"
)


def _normalize_host(host: str) -> str:
    host = (host or "").strip().rstrip("/")
    if host and not host.startswith(("http://", "https://")):
        host = f"https://{host}"
    return host


def _is_ip(value: str) -> bool:
    return bool(_IP_RE.match(value))


def _looks_like_subdomain(fqdn: str) -> bool:
    labels = [p for p in fqdn.split(".") if p]
    return len(labels) >= 3


def _netmask_to_prefix(mask: str) -> Optional[int]:
    """Convert a dotted netmask ('255.255.255.0') to a prefix length (24)."""
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except (ipaddress.NetmaskValueError, ValueError):
        return None


def _parse_subnet(raw: str) -> Optional[Tuple[str, int]]:
    """Return (network_ip, prefix_len) from a FortiOS subnet field.

    Accepts "10.0.0.0 255.255.255.0" (space form) and "10.0.0.0/24" (CIDR form).
    """
    value = (raw or "").strip()
    if not value:
        return None
    if "/" in value:
        ip_part, prefix_part = value.split("/", 1)
        ip_part = ip_part.strip()
        prefix_part = prefix_part.strip()
        if prefix_part.isdigit():
            prefix = int(prefix_part)
        else:
            prefix = _netmask_to_prefix(prefix_part)
    elif " " in value:
        ip_part, mask_part = value.split(None, 1)
        ip_part = ip_part.strip()
        prefix = _netmask_to_prefix(mask_part.strip())
    else:
        ip_part, prefix = value, 32
    if not _is_ip(ip_part) or prefix is None or not (0 <= prefix <= 32):
        return None
    return ip_part, prefix


def parse_address_object(entry: Dict) -> Optional[Tuple[str, AssetType, str]]:
    """Return (asset_value, asset_type, address_kind) or None if unusable."""
    if not isinstance(entry, dict):
        return None

    obj_type = str(entry.get("type") or "").strip().lower()

    # ipmask is the FortiOS default when 'type' is omitted.
    if obj_type in ("", "ipmask", "ipprefix"):
        subnet = entry.get("subnet")
        if isinstance(subnet, str) and subnet.strip():
            parsed = _parse_subnet(subnet)
            if parsed:
                ip_part, prefix = parsed
                if prefix == 32:
                    return ip_part, AssetType.IP_ADDRESS, "ip"
                return f"{ip_part}/{prefix}", AssetType.IP_RANGE, "cidr"

    if obj_type == "fqdn":
        fqdn = entry.get("fqdn")
        if isinstance(fqdn, str) and fqdn.strip():
            name = fqdn.strip().rstrip(".").lower()
            # Wildcard FQDN objects (*.example.com) are not resolvable assets.
            if name and not name.startswith("*"):
                atype = AssetType.SUBDOMAIN if _looks_like_subdomain(name) else AssetType.DOMAIN
                return name, atype, "fqdn"

    if obj_type == "iprange":
        start = entry.get("start-ip") or entry.get("start_ip")
        if isinstance(start, str) and _is_ip(start.strip()):
            return start.strip(), AssetType.IP_ADDRESS, "range"

    # Fall back to a bare subnet when no explicit type is present but the field is.
    if not obj_type:
        subnet = entry.get("subnet")
        if isinstance(subnet, str) and subnet.strip():
            parsed = _parse_subnet(subnet)
            if parsed:
                ip_part, prefix = parsed
                if prefix == 32:
                    return ip_part, AssetType.IP_ADDRESS, "ip"
                return f"{ip_part}/{prefix}", AssetType.IP_RANGE, "cidr"

    return None


class FortiGateClient:
    """Thin async client for the read-only FortiOS REST configuration API."""

    def __init__(
        self,
        fortigate_host: str,
        api_token: str,
        *,
        vdom: Optional[str] = None,
        verify_ssl: bool = True,
    ):
        self.base_url = _normalize_host(fortigate_host)
        self.vdom = vdom.strip() if vdom and vdom.strip() else None
        self.verify_ssl = verify_ssl
        self._headers = {
            "Authorization": f"Bearer {api_token}",
            "Accept": "application/json",
        }

    def _url(self, resource_path: str) -> str:
        return f"{self.base_url}/api/v2/cmdb/{resource_path.lstrip('/')}"

    async def _get(self, resource_path: str) -> Optional[Dict]:
        url = self._url(resource_path)
        params: Dict[str, str] = {}
        if self.vdom:
            params["vdom"] = self.vdom
        try:
            async with httpx.AsyncClient(
                timeout=REQUEST_TIMEOUT,
                headers=self._headers,
                verify=self.verify_ssl,
            ) as client:
                resp = await client.get(url, params=params)
                if resp.status_code == 429:
                    logger.warning("FortiGate rate limited on %s, backing off 10s", resource_path)
                    await asyncio.sleep(10)
                    resp = await client.get(url, params=params)
                if resp.status_code in (401, 403):
                    logger.error(
                        "FortiGate: unauthorized (HTTP %s) on %s", resp.status_code, resource_path
                    )
                    return None
                if resp.status_code != 200:
                    logger.warning(
                        "FortiGate GET %s -> HTTP %s: %s",
                        resource_path,
                        resp.status_code,
                        resp.text[:300],
                    )
                    return None
                return resp.json()
        except Exception as exc:  # noqa: BLE001 — network errors are expected
            logger.error("FortiGate GET %s error: %s", resource_path, exc)
            return None

    @staticmethod
    def _results(payload: Optional[Dict]) -> List[Dict]:
        if not isinstance(payload, dict):
            return []
        results = payload.get("results")
        if isinstance(results, list):
            return [r for r in results if isinstance(r, dict)]
        return []

    async def list_addresses(self) -> List[Dict]:
        payload = await self._get("firewall/address")
        return self._results(payload)

    async def list_address_groups(self) -> List[Dict]:
        payload = await self._get("firewall/addrgrp")
        return self._results(payload)


async def test_connection(
    fortigate_host: str,
    api_token: str,
    *,
    vdom: Optional[str] = None,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    """Validate FortiGate credentials with a lightweight address probe."""
    host = _normalize_host(fortigate_host)
    parsed = urlparse(host)
    if not parsed.scheme or not parsed.netloc:
        return {
            "ok": False,
            "message": "FortiGate host must be a full URL (e.g. https://fortigate.example.com).",
            "address_count": None,
        }

    client = FortiGateClient(host, api_token, vdom=vdom, verify_ssl=verify_ssl)
    payload = await client._get("firewall/address")
    if payload is None:
        scope = f"VDOM '{vdom}'" if vdom else "the management VDOM"
        return {
            "ok": False,
            "message": (
                f"Could not authenticate to FortiGate at {host} ({scope}). "
                "Check the host URL, REST API token, VDOM, and network connectivity."
            ),
            "address_count": None,
        }

    count = len(FortiGateClient._results(payload))
    scope_label = f"VDOM '{vdom}'" if vdom else "management VDOM"
    return {
        "ok": True,
        "message": f"Connected to FortiGate successfully ({scope_label}).",
        "address_count": count,
    }


# ── Address object → asset ingestion ─────────────────────────────────────────


def _group_membership_index(groups: List[Dict]) -> Dict[str, List[str]]:
    """Map address object name → list of containing address-group names."""
    index: Dict[str, List[str]] = {}
    for group in groups:
        group_name = group.get("name") or group.get("q_origin_key")
        if not group_name:
            continue
        members = group.get("member")
        if not isinstance(members, list):
            continue
        for member in members:
            member_name = None
            if isinstance(member, dict):
                member_name = member.get("name") or member.get("q_origin_key")
            elif isinstance(member, str):
                member_name = member
            if member_name and str(member_name).strip():
                index.setdefault(str(member_name).strip(), []).append(str(group_name))
    return index


class _Stats:
    def __init__(self) -> None:
        self.assets_created = 0
        self.assets_updated = 0
        self.addresses_seen = 0
        self.address_groups_seen = 0
        self.ips_imported = 0
        self.cidrs_imported = 0
        self.fqdns_imported = 0
        self.ranges_seeded = 0
        self.assets_missing_from_source = 0

    def as_dict(self) -> Dict[str, int]:
        return {
            "assets_created": self.assets_created,
            "assets_updated": self.assets_updated,
            "addresses_seen": self.addresses_seen,
            "address_groups_seen": self.address_groups_seen,
            "ips_imported": self.ips_imported,
            "cidrs_imported": self.cidrs_imported,
            "fqdns_imported": self.fqdns_imported,
            "ranges_seeded": self.ranges_seeded,
            "assets_missing_from_source": self.assets_missing_from_source,
        }


def _bump_kind(stats: _Stats, kind: str) -> None:
    if kind == "ip":
        stats.ips_imported += 1
    elif kind == "cidr":
        stats.cidrs_imported += 1
    elif kind == "fqdn":
        stats.fqdns_imported += 1
    elif kind in ("range", "wildcard"):
        stats.ranges_seeded += 1


def _upsert_asset(
    db: Session,
    integration: FortiGateIntegration,
    value: str,
    asset_type: AssetType,
    stats: _Stats,
    *,
    object_name: str,
    address_kind: str,
    description: Optional[str] = None,
    group_names: Optional[List[str]] = None,
) -> Optional[Asset]:
    value = (value or "").strip()
    if not value:
        return None

    org_id = integration.organization_id
    vdom = integration.vdom or "root"
    existing = (
        db.query(Asset)
        .filter(Asset.organization_id == org_id, Asset.value == value)
        .first()
    )

    meta_patch = {
        "fortigate_integration_id": integration.id,
        "fortigate_object_name": object_name,
        "fortigate_vdom": vdom,
        "fortigate_address_kind": address_kind,
        "fortigate_host": integration.fortigate_host,
        "fortigate_groups": group_names or [],
        "cloud_service": CLOUD_SERVICE_TAG,
    }

    desired_tags = {SOURCE_TAG, CLOUD_SERVICE_TAG, f"fortigate-vdom:{vdom}"}
    for group_name in group_names or []:
        desired_tags.add(f"fortigate-group:{group_name}")

    if existing:
        existing.last_seen = datetime.utcnow()
        tags = [t for t in (existing.tags or []) if t != "fortigate:removed"]
        for t in desired_tags:
            if t not in tags:
                tags.append(t)
        existing.tags = tags
        meta = dict(existing.metadata_ or {})
        meta.update(meta_patch)
        existing.metadata_ = meta
        if description and not existing.description:
            existing.description = description
        stats.assets_updated += 1
        return existing

    asset = Asset(
        name=object_name[:255] if object_name else value[:255],
        asset_type=asset_type,
        value=value[:500],
        organization_id=org_id,
        status=AssetStatus.DISCOVERED,
        description=description,
        discovery_source=DISCOVERY_SOURCE,
        association_reason=(
            f"Address object '{object_name}' imported from Fortinet FortiGate "
            f"(VDOM {vdom})"
        ),
        association_confidence=85,
        tags=sorted(desired_tags),
        metadata_=meta_patch,
        system_type="firewall",
        device_class="Network Infrastructure",
        device_subclass="Firewall and Next Generation Firewall",
    )
    db.add(asset)
    db.flush()
    stats.assets_created += 1
    return asset


def _import_address_entries(
    db: Session,
    integration: FortiGateIntegration,
    addresses: List[Dict],
    groups: List[Dict],
    stats: _Stats,
) -> set[str]:
    stats.address_groups_seen = len(groups)
    stats.addresses_seen = len(addresses)
    membership = _group_membership_index(groups)
    seen_values: set[str] = set()

    for entry in addresses:
        object_name = str(entry.get("name") or entry.get("q_origin_key") or "").strip()
        parsed = parse_address_object(entry)
        if not parsed:
            continue
        value, asset_type, kind = parsed
        groups_for_obj = membership.get(object_name, []) if object_name else []
        comment = entry.get("comment")
        asset = _upsert_asset(
            db,
            integration,
            value,
            asset_type,
            stats,
            object_name=object_name or value,
            address_kind=kind,
            description=comment if isinstance(comment, str) and comment.strip() else None,
            group_names=groups_for_obj,
        )
        if asset:
            seen_values.add(value)
            _bump_kind(stats, kind)
    return seen_values


def _mark_missing_assets(
    db: Session,
    integration: FortiGateIntegration,
    seen_values: set[str],
    stats: _Stats,
) -> None:
    prior = (
        db.query(Asset)
        .filter(
            Asset.organization_id == integration.organization_id,
            Asset.discovery_source == DISCOVERY_SOURCE,
        )
        .all()
    )
    for asset in prior:
        meta = asset.metadata_ or {}
        if meta.get("fortigate_integration_id") != integration.id:
            continue
        if asset.value not in seen_values:
            stats.assets_missing_from_source += 1
            tags = list(asset.tags or [])
            if "fortigate:removed" not in tags:
                tags.append("fortigate:removed")
                asset.tags = tags


async def sync_integration(db: Session, integration: FortiGateIntegration) -> Dict[str, Any]:
    """Import firewall address objects from the FortiGate REST API."""
    org_id = integration.organization_id
    stats = _Stats()

    api_token = integration.get_api_token()
    if not api_token:
        return {
            "ok": False,
            "message": "No API token stored for this connection.",
            **stats.as_dict(),
        }
    if not integration.fortigate_host:
        return {
            "ok": False,
            "message": "No FortiGate host configured for this connection.",
            **stats.as_dict(),
        }

    try:
        client = FortiGateClient(
            integration.fortigate_host,
            api_token,
            vdom=integration.vdom,
            verify_ssl=bool(integration.verify_ssl),
        )
        groups = await client.list_address_groups()
        await asyncio.sleep(RATE_LIMIT_DELAY)
        addresses = await client.list_addresses()

        seen = _import_address_entries(db, integration, addresses, groups, stats)
        _mark_missing_assets(db, integration, seen, stats)

        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = True
        integration.last_error = None
        integration.last_sync_stats = stats.as_dict()
        db.commit()

        return {
            "ok": True,
            "message": (
                f"Imported {stats.assets_created} new asset(s) from FortiGate "
                f"({stats.addresses_seen} address object(s) seen)."
            ),
            **stats.as_dict(),
        }
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.exception("FortiGate sync failed for org %s", org_id)
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = str(exc)[:1000]
        db.commit()
        return {
            "ok": False,
            "message": f"Sync failed: {exc}",
            **stats.as_dict(),
        }
