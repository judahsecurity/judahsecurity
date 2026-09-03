"""Cisco ASA integration service.

Read-only import of network objects as assets from the Cisco ASA REST API:

    GET /api/objects/networkobjects  → host / network / range / FQDN objects

Each object carries a ``host`` block ``{"kind": ..., "value": ...}`` whose kind
selects the mapping:
    IPv4Address / IPv6Address → single IP
    IPv4Network / IPv6Network → CIDR subnet
    IPv4Range                 → seed the first IP
    IPv4FQDN / FQDN           → FQDN

Authentication uses HTTP Basic (username + password). All calls are read-only;
the integration never writes configuration back to the ASA.
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
from app.models.cisco_asa_integration import CiscoAsaIntegration

logger = logging.getLogger(__name__)

DISCOVERY_SOURCE = "cisco_asa"
CLOUD_SERVICE_TAG = "cisco"
SOURCE_TAG = f"source:{DISCOVERY_SOURCE}"

REQUEST_TIMEOUT = httpx.Timeout(45.0, connect=15.0)
RATE_LIMIT_DELAY = 0.1
PAGE_SIZE = 100
MAX_PAGES = 500

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


def parse_network_object(entry: Dict) -> Optional[Tuple[str, AssetType, str]]:
    """Map an ASA network object to (value, asset_type, kind)."""
    if not isinstance(entry, dict):
        return None
    host = entry.get("host")
    if not isinstance(host, dict):
        return None
    kind = str(host.get("kind") or "").strip()
    value = host.get("value")
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()

    if kind in ("IPv4Address", "IPv6Address"):
        if _is_ip(value):
            return value, AssetType.IP_ADDRESS, "ip"
        return None

    if kind in ("IPv4Network", "IPv6Network"):
        if "/" in value:
            ip_part, prefix_part = value.split("/", 1)
            ip_part = ip_part.strip()
            prefix_part = prefix_part.strip()
            if _is_ip(ip_part) and prefix_part.isdigit():
                prefix = int(prefix_part)
                if 0 <= prefix <= 32:
                    if prefix == 32:
                        return ip_part, AssetType.IP_ADDRESS, "ip"
                    return f"{ip_part}/{prefix}", AssetType.IP_RANGE, "cidr"
            # ASA may render IPv4 networks as "10.0.0.0 255.255.255.0".
        if " " in value:
            ip_part, mask_part = value.split(None, 1)
            try:
                prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask_part.strip()}").prefixlen
            except (ipaddress.NetmaskValueError, ValueError):
                return None
            if _is_ip(ip_part.strip()):
                if prefix == 32:
                    return ip_part.strip(), AssetType.IP_ADDRESS, "ip"
                return f"{ip_part.strip()}/{prefix}", AssetType.IP_RANGE, "cidr"
        return None

    if kind == "IPv4Range":
        first = value.split("-", 1)[0].strip()
        if _is_ip(first):
            return first, AssetType.IP_ADDRESS, "range"
        return None

    if kind in ("IPv4FQDN", "IPv6FQDN", "FQDN"):
        name = value.rstrip(".").lower()
        if name and not name.startswith("*") and "." in name:
            atype = AssetType.SUBDOMAIN if _looks_like_subdomain(name) else AssetType.DOMAIN
            return name, atype, "fqdn"
        return None

    return None


class CiscoAsaClient:
    """Thin async client for the read-only Cisco ASA REST API."""

    def __init__(
        self,
        asa_host: str,
        username: str,
        password: str,
        *,
        verify_ssl: bool = True,
    ):
        self.base_url = _normalize_host(asa_host)
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl

    async def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Optional[Dict]:
        url = f"{self.base_url}{path}"
        try:
            async with httpx.AsyncClient(
                timeout=REQUEST_TIMEOUT,
                verify=self.verify_ssl,
                auth=(self.username, self.password),
                headers={"Accept": "application/json", "Content-Type": "application/json"},
            ) as client:
                resp = await client.get(url, params=params or {})
                if resp.status_code == 429:
                    logger.warning("ASA rate limited on %s, backing off 10s", path)
                    await asyncio.sleep(10)
                    resp = await client.get(url, params=params or {})
                if resp.status_code in (401, 403):
                    logger.error("ASA unauthorized (HTTP %s) on %s", resp.status_code, path)
                    return None
                if resp.status_code >= 400:
                    logger.warning("ASA GET %s -> HTTP %s: %s", path, resp.status_code, resp.text[:200])
                    return None
                return resp.json()
        except Exception as exc:  # noqa: BLE001
            logger.error("ASA GET %s error: %s", path, exc)
            return None

    async def list_network_objects(self) -> List[Dict]:
        items: List[Dict] = []
        offset = 0
        for _ in range(MAX_PAGES):
            payload = await self._get(
                "/api/objects/networkobjects",
                params={"offset": offset, "limit": PAGE_SIZE},
            )
            if payload is None:
                break
            batch = payload.get("items")
            if not isinstance(batch, list) or not batch:
                break
            items.extend([i for i in batch if isinstance(i, dict)])
            range_info = payload.get("rangeInfo") if isinstance(payload.get("rangeInfo"), dict) else {}
            total = range_info.get("total")
            if isinstance(total, int) and len(items) >= total:
                break
            if len(batch) < PAGE_SIZE:
                break
            offset += len(batch)
            await asyncio.sleep(RATE_LIMIT_DELAY)
        return items


async def test_connection(
    asa_host: str,
    username: str,
    password: str,
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    host = _normalize_host(asa_host)
    parsed = urlparse(host)
    if not parsed.scheme or not parsed.netloc:
        return {
            "ok": False,
            "message": "ASA host must be a full URL (e.g. https://asa.example.com).",
            "object_count": None,
        }
    client = CiscoAsaClient(host, username, password, verify_ssl=verify_ssl)
    payload = await client._get("/api/objects/networkobjects", params={"limit": 1})
    if payload is None:
        return {
            "ok": False,
            "message": (
                f"Could not authenticate to Cisco ASA at {host}. Check the host URL, credentials, "
                "that the ASA REST API agent is enabled, and network connectivity."
            ),
            "object_count": None,
        }
    range_info = payload.get("rangeInfo") if isinstance(payload.get("rangeInfo"), dict) else {}
    count = range_info.get("total")
    if not isinstance(count, int):
        items = payload.get("items")
        count = len(items) if isinstance(items, list) else 0
    return {
        "ok": True,
        "message": f"Connected to Cisco ASA at {host}.",
        "object_count": count,
    }


class _Stats:
    def __init__(self) -> None:
        self.assets_created = 0
        self.assets_updated = 0
        self.objects_seen = 0
        self.ips_imported = 0
        self.cidrs_imported = 0
        self.fqdns_imported = 0
        self.ranges_seeded = 0
        self.assets_missing_from_source = 0

    def as_dict(self) -> Dict[str, int]:
        return {
            "assets_created": self.assets_created,
            "assets_updated": self.assets_updated,
            "objects_seen": self.objects_seen,
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
    elif kind == "range":
        stats.ranges_seeded += 1


def _upsert_asset(
    db: Session,
    integration: CiscoAsaIntegration,
    value: str,
    asset_type: AssetType,
    stats: _Stats,
    *,
    object_name: str,
    address_kind: str,
    description: Optional[str] = None,
) -> Optional[Asset]:
    value = (value or "").strip()
    if not value:
        return None

    org_id = integration.organization_id
    existing = (
        db.query(Asset)
        .filter(Asset.organization_id == org_id, Asset.value == value)
        .first()
    )

    is_fqdn = asset_type in (AssetType.DOMAIN, AssetType.SUBDOMAIN)

    meta_patch = {
        "cisco_asa_integration_id": integration.id,
        "cisco_asa_object_name": object_name,
        "cisco_asa_address_kind": address_kind,
        "cisco_asa_host": integration.asa_host,
        "cloud_service": CLOUD_SERVICE_TAG,
    }

    desired_tags = {SOURCE_TAG, CLOUD_SERVICE_TAG, f"cisco-asa-kind:{address_kind}"}

    if existing:
        existing.last_seen = datetime.utcnow()
        tags = [t for t in (existing.tags or []) if t != "cisco_asa:removed"]
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
            f"Network object '{object_name}' imported from Cisco ASA ({integration.name})"
        ),
        association_confidence=85,
        tags=sorted(desired_tags),
        metadata_=meta_patch,
        system_type="firewall" if not is_fqdn else None,
        device_class="Network Infrastructure" if not is_fqdn else None,
        device_subclass="Firewall and Next Generation Firewall" if not is_fqdn else None,
    )
    db.add(asset)
    db.flush()
    stats.assets_created += 1
    return asset


def _import_objects(
    db: Session,
    integration: CiscoAsaIntegration,
    objects: List[Dict],
    stats: _Stats,
) -> set[str]:
    stats.objects_seen = len(objects)
    seen_values: set[str] = set()

    for entry in objects:
        parsed = parse_network_object(entry)
        if not parsed:
            continue
        value, asset_type, kind = parsed
        object_name = str(entry.get("name") or entry.get("objectId") or value).strip()
        desc = entry.get("description")
        asset = _upsert_asset(
            db, integration, value, asset_type, stats,
            object_name=object_name or value, address_kind=kind,
            description=desc if isinstance(desc, str) and desc.strip() else None,
        )
        if asset:
            seen_values.add(value)
            _bump_kind(stats, kind)
    return seen_values


def _mark_missing_assets(
    db: Session,
    integration: CiscoAsaIntegration,
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
        if meta.get("cisco_asa_integration_id") != integration.id:
            continue
        if asset.value not in seen_values:
            stats.assets_missing_from_source += 1
            tags = list(asset.tags or [])
            if "cisco_asa:removed" not in tags:
                tags.append("cisco_asa:removed")
                asset.tags = tags


async def sync_integration(db: Session, integration: CiscoAsaIntegration) -> Dict[str, Any]:
    """Import network objects from the Cisco ASA REST API."""
    org_id = integration.organization_id
    stats = _Stats()

    username = integration.get_username()
    password = integration.get_password()
    if not username or not password:
        return {
            "ok": False,
            "message": "No credentials stored for this connection.",
            **stats.as_dict(),
        }
    if not integration.asa_host:
        return {
            "ok": False,
            "message": "No ASA host configured for this connection.",
            **stats.as_dict(),
        }

    try:
        client = CiscoAsaClient(
            integration.asa_host,
            username,
            password,
            verify_ssl=bool(integration.verify_ssl),
        )
        objects = await client.list_network_objects()
        seen = _import_objects(db, integration, objects, stats)
        _mark_missing_assets(db, integration, seen, stats)

        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = True
        integration.last_error = None
        integration.last_sync_stats = stats.as_dict()
        db.commit()

        return {
            "ok": True,
            "message": (
                f"Imported {stats.assets_created} new asset(s) from Cisco ASA "
                f"({stats.objects_seen} network object(s) seen)."
            ),
            **stats.as_dict(),
        }
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.exception("Cisco ASA sync failed for org %s", org_id)
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = str(exc)[:1000]
        db.commit()
        return {
            "ok": False,
            "message": f"Sync failed: {exc}",
            **stats.as_dict(),
        }
