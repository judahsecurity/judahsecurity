"""pfSense integration service.

Read-only import of firewall alias entries as assets from the pfSense REST
API (v2):

    GET /api/v2/firewall/aliases   → host / network aliases

Each ``host`` or ``network`` alias carries an ``address`` list whose entries
are single IPs, CIDR subnets, or FQDNs. Entries are classified and imported
as IP, CIDR, or domain assets. Authentication uses an API key in the
``X-API-Key`` header. All calls are read-only.
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetStatus, AssetType
from app.models.pfsense_integration import PfSenseIntegration

logger = logging.getLogger(__name__)

DISCOVERY_SOURCE = "pfsense"
CLOUD_SERVICE_TAG = "pfsense"
SOURCE_TAG = f"source:{DISCOVERY_SOURCE}"

REQUEST_TIMEOUT = httpx.Timeout(60.0, connect=15.0)
RATE_LIMIT_DELAY = 0.1
PAGE_SIZE = 200
MAX_PAGES = 200

_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$"
)
_HOST_ALIAS_TYPES = {"host", "network"}


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


def classify_alias_entry(entry: str) -> Optional[Tuple[str, AssetType, str]]:
    """Classify a single pfSense alias address entry.

    Returns (value, asset_type, kind) or None for ports / unusable entries.
    """
    if not isinstance(entry, str):
        return None
    value = entry.strip()
    if not value:
        return None
    # Ignore bare ports and port ranges (numeric or numeric:numeric).
    if value.isdigit() or re.fullmatch(r"\d+:\d+", value):
        return None

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
        return None

    if _is_ip(value):
        return value, AssetType.IP_ADDRESS, "ip"

    # Otherwise treat as an FQDN if it looks like a hostname.
    name = value.rstrip(".").lower()
    if "." in name and not name.startswith("*") and re.search(r"[a-z]", name):
        atype = AssetType.SUBDOMAIN if _looks_like_subdomain(name) else AssetType.DOMAIN
        return name, atype, "fqdn"

    return None


def _alias_addresses(alias: Dict) -> List[str]:
    """Return the address entries of an alias as a list of strings."""
    addr = alias.get("address")
    if isinstance(addr, list):
        return [str(a) for a in addr if isinstance(a, (str, int))]
    if isinstance(addr, str) and addr.strip():
        # Older shapes store a space/comma separated string.
        return [p for p in re.split(r"[\s,]+", addr.strip()) if p]
    return []


class PfSenseClient:
    """Thin async client for the read-only pfSense REST API (v2)."""

    def __init__(
        self,
        pfsense_host: str,
        api_key: str,
        *,
        verify_ssl: bool = True,
    ):
        self.base_url = _normalize_host(pfsense_host)
        self.verify_ssl = verify_ssl
        self._headers = {"X-API-Key": api_key, "Accept": "application/json"}

    async def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Optional[Dict]:
        url = f"{self.base_url}{path}"
        try:
            async with httpx.AsyncClient(
                timeout=REQUEST_TIMEOUT,
                headers=self._headers,
                verify=self.verify_ssl,
            ) as client:
                resp = await client.get(url, params=params or {})
                if resp.status_code == 429:
                    logger.warning("pfSense rate limited on %s, backing off 10s", path)
                    await asyncio.sleep(10)
                    resp = await client.get(url, params=params or {})
                if resp.status_code in (401, 403):
                    logger.error("pfSense unauthorized (HTTP %s) on %s", resp.status_code, path)
                    return None
                if resp.status_code >= 400:
                    logger.warning("pfSense GET %s -> HTTP %s: %s", path, resp.status_code, resp.text[:200])
                    return None
                return resp.json()
        except Exception as exc:  # noqa: BLE001
            logger.error("pfSense GET %s error: %s", path, exc)
            return None

    async def list_aliases(self) -> List[Dict]:
        aliases: List[Dict] = []
        offset = 0
        for _ in range(MAX_PAGES):
            payload = await self._get(
                "/api/v2/firewall/aliases",
                params={"limit": PAGE_SIZE, "offset": offset},
            )
            if payload is None:
                break
            data = payload.get("data")
            if not isinstance(data, list) or not data:
                break
            batch = [d for d in data if isinstance(d, dict)]
            aliases.extend(batch)
            if len(data) < PAGE_SIZE:
                break
            offset += len(data)
            await asyncio.sleep(RATE_LIMIT_DELAY)
        return aliases


async def test_connection(
    pfsense_host: str,
    api_key: str,
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    host = _normalize_host(pfsense_host)
    parsed = urlparse(host)
    if not parsed.scheme or not parsed.netloc:
        return {
            "ok": False,
            "message": "pfSense host must be a full URL (e.g. https://pfsense.example.com).",
            "alias_count": None,
        }
    client = PfSenseClient(host, api_key, verify_ssl=verify_ssl)
    payload = await client._get("/api/v2/firewall/aliases", params={"limit": 1})
    if payload is None:
        return {
            "ok": False,
            "message": (
                f"Could not authenticate to pfSense at {host}. Check the host URL, API key, "
                "that the REST API package is installed, and network connectivity."
            ),
            "alias_count": None,
        }
    aliases = await client.list_aliases()
    return {
        "ok": True,
        "message": f"Connected to pfSense at {host}.",
        "alias_count": len(aliases),
    }


class _Stats:
    def __init__(self) -> None:
        self.assets_created = 0
        self.assets_updated = 0
        self.aliases_seen = 0
        self.entries_seen = 0
        self.ips_imported = 0
        self.cidrs_imported = 0
        self.fqdns_imported = 0
        self.assets_missing_from_source = 0

    def as_dict(self) -> Dict[str, int]:
        return {
            "assets_created": self.assets_created,
            "assets_updated": self.assets_updated,
            "aliases_seen": self.aliases_seen,
            "entries_seen": self.entries_seen,
            "ips_imported": self.ips_imported,
            "cidrs_imported": self.cidrs_imported,
            "fqdns_imported": self.fqdns_imported,
            "assets_missing_from_source": self.assets_missing_from_source,
        }


def _bump_kind(stats: _Stats, kind: str) -> None:
    if kind == "ip":
        stats.ips_imported += 1
    elif kind == "cidr":
        stats.cidrs_imported += 1
    elif kind == "fqdn":
        stats.fqdns_imported += 1


def _upsert_asset(
    db: Session,
    integration: PfSenseIntegration,
    value: str,
    asset_type: AssetType,
    stats: _Stats,
    *,
    alias_name: str,
    address_kind: str,
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
        "pfsense_integration_id": integration.id,
        "pfsense_alias_name": alias_name,
        "pfsense_address_kind": address_kind,
        "pfsense_host": integration.pfsense_host,
        "cloud_service": CLOUD_SERVICE_TAG,
    }

    desired_tags = {SOURCE_TAG, CLOUD_SERVICE_TAG, f"pfsense-alias:{alias_name}"}

    if existing:
        existing.last_seen = datetime.utcnow()
        tags = [t for t in (existing.tags or []) if t != "pfsense:removed"]
        if any(str(t).startswith("pfsense-alias:") for t in tags):
            # Keep alias tags from other aliases; ensure this one is present.
            pass
        for t in desired_tags:
            if t not in tags:
                tags.append(t)
        existing.tags = tags
        meta = dict(existing.metadata_ or {})
        meta.update(meta_patch)
        existing.metadata_ = meta
        stats.assets_updated += 1
        return existing

    asset = Asset(
        name=(alias_name or value)[:255],
        asset_type=asset_type,
        value=value[:500],
        organization_id=org_id,
        status=AssetStatus.DISCOVERED,
        discovery_source=DISCOVERY_SOURCE,
        association_reason=(
            f"Firewall alias '{alias_name}' entry imported from pfSense ({integration.name})"
        ),
        association_confidence=80,
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


def _import_aliases(
    db: Session,
    integration: PfSenseIntegration,
    aliases: List[Dict],
    stats: _Stats,
) -> set[str]:
    host_aliases = [a for a in aliases if str(a.get("type") or "").strip().lower() in _HOST_ALIAS_TYPES]
    stats.aliases_seen = len(host_aliases)
    seen_values: set[str] = set()

    for alias in host_aliases:
        alias_name = str(alias.get("name") or "").strip() or "alias"
        for entry in _alias_addresses(alias):
            stats.entries_seen += 1
            classified = classify_alias_entry(entry)
            if not classified:
                continue
            value, asset_type, kind = classified
            asset = _upsert_asset(
                db, integration, value, asset_type, stats,
                alias_name=alias_name, address_kind=kind,
            )
            if asset:
                seen_values.add(value)
                _bump_kind(stats, kind)
    return seen_values


def _mark_missing_assets(
    db: Session,
    integration: PfSenseIntegration,
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
        if meta.get("pfsense_integration_id") != integration.id:
            continue
        if asset.value not in seen_values:
            stats.assets_missing_from_source += 1
            tags = list(asset.tags or [])
            if "pfsense:removed" not in tags:
                tags.append("pfsense:removed")
                asset.tags = tags


async def sync_integration(db: Session, integration: PfSenseIntegration) -> Dict[str, Any]:
    """Import firewall alias entries from the pfSense REST API."""
    org_id = integration.organization_id
    stats = _Stats()

    api_key = integration.get_api_key()
    if not api_key:
        return {
            "ok": False,
            "message": "No API key stored for this connection.",
            **stats.as_dict(),
        }
    if not integration.pfsense_host:
        return {
            "ok": False,
            "message": "No pfSense host configured for this connection.",
            **stats.as_dict(),
        }

    try:
        client = PfSenseClient(
            integration.pfsense_host,
            api_key,
            verify_ssl=bool(integration.verify_ssl),
        )
        aliases = await client.list_aliases()
        seen = _import_aliases(db, integration, aliases, stats)
        _mark_missing_assets(db, integration, seen, stats)

        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = True
        integration.last_error = None
        integration.last_sync_stats = stats.as_dict()
        db.commit()

        return {
            "ok": True,
            "message": (
                f"Imported {stats.assets_created} new asset(s) from pfSense "
                f"({stats.aliases_seen} host/network alias(es), {stats.entries_seen} entry(ies) seen)."
            ),
            **stats.as_dict(),
        }
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.exception("pfSense sync failed for org %s", org_id)
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = str(exc)[:1000]
        db.commit()
        return {
            "ok": False,
            "message": f"Sync failed: {exc}",
            **stats.as_dict(),
        }
