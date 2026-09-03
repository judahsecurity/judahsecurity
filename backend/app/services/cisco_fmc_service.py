"""Cisco Firepower Management Center (FMC) integration service.

Read-only import of network objects as assets from the FMC REST API:

    object/hosts    → single hosts (value = "1.2.3.4")        → IP assets
    object/networks → networks (value = "10.0.0.0/24")        → CIDR assets
    object/ranges   → ranges (value = "10.0.0.1-10.0.0.9")    → seed first IP
    object/fqdns    → FQDN objects (value = "www.example.com") → domain assets

Authentication (token-based):
    POST /api/fmc_platform/v1/auth/generatetoken   (HTTP Basic user:pass)
        → response headers X-auth-access-token and DOMAIN_UUID
    Subsequent GETs send header  X-auth-access-token: <token>

Object list calls use ``?expanded=true`` so each item carries its value, and
page through the ``paging`` block with limit/offset. All calls are read-only;
the integration never writes configuration back to FMC.
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
from app.models.cisco_fmc_integration import CiscoFmcIntegration

logger = logging.getLogger(__name__)

DISCOVERY_SOURCE = "cisco_fmc"
CLOUD_SERVICE_TAG = "cisco"
SOURCE_TAG = f"source:{DISCOVERY_SOURCE}"

REQUEST_TIMEOUT = httpx.Timeout(60.0, connect=15.0)
RATE_LIMIT_DELAY = 0.1
PAGE_SIZE = 1000
MAX_PAGES = 200

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


class CiscoFmcError(RuntimeError):
    """Raised when the FMC API returns an error or authentication fails."""


class CiscoFmcClient:
    """Async context-managed, read-only Cisco FMC REST API client."""

    def __init__(
        self,
        fmc_host: str,
        username: str,
        password: str,
        *,
        domain_uuid: Optional[str] = None,
        verify_ssl: bool = True,
    ):
        self.base_url = _normalize_host(fmc_host)
        self.username = username
        self.password = password
        self.domain_uuid = domain_uuid.strip() if domain_uuid and domain_uuid.strip() else None
        self.verify_ssl = verify_ssl
        self._token: Optional[str] = None
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "CiscoFmcClient":
        self._client = httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=REQUEST_TIMEOUT,
        )
        await self.login()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _require_client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("CiscoFmcClient must be used as an async context manager.")
        return self._client

    async def login(self) -> None:
        client = self._require_client()
        url = f"{self.base_url}/api/fmc_platform/v1/auth/generatetoken"
        resp = await client.post(url, auth=(self.username, self.password))
        if resp.status_code == 401:
            raise CiscoFmcError("FMC authentication failed (401): check username and password.")
        if resp.status_code >= 400:
            raise CiscoFmcError(
                f"FMC token request failed ({resp.status_code}): {resp.text[:200]}"
            )
        token = resp.headers.get("X-auth-access-token")
        if not token:
            raise CiscoFmcError("FMC login succeeded but no access token was returned.")
        self._token = token
        # Pin the caller's domain, else the default returned by FMC.
        if not self.domain_uuid:
            self.domain_uuid = resp.headers.get("DOMAIN_UUID") or resp.headers.get("domain_uuid")
        if not self.domain_uuid:
            raise CiscoFmcError("FMC login did not return a domain UUID; specify one explicitly.")

    async def _get(self, resource_path: str, params: Optional[Dict[str, Any]] = None) -> Optional[Dict]:
        client = self._require_client()
        url = f"{self.base_url}/api/fmc_config/v1/domain/{self.domain_uuid}/{resource_path.lstrip('/')}"
        headers = {"X-auth-access-token": self._token or "", "Accept": "application/json"}
        resp = await client.get(url, headers=headers, params=params or {})
        if resp.status_code == 429:
            logger.warning("FMC rate limited on %s, backing off 10s", resource_path)
            await asyncio.sleep(10)
            resp = await client.get(url, headers=headers, params=params or {})
        if resp.status_code in (401, 403):
            logger.error("FMC unauthorized (HTTP %s) on %s", resp.status_code, resource_path)
            return None
        if resp.status_code >= 400:
            logger.warning("FMC GET %s -> HTTP %s: %s", resource_path, resp.status_code, resp.text[:200])
            return None
        try:
            return resp.json()
        except ValueError:
            return None

    async def _paginate(self, resource_path: str) -> List[Dict]:
        items: List[Dict] = []
        offset = 0
        for _ in range(MAX_PAGES):
            payload = await self._get(
                resource_path,
                params={"expanded": "true", "limit": PAGE_SIZE, "offset": offset},
            )
            if payload is None:
                break
            batch = payload.get("items")
            if not isinstance(batch, list) or not batch:
                break
            items.extend([i for i in batch if isinstance(i, dict)])
            paging = payload.get("paging") if isinstance(payload.get("paging"), dict) else {}
            count = paging.get("count")
            if isinstance(count, int) and len(items) >= count:
                break
            if len(batch) < PAGE_SIZE:
                break
            offset += len(batch)
            await asyncio.sleep(RATE_LIMIT_DELAY)
        return items

    async def list_hosts(self) -> List[Dict]:
        return await self._paginate("object/hosts")

    async def list_networks(self) -> List[Dict]:
        return await self._paginate("object/networks")

    async def list_ranges(self) -> List[Dict]:
        return await self._paginate("object/ranges")

    async def list_fqdns(self) -> List[Dict]:
        return await self._paginate("object/fqdns")


async def test_connection(
    fmc_host: str,
    username: str,
    password: str,
    *,
    domain_uuid: Optional[str] = None,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    host = _normalize_host(fmc_host)
    parsed = urlparse(host)
    if not parsed.scheme or not parsed.netloc:
        return {
            "ok": False,
            "message": "FMC host must be a full URL (e.g. https://fmc.example.com).",
            "object_count": None,
        }
    try:
        async with CiscoFmcClient(
            host, username, password, domain_uuid=domain_uuid, verify_ssl=verify_ssl
        ) as client:
            hosts = await client.list_hosts()
            return {
                "ok": True,
                "message": f"Connected to Cisco FMC (domain {client.domain_uuid}).",
                "object_count": len(hosts),
            }
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "message": str(exc)[:500],
            "object_count": None,
        }


# ── Network object → asset value mapping ─────────────────────────────────────


def parse_host(entry: Dict) -> Optional[Tuple[str, AssetType, str]]:
    value = entry.get("value")
    if isinstance(value, str) and _is_ip(value.strip()):
        return value.strip(), AssetType.IP_ADDRESS, "ip"
    return None


def parse_network(entry: Dict) -> Optional[Tuple[str, AssetType, str]]:
    value = entry.get("value")
    if not isinstance(value, str) or "/" not in value:
        return None
    ip_part, prefix_part = value.split("/", 1)
    ip_part = ip_part.strip()
    prefix_part = prefix_part.strip()
    if not _is_ip(ip_part) or not prefix_part.isdigit():
        return None
    prefix = int(prefix_part)
    if not (0 <= prefix <= 32):
        return None
    if prefix == 32:
        return ip_part, AssetType.IP_ADDRESS, "ip"
    return f"{ip_part}/{prefix}", AssetType.IP_RANGE, "cidr"


def parse_range(entry: Dict) -> Optional[Tuple[str, AssetType, str]]:
    value = entry.get("value")
    if isinstance(value, str) and "-" in value:
        first = value.split("-", 1)[0].strip()
        if _is_ip(first):
            return first, AssetType.IP_ADDRESS, "range"
    return None


def parse_fqdn(entry: Dict) -> Optional[Tuple[str, AssetType, str]]:
    value = entry.get("value")
    if isinstance(value, str) and value.strip():
        name = value.strip().rstrip(".").lower()
        if name and not name.startswith("*") and "." in name:
            atype = AssetType.SUBDOMAIN if _looks_like_subdomain(name) else AssetType.DOMAIN
            return name, atype, "fqdn"
    return None


class _Stats:
    def __init__(self) -> None:
        self.assets_created = 0
        self.assets_updated = 0
        self.hosts_seen = 0
        self.networks_seen = 0
        self.ranges_seen = 0
        self.fqdns_seen = 0
        self.ips_imported = 0
        self.cidrs_imported = 0
        self.fqdns_imported = 0
        self.ranges_seeded = 0
        self.assets_missing_from_source = 0

    def as_dict(self) -> Dict[str, int]:
        return {
            "assets_created": self.assets_created,
            "assets_updated": self.assets_updated,
            "hosts_seen": self.hosts_seen,
            "networks_seen": self.networks_seen,
            "ranges_seen": self.ranges_seen,
            "fqdns_seen": self.fqdns_seen,
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
    integration: CiscoFmcIntegration,
    value: str,
    asset_type: AssetType,
    stats: _Stats,
    *,
    object_name: str,
    address_kind: str,
    object_type: str,
    description: Optional[str] = None,
) -> Optional[Asset]:
    value = (value or "").strip()
    if not value:
        return None

    org_id = integration.organization_id
    domain = integration.domain_uuid or "Global"
    existing = (
        db.query(Asset)
        .filter(Asset.organization_id == org_id, Asset.value == value)
        .first()
    )

    is_fqdn = asset_type in (AssetType.DOMAIN, AssetType.SUBDOMAIN)
    system_type = "firewall" if not is_fqdn else None

    meta_patch = {
        "cisco_fmc_integration_id": integration.id,
        "cisco_fmc_object_name": object_name,
        "cisco_fmc_object_type": object_type,
        "cisco_fmc_domain": domain,
        "cisco_fmc_address_kind": address_kind,
        "cisco_fmc_host": integration.fmc_host,
        "cloud_service": CLOUD_SERVICE_TAG,
    }

    desired_tags = {
        SOURCE_TAG,
        CLOUD_SERVICE_TAG,
        f"cisco-fmc-type:{object_type}",
    }

    if existing:
        existing.last_seen = datetime.utcnow()
        tags = [t for t in (existing.tags or []) if t != "cisco_fmc:removed"]
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
            f"{object_type.capitalize()} object '{object_name}' imported from "
            f"Cisco FMC (domain {domain})"
        ),
        association_confidence=85,
        tags=sorted(desired_tags),
        metadata_=meta_patch,
        system_type=system_type,
        device_class="Network Infrastructure" if not is_fqdn else None,
        device_subclass="Firewall and Next Generation Firewall" if not is_fqdn else None,
    )
    db.add(asset)
    db.flush()
    stats.assets_created += 1
    return asset


def _import_objects(
    db: Session,
    integration: CiscoFmcIntegration,
    hosts: List[Dict],
    networks: List[Dict],
    ranges: List[Dict],
    fqdns: List[Dict],
    stats: _Stats,
) -> set[str]:
    stats.hosts_seen = len(hosts)
    stats.networks_seen = len(networks)
    stats.ranges_seen = len(ranges)
    stats.fqdns_seen = len(fqdns)
    seen_values: set[str] = set()

    def _ingest(entries: List[Dict], parser, object_type: str) -> None:
        for entry in entries:
            parsed = parser(entry)
            if not parsed:
                continue
            value, asset_type, kind = parsed
            object_name = str(entry.get("name") or entry.get("id") or value).strip()
            desc = entry.get("description")
            asset = _upsert_asset(
                db,
                integration,
                value,
                asset_type,
                stats,
                object_name=object_name or value,
                address_kind=kind,
                object_type=object_type,
                description=desc if isinstance(desc, str) and desc.strip() else None,
            )
            if asset:
                seen_values.add(value)
                _bump_kind(stats, kind)

    _ingest(hosts, parse_host, "host")
    _ingest(networks, parse_network, "network")
    _ingest(ranges, parse_range, "range")
    _ingest(fqdns, parse_fqdn, "fqdn")
    return seen_values


def _mark_missing_assets(
    db: Session,
    integration: CiscoFmcIntegration,
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
        if meta.get("cisco_fmc_integration_id") != integration.id:
            continue
        if asset.value not in seen_values:
            stats.assets_missing_from_source += 1
            tags = list(asset.tags or [])
            if "cisco_fmc:removed" not in tags:
                tags.append("cisco_fmc:removed")
                asset.tags = tags


async def sync_integration(db: Session, integration: CiscoFmcIntegration) -> Dict[str, Any]:
    """Import host / network / range / FQDN objects from Cisco FMC."""
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
    if not integration.fmc_host:
        return {
            "ok": False,
            "message": "No FMC host configured for this connection.",
            **stats.as_dict(),
        }

    try:
        async with CiscoFmcClient(
            integration.fmc_host,
            username,
            password,
            domain_uuid=integration.domain_uuid,
            verify_ssl=bool(integration.verify_ssl),
        ) as client:
            hosts = await client.list_hosts()
            networks = await client.list_networks()
            ranges = await client.list_ranges()
            fqdns = await client.list_fqdns()

        seen = _import_objects(db, integration, hosts, networks, ranges, fqdns, stats)
        _mark_missing_assets(db, integration, seen, stats)

        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = True
        integration.last_error = None
        integration.last_sync_stats = stats.as_dict()
        db.commit()

        return {
            "ok": True,
            "message": (
                f"Imported {stats.assets_created} new asset(s) from Cisco FMC "
                f"({stats.hosts_seen} host(s), {stats.networks_seen} network(s), "
                f"{stats.ranges_seen} range(s), {stats.fqdns_seen} FQDN(s) seen)."
            ),
            **stats.as_dict(),
        }
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.exception("Cisco FMC sync failed for org %s", org_id)
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = str(exc)[:1000]
        db.commit()
        return {
            "ok": False,
            "message": f"Sync failed: {exc}",
            **stats.as_dict(),
        }
