"""SonicWall (SonicOS) integration service.

Read-only import of address objects as assets from the SonicOS API:

    address-objects/ipv4  → host / network / range objects  → IP / CIDR assets
    address-objects/fqdn  → FQDN objects                     → domain assets

Authentication:
    POST   /api/sonicos/auth   (HTTP Basic user:pass)  → session
    GET    /api/sonicos/address-objects/ipv4
    GET    /api/sonicos/address-objects/fqdn
    DELETE /api/sonicos/auth   (end the session)

All calls are read-only; the integration never commits configuration to the
SonicWall.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetStatus, AssetType
from app.models.sonicwall_integration import SonicWallIntegration

logger = logging.getLogger(__name__)

DISCOVERY_SOURCE = "sonicwall"
CLOUD_SERVICE_TAG = "sonicwall"
SOURCE_TAG = f"source:{DISCOVERY_SOURCE}"

REQUEST_TIMEOUT = httpx.Timeout(60.0, connect=15.0)

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
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except (ipaddress.NetmaskValueError, ValueError):
        return None


class SonicWallError(RuntimeError):
    """Raised when the SonicOS API returns an error or authentication fails."""


class SonicWallClient:
    """Async context-managed, read-only SonicOS API client."""

    def __init__(
        self,
        sonicwall_host: str,
        username: str,
        password: str,
        *,
        verify_ssl: bool = True,
    ):
        self.base_url = _normalize_host(sonicwall_host)
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self._client: Optional[httpx.AsyncClient] = None
        self._authed = False

    async def __aenter__(self) -> "SonicWallClient":
        self._client = httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=REQUEST_TIMEOUT,
            headers={"Accept": "application/json"},
        )
        await self.login()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        try:
            await self.logout()
        finally:
            if self._client is not None:
                await self._client.aclose()
                self._client = None

    def _require_client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("SonicWallClient must be used as an async context manager.")
        return self._client

    async def login(self) -> None:
        client = self._require_client()
        url = f"{self.base_url}/api/sonicos/auth"
        resp = await client.post(url, auth=(self.username, self.password))
        if resp.status_code == 401:
            raise SonicWallError("SonicWall authentication failed (401): check username and password.")
        if resp.status_code >= 400:
            raise SonicWallError(
                f"SonicWall login failed ({resp.status_code}): {resp.text[:200]}"
            )
        self._authed = True

    async def logout(self) -> None:
        """Best-effort session teardown."""
        if not self._authed or self._client is None:
            self._authed = False
            return
        try:
            await self._client.delete(f"{self.base_url}/api/sonicos/auth")
        except Exception as exc:  # noqa: BLE001
            logger.debug("SonicWall logout failed (non-fatal): %s", exc)
        finally:
            self._authed = False

    async def _get(self, path: str) -> Optional[Dict]:
        client = self._require_client()
        resp = await client.get(f"{self.base_url}{path}")
        if resp.status_code in (401, 403):
            logger.error("SonicWall unauthorized (HTTP %s) on %s", resp.status_code, path)
            return None
        if resp.status_code >= 400:
            logger.warning("SonicWall GET %s -> HTTP %s: %s", path, resp.status_code, resp.text[:200])
            return None
        try:
            return resp.json()
        except ValueError:
            return None

    @staticmethod
    def _address_objects(payload: Optional[Dict]) -> List[Dict]:
        if not isinstance(payload, dict):
            return []
        objs = payload.get("address_objects")
        if isinstance(objs, list):
            return [o for o in objs if isinstance(o, dict)]
        return []

    async def list_ipv4_objects(self) -> List[Dict]:
        return self._address_objects(await self._get("/api/sonicos/address-objects/ipv4"))

    async def list_fqdn_objects(self) -> List[Dict]:
        return self._address_objects(await self._get("/api/sonicos/address-objects/fqdn"))


async def test_connection(
    sonicwall_host: str,
    username: str,
    password: str,
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    host = _normalize_host(sonicwall_host)
    parsed = urlparse(host)
    if not parsed.scheme or not parsed.netloc:
        return {
            "ok": False,
            "message": "SonicWall host must be a full URL (e.g. https://sonicwall.example.com).",
            "address_count": None,
        }
    try:
        async with SonicWallClient(host, username, password, verify_ssl=verify_ssl) as client:
            objs = await client.list_ipv4_objects()
            return {
                "ok": True,
                "message": f"Connected to SonicWall at {host}.",
                "address_count": len(objs),
            }
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "message": str(exc)[:500],
            "address_count": None,
        }


# ── Address object → asset value mapping ─────────────────────────────────────


def parse_ipv4_object(entry: Dict) -> Optional[Tuple[str, AssetType, str]]:
    """Parse a SonicOS ipv4 address object wrapper ``{"ipv4": {...}}``."""
    inner = entry.get("ipv4") if isinstance(entry.get("ipv4"), dict) else entry
    if not isinstance(inner, dict):
        return None

    host = inner.get("host")
    if isinstance(host, dict):
        ip = host.get("ip")
        if isinstance(ip, str) and _is_ip(ip.strip()):
            return ip.strip(), AssetType.IP_ADDRESS, "ip"

    network = inner.get("network")
    if isinstance(network, dict):
        subnet = network.get("subnet")
        mask = network.get("mask")
        if isinstance(subnet, str) and _is_ip(subnet.strip()) and isinstance(mask, str):
            prefix = _netmask_to_prefix(mask.strip()) if not mask.strip().isdigit() else int(mask.strip())
            if prefix is not None and 0 <= prefix <= 32:
                if prefix == 32:
                    return subnet.strip(), AssetType.IP_ADDRESS, "ip"
                return f"{subnet.strip()}/{prefix}", AssetType.IP_RANGE, "cidr"

    rng = inner.get("range")
    if isinstance(rng, dict):
        begin = rng.get("begin")
        if isinstance(begin, str) and _is_ip(begin.strip()):
            return begin.strip(), AssetType.IP_ADDRESS, "range"

    return None


def parse_fqdn_object(entry: Dict) -> Optional[Tuple[str, AssetType, str]]:
    inner = entry.get("fqdn") if isinstance(entry.get("fqdn"), dict) else entry
    if not isinstance(inner, dict):
        return None
    domain = inner.get("domain") or inner.get("host")
    if isinstance(domain, str) and domain.strip():
        name = domain.strip().rstrip(".").lower()
        if name and not name.startswith("*") and "." in name:
            atype = AssetType.SUBDOMAIN if _looks_like_subdomain(name) else AssetType.DOMAIN
            return name, atype, "fqdn"
    return None


def _object_name(entry: Dict, inner_key: str) -> str:
    inner = entry.get(inner_key) if isinstance(entry.get(inner_key), dict) else entry
    if isinstance(inner, dict):
        name = inner.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
    return ""


class _Stats:
    def __init__(self) -> None:
        self.assets_created = 0
        self.assets_updated = 0
        self.addresses_seen = 0
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
    integration: SonicWallIntegration,
    value: str,
    asset_type: AssetType,
    stats: _Stats,
    *,
    object_name: str,
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
        "sonicwall_integration_id": integration.id,
        "sonicwall_object_name": object_name,
        "sonicwall_address_kind": address_kind,
        "sonicwall_host": integration.sonicwall_host,
        "cloud_service": CLOUD_SERVICE_TAG,
    }

    desired_tags = {SOURCE_TAG, CLOUD_SERVICE_TAG, f"sonicwall-kind:{address_kind}"}

    if existing:
        existing.last_seen = datetime.utcnow()
        tags = [t for t in (existing.tags or []) if t != "sonicwall:removed"]
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
        name=object_name[:255] if object_name else value[:255],
        asset_type=asset_type,
        value=value[:500],
        organization_id=org_id,
        status=AssetStatus.DISCOVERED,
        discovery_source=DISCOVERY_SOURCE,
        association_reason=(
            f"Address object '{object_name}' imported from SonicWall ({integration.name})"
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
    integration: SonicWallIntegration,
    ipv4_objects: List[Dict],
    fqdn_objects: List[Dict],
    stats: _Stats,
) -> set[str]:
    stats.addresses_seen = len(ipv4_objects) + len(fqdn_objects)
    seen_values: set[str] = set()

    for entry in ipv4_objects:
        parsed = parse_ipv4_object(entry)
        if not parsed:
            continue
        value, asset_type, kind = parsed
        name = _object_name(entry, "ipv4") or value
        asset = _upsert_asset(db, integration, value, asset_type, stats, object_name=name, address_kind=kind)
        if asset:
            seen_values.add(value)
            _bump_kind(stats, kind)

    for entry in fqdn_objects:
        parsed = parse_fqdn_object(entry)
        if not parsed:
            continue
        value, asset_type, kind = parsed
        name = _object_name(entry, "fqdn") or value
        asset = _upsert_asset(db, integration, value, asset_type, stats, object_name=name, address_kind=kind)
        if asset:
            seen_values.add(value)
            _bump_kind(stats, kind)

    return seen_values


def _mark_missing_assets(
    db: Session,
    integration: SonicWallIntegration,
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
        if meta.get("sonicwall_integration_id") != integration.id:
            continue
        if asset.value not in seen_values:
            stats.assets_missing_from_source += 1
            tags = list(asset.tags or [])
            if "sonicwall:removed" not in tags:
                tags.append("sonicwall:removed")
                asset.tags = tags


async def sync_integration(db: Session, integration: SonicWallIntegration) -> Dict[str, Any]:
    """Import address objects from the SonicWall SonicOS API."""
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
    if not integration.sonicwall_host:
        return {
            "ok": False,
            "message": "No SonicWall host configured for this connection.",
            **stats.as_dict(),
        }

    try:
        async with SonicWallClient(
            integration.sonicwall_host,
            username,
            password,
            verify_ssl=bool(integration.verify_ssl),
        ) as client:
            ipv4_objects = await client.list_ipv4_objects()
            fqdn_objects = await client.list_fqdn_objects()

        seen = _import_objects(db, integration, ipv4_objects, fqdn_objects, stats)
        _mark_missing_assets(db, integration, seen, stats)

        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = True
        integration.last_error = None
        integration.last_sync_stats = stats.as_dict()
        db.commit()

        return {
            "ok": True,
            "message": (
                f"Imported {stats.assets_created} new asset(s) from SonicWall "
                f"({stats.addresses_seen} address object(s) seen)."
            ),
            **stats.as_dict(),
        }
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.exception("SonicWall sync failed for org %s", org_id)
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = str(exc)[:1000]
        db.commit()
        return {
            "ok": False,
            "message": f"Sync failed: {exc}",
            **stats.as_dict(),
        }
