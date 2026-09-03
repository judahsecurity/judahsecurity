"""Check Point integration service.

Read-only import of network objects as assets from the Check Point Management
Web API:

    show-hosts           → single hosts (ipv4-address)          → IP assets
    show-networks        → networks (subnet4 / mask-length4)    → CIDR assets
    show-address-ranges  → ranges (ipv4-address-first/last)     → seed first IP

Best-practice client behavior:
    - Read-only session login (``read-only: true``) so no publish lock is held
    - Shared httpx session with the ``X-chkp-sid`` header
    - Explicit logout so sessions do not linger on the management server
    - Paginated show commands (limit / offset until ``to`` reaches ``total``)

API reference (Management Web API):
    Login  : POST /web_api/login   {user, password, [domain], read-only}
    Show   : POST /web_api/show-hosts | show-networks | show-address-ranges
    Logout : POST /web_api/logout
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
from app.models.checkpoint_integration import CheckPointIntegration

logger = logging.getLogger(__name__)

DISCOVERY_SOURCE = "checkpoint"
CLOUD_SERVICE_TAG = "checkpoint"
SOURCE_TAG = f"source:{DISCOVERY_SOURCE}"

REQUEST_TIMEOUT = httpx.Timeout(60.0, connect=15.0)
RATE_LIMIT_DELAY = 0.1
PAGE_SIZE = 500
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


class CheckPointError(RuntimeError):
    """Raised when the management API returns an error payload."""


class CheckPointClient:
    """Async context-managed, read-only Check Point Management Web API client."""

    def __init__(
        self,
        management_host: str,
        username: str,
        password: str,
        *,
        domain: Optional[str] = None,
        verify_ssl: bool = True,
    ):
        self.base_url = _normalize_host(management_host)
        self.username = username
        self.password = password
        self.domain = domain.strip() if domain and domain.strip() else None
        self.verify_ssl = verify_ssl
        self._sid: Optional[str] = None
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "CheckPointClient":
        self._client = httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=REQUEST_TIMEOUT,
            headers={"Content-Type": "application/json"},
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
            raise RuntimeError("CheckPointClient must be used as an async context manager.")
        return self._client

    def _url(self, command: str) -> str:
        return f"{self.base_url}/web_api/{command.lstrip('/')}"

    async def _post(self, command: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        client = self._require_client()
        headers: Dict[str, str] = {}
        if self._sid:
            headers["X-chkp-sid"] = self._sid
        resp = await client.post(self._url(command), json=payload, headers=headers)
        try:
            data = resp.json()
        except ValueError:
            data = {}
        if resp.status_code >= 400:
            message = ""
            if isinstance(data, dict):
                message = data.get("message") or data.get("errors") or ""
            raise CheckPointError(
                f"Check Point {command} failed ({resp.status_code}): {str(message)[:300]}"
            )
        return data if isinstance(data, dict) else {}

    async def login(self) -> None:
        payload: Dict[str, Any] = {
            "user": self.username,
            "password": self.password,
            "read-only": True,
        }
        if self.domain:
            payload["domain"] = self.domain
        data = await self._post("login", payload)
        sid = data.get("sid")
        if not sid:
            raise CheckPointError("Check Point login succeeded but no session id was returned.")
        self._sid = sid

    async def logout(self) -> None:
        """Best-effort session teardown so sessions do not linger on the server."""
        if not self._sid or self._client is None:
            self._sid = None
            return
        try:
            await self._post("logout", {})
        except Exception as exc:  # noqa: BLE001
            logger.debug("Check Point logout failed (non-fatal): %s", exc)
        finally:
            self._sid = None

    async def _show_collection(self, command: str) -> List[Dict[str, Any]]:
        """Page through a show-* command until all objects are retrieved."""
        objects: List[Dict[str, Any]] = []
        offset = 0
        for _ in range(MAX_PAGES):
            data = await self._post(
                command,
                {"limit": PAGE_SIZE, "offset": offset, "details-level": "standard"},
            )
            batch = data.get("objects")
            if not isinstance(batch, list) or not batch:
                break
            objects.extend([o for o in batch if isinstance(o, dict)])
            total = data.get("total")
            to = data.get("to")
            if isinstance(total, int) and isinstance(to, int):
                if to >= total:
                    break
                offset = to
            else:
                if len(batch) < PAGE_SIZE:
                    break
                offset += len(batch)
            await asyncio.sleep(RATE_LIMIT_DELAY)
        return objects

    async def show_hosts(self) -> List[Dict[str, Any]]:
        return await self._show_collection("show-hosts")

    async def show_networks(self) -> List[Dict[str, Any]]:
        return await self._show_collection("show-networks")

    async def show_address_ranges(self) -> List[Dict[str, Any]]:
        return await self._show_collection("show-address-ranges")


async def test_connection(
    management_host: str,
    username: str,
    password: str,
    *,
    domain: Optional[str] = None,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    host = _normalize_host(management_host)
    parsed = urlparse(host)
    if not parsed.scheme or not parsed.netloc:
        return {
            "ok": False,
            "message": "Management host must be a full URL (e.g. https://mgmt.example.com).",
            "object_count": None,
        }
    try:
        async with CheckPointClient(
            host, username, password, domain=domain, verify_ssl=verify_ssl
        ) as client:
            hosts = await client.show_hosts()
            scope = f"domain '{domain}'" if domain else "the management server"
            return {
                "ok": True,
                "message": f"Connected to Check Point {scope}.",
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
    ip = entry.get("ipv4-address") or entry.get("ipv4_address")
    if isinstance(ip, str) and _is_ip(ip.strip()):
        return ip.strip(), AssetType.IP_ADDRESS, "ip"
    return None


def parse_network(entry: Dict) -> Optional[Tuple[str, AssetType, str]]:
    subnet = entry.get("subnet4") or entry.get("subnet")
    mask_len = entry.get("mask-length4")
    if mask_len is None:
        mask_len = entry.get("mask_length4")
    if isinstance(subnet, str) and _is_ip(subnet.strip()) and mask_len is not None:
        try:
            prefix = int(mask_len)
        except (TypeError, ValueError):
            return None
        if 0 <= prefix <= 32:
            if prefix == 32:
                return subnet.strip(), AssetType.IP_ADDRESS, "ip"
            return f"{subnet.strip()}/{prefix}", AssetType.IP_RANGE, "cidr"
    return None


def parse_address_range(entry: Dict) -> Optional[Tuple[str, AssetType, str]]:
    first = entry.get("ipv4-address-first") or entry.get("ipv4_address_first")
    if isinstance(first, str) and _is_ip(first.strip()):
        return first.strip(), AssetType.IP_ADDRESS, "range"
    return None


class _Stats:
    def __init__(self) -> None:
        self.assets_created = 0
        self.assets_updated = 0
        self.hosts_seen = 0
        self.networks_seen = 0
        self.ranges_seen = 0
        self.ips_imported = 0
        self.cidrs_imported = 0
        self.ranges_seeded = 0
        self.assets_missing_from_source = 0

    def as_dict(self) -> Dict[str, int]:
        return {
            "assets_created": self.assets_created,
            "assets_updated": self.assets_updated,
            "hosts_seen": self.hosts_seen,
            "networks_seen": self.networks_seen,
            "ranges_seen": self.ranges_seen,
            "ips_imported": self.ips_imported,
            "cidrs_imported": self.cidrs_imported,
            "ranges_seeded": self.ranges_seeded,
            "assets_missing_from_source": self.assets_missing_from_source,
        }


def _bump_kind(stats: _Stats, kind: str) -> None:
    if kind == "ip":
        stats.ips_imported += 1
    elif kind == "cidr":
        stats.cidrs_imported += 1
    elif kind == "range":
        stats.ranges_seeded += 1


def _upsert_asset(
    db: Session,
    integration: CheckPointIntegration,
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
    domain = integration.domain or "SMS"
    existing = (
        db.query(Asset)
        .filter(Asset.organization_id == org_id, Asset.value == value)
        .first()
    )

    meta_patch = {
        "checkpoint_integration_id": integration.id,
        "checkpoint_object_name": object_name,
        "checkpoint_object_type": object_type,
        "checkpoint_domain": domain,
        "checkpoint_address_kind": address_kind,
        "checkpoint_host": integration.management_host,
        "cloud_service": CLOUD_SERVICE_TAG,
    }

    desired_tags = {
        SOURCE_TAG,
        CLOUD_SERVICE_TAG,
        f"checkpoint-domain:{domain}",
        f"checkpoint-type:{object_type}",
    }

    if existing:
        existing.last_seen = datetime.utcnow()
        tags = [t for t in (existing.tags or []) if t != "checkpoint:removed"]
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
            f"Check Point ({domain})"
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


def _import_objects(
    db: Session,
    integration: CheckPointIntegration,
    hosts: List[Dict],
    networks: List[Dict],
    ranges: List[Dict],
    stats: _Stats,
) -> set[str]:
    stats.hosts_seen = len(hosts)
    stats.networks_seen = len(networks)
    stats.ranges_seen = len(ranges)
    seen_values: set[str] = set()

    def _ingest(entries: List[Dict], parser, object_type: str) -> None:
        for entry in entries:
            parsed = parser(entry)
            if not parsed:
                continue
            value, asset_type, kind = parsed
            object_name = str(entry.get("name") or entry.get("uid") or value).strip()
            comments = entry.get("comments")
            asset = _upsert_asset(
                db,
                integration,
                value,
                asset_type,
                stats,
                object_name=object_name or value,
                address_kind=kind,
                object_type=object_type,
                description=comments if isinstance(comments, str) and comments.strip() else None,
            )
            if asset:
                seen_values.add(value)
                _bump_kind(stats, kind)

    _ingest(hosts, parse_host, "host")
    _ingest(networks, parse_network, "network")
    _ingest(ranges, parse_address_range, "address-range")
    return seen_values


def _mark_missing_assets(
    db: Session,
    integration: CheckPointIntegration,
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
        if meta.get("checkpoint_integration_id") != integration.id:
            continue
        if asset.value not in seen_values:
            stats.assets_missing_from_source += 1
            tags = list(asset.tags or [])
            if "checkpoint:removed" not in tags:
                tags.append("checkpoint:removed")
                asset.tags = tags


async def sync_integration(db: Session, integration: CheckPointIntegration) -> Dict[str, Any]:
    """Import host / network / address-range objects from Check Point."""
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
    if not integration.management_host:
        return {
            "ok": False,
            "message": "No management host configured for this connection.",
            **stats.as_dict(),
        }

    try:
        async with CheckPointClient(
            integration.management_host,
            username,
            password,
            domain=integration.domain,
            verify_ssl=bool(integration.verify_ssl),
        ) as client:
            hosts = await client.show_hosts()
            networks = await client.show_networks()
            ranges = await client.show_address_ranges()

        seen = _import_objects(db, integration, hosts, networks, ranges, stats)
        _mark_missing_assets(db, integration, seen, stats)

        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = True
        integration.last_error = None
        integration.last_sync_stats = stats.as_dict()
        db.commit()

        return {
            "ok": True,
            "message": (
                f"Imported {stats.assets_created} new asset(s) from Check Point "
                f"({stats.hosts_seen} host(s), {stats.networks_seen} network(s), "
                f"{stats.ranges_seen} range(s) seen)."
            ),
            **stats.as_dict(),
        }
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.exception("Check Point sync failed for org %s", org_id)
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = str(exc)[:1000]
        db.commit()
        return {
            "ok": False,
            "message": f"Sync failed: {exc}",
            **stats.as_dict(),
        }
