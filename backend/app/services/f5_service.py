"""F5 BIG-IP LTM reachability integration service.

Read-only import of VIP → pool → member mappings so ASM can show which
internal IPs are reachable from the internet through load balancers.

Best-practice client behavior:
    - Shared httpx session (connection reuse)
    - Token auth + explicit token logout
    - Paginated list calls
    - Field selection to minimize payload
    - Aggregate mappings in-memory so VIP member lists reflect the current sync

API reference (iControl REST):
    Auth     : POST /mgmt/shared/authn/login  → X-F5-Auth-Token
    Logout   : DELETE /mgmt/shared/authz/tokens/{token}
    Virtuals : GET  /mgmt/tm/ltm/virtual
    Pools    : GET  /mgmt/tm/ltm/pool/~Partition~Name/members
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import httpx
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetStatus, AssetType
from app.models.f5_integration import F5Integration

logger = logging.getLogger(__name__)

DISCOVERY_SOURCE = "f5"
CLOUD_SERVICE_TAG = "f5"
SOURCE_TAG = f"source:{DISCOVERY_SOURCE}"
RATE_LIMIT_DELAY = 0.1
PAGE_SIZE = 200
MAX_PAGES = 250
REQUEST_TIMEOUT = httpx.Timeout(60.0, connect=15.0)

# destination examples: "10.0.0.1:443", "/Common/10.0.0.1:443", "2001:db8::1.443"
_DEST_IPV4 = re.compile(
    r"(?:^|/)(?P<ip>(?:\d{1,3}\.){3}\d{1,3})(?:%\d+)?(?::(?P<port>\d+))?$"
)
_DEST_IPV6 = re.compile(
    r"(?:^|/)(?P<ip>\[[^\]]+\]|[0-9a-fA-F:]+)(?:%\d+)?(?:[.:](?P<port>\d+))?$"
)

_VIRTUAL_SELECT = "name,fullPath,partition,destination,enabled,disabled,pool"
_MEMBER_SELECT = "name,address,state,session"


def _normalize_host(host: str) -> str:
    host = (host or "").strip().rstrip("/")
    if host and not host.startswith(("http://", "https://")):
        host = f"https://{host}"
    return host


def _strip_partition_path(name: str) -> str:
    """'/Common/my-pool' → 'my-pool'; bare names unchanged."""
    if not name:
        return ""
    name = name.strip()
    if name.startswith("/"):
        parts = [p for p in name.split("/") if p]
        return parts[-1] if parts else name
    return name


def _parse_destination(destination: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Return (ip, port) from an LTM virtual destination string."""
    if not isinstance(destination, str) or not destination.strip():
        return None, None
    dest = destination.strip()
    # Drop leading partition path: /Common/1.2.3.4:443
    if dest.startswith("/") and dest.count("/") >= 2:
        dest = dest.split("/", 2)[-1]

    m = _DEST_IPV4.search(dest) if "." in dest and dest.count(":") <= 1 else None
    if m:
        return m.group("ip"), m.group("port")

    # IPv6 forms: 2001:db8::1.443 or [2001:db8::1]:443
    m6 = _DEST_IPV6.search(dest)
    if m6:
        ip = m6.group("ip").strip("[]")
        if ":" in ip:
            return ip, m6.group("port")
    return None, None


def _parse_member_address(raw: Any) -> Optional[str]:
    if not isinstance(raw, str) or not raw.strip():
        return None
    addr = raw.strip()
    # address may be "10.1.1.1%0" or "10.1.1.1"
    if "%" in addr:
        addr = addr.split("%", 1)[0]
    # member name form "10.1.1.1:80"
    if addr.count(":") == 1 and "." in addr:
        addr = addr.split(":", 1)[0]
    return addr.strip() or None


def _pool_api_path(pool_ref: str) -> str:
    """Convert '/Common/my-pool' to '~Common~my-pool' for the REST path."""
    ref = (pool_ref or "").strip()
    if not ref:
        return ""
    if ref.startswith("~"):
        return ref
    if ref.startswith("/"):
        return "~" + "~".join(p for p in ref.split("/") if p)
    return f"~Common~{ref}"


def _virtual_enabled(virtual: Dict[str, Any]) -> bool:
    """Normalize BIG-IP enabled/disabled flags across API variants."""
    if virtual.get("disabled") is True:
        return False
    disabled = virtual.get("disabled")
    if isinstance(disabled, str) and disabled.lower() in ("true", "1", "yes"):
        return False
    if virtual.get("enabled") is False:
        return False
    enabled = virtual.get("enabled")
    if isinstance(enabled, str) and enabled.lower() in ("false", "0", "no"):
        return False
    return True


class F5Client:
    """Async context-managed, read-only F5 iControl REST client."""

    def __init__(
        self,
        bigip_host: str,
        username: str,
        password: str,
        *,
        partition: Optional[str] = None,
        verify_ssl: bool = True,
    ):
        self.base_url = _normalize_host(bigip_host)
        self.username = username
        self.password = password
        self.partition = partition.strip() if partition and partition.strip() else None
        self.verify_ssl = verify_ssl
        self._token: Optional[str] = None
        self._token_name: Optional[str] = None
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "F5Client":
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
            raise RuntimeError("F5Client must be used as an async context manager.")
        return self._client

    def _auth_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        if self._token:
            headers["X-F5-Auth-Token"] = self._token
        return headers

    async def login(self) -> None:
        client = self._require_client()
        url = f"{self.base_url}/mgmt/shared/authn/login"
        payload = {
            "username": self.username,
            "password": self.password,
            "loginProviderName": "tmos",
        }
        resp = await client.post(url, json=payload)
        if resp.status_code >= 400:
            # Never echo credentials; truncate body only.
            detail = resp.text[:300]
            raise RuntimeError(f"F5 login failed ({resp.status_code}): {detail}")
        data = resp.json()
        token_obj = data.get("token") if isinstance(data.get("token"), dict) else {}
        token = token_obj.get("token")
        if not token:
            raise RuntimeError("F5 login succeeded but no token was returned.")
        self._token = token
        # Token name is preferred for logout URL on some versions.
        self._token_name = token_obj.get("name") or token

    async def logout(self) -> None:
        """Best-effort token revocation so sessions do not linger on BIG-IP."""
        if not self._token or self._client is None:
            self._token = None
            self._token_name = None
            return
        token_id = self._token_name or self._token
        url = f"{self.base_url}/mgmt/shared/authz/tokens/{quote(str(token_id), safe='')}"
        try:
            await self._client.delete(url, headers=self._auth_headers())
        except Exception as exc:  # noqa: BLE001
            logger.debug("F5 token logout failed (non-fatal): %s", exc)
        finally:
            self._token = None
            self._token_name = None

    async def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        client = self._require_client()
        if not self._token:
            await self.login()
        url = f"{self.base_url}{path}"
        resp = await client.get(url, headers=self._auth_headers(), params=params or {})
        if resp.status_code == 401:
            await self.login()
            resp = await client.get(url, headers=self._auth_headers(), params=params or {})
        if resp.status_code >= 400:
            raise RuntimeError(f"F5 GET {path} failed ({resp.status_code}): {resp.text[:300]}")
        data = resp.json()
        return data if isinstance(data, dict) else {}

    async def _paginate(
        self,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Page through iControl collections via $top/$skip."""
        base_params: Dict[str, Any] = dict(params or {})
        items: List[Dict[str, Any]] = []
        skip = 0
        for _ in range(MAX_PAGES):
            page_params = {**base_params, "$top": PAGE_SIZE, "$skip": skip}
            data = await self._get(path, params=page_params)
            page = data.get("items") or []
            if not isinstance(page, list):
                break
            typed = [i for i in page if isinstance(i, dict)]
            items.extend(typed)
            if len(page) < PAGE_SIZE:
                break
            skip += PAGE_SIZE
            await asyncio.sleep(RATE_LIMIT_DELAY)
        return items

    async def list_virtuals(self) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {"$select": _VIRTUAL_SELECT}
        if self.partition:
            params["$filter"] = f"partition eq {self.partition}"
        items = await self._paginate("/mgmt/tm/ltm/virtual", params=params)
        if self.partition:
            items = [
                v for v in items
                if (v.get("partition") or "Common") == self.partition
            ]
        return items

    async def list_pool_members(self, pool_ref: str) -> List[Dict[str, Any]]:
        path_key = _pool_api_path(pool_ref)
        if not path_key:
            return []
        encoded = quote(path_key, safe="~")
        try:
            return await self._paginate(
                f"/mgmt/tm/ltm/pool/{encoded}/members",
                params={"$select": _MEMBER_SELECT},
            )
        except RuntimeError as exc:
            logger.warning("Failed to list members for pool %s: %s", pool_ref, exc)
            return []


async def test_connection(
    bigip_host: str,
    username: str,
    password: str,
    *,
    partition: Optional[str] = None,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    try:
        async with F5Client(
            bigip_host,
            username,
            password,
            partition=partition,
            verify_ssl=verify_ssl,
        ) as client:
            virtuals = await client.list_virtuals()
            return {
                "ok": True,
                "message": f"Connected to F5 BIG-IP at {_normalize_host(bigip_host)}.",
                "virtual_count": len(virtuals),
            }
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "message": str(exc)[:500],
            "virtual_count": None,
        }


class _Stats:
    def __init__(self) -> None:
        self.assets_created = 0
        self.assets_updated = 0
        self.virtuals_seen = 0
        self.vips_imported = 0
        self.members_imported = 0
        self.mappings_seen = 0
        self.assets_missing_from_source = 0

    def as_dict(self) -> Dict[str, int]:
        return {
            "assets_created": self.assets_created,
            "assets_updated": self.assets_updated,
            "virtuals_seen": self.virtuals_seen,
            "vips_imported": self.vips_imported,
            "members_imported": self.members_imported,
            "mappings_seen": self.mappings_seen,
            "assets_missing_from_source": self.assets_missing_from_source,
        }


def _owned_by_this_integration(asset: Asset, integration_id: int) -> bool:
    meta = asset.metadata_ or {}
    if meta.get("f5_integration_id") == integration_id:
        return True
    return asset.discovery_source == DISCOVERY_SOURCE and meta.get("f5_integration_id") is None


def _upsert_vip_asset(
    db: Session,
    integration: F5Integration,
    *,
    vip_ip: str,
    virtual_names: List[str],
    partition: str,
    pool_names: List[str],
    destinations: List[str],
    enabled: bool,
    members: List[Dict[str, Any]],
    stats: _Stats,
) -> Optional[Asset]:
    vip_ip = (vip_ip or "").strip()
    if not vip_ip:
        return None

    org_id = integration.organization_id
    existing = (
        db.query(Asset)
        .filter(Asset.organization_id == org_id, Asset.value == vip_ip)
        .first()
    )

    primary_virtual = virtual_names[0] if virtual_names else vip_ip
    primary_pool = pool_names[0] if pool_names else None
    primary_destination = destinations[0] if destinations else None

    member_payload = [
        {
            "ip": m.get("ip"),
            "port": m.get("port"),
            "state": m.get("state"),
            "session": m.get("session"),
            "name": m.get("name"),
        }
        for m in members
        if m.get("ip")
    ]

    meta_patch: Dict[str, Any] = {
        "f5_integration_id": integration.id,
        "f5_virtual_name": primary_virtual,
        "f5_virtual_names": virtual_names,
        "f5_partition": partition,
        "f5_pool": primary_pool,
        "f5_pools": pool_names,
        "f5_destination": primary_destination,
        "f5_destinations": destinations,
        "f5_enabled": enabled,
        "f5_pool_members": member_payload,
        "f5_host": integration.bigip_host,
        "cloud_service": CLOUD_SERVICE_TAG,
    }

    desired_tags = {SOURCE_TAG, CLOUD_SERVICE_TAG, "f5:vip", f"f5-partition:{partition}"}
    if not enabled:
        desired_tags.add("f5:disabled")
    for pool_name in pool_names:
        desired_tags.add(f"f5-pool:{pool_name}")

    # Disabled VIPs are inventory-only, not internet-reachable entry points.
    want_public = bool(enabled)

    if existing:
        existing.last_seen = datetime.utcnow()
        tags = [t for t in (existing.tags or []) if t not in ("f5:removed", "f5:disabled")]
        # Drop stale f5-pool:* tags owned by prior syncs for this VIP, then re-add.
        if _owned_by_this_integration(existing, integration.id):
            tags = [t for t in tags if not str(t).startswith("f5-pool:")]
        for t in desired_tags:
            if t not in tags:
                tags.append(t)
        existing.tags = tags
        meta = dict(existing.metadata_ or {})
        meta.update(meta_patch)
        existing.metadata_ = meta
        if _owned_by_this_integration(existing, integration.id):
            existing.is_public = want_public
            existing.discovery_source = DISCOVERY_SOURCE
            existing.name = (primary_virtual or vip_ip)[:255]
        if not existing.ip_address:
            existing.ip_address = vip_ip
        if not existing.ip_addresses:
            existing.ip_addresses = [vip_ip]
        elif vip_ip not in (existing.ip_addresses or []):
            existing.ip_addresses = list(existing.ip_addresses or []) + [vip_ip]
        stats.assets_updated += 1
        return existing

    asset = Asset(
        name=(primary_virtual or vip_ip)[:255],
        asset_type=AssetType.IP_ADDRESS,
        value=vip_ip[:500],
        organization_id=org_id,
        status=AssetStatus.DISCOVERED,
        description=f"F5 virtual server VIP ({primary_virtual})",
        discovery_source=DISCOVERY_SOURCE,
        association_reason=(
            f"VIP for virtual '{primary_virtual}' imported from F5 BIG-IP "
            f"({integration.name})"
        ),
        association_confidence=90,
        tags=sorted(desired_tags),
        metadata_=meta_patch,
        system_type="load_balancer",
        device_class="Network Infrastructure",
        device_subclass="Load Balancer",
        is_public=want_public,
        ip_address=vip_ip,
        ip_addresses=[vip_ip],
    )
    db.add(asset)
    db.flush()
    stats.assets_created += 1
    return asset


def _upsert_member_asset(
    db: Session,
    integration: F5Integration,
    *,
    member_ip: str,
    member_port: Optional[str],
    vip_ip: str,
    vip_asset: Asset,
    virtual_name: str,
    pool_name: Optional[str],
    member_state: Optional[str],
    stats: _Stats,
) -> Optional[Asset]:
    member_ip = (member_ip or "").strip()
    if not member_ip or member_ip == vip_ip:
        return None

    org_id = integration.organization_id
    existing = (
        db.query(Asset)
        .filter(Asset.organization_id == org_id, Asset.value == member_ip)
        .first()
    )

    meta_patch: Dict[str, Any] = {
        "f5_integration_id": integration.id,
        "f5_reachable_via_vip": vip_ip,
        "f5_pool": pool_name,
        "f5_member_port": member_port,
        "f5_virtual_name": virtual_name,
        "f5_member_state": member_state,
        "f5_host": integration.bigip_host,
        "cloud_service": CLOUD_SERVICE_TAG,
    }

    desired_tags = {
        SOURCE_TAG,
        CLOUD_SERVICE_TAG,
        "f5:pool-member",
        f"f5-via-vip:{vip_ip}",
    }
    if pool_name:
        desired_tags.add(f"f5-pool:{pool_name}")

    if existing:
        existing.last_seen = datetime.utcnow()
        tags = [t for t in (existing.tags or []) if t != "f5:removed"]
        for t in desired_tags:
            if t not in tags:
                tags.append(t)
        existing.tags = tags
        meta = dict(existing.metadata_ or {})
        via = meta.get("f5_reachable_via_vips") if isinstance(meta.get("f5_reachable_via_vips"), list) else []
        if meta.get("f5_reachable_via_vip") and meta["f5_reachable_via_vip"] not in via:
            via.append(meta["f5_reachable_via_vip"])
        if vip_ip not in via:
            via.append(vip_ip)
        meta_patch["f5_reachable_via_vips"] = via
        meta.update(meta_patch)
        existing.metadata_ = meta
        if _owned_by_this_integration(existing, integration.id):
            existing.is_public = False
            existing.discovery_source = DISCOVERY_SOURCE
            if not existing.parent_id:
                existing.parent_id = vip_asset.id
        if not existing.ip_address:
            existing.ip_address = member_ip
        if not existing.ip_addresses:
            existing.ip_addresses = [member_ip]
        elif member_ip not in (existing.ip_addresses or []):
            existing.ip_addresses = list(existing.ip_addresses or []) + [member_ip]
        stats.assets_updated += 1
        return existing

    asset = Asset(
        name=f"{member_ip} (via {vip_ip})"[:255],
        asset_type=AssetType.IP_ADDRESS,
        value=member_ip[:500],
        organization_id=org_id,
        parent_id=vip_asset.id,
        status=AssetStatus.DISCOVERED,
        description=f"F5 pool member reachable via VIP {vip_ip}",
        discovery_source=DISCOVERY_SOURCE,
        association_reason=(
            f"Pool member behind VIP {vip_ip} (virtual '{virtual_name}') "
            f"imported from F5 BIG-IP ({integration.name})"
        ),
        association_confidence=90,
        tags=sorted(desired_tags),
        metadata_={
            **meta_patch,
            "f5_reachable_via_vips": [vip_ip],
        },
        system_type="server",
        device_class="Server",
        device_subclass="Load Balancer Backend",
        is_public=False,
        ip_address=member_ip,
        ip_addresses=[member_ip],
    )
    db.add(asset)
    db.flush()
    stats.assets_created += 1
    return asset


def _mark_missing_assets(
    db: Session,
    integration: F5Integration,
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
        if meta.get("f5_integration_id") != integration.id:
            continue
        if asset.value not in seen_values:
            stats.assets_missing_from_source += 1
            tags = list(asset.tags or [])
            if "f5:removed" not in tags:
                tags.append("f5:removed")
                asset.tags = tags


def _parse_pool_members(raw_members: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    parsed: List[Dict[str, Any]] = []
    for raw in raw_members:
        addr = _parse_member_address(raw.get("address") or raw.get("name"))
        if not addr:
            continue
        port = None
        name = raw.get("name")
        if isinstance(name, str) and ":" in name:
            # IPv4 name:port — take trailing port; IPv6 names use '.' before port on F5.
            if name.count(":") == 1 and "." in name:
                port = name.rsplit(":", 1)[-1]
            elif "." in name.rsplit(":", 1)[-1]:
                # uncommon; leave port unset
                port = None
            else:
                maybe = name.rsplit(":", 1)[-1]
                if maybe.isdigit():
                    port = maybe
        parsed.append(
            {
                "ip": addr,
                "port": port,
                "state": raw.get("state"),
                "session": raw.get("session"),
                "name": name,
            }
        )
    return parsed


async def _collect_vip_aggregates(client: F5Client) -> Dict[str, Dict[str, Any]]:
    """Pull virtuals/members and aggregate by VIP IP for a consistent sync snapshot."""
    virtuals = await client.list_virtuals()
    pool_cache: Dict[str, List[Dict[str, Any]]] = {}
    aggregates: Dict[str, Dict[str, Any]] = {}

    for virtual in virtuals:
        virtual_name = str(virtual.get("name") or virtual.get("fullPath") or "").strip()
        partition = str(virtual.get("partition") or "Common")
        destination = virtual.get("destination")
        vip_ip, vip_port = _parse_destination(destination if isinstance(destination, str) else None)
        if not vip_ip:
            logger.debug("Skipping virtual with unparseable destination: %s", destination)
            continue

        enabled = _virtual_enabled(virtual)

        pool_ref = virtual.get("pool")
        if isinstance(pool_ref, dict):
            pool_ref = pool_ref.get("fullPath") or pool_ref.get("name")
        pool_ref = pool_ref if isinstance(pool_ref, str) and pool_ref.strip() else None
        pool_name = _strip_partition_path(pool_ref) if pool_ref else None

        members: List[Dict[str, Any]] = []
        if pool_ref:
            if pool_ref not in pool_cache:
                raw_members = await client.list_pool_members(pool_ref)
                await asyncio.sleep(RATE_LIMIT_DELAY)
                pool_cache[pool_ref] = _parse_pool_members(raw_members)
            members = pool_cache[pool_ref]

        agg = aggregates.get(vip_ip)
        if not agg:
            agg = {
                "vip_ip": vip_ip,
                "vip_ports": set(),
                "virtual_names": [],
                "partition": partition,
                "destinations": [],
                # VIP is internet-reachable if ANY virtual on that IP is enabled.
                "enabled": False,
                "pool_names": [],
                "members": {},
                "virtuals_seen": 0,
            }
            aggregates[vip_ip] = agg

        agg["virtuals_seen"] += 1
        if vip_port:
            agg["vip_ports"].add(vip_port)
        if virtual_name and virtual_name not in agg["virtual_names"]:
            agg["virtual_names"].append(virtual_name)
        if isinstance(destination, str) and destination not in agg["destinations"]:
            agg["destinations"].append(destination)
        if enabled:
            agg["enabled"] = True
        if pool_name and pool_name not in agg["pool_names"]:
            agg["pool_names"].append(pool_name)
        for member in members:
            key = f"{member.get('ip')}:{member.get('port')}"
            agg["members"][key] = member

    return aggregates


async def sync_integration(db: Session, integration: F5Integration) -> Dict[str, Any]:
    """Import VIP → pool-member reachability mappings from F5 BIG-IP."""
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
    if not integration.bigip_host:
        return {
            "ok": False,
            "message": "No BIG-IP host configured for this connection.",
            **stats.as_dict(),
        }

    try:
        async with F5Client(
            integration.bigip_host,
            username,
            password,
            partition=integration.partition,
            verify_ssl=bool(integration.verify_ssl),
        ) as client:
            aggregates = await _collect_vip_aggregates(client)

        stats.virtuals_seen = sum(int(a["virtuals_seen"]) for a in aggregates.values())
        stats.mappings_seen = sum(len(a["members"]) for a in aggregates.values())

        seen_values: set[str] = set()
        member_seen: set[str] = set()

        for vip_ip, agg in aggregates.items():
            members = list(agg["members"].values())
            vip_asset = _upsert_vip_asset(
                db,
                integration,
                vip_ip=vip_ip,
                virtual_names=list(agg["virtual_names"]),
                partition=str(agg["partition"]),
                pool_names=list(agg["pool_names"]),
                destinations=list(agg["destinations"]),
                enabled=bool(agg["enabled"]),
                members=members,
                stats=stats,
            )
            if not vip_asset:
                continue
            seen_values.add(vip_ip)
            stats.vips_imported += 1

            for member in members:
                member_asset = _upsert_member_asset(
                    db,
                    integration,
                    member_ip=member["ip"],
                    member_port=member.get("port"),
                    vip_ip=vip_ip,
                    vip_asset=vip_asset,
                    virtual_name=(agg["virtual_names"][0] if agg["virtual_names"] else vip_ip),
                    pool_name=(agg["pool_names"][0] if agg["pool_names"] else None),
                    member_state=member.get("state"),
                    stats=stats,
                )
                if member_asset:
                    seen_values.add(member["ip"])
                    if member["ip"] not in member_seen:
                        member_seen.add(member["ip"])
                        stats.members_imported += 1

        _mark_missing_assets(db, integration, seen_values, stats)

        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = True
        integration.last_error = None
        integration.last_sync_stats = stats.as_dict()
        db.commit()

        return {
            "ok": True,
            "message": (
                f"Imported {stats.vips_imported} VIP(s) and {stats.members_imported} "
                f"pool member(s) from F5 ({stats.virtuals_seen} virtual(s) seen)."
            ),
            **stats.as_dict(),
        }
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.exception("F5 sync failed for org %s", org_id)
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = str(exc)[:1000]
        db.commit()
        return {
            "ok": False,
            "message": f"Sync failed: {exc}",
            **stats.as_dict(),
        }
