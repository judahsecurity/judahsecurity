"""Read-only Falcon asset and Spotlight import for Judah exposure management."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from datetime import datetime, timezone
from typing import Any, AsyncIterator

import httpx
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetStatus, AssetType
from app.models.crowdstrike_integration import CrowdStrikeAssetLink, CrowdStrikeIntegration
from app.models.port_service import PortService, PortState, Protocol
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus

logger = logging.getLogger(__name__)

# Fixed hosts prevent an API credential from being sent to a user-supplied URL.
REGION_URLS = {
    "us-1": "https://api.crowdstrike.com",
    "us-2": "https://api.us-2.crowdstrike.com",
    "eu-1": "https://api.eu-1.crowdstrike.com",
    "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
}
SOURCE = "crowdstrike"
MAX_PAGES = 5000


class CrowdStrikeError(RuntimeError):
    """Safe error text that never includes tokens, credentials, or API response bodies."""


def _resources(payload: dict[str, Any], label: str) -> list[Any]:
    resources = payload.get("resources")
    if not isinstance(resources, list):
        raise CrowdStrikeError(f"{label} returned an unexpected resources payload.")
    return resources


class CrowdStrikeClient:
    def __init__(self, region: str, client_id: str, client_secret: str) -> None:
        if region not in REGION_URLS:
            raise CrowdStrikeError("Select a supported CrowdStrike cloud region.")
        if not client_id or not client_secret:
            raise CrowdStrikeError("CrowdStrike client credentials are missing.")
        self.base_url = REGION_URLS[region]
        self.client_id = client_id
        self.client_secret = client_secret
        self.token: str | None = None
        self.http = httpx.AsyncClient(base_url=self.base_url, timeout=45.0)

    async def __aenter__(self) -> "CrowdStrikeClient":
        return self

    async def __aexit__(self, *_args: Any) -> None:
        await self.http.aclose()

    async def _request(self, method: str, path: str, *, auth: bool = True, **kwargs: Any) -> dict[str, Any]:
        if auth and not self.token:
            await self.authenticate()
        headers = {"Accept": "application/json"}
        if auth:
            headers["Authorization"] = f"Bearer {self.token}"
        refreshed = False
        attempt = 0
        while attempt < 4:
            try:
                response = await self.http.request(method, path, headers=headers, **kwargs)
            except httpx.HTTPError as exc:
                if attempt == 3:
                    raise CrowdStrikeError("Could not reach the CrowdStrike API.") from exc
                await asyncio.sleep(2 ** attempt)
                attempt += 1
                continue
            if response.status_code in {429, 502, 503, 504} and attempt < 3:
                retry_after = response.headers.get("Retry-After", "")
                delay = min(60, max(0, int(retry_after))) if retry_after.isdigit() else 2 ** attempt
                await asyncio.sleep(delay)
                attempt += 1
                continue
            if response.status_code == 401 and auth and not refreshed:
                await self.authenticate()
                headers["Authorization"] = f"Bearer {self.token}"
                refreshed = True
                continue
            if response.status_code in {401, 403}:
                raise CrowdStrikeError(f"CrowdStrike denied {path} (HTTP {response.status_code}); check license and API scopes.")
            if response.status_code >= 400:
                raise CrowdStrikeError(f"CrowdStrike {path} failed (HTTP {response.status_code}).")
            try:
                payload = response.json()
            except ValueError as exc:
                raise CrowdStrikeError(f"CrowdStrike {path} returned invalid JSON.") from exc
            if not isinstance(payload, dict) or payload.get("errors"):
                raise CrowdStrikeError(f"CrowdStrike {path} returned an API error.")
            return payload
        raise CrowdStrikeError(f"CrowdStrike {path} failed after retries.")

    async def authenticate(self) -> None:
        payload = await self._request(
            "POST", "/oauth2/token", auth=False,
            data={"client_id": self.client_id, "client_secret": self.client_secret},
        )
        token = payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise CrowdStrikeError("CrowdStrike authentication returned no access token.")
        self.token = token

    async def _pages(self, path: str, *, params: dict[str, Any], cursor_key: str) -> AsyncIterator[list[Any]]:
        cursor: str | None = None
        seen: set[str] = set()
        for _ in range(MAX_PAGES):
            query = dict(params)
            if cursor:
                query[cursor_key] = cursor
            payload = await self._request("GET", path, params=query)
            batch = _resources(payload, path)
            yield batch
            page = (payload.get("meta") or {}).get("pagination") or {}
            following = page.get("after") or page.get("next")
            if not following:
                return
            if not isinstance(following, str) or following in seen or following == cursor:
                raise CrowdStrikeError(f"CrowdStrike {path} returned a repeated page cursor.")
            seen.add(following)
            cursor = following
        raise CrowdStrikeError(f"CrowdStrike {path} exceeded the pagination safety limit.")

    async def external_assets(self) -> AsyncIterator[list[dict[str, Any]]]:
        async for ids in self._pages("/fem/queries/external-assets/v2", params={"limit": 1000}, cursor_key="after"):
            if not all(isinstance(item, str) for item in ids):
                raise CrowdStrikeError("CrowdStrike external asset query returned invalid IDs.")
            for start in range(0, len(ids), 100):
                payload = await self._request("GET", "/fem/entities/external-assets/v1", params={"ids": ids[start:start + 100]})
                yield _resources(payload, "External assets")

    async def hosts(self) -> AsyncIterator[list[dict[str, Any]]]:
        async for batch in self._pages(
            "/devices/combined/devices/v1", params={"limit": 1000, "sort": "device_id.asc"}, cursor_key="offset"
        ):
            yield batch

    async def spotlight(self) -> AsyncIterator[list[dict[str, Any]]]:
        async for batch in self._pages(
            "/spotlight/combined/vulnerabilities/v1",
            params={"limit": 1000, "facet": ["host_info", "cve", "remediation", "evaluation_logic"]},
            cursor_key="after",
        ):
            yield batch


def _client_for(integration: CrowdStrikeIntegration) -> CrowdStrikeClient:
    return CrowdStrikeClient(integration.cloud_region, integration.get_client_id(), integration.get_client_secret())


async def test_connection(region: str, client_id: str, client_secret: str, *, external: bool, hosts: bool, spotlight: bool) -> dict[str, Any]:
    try:
        async with CrowdStrikeClient(region, client_id, client_secret) as client:
            if external:
                await client._request("GET", "/fem/queries/external-assets/v2", params={"limit": 1})
            if hosts or spotlight:
                await client._request("GET", "/devices/combined/devices/v1", params={"limit": 1})
            if spotlight:
                await client._request("GET", "/spotlight/combined/vulnerabilities/v1", params={"limit": 1})
        return {"ok": True, "message": "CrowdStrike credentials and selected read scopes were verified."}
    except CrowdStrikeError as exc:
        return {"ok": False, "message": str(exc)}


def _utc(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc).replace(tzinfo=None) if parsed.tzinfo else parsed
    except ValueError:
        return None


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _external_identity(source: dict[str, Any]) -> tuple[AssetType, str] | None:
    domain = str(_as_dict(source.get("dns_domain")).get("fqdn") or "").strip().lower().rstrip(".")
    if domain:
        return AssetType.DOMAIN, domain
    address = str(_as_dict(source.get("ip")).get("ip_address") or "").strip()
    try:
        if address:
            return AssetType.IP_ADDRESS, str(ipaddress.ip_address(address))
    except ValueError:
        pass
    return None


def _link_asset(db: Session, integration: CrowdStrikeIntegration, kind: str, source_id: str, cid: str, *, value: str, asset_type: AssetType, name: str, allow_match: bool) -> tuple[Asset, bool]:
    link = db.query(CrowdStrikeAssetLink).filter_by(integration_id=integration.id, source_kind=kind, source_id=source_id).first()
    asset = db.get(Asset, link.asset_id) if link else None
    created = False
    if asset is None and allow_match:
        asset = db.query(Asset).filter_by(organization_id=integration.organization_id, asset_type=asset_type, value=value).first()
    if asset is None:
        asset = Asset(
            organization_id=integration.organization_id, asset_type=asset_type, value=value[:500], name=name[:255],
            status=AssetStatus.DISCOVERED, discovery_source=SOURCE, association_reason="Imported from CrowdStrike Falcon",
            association_confidence=80, in_scope=False, is_owned=False, is_public=False,
            tags=["source:crowdstrike"],
        )
        db.add(asset)
        db.flush()
        created = True
    if link is None:
        db.add(CrowdStrikeAssetLink(integration_id=integration.id, asset_id=asset.id, source_kind=kind, source_id=source_id[:255], cid=cid, last_seen=datetime.utcnow()))
    else:
        link.last_seen = datetime.utcnow()
    return asset, created


def _merge_source_metadata(asset: Asset, kind: str, source_id: str, cid: str, source: dict[str, Any]) -> None:
    metadata = dict(asset.metadata_ or {})
    cs = dict(metadata.get(SOURCE) or {})
    cs[kind] = {
        "id": source_id, "cid": cid, "last_seen": source.get("last_seen"),
        "internet_exposure": source.get("internet_exposure"), "criticality": source.get("criticality"),
        "perimeter": source.get("perimeter"), "triage": source.get("triage"),
        "subsidiaries": source.get("subsidiaries"),
        "aid": _as_dict(source.get("ip")).get("aid") if kind == "external" else source_id,
    }
    metadata[SOURCE] = cs
    asset.metadata_ = metadata
    tags = list(asset.tags or [])
    if "source:crowdstrike" not in tags:
        asset.tags = tags + ["source:crowdstrike"]
    asset.last_seen = _utc(source.get("last_seen")) or datetime.utcnow()


def _upsert_external(db: Session, integration: CrowdStrikeIntegration, source: dict[str, Any], stats: dict[str, int]) -> None:
    identity = _external_identity(source)
    source_id = str(source.get("id") or "")
    if not identity or not source_id:
        return
    asset_type, value = identity
    cid = str(source.get("cid") or "")
    asset, created = _link_asset(db, integration, "external", source_id, cid, value=value, asset_type=asset_type, name=value, allow_match=True)
    stats["assets_created" if created else "assets_updated"] += 1
    _merge_source_metadata(asset, "external", source_id, cid, source)
    exposure = str(source.get("internet_exposure") or "").lower()
    if exposure in {"yes", "true", "exposed", "internet"}:
        asset.is_public = True
    ip_data = _as_dict(source.get("ip"))
    domain_data = _as_dict(source.get("dns_domain"))
    addresses = domain_data.get("resolved_ips") or []
    if asset_type == AssetType.IP_ADDRESS:
        addresses = [value]
    if isinstance(addresses, list):
        valid_ips = []
        for item in addresses:
            try:
                valid_ips.append(str(ipaddress.ip_address(str(item))))
            except ValueError:
                continue
        if valid_ips:
            asset.ip_addresses = valid_ips
            asset.ip_address = valid_ips[0]
    services = [item for group in (ip_data.get("services"), domain_data.get("services"))
                if isinstance(group, list) for item in group]
    for service in services:
        if isinstance(service, dict):
            _upsert_port(db, asset, service, stats)


def _upsert_port(db: Session, asset: Asset, source: dict[str, Any], stats: dict[str, int]) -> None:
    try:
        port = int(source.get("port") or source.get("protocol_port"))
    except (TypeError, ValueError):
        return
    if not 0 < port <= 65535:
        return
    transport = str(source.get("transport") or "tcp").lower()
    if transport not in {"tcp", "udp", "sctp"}:
        return
    protocol = Protocol(transport)
    observation = {"last_seen": source.get("last_seen"), "applications": source.get("applications") or [], "status": source.get("status")}
    record = db.query(PortService).filter_by(asset_id=asset.id, port=port, protocol=protocol).first()
    if record is None:
        record = PortService(asset_id=asset.id, port=port, protocol=protocol, state=PortState.OPEN, discovered_by=SOURCE, verified=False)
        db.add(record)
        stats["ports_created"] += 1
    else:
        stats["ports_updated"] += 1
    applications = source.get("applications") or []
    application = next((item for item in applications if isinstance(item, dict)), None) if isinstance(applications, list) else None
    if application:
        record.service_name = str(application.get("name") or "")[:100] or record.service_name
        record.service_product = str(application.get("vendor") or "")[:255] or record.service_product
        record.service_version = str(application.get("version") or "")[:100] or record.service_version
        record.cpe = str(application.get("cpe") or "")[:255] or record.cpe
    metadata = dict(record.metadata_ or {})
    metadata[SOURCE] = observation
    record.metadata_ = metadata
    record.last_seen = _utc(source.get("last_seen")) or datetime.utcnow()


def _upsert_host(db: Session, integration: CrowdStrikeIntegration, source: dict[str, Any], stats: dict[str, int]) -> None:
    aid = str(source.get("device_id") or source.get("aid") or "")
    if not aid:
        return
    cid = str(source.get("cid") or "")
    hostname = str(source.get("hostname") or "").strip()
    value = hostname or f"crowdstrike:{cid}:{aid}"
    asset, created = _link_asset(db, integration, "host", aid, cid, value=value, asset_type=AssetType.OTHER, name=hostname or aid, allow_match=False)
    stats["assets_created" if created else "assets_updated"] += 1
    _merge_source_metadata(asset, "host", aid, cid, source)
    asset.operating_system = str(source.get("os_product_name") or source.get("platform_name") or asset.operating_system or "")[:200] or None
    ips = []
    for key in ("local_ip", "external_ip"):
        try:
            raw = source.get(key)
            if isinstance(raw, dict):
                raw = raw.get("ip") or raw.get("address")
            if raw:
                ips.append(str(ipaddress.ip_address(str(raw))))
        except ValueError:
            pass
    if ips:
        asset.ip_addresses = ips
        asset.ip_address = ips[0]


def _severity(value: Any) -> Severity:
    name = str(value or "").lower()
    return {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW, "informational": Severity.INFO}.get(name, Severity.MEDIUM)


def _upsert_finding(db: Session, integration: CrowdStrikeIntegration, source: dict[str, Any], host_assets: dict[tuple[str, str], Asset], stats: dict[str, int]) -> None:
    finding_id = str(source.get("id") or source.get("vulnerability_id") or "")
    aid = str(source.get("aid") or "")
    cid = str(source.get("cid") or "")
    asset = host_assets.get((cid, aid))
    if not finding_id or asset is None:
        return
    cve = _as_dict(source.get("cve"))
    cve_id = str(cve.get("id") or "") or None
    key = f"cs:{integration.id}:{finding_id}"[:255]
    vuln = db.query(Vulnerability).filter_by(asset_id=asset.id, detected_by=SOURCE, template_id=key).first()
    created = vuln is None
    if created:
        vuln = Vulnerability(asset_id=asset.id, title=cve_id or f"CrowdStrike finding {finding_id}", severity=Severity.MEDIUM, detected_by=SOURCE, template_id=key)
        db.add(vuln)
    score = cve.get("base_score")
    try:
        vuln.cvss_score = float(score) if score is not None else None
    except (TypeError, ValueError):
        vuln.cvss_score = None
    vuln.title = str(cve_id or source.get("vulnerability_id") or f"CrowdStrike finding {finding_id}")[:500]
    vuln.description = cve.get("description") or source.get("description")
    vuln.cve_id = cve_id
    vuln.severity = _severity(cve.get("severity"))
    remediation = _as_dict(source.get("remediation")).get("recommendation")
    if isinstance(remediation, str):
        vuln.remediation = remediation
    old_status = vuln.status
    closed = str(source.get("status") or "").lower() in {"closed", "resolved"}
    if closed:
        vuln.status = VulnerabilityStatus.RESOLVED
        vuln.resolved_at = _utc(source.get("closed_timestamp")) or datetime.utcnow()
    elif created or old_status == VulnerabilityStatus.RESOLVED:
        vuln.status = VulnerabilityStatus.OPEN
        vuln.resolved_at = None
    if closed and not created and old_status != VulnerabilityStatus.RESOLVED:
        stats["vulns_resolved"] += 1
    vuln.detection_confidence = "version_only"
    vuln.first_detected = _utc(source.get("created_timestamp")) or vuln.first_detected or datetime.utcnow()
    vuln.last_detected = _utc(source.get("updated_timestamp")) or datetime.utcnow()
    tags = list(vuln.tags or [])
    if "source:crowdstrike" not in tags:
        vuln.tags = tags + ["source:crowdstrike"]
    metadata = dict(vuln.metadata_ or {})
    metadata["crowdstrike"] = {
        "integration_id": integration.id, "finding_id": finding_id, "cid": cid, "aid": aid,
        "status": source.get("status"), "risk_score": source.get("risk_score"),
        "exploit_validation_status": source.get("exploit_validation_status"),
        "assessment_status": source.get("assessment_status"),
        "assessment_reason": source.get("assessment_reason"),
        "evaluation_logic": source.get("evaluation_logic"),
        "services": source.get("services"),
    }
    vuln.metadata_ = metadata
    stats["vulns_created" if created else "vulns_updated"] += 1


def _stats() -> dict[str, int]:
    return {key: 0 for key in (
        "assets_created", "assets_updated", "ports_created", "ports_updated", "vulns_created", "vulns_updated",
        "vulns_resolved", "external_seen", "hosts_seen", "findings_seen",
    )}


async def sync_integration(db: Session, integration: CrowdStrikeIntegration) -> dict[str, Any]:
    stats = _stats()
    host_assets: dict[tuple[str, str], Asset] = {}
    try:
        async with _client_for(integration) as client:
            if integration.import_external_assets:
                async for batch in client.external_assets():
                    for source in batch:
                        if isinstance(source, dict):
                            stats["external_seen"] += 1
                            _upsert_external(db, integration, source, stats)
            if integration.import_hosts or integration.import_spotlight:
                async for batch in client.hosts():
                    for source in batch:
                        if isinstance(source, dict):
                            stats["hosts_seen"] += 1
                            _upsert_host(db, integration, source, stats)
                db.flush()
                links = db.query(CrowdStrikeAssetLink).filter_by(integration_id=integration.id, source_kind="host").all()
                for link in links:
                    asset = db.get(Asset, link.asset_id)
                    if asset is not None:
                        host_assets[(link.cid or "", link.source_id)] = asset
            if integration.import_spotlight:
                async for batch in client.spotlight():
                    for source in batch:
                        if isinstance(source, dict):
                            stats["findings_seen"] += 1
                            _upsert_finding(db, integration, source, host_assets, stats)
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = True
        integration.last_sync_stats = stats
        integration.last_error = None
        db.commit()
        return {"ok": True, "message": "CrowdStrike assets and findings synchronized.", **stats}
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        stats = _stats()
        logger.exception("CrowdStrike sync failed for organization %s", integration.organization_id)
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = str(exc)[:1000] if isinstance(exc, CrowdStrikeError) else "Unexpected sync error."
        db.commit()
        return {"ok": False, "message": integration.last_error, **stats}
