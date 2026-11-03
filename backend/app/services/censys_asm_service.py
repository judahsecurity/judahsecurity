"""Censys ASM integration service.

Read-only client for the Censys Attack Surface Management API plus the sync
logic that imports Censys-attributed risks and assets into this platform.

API reference:
    Base URL : https://app.censys.io/api
    Auth     : request header ``Censys-Api-Key: <workspace-scoped key>``
    Assets   : GET /v1/assets/{hosts,domains,subdomains,certificates}
    Risks    : GET /v2/risk-instances
    Account  : GET /integrations/v1/account  (used to validate a key)

The Censys ASM key is a single token (not an ID:secret pair) and grants full
read access to exactly one workspace.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetStatus, AssetType
from app.models.censys_integration import CensysAsmIntegration
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus

logger = logging.getLogger(__name__)

DISCOVERY_SOURCE = "censys_asm"

# Censys ASM risk severities → internal Severity enum.
_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}


def _map_severity(value: Optional[str]) -> Severity:
    return _SEVERITY_MAP.get((value or "").strip().lower(), Severity.MEDIUM)


class CensysAsmClient:
    """Thin async client for the read-only Censys ASM API."""

    BASE_URL = "https://app.censys.io/api"
    PAGE_SIZE = 100
    MAX_PAGES = 200  # safety cap: up to 20k records per asset type
    RATE_LIMIT_DELAY = 0.4  # matches DEFAULT_RATE_LIMITS[censys]

    def __init__(self, api_key: str):
        self.api_key = api_key
        self._headers = {
            "Censys-Api-Key": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def _get(self, path: str, params: Optional[Dict] = None) -> Optional[Dict]:
        url = f"{self.BASE_URL}{path}"
        try:
            async with httpx.AsyncClient(timeout=30.0, headers=self._headers) as client:
                resp = await client.get(url, params=params)
                if resp.status_code == 429:
                    logger.warning("Censys ASM rate limited on %s, backing off 10s", path)
                    await asyncio.sleep(10)
                    return await self._get(path, params)
                if resp.status_code in (401, 403):
                    logger.error("Censys ASM: unauthorized (HTTP %s) on %s", resp.status_code, path)
                    return None
                if resp.status_code != 200:
                    logger.warning(
                        "Censys ASM GET %s -> HTTP %s: %s", path, resp.status_code, resp.text[:200]
                    )
                    return None
                return resp.json()
        except Exception as exc:  # noqa: BLE001 — network errors are expected
            logger.error("Censys ASM GET %s error: %s", path, exc)
            return None

    # ── Validation ───────────────────────────────────────────────────────────
    async def get_account(self) -> Optional[Dict]:
        """Fetch workspace/account info. Non-None => the key is valid."""
        return await self._get("/integrations/v1/account")

    # ── Paginated asset fetch ─────────────────────────────────────────────────
    async def _paginate(self, path: str, keyword: str) -> List[Dict]:
        results: List[Dict] = []
        page = 1
        while page <= self.MAX_PAGES:
            payload = await self._get(path, params={"pageNumber": page, "pageSize": self.PAGE_SIZE})
            if not payload:
                break
            batch = payload.get(keyword) or payload.get("assets") or []
            if not isinstance(batch, list):
                break
            results.extend(batch)
            total_pages = payload.get("totalPages") or payload.get("total_pages") or 1
            if page >= total_pages or not batch:
                break
            page += 1
            await asyncio.sleep(self.RATE_LIMIT_DELAY)
        return results

    async def get_hosts(self) -> List[Dict]:
        return await self._paginate("/v1/assets/hosts", "assets")

    async def get_domains(self) -> List[Dict]:
        return await self._paginate("/v1/assets/domains", "assets")

    async def get_subdomains(self) -> List[Dict]:
        return await self._paginate("/v1/assets/subdomains", "subdomains")

    async def get_certificates(self) -> List[Dict]:
        return await self._paginate("/v1/assets/certificates", "assets")

    # ── Risks ─────────────────────────────────────────────────────────────────
    async def get_risk_instances(self) -> List[Dict]:
        """Fetch open risk instances (paginated by cursor when provided)."""
        results: List[Dict] = []
        cursor: Optional[str] = None
        for _ in range(self.MAX_PAGES):
            params: Dict[str, Any] = {"includeEvents": "false", "limit": self.PAGE_SIZE}
            if cursor:
                params["cursor"] = cursor
            payload = await self._get("/v2/risk-instances", params=params)
            if not payload:
                break
            data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
            batch = (
                data.get("risks")
                or data.get("riskInstances")
                or data.get("results")
                or []
            )
            if not isinstance(batch, list) or not batch:
                break
            results.extend(batch)
            cursor = (
                payload.get("nextCursor")
                or payload.get("cursor")
                or (data.get("nextCursor") if isinstance(data, dict) else None)
            )
            if not cursor:
                break
            await asyncio.sleep(self.RATE_LIMIT_DELAY)
        return results


async def test_connection(api_key: str) -> Dict[str, Any]:
    """Validate a Censys ASM API key. Returns {ok, message, workspace_id}."""
    client = CensysAsmClient(api_key)
    account = await client.get_account()
    if account is None:
        return {"ok": False, "message": "Could not authenticate to Censys ASM with this API key.", "workspace_id": None}
    workspace_id = account.get("workspaceId") or account.get("workspace_id")
    return {
        "ok": True,
        "message": "Connected to Censys ASM successfully.",
        "workspace_id": str(workspace_id) if workspace_id else None,
    }


# ── Field extraction helpers (defensive; Censys field names vary) ─────────────

def _first(d: Dict, *keys: str) -> Optional[Any]:
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return v
    return None


def _host_ip(asset: Dict) -> Optional[str]:
    return _first(asset, "assetId", "ip", "ipAddress", "ip_address")


def _domain_name(asset: Dict) -> Optional[str]:
    return _first(asset, "assetId", "domain", "name")


def _subdomain_name(asset: Dict) -> Optional[str]:
    return _first(asset, "subdomain", "assetId", "name")


def _cert_fingerprint(asset: Dict) -> Optional[str]:
    return _first(asset, "assetId", "fingerprintSha256", "fingerprint_sha256", "fingerprint")


def _risk_affected_assets(risk: Dict) -> List[Dict]:
    """Return [{'type':..., 'id':...}] entries a risk instance affects."""
    for key in ("affectedAssets", "affected_assets", "assets"):
        v = risk.get(key)
        if isinstance(v, list) and v:
            return v
    # Some payloads carry a single asset reference inline.
    single = risk.get("asset") or risk.get("context")
    if isinstance(single, dict):
        return [single]
    return []


# ── Sync orchestration ────────────────────────────────────────────────────────

class _Stats:
    def __init__(self) -> None:
        self.assets_created = 0
        self.assets_updated = 0
        self.vulns_created = 0
        self.vulns_updated = 0
        self.hosts_seen = 0
        self.domains_seen = 0
        self.subdomains_seen = 0
        self.certificates_seen = 0
        self.risks_seen = 0

    def as_dict(self) -> Dict[str, int]:
        return {
            "assets_created": self.assets_created,
            "assets_updated": self.assets_updated,
            "vulns_created": self.vulns_created,
            "vulns_updated": self.vulns_updated,
            "hosts_seen": self.hosts_seen,
            "domains_seen": self.domains_seen,
            "subdomains_seen": self.subdomains_seen,
            "certificates_seen": self.certificates_seen,
            "risks_seen": self.risks_seen,
        }


def _upsert_asset(
    db: Session,
    org_id: int,
    value: str,
    asset_type: AssetType,
    stats: _Stats,
    *,
    metadata: Optional[Dict] = None,
) -> Optional[Asset]:
    """Create the asset if missing, else refresh last_seen. Returns the asset."""
    value = (value or "").strip()
    if not value:
        return None
    existing = (
        db.query(Asset)
        .filter(Asset.organization_id == org_id, Asset.value == value)
        .first()
    )
    if existing:
        existing.last_seen = datetime.utcnow()
        tags = list(existing.tags or [])
        if f"source:{DISCOVERY_SOURCE}" not in tags:
            tags.append(f"source:{DISCOVERY_SOURCE}")
            existing.tags = tags
        stats.assets_updated += 1
        return existing

    asset = Asset(
        name=value,
        asset_type=asset_type,
        value=value,
        organization_id=org_id,
        status=AssetStatus.DISCOVERED,
        discovery_source=DISCOVERY_SOURCE,
        association_reason="Attributed to the organization by Censys ASM",
        association_confidence=90,
        tags=[f"source:{DISCOVERY_SOURCE}"],
        metadata_=metadata or {},
    )
    db.add(asset)
    db.flush()  # assign id for risk association
    stats.assets_created += 1
    return asset


async def sync_integration(db: Session, integration: CensysAsmIntegration) -> Dict[str, Any]:
    """Pull assets and/or risks for a Censys ASM workspace and import them.

    Returns a result dict compatible with :class:`CensysSyncResult`.
    """
    org_id = integration.organization_id
    api_key = integration.get_api_key()
    if not api_key:
        return {"ok": False, "message": "No API key stored for this connection."}

    client = CensysAsmClient(api_key)
    stats = _Stats()

    # Map "value" -> Asset for quick risk association within this run.
    asset_index: Dict[str, Asset] = {}

    try:
        if integration.import_assets:
            hosts = await client.get_hosts()
            stats.hosts_seen = len(hosts)
            for h in hosts:
                ip = _host_ip(h)
                if ip:
                    a = _upsert_asset(db, org_id, ip, AssetType.IP_ADDRESS, stats)
                    if a:
                        asset_index[ip] = a

            domains = await client.get_domains()
            stats.domains_seen = len(domains)
            for d in domains:
                name = _domain_name(d)
                if name:
                    a = _upsert_asset(db, org_id, name, AssetType.DOMAIN, stats)
                    if a:
                        asset_index[name] = a

            subdomains = await client.get_subdomains()
            stats.subdomains_seen = len(subdomains)
            for s in subdomains:
                name = _subdomain_name(s)
                if name:
                    a = _upsert_asset(db, org_id, name, AssetType.SUBDOMAIN, stats)
                    if a:
                        asset_index[name] = a

            certs = await client.get_certificates()
            stats.certificates_seen = len(certs)
            for c in certs:
                fp = _cert_fingerprint(c)
                if fp:
                    a = _upsert_asset(
                        db, org_id, fp, AssetType.CERTIFICATE, stats,
                        metadata={"censys_certificate": c},
                    )
                    if a:
                        asset_index[fp] = a

            db.commit()

        if integration.import_vulnerabilities:
            risks = await client.get_risk_instances()
            stats.risks_seen = len(risks)
            for risk in risks:
                _import_risk(db, org_id, risk, asset_index, stats, integration.import_assets)
            db.commit()

        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = True
        integration.last_error = None
        integration.last_sync_stats = stats.as_dict()
        db.commit()

        from app.services.integration_graph_sync import sync_integration_assets_to_graph
        await sync_integration_assets_to_graph(
            org_id, {asset.value for asset in asset_index.values()}
        )

        return {
            "ok": True,
            "message": (
                f"Imported {stats.assets_created} new asset(s) and "
                f"{stats.vulns_created} new risk(s) from Censys ASM."
            ),
            **stats.as_dict(),
        }
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.exception("Censys ASM sync failed for org %s", org_id)
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = str(exc)[:1000]
        db.commit()
        return {"ok": False, "message": f"Sync failed: {exc}", **stats.as_dict()}


def _import_risk(
    db: Session,
    org_id: int,
    risk: Dict,
    asset_index: Dict[str, Asset],
    stats: _Stats,
    can_create_assets: bool,
) -> None:
    """Import a single Censys risk instance as a Vulnerability."""
    risk_id = _first(risk, "id", "riskInstanceId", "risk_instance_id")
    title = _first(risk, "title", "name", "type") or "Censys ASM risk"
    severity = _map_severity(_first(risk, "severity", "riskSeverity"))
    description = _first(risk, "description", "summary")

    affected = _risk_affected_assets(risk)
    if not affected:
        return

    for ref in affected:
        ref_id = _first(ref, "id", "assetId", "value", "ip", "domain")
        ref_type = (_first(ref, "type", "assetType") or "").upper()
        if not ref_id:
            continue

        asset = asset_index.get(ref_id)
        if asset is None:
            asset = (
                db.query(Asset)
                .filter(Asset.organization_id == org_id, Asset.value == ref_id)
                .first()
            )
        if asset is None:
            if not can_create_assets:
                continue
            atype = {
                "HOST": AssetType.IP_ADDRESS,
                "DOMAIN": AssetType.DOMAIN,
                "SUBDOMAIN": AssetType.SUBDOMAIN,
                "CERT": AssetType.CERTIFICATE,
                "CERTIFICATE": AssetType.CERTIFICATE,
            }.get(ref_type, AssetType.OTHER)
            asset = _upsert_asset(db, org_id, ref_id, atype, stats)
            if asset:
                asset_index[ref_id] = asset
        if asset is None:
            continue
        asset_index[asset.value] = asset

        # Dedup: match by Censys risk id in metadata, else by title+asset.
        existing = None
        if risk_id:
            existing = (
                db.query(Vulnerability)
                .filter(
                    Vulnerability.asset_id == asset.id,
                    Vulnerability.metadata_["censys_risk_id"].astext == str(risk_id),
                )
                .first()
            )
        if existing is None:
            existing = (
                db.query(Vulnerability)
                .filter(
                    Vulnerability.asset_id == asset.id,
                    Vulnerability.title == title,
                    Vulnerability.detected_by == DISCOVERY_SOURCE,
                )
                .first()
            )

        if existing:
            existing.severity = severity
            existing.last_detected = datetime.utcnow()
            stats.vulns_updated += 1
            continue

        vuln = Vulnerability(
            title=title[:500],
            description=description,
            severity=severity,
            asset_id=asset.id,
            detected_by=DISCOVERY_SOURCE,
            status=VulnerabilityStatus.OPEN,
            tags=["source:censys_asm"],
            metadata_={
                "censys_risk_id": str(risk_id) if risk_id else None,
                "censys_risk_type": _first(risk, "type", "riskType"),
                "source": DISCOVERY_SOURCE,
            },
        )
        db.add(vuln)
        stats.vulns_created += 1
