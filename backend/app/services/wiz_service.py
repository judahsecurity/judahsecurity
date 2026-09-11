"""Read-only Wiz GraphQL client and exposure-management importer."""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetStatus, AssetType
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus
from app.models.wiz_integration import WizIntegration

logger = logging.getLogger(__name__)

DISCOVERY_SOURCE = "wiz"
DEFAULT_AUTH_URL = "https://auth.app.wiz.io/oauth/token"
DEFAULT_AUDIENCE = "wiz-api"

VULNERABILITY_FINDINGS_QUERY = """
query JudahWizVulnerabilityFindings($first: Int!, $after: String) {
  vulnerabilityFindings(first: $first, after: $after) {
    nodes {
      id
      portalUrl
      name
      CVEDescription
      score
      severity
      nvdSeverity
      vendorSeverity
      status
      firstDetectedAt
      lastDetectedAt
      resolvedAt
      description
      remediation
      detailedName
      version
      fixedVersion
      link
      projects { id name }
      vulnerableAsset {
        __typename
        ... on VulnerableAssetBase {
          id
          type
          name
          region
          providerUniqueId
          cloudProviderURL
          cloudPlatform
          status
          subscriptionName
          subscriptionExternalId
          subscriptionId
          tags
          hasLimitedInternetExposure
          hasWideInternetExposure
        }
        ... on VulnerableAssetVirtualMachine {
          operatingSystem
          ipAddresses
          imageName
          nativeType
        }
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


class WizApiError(RuntimeError):
    """A safe, user-displayable Wiz API error."""


def _validate_wiz_url(value: str, label: str) -> str:
    raw = (value or "").strip().rstrip("/")
    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not host or parsed.username or parsed.password:
        raise WizApiError(f"{label} must be an HTTPS Wiz URL without embedded credentials.")
    if not (host.endswith(".wiz.io") or host.endswith(".wiz.us")):
        raise WizApiError(f"{label} must use a wiz.io or wiz.us host.")
    return raw


class WizClient:
    """Minimal OAuth2 + GraphQL client for Wiz vulnerability findings."""

    PAGE_SIZE = 100
    MAX_PAGES = 500

    def __init__(
        self,
        api_endpoint: str,
        client_id: str,
        client_secret: str,
        *,
        auth_url: str = DEFAULT_AUTH_URL,
        audience: str = DEFAULT_AUDIENCE,
    ) -> None:
        endpoint = _validate_wiz_url(api_endpoint, "API endpoint")
        self.api_endpoint = endpoint if endpoint.endswith("/graphql") else f"{endpoint}/graphql"
        self.auth_url = _validate_wiz_url(auth_url, "Authentication URL")
        self.client_id = client_id
        self.client_secret = client_secret
        self.audience = audience or DEFAULT_AUDIENCE
        self._token: Optional[str] = None

    async def authenticate(self) -> str:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    self.auth_url,
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "audience": self.audience,
                    },
                    headers={"Accept": "application/json"},
                )
        except httpx.HTTPError as exc:
            raise WizApiError(f"Could not reach the Wiz authentication endpoint: {exc}") from exc
        if response.status_code != 200:
            raise WizApiError(f"Wiz authentication failed (HTTP {response.status_code}).")
        try:
            token = response.json().get("access_token")
        except ValueError as exc:
            raise WizApiError("Wiz authentication returned an invalid JSON response.") from exc
        if not token:
            raise WizApiError("Wiz authentication response did not contain an access token.")
        self._token = str(token)
        return self._token

    async def graphql(self, query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
        token = self._token or await self.authenticate()
        for attempt in range(4):
            try:
                async with httpx.AsyncClient(timeout=60.0) as client:
                    response = await client.post(
                        self.api_endpoint,
                        json={"query": query, "variables": variables},
                        headers={
                            "Authorization": f"Bearer {token}",
                            "Accept": "application/json",
                            "Content-Type": "application/json",
                        },
                    )
            except httpx.HTTPError as exc:
                if attempt == 3:
                    raise WizApiError(f"Could not reach the Wiz GraphQL endpoint: {exc}") from exc
                await asyncio.sleep(2**attempt)
                continue
            if response.status_code in (429, 502, 503, 504) and attempt < 3:
                await asyncio.sleep(2**attempt)
                continue
            if response.status_code in (401, 403):
                raise WizApiError(
                    f"Wiz rejected the request (HTTP {response.status_code}); check credentials and read scopes."
                )
            if response.status_code != 200:
                raise WizApiError(f"Wiz GraphQL request failed (HTTP {response.status_code}).")
            try:
                payload = response.json()
            except ValueError as exc:
                raise WizApiError("Wiz GraphQL returned an invalid JSON response.") from exc
            if payload.get("errors"):
                messages = "; ".join(
                    str(item.get("message", "GraphQL error")) for item in payload["errors"][:3]
                )
                raise WizApiError(f"Wiz GraphQL error: {messages[:700]}")
            return payload.get("data") or {}
        raise WizApiError("Wiz GraphQL request failed after retries.")

    async def get_vulnerability_findings(self, *, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        cursor: Optional[str] = None
        for _ in range(self.MAX_PAGES):
            data = await self.graphql(
                VULNERABILITY_FINDINGS_QUERY,
                {"first": min(self.PAGE_SIZE, limit or self.PAGE_SIZE), "after": cursor},
            )
            connection = data.get("vulnerabilityFindings") or {}
            batch = connection.get("nodes") or []
            if not isinstance(batch, list):
                raise WizApiError("Wiz returned an unexpected vulnerability findings payload.")
            findings.extend(item for item in batch if isinstance(item, dict))
            page_info = connection.get("pageInfo") or {}
            if limit and len(findings) >= limit:
                return findings[:limit]
            if not page_info.get("hasNextPage"):
                break
            cursor = page_info.get("endCursor")
            if not cursor:
                break
        return findings


def _client_for(integration: WizIntegration) -> WizClient:
    client_id = integration.get_client_id()
    client_secret = integration.get_client_secret()
    if not client_id or not client_secret:
        raise WizApiError("No Wiz client credentials are stored for this connection.")
    return WizClient(
        integration.api_endpoint,
        client_id,
        client_secret,
        auth_url=integration.auth_url,
        audience=integration.audience,
    )


async def test_connection(
    api_endpoint: str,
    client_id: str,
    client_secret: str,
    *,
    auth_url: str = DEFAULT_AUTH_URL,
    audience: str = DEFAULT_AUDIENCE,
) -> Dict[str, Any]:
    try:
        client = WizClient(
            api_endpoint,
            client_id,
            client_secret,
            auth_url=auth_url,
            audience=audience,
        )
        await client.get_vulnerability_findings(limit=1)
        return {
            "ok": True,
            "message": "Connected to Wiz and verified vulnerability-findings access.",
            "findings_accessible": True,
        }
    except WizApiError as exc:
        return {"ok": False, "message": str(exc), "findings_accessible": False}


def _map_severity(value: Any) -> Severity:
    return _SEVERITY_MAP.get(str(value or "").strip().lower(), Severity.MEDIUM)


def _parse_datetime(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except (TypeError, ValueError):
        return None


def _is_virtual_machine(asset: Dict[str, Any]) -> bool:
    markers = " ".join(
        str(asset.get(key) or "") for key in ("__typename", "type", "nativeType")
    ).upper()
    return "VIRTUALMACHINE" in markers.replace("_", "") or bool(asset.get("operatingSystem"))


def _is_internet_exposed(asset: Dict[str, Any]) -> bool:
    return bool(asset.get("hasWideInternetExposure") or asset.get("hasLimitedInternetExposure"))


def _asset_value(asset: Dict[str, Any]) -> Optional[str]:
    return next(
        (
            str(value).strip()
            for value in (
                asset.get("providerUniqueId"),
                asset.get("id"),
                asset.get("name"),
                *((asset.get("ipAddresses") or []) if isinstance(asset.get("ipAddresses"), list) else []),
            )
            if value not in (None, "") and str(value).strip()
        ),
        None,
    )


class _Stats:
    def __init__(self) -> None:
        self.assets_created = 0
        self.assets_updated = 0
        self.vulns_created = 0
        self.vulns_updated = 0
        self.findings_seen = 0
        self.findings_filtered = 0

    def as_dict(self) -> Dict[str, int]:
        return vars(self).copy()


def _upsert_asset(db: Session, org_id: int, source: Dict[str, Any], stats: _Stats) -> Asset:
    value = _asset_value(source)
    if not value:
        raise ValueError("Wiz virtual machine has no stable identifier")
    asset = db.query(Asset).filter(Asset.organization_id == org_id, Asset.value == value).first()
    ips = [str(ip) for ip in (source.get("ipAddresses") or []) if ip]
    metadata = dict(asset.metadata_ or {}) if asset else {}
    metadata["wiz"] = {
        "id": source.get("id"),
        "provider_unique_id": source.get("providerUniqueId"),
        "cloud_platform": source.get("cloudPlatform"),
        "cloud_provider_url": source.get("cloudProviderURL"),
        "subscription_id": source.get("subscriptionId"),
        "subscription_external_id": source.get("subscriptionExternalId"),
        "subscription_name": source.get("subscriptionName"),
        "region": source.get("region"),
        "native_type": source.get("nativeType"),
        "image_name": source.get("imageName"),
        "status": source.get("status"),
        "tags": source.get("tags") or [],
        "has_wide_internet_exposure": bool(source.get("hasWideInternetExposure")),
        "has_limited_internet_exposure": bool(source.get("hasLimitedInternetExposure")),
    }
    if asset:
        asset.name = str(source.get("name") or asset.name)[:255]
        asset.last_seen = datetime.utcnow()
        operating_system = source.get("operatingSystem")
        if operating_system:
            asset.operating_system = str(operating_system)[:200]
        asset.ip_addresses = ips or asset.ip_addresses
        asset.ip_address = (ips[0] if ips else asset.ip_address)
        asset.hosting_provider = (
            str(source.get("cloudPlatform") or asset.hosting_provider or "").lower()[:100] or None
        )
        asset.hosting_type = "cloud"
        asset.is_public = _is_internet_exposed(source)
        asset.metadata_ = metadata
        tags = list(asset.tags or [])
        if "source:wiz" not in tags:
            tags.append("source:wiz")
            asset.tags = tags
        stats.assets_updated += 1
        return asset
    asset = Asset(
        name=str(source.get("name") or value)[:255],
        asset_type=AssetType.CLOUD_RESOURCE,
        value=value[:500],
        organization_id=org_id,
        status=AssetStatus.DISCOVERED,
        discovery_source=DISCOVERY_SOURCE,
        association_reason="Virtual machine attributed to the organization by Wiz",
        association_confidence=95,
        tags=["source:wiz"],
        metadata_=metadata,
        operating_system=(str(source.get("operatingSystem"))[:200] if source.get("operatingSystem") else None),
        ip_addresses=ips,
        ip_address=ips[0] if ips else None,
        hosting_type="cloud",
        hosting_provider=str(source.get("cloudPlatform") or "").lower()[:100] or None,
        is_public=_is_internet_exposed(source),
    )
    db.add(asset)
    db.flush()
    stats.assets_created += 1
    return asset


def _cve_id(finding: Dict[str, Any]) -> Optional[str]:
    for value in (finding.get("name"), finding.get("detailedName"), finding.get("CVEDescription")):
        match = _CVE_RE.search(str(value or ""))
        if match:
            return match.group(0).upper()
    return None


def _upsert_vulnerability(
    db: Session, asset: Asset, finding: Dict[str, Any], stats: _Stats
) -> None:
    finding_id = str(finding.get("id") or "").strip()
    title = str(finding.get("detailedName") or finding.get("name") or "Wiz vulnerability")[:500]
    existing = None
    if finding_id:
        existing = db.query(Vulnerability).filter(
            Vulnerability.asset_id == asset.id,
            Vulnerability.detected_by == DISCOVERY_SOURCE,
            Vulnerability.template_id == f"wiz:{finding_id}"[:255],
        ).first()
    if existing is None:
        existing = db.query(Vulnerability).filter(
            Vulnerability.asset_id == asset.id,
            Vulnerability.detected_by == DISCOVERY_SOURCE,
            Vulnerability.title == title,
        ).first()

    severity = _map_severity(
        finding.get("severity") or finding.get("vendorSeverity") or finding.get("nvdSeverity")
    )
    raw_status = str(finding.get("status") or "OPEN").upper()
    resolved = raw_status in {"RESOLVED", "CLOSED"} or bool(finding.get("resolvedAt"))
    score = finding.get("score")
    try:
        cvss_score = float(score) if score is not None else None
    except (TypeError, ValueError):
        cvss_score = None
    references = [
        str(url) for url in (finding.get("portalUrl"), finding.get("link")) if url
    ]
    metadata = {
        "source": DISCOVERY_SOURCE,
        "wiz_finding_id": finding_id or None,
        "wiz_status": raw_status,
        "vendor_severity": finding.get("vendorSeverity"),
        "nvd_severity": finding.get("nvdSeverity"),
        "version": finding.get("version"),
        "fixed_version": finding.get("fixedVersion"),
        "projects": finding.get("projects") or [],
    }
    if existing:
        existing.title = title
        existing.description = finding.get("description") or finding.get("CVEDescription")
        existing.severity = severity
        existing.cvss_score = cvss_score
        existing.cve_id = _cve_id(finding)
        existing.references = references
        existing.remediation = finding.get("remediation")
        existing.affected_component = (
            str(finding.get("version"))[:500] if finding.get("version") is not None else None
        )
        existing.last_detected = _parse_datetime(finding.get("lastDetectedAt")) or datetime.utcnow()
        existing.metadata_ = metadata
        if resolved:
            existing.status = VulnerabilityStatus.RESOLVED
            existing.resolved_at = _parse_datetime(finding.get("resolvedAt")) or datetime.utcnow()
        elif existing.status == VulnerabilityStatus.RESOLVED:
            existing.status = VulnerabilityStatus.OPEN
            existing.resolved_at = None
        stats.vulns_updated += 1
        return
    vulnerability = Vulnerability(
        title=title,
        description=finding.get("description") or finding.get("CVEDescription"),
        severity=severity,
        cvss_score=cvss_score,
        cve_id=_cve_id(finding),
        references=references,
        remediation=finding.get("remediation"),
        affected_component=(
            str(finding.get("version"))[:500] if finding.get("version") is not None else None
        ),
        asset_id=asset.id,
        detected_by=DISCOVERY_SOURCE,
        template_id=f"wiz:{finding_id}"[:255] if finding_id else None,
        status=VulnerabilityStatus.RESOLVED if resolved else VulnerabilityStatus.OPEN,
        first_detected=_parse_datetime(finding.get("firstDetectedAt")) or datetime.utcnow(),
        last_detected=_parse_datetime(finding.get("lastDetectedAt")) or datetime.utcnow(),
        resolved_at=_parse_datetime(finding.get("resolvedAt")) if resolved else None,
        tags=["source:wiz"],
        metadata_=metadata,
    )
    db.add(vulnerability)
    stats.vulns_created += 1


async def sync_integration(db: Session, integration: WizIntegration) -> Dict[str, Any]:
    stats = _Stats()
    try:
        findings = await _client_for(integration).get_vulnerability_findings()
        stats.findings_seen = len(findings)
        asset_cache: Dict[str, Asset] = {}
        for finding in findings:
            source = finding.get("vulnerableAsset") or {}
            if not isinstance(source, dict) or not _is_virtual_machine(source):
                stats.findings_filtered += 1
                continue
            if integration.internet_exposed_only and not _is_internet_exposed(source):
                stats.findings_filtered += 1
                continue
            value = _asset_value(source)
            if not value:
                stats.findings_filtered += 1
                continue
            asset = asset_cache.get(value)
            if asset is None:
                existing = db.query(Asset).filter(
                    Asset.organization_id == integration.organization_id,
                    Asset.value == value,
                ).first()
                if not integration.import_assets and existing is None:
                    stats.findings_filtered += 1
                    continue
                asset = _upsert_asset(db, integration.organization_id, source, stats)
                asset_cache[value] = asset
            if integration.import_vulnerabilities:
                _upsert_vulnerability(db, asset, finding, stats)

        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = True
        integration.last_error = None
        integration.last_sync_stats = stats.as_dict()
        db.commit()
        return {
            "ok": True,
            "message": (
                f"Imported {stats.assets_created} new VM asset(s) and "
                f"{stats.vulns_created} new vulnerability finding(s) from Wiz."
            ),
            **stats.as_dict(),
        }
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.exception("Wiz sync failed for organization %s", integration.organization_id)
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = str(exc)[:1000]
        db.commit()
        return {"ok": False, "message": f"Sync failed: {exc}", **stats.as_dict()}
