"""
Ingestion Service

Processes findings submitted by external agents (Aegis Vanguard, CI/CD pipelines, etc.)
and maps them into the ASM platform's data model (Assets, PortServices, Vulnerabilities).
"""

import hashlib
import logging
import secrets
import time
import uuid
from datetime import datetime, timedelta
from typing import Optional, List, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import and_

from app.models.asset import Asset, AssetType, AssetStatus
from app.models.port_service import PortService, Protocol, PortState
from app.models.vulnerability import Vulnerability, Severity as VulnSeverity, VulnerabilityStatus
from app.models.agent_api_key import AgentAPIKey
from app.schemas.unified_results import UnifiedFinding, ResultType, Severity
from app.schemas.ingestion import (
    IngestionBatchRequest,
    IngestionBatchResponse,
    IngestionFindingResult,
)

logger = logging.getLogger(__name__)

RESULT_TYPE_TO_ASSET_TYPE = {
    ResultType.DOMAIN: AssetType.DOMAIN,
    ResultType.SUBDOMAIN: AssetType.SUBDOMAIN,
    ResultType.IP_ADDRESS: AssetType.IP_ADDRESS,
    ResultType.IP_RANGE: AssetType.IP_RANGE,
    ResultType.URL: AssetType.URL,
    ResultType.CERTIFICATE: AssetType.CERTIFICATE,
    ResultType.PORT: AssetType.SUBDOMAIN,
    ResultType.VULNERABILITY: AssetType.SUBDOMAIN,
    ResultType.TECHNOLOGY: AssetType.SUBDOMAIN,
    ResultType.DNS_RECORD: AssetType.SUBDOMAIN,
    ResultType.SCREENSHOT: AssetType.URL,
    ResultType.WAYBACK_URL: AssetType.URL,
    ResultType.TAKEOVER: AssetType.SUBDOMAIN,
    ResultType.TLS_ANALYSIS: AssetType.SUBDOMAIN,
    ResultType.SECURITY_HEADER: AssetType.SUBDOMAIN,
    ResultType.MAIL_INFRASTRUCTURE: AssetType.DOMAIN,
    ResultType.THIRD_PARTY_VENDOR: AssetType.SUBDOMAIN,
}

SEVERITY_MAP = {
    Severity.CRITICAL: VulnSeverity.CRITICAL,
    Severity.HIGH: VulnSeverity.HIGH,
    Severity.MEDIUM: VulnSeverity.MEDIUM,
    Severity.LOW: VulnSeverity.LOW,
    Severity.INFO: VulnSeverity.INFO,
    Severity.UNKNOWN: VulnSeverity.INFO,
}


def _extract_root_domain(host: str) -> str:
    """Extract root domain from a hostname (e.g. api.example.com -> example.com)."""
    if not host:
        return ""
    parts = host.strip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _find_or_create_asset(
    db: Session,
    org_id: int,
    finding: UnifiedFinding,
) -> Asset:
    """Find an existing asset or create a new one from a finding."""
    value = finding.host or finding.ip or finding.url or finding.target
    asset_type = RESULT_TYPE_TO_ASSET_TYPE.get(finding.type, AssetType.OTHER)

    if finding.type in (ResultType.DOMAIN, ResultType.SUBDOMAIN):
        asset_type = AssetType.SUBDOMAIN if "." in value and value.count(".") > 1 else AssetType.DOMAIN
    elif finding.type == ResultType.IP_ADDRESS:
        asset_type = AssetType.IP_ADDRESS

    existing = (
        db.query(Asset)
        .filter(
            Asset.organization_id == org_id,
            Asset.value == value,
            Asset.asset_type == asset_type,
        )
        .first()
    )
    if existing:
        existing.last_seen = datetime.utcnow()
        if finding.ip and not existing.ip_address:
            existing.ip_address = finding.ip
        return existing

    root_domain = _extract_root_domain(value) if asset_type in (AssetType.DOMAIN, AssetType.SUBDOMAIN) else None
    asset = Asset(
        name=value,
        value=value,
        asset_type=asset_type,
        status=AssetStatus.DISCOVERED,
        organization_id=org_id,
        ip_address=finding.ip,
        root_domain=root_domain,
        discovery_source=f"agent:{finding.source}",
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
    )
    db.add(asset)
    db.flush()
    return asset


def _upsert_port_service(
    db: Session,
    asset: Asset,
    finding: UnifiedFinding,
) -> Tuple[Optional[PortService], str]:
    """Create or update a port service record. Returns (port_service, status)."""
    if finding.port is None:
        return None, "skipped"

    protocol = Protocol.TCP
    if finding.protocol and finding.protocol.lower() == "udp":
        protocol = Protocol.UDP

    existing = (
        db.query(PortService)
        .filter(
            PortService.asset_id == asset.id,
            PortService.port == finding.port,
            PortService.protocol == protocol,
        )
        .first()
    )

    if existing:
        if finding.service_name:
            existing.service_name = finding.service_name
        if finding.service_version:
            existing.service_version = finding.service_version
        if finding.service_product:
            existing.service_product = finding.service_product
        if finding.banner:
            existing.banner = finding.banner
        existing.last_seen = datetime.utcnow()
        return existing, "updated"

    ps = PortService(
        asset_id=asset.id,
        port=finding.port,
        protocol=protocol,
        service_name=finding.service_name,
        service_product=finding.service_product,
        service_version=finding.service_version,
        banner=finding.banner,
        state=PortState.OPEN if finding.state == "open" else PortState.UNKNOWN,
        discovered_by=finding.source,
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
    )
    db.add(ps)
    db.flush()
    return ps, "created"


def _upsert_vulnerability(
    db: Session,
    asset: Asset,
    finding: UnifiedFinding,
) -> Tuple[Optional[Vulnerability], str, Optional[str]]:
    """
    Create or update a vulnerability record.

    Returns (vuln, status, old_status_value_if_reactivated).
    Possible status values: "skipped", "duplicate", "reactivated", "created".
    old_status_value is only set when status == "reactivated".
    """
    if finding.type != ResultType.VULNERABILITY:
        return None, "skipped", None

    filters = [Vulnerability.asset_id == asset.id]
    if finding.template_id:
        filters.append(Vulnerability.template_id == finding.template_id)
    elif finding.cve_id:
        filters.append(Vulnerability.cve_id == finding.cve_id)
    else:
        filters.append(Vulnerability.title == (finding.title or "Unknown"))

    existing = db.query(Vulnerability).filter(and_(*filters)).first()
    if existing:
        old_status = existing.status
        existing.last_detected = datetime.utcnow()
        from app.services.reactivation_service import reactivate_if_closed
        if reactivate_if_closed(existing):
            return existing, "reactivated", old_status.value
        return existing, "duplicate", None

    vuln = Vulnerability(
        title=finding.title or "Untitled Finding",
        description=finding.description,
        severity=SEVERITY_MAP.get(finding.severity, VulnSeverity.INFO),
        cvss_score=finding.cvss_score,
        cve_id=finding.cve_id,
        cwe_id=finding.cwe_id,
        references=finding.references or [],
        asset_id=asset.id,
        detected_by=finding.source,
        template_id=finding.template_id,
        status=VulnerabilityStatus.OPEN,
        tags=finding.tags or [],
        evidence=finding.url,
        first_detected=datetime.utcnow(),
        last_detected=datetime.utcnow(),
    )
    db.add(vuln)
    db.flush()

    # Delphi enrichment: attach CISA KEV + EPSS signals to new CVE findings so
    # the UI can prioritise actively-exploited vulns at ingest time. Best-effort
    # only — enrichment failures never block ingestion.
    if finding.cve_id:
        try:
            from app.core.config import settings as _settings
            if getattr(_settings, "DELPHI_AUTO_ENRICH_ON_INGEST", True):
                from app.services.delphi_enrichment_service import get_delphi_service
                get_delphi_service().enrich_vulnerability(vuln)
        except Exception as exc:
            logger.debug("Delphi auto-enrich skipped for %s: %s", finding.cve_id, exc)

    # Oracle enrichment: queue a non-blocking background LLM analysis for all
    # new findings when ORACLE_AUTO_ENRICH_ON_INGEST is enabled. Covers CVE,
    # generic, secret, misconfiguration, and exposed-service findings. The call
    # opens its own DB session and runs in a daemon thread — never blocks ingest.
    if vuln.id is not None:
        try:
            from app.core.config import settings as _settings
            if getattr(_settings, "ORACLE_AUTO_ENRICH_ON_INGEST", True):
                from app.services.oracle_enrichment_service import enqueue_background_enrichment
                enqueue_background_enrichment(vuln.id)
        except Exception as exc:
            logger.debug("Oracle auto-enrich skipped for vuln %s: %s", vuln.id, exc)

    return vuln, "created", None


def _enrich_takeover(asset: Asset, finding: UnifiedFinding):
    """Enrich asset with subdomain takeover data and escalate as vulnerability."""
    meta = dict(asset.metadata_ or {})
    meta["takeover"] = {
        "status": finding.takeover_status,
        "service": finding.takeover_service,
        "cname_target": finding.cname_target,
        "detected_at": datetime.utcnow().isoformat(),
    }
    asset.metadata_ = meta

    sev = finding.severity
    if finding.takeover_status == "confirmed":
        finding.severity = Severity.HIGH
    elif finding.takeover_status == "potential":
        finding.severity = Severity.MEDIUM if sev == Severity.INFO else sev

    if not finding.title:
        finding.title = f"Subdomain Takeover ({finding.takeover_status}): {finding.host}"
    finding.type = ResultType.VULNERABILITY


def _enrich_tls(asset: Asset, finding: UnifiedFinding):
    """Enrich asset with deep TLS analysis data."""
    ssl_info = dict(asset.ssl_info or {})
    ssl_info.update({
        "tls_version": finding.tls_version,
        "cipher_suite": finding.cipher_suite,
        "cert_score": finding.cert_score,
        "key_algorithm": finding.key_algorithm,
        "key_size": finding.key_size,
        "ca_type": finding.ca_type,
        "cert_expiry_days": finding.cert_expiry_days,
        "analyzed_at": datetime.utcnow().isoformat(),
    })
    if finding.raw_data:
        ssl_info["tls_raw"] = finding.raw_data
    asset.ssl_info = ssl_info


def _enrich_security_headers(asset: Asset, finding: UnifiedFinding):
    """Enrich asset with security header compliance data."""
    meta = dict(asset.metadata_ or {})
    meta["security_headers"] = finding.security_headers or {}
    meta["cors_policy"] = finding.cors_policy or {}
    meta["header_analysis_at"] = datetime.utcnow().isoformat()
    asset.metadata_ = meta


def _enrich_mail_infrastructure(asset: Asset, finding: UnifiedFinding):
    """Enrich asset with mail infrastructure intelligence."""
    dns = dict(asset.dns_records or {})
    if finding.mail_records:
        dns["mail_infrastructure"] = finding.mail_records
    if finding.mail_provider:
        dns["mail_provider"] = finding.mail_provider
    if finding.email_risk_score is not None:
        dns["email_risk_score"] = finding.email_risk_score
    dns["mail_analyzed_at"] = datetime.utcnow().isoformat()
    asset.dns_records = dns


def _enrich_third_party(asset: Asset, finding: UnifiedFinding):
    """Enrich asset with third-party vendor intelligence."""
    meta = dict(asset.metadata_ or {})
    vendors = meta.get("third_party_vendors", [])
    vendor_entry = {
        "name": finding.vendor_name,
        "category": finding.vendor_category,
        "source": finding.vendor_detection_source,
        "detected_at": datetime.utcnow().isoformat(),
    }
    existing_names = {v.get("name") for v in vendors}
    if finding.vendor_name not in existing_names:
        vendors.append(vendor_entry)
    meta["third_party_vendors"] = vendors
    asset.metadata_ = meta


def process_ingestion_batch(
    db: Session,
    request: IngestionBatchRequest,
    organization_id: int,
) -> IngestionBatchResponse:
    """Process a batch of findings from an external agent."""
    batch_id = str(uuid.uuid4())
    start = time.monotonic()
    results: List[IngestionFindingResult] = []
    created = updated = duplicates = errors = 0
    # Track reactivated findings so we can sync their Jira tickets after commit.
    reactivations: List[Tuple[int, str]] = []  # (vuln_id, old_status_value)

    for idx, finding in enumerate(request.findings):
        try:
            finding.organization_id = organization_id
            asset = _find_or_create_asset(db, organization_id, finding)
            status = "created"
            finding_id = None

            if finding.type == ResultType.PORT:
                ps, ps_status = _upsert_port_service(db, asset, finding)
                status = ps_status
                finding_id = ps.id if ps else None

            elif finding.type == ResultType.VULNERABILITY:
                vuln, v_status, old_st = _upsert_vulnerability(db, asset, finding)
                status = v_status
                finding_id = vuln.id if vuln else None
                if v_status == "reactivated" and vuln and old_st:
                    reactivations.append((vuln.id, old_st))

            elif finding.type == ResultType.TAKEOVER:
                _enrich_takeover(asset, finding)
                vuln, v_status, old_st = _upsert_vulnerability(db, asset, finding)
                status = v_status
                finding_id = vuln.id if vuln else None
                if v_status == "reactivated" and vuln and old_st:
                    reactivations.append((vuln.id, old_st))

            elif finding.type == ResultType.TLS_ANALYSIS:
                _enrich_tls(asset, finding)
                status = "updated"

            elif finding.type == ResultType.SECURITY_HEADER:
                _enrich_security_headers(asset, finding)
                status = "updated"

            elif finding.type == ResultType.MAIL_INFRASTRUCTURE:
                _enrich_mail_infrastructure(asset, finding)
                status = "updated"

            elif finding.type == ResultType.THIRD_PARTY_VENDOR:
                _enrich_third_party(asset, finding)
                status = "updated"

            elif finding.type in (ResultType.DOMAIN, ResultType.SUBDOMAIN, ResultType.IP_ADDRESS, ResultType.IP_RANGE, ResultType.URL):
                pass  # asset creation above is sufficient

            if status == "created":
                created += 1
            elif status in ("updated", "reactivated"):
                updated += 1
            elif status == "duplicate":
                duplicates += 1

            results.append(IngestionFindingResult(
                index=idx,
                status=status,
                asset_id=asset.id,
                finding_id=finding_id,
            ))

        except Exception as e:
            errors += 1
            logger.warning(f"Ingestion error at index {idx}: {e}")
            results.append(IngestionFindingResult(
                index=idx,
                status="error",
                message=str(e)[:200],
            ))

    db.commit()

    # After commit, trigger Jira reopen syncs for reactivated findings.
    # Each call spawns a self-contained daemon thread with its own DB session.
    if reactivations:
        from app.services.reactivation_service import trigger_jira_reopen_background
        for vuln_id, old_st in reactivations:
            trigger_jira_reopen_background(vuln_id, old_st)

    elapsed_ms = (time.monotonic() - start) * 1000

    logger.info(
        f"Ingestion batch {batch_id}: {len(request.findings)} findings, "
        f"{created} created, {updated} updated "
        f"({len(reactivations)} reactivated), {duplicates} dupes, {errors} errors "
        f"({elapsed_ms:.1f}ms)"
    )

    return IngestionBatchResponse(
        batch_id=batch_id,
        total_submitted=len(request.findings),
        created=created,
        updated=updated,
        duplicates=duplicates,
        errors=errors,
        results=results,
        processing_time_ms=round(elapsed_ms, 1),
    )


# =========================================================================
# API Key Management
# =========================================================================

def generate_agent_api_key() -> Tuple[str, str, str]:
    """Generate a new API key. Returns (key_id, full_key, key_hash)."""
    key_id = secrets.token_hex(16)
    raw_key = secrets.token_urlsafe(48)
    full_key = f"tfasm_{raw_key}"
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()
    return key_id, full_key, key_hash


def verify_agent_api_key(db: Session, api_key: str) -> Optional[AgentAPIKey]:
    """Verify an API key and return the associated record if valid."""
    if not api_key or not api_key.startswith("tfasm_"):
        return None

    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    record = (
        db.query(AgentAPIKey)
        .filter(
            AgentAPIKey.key_hash == key_hash,
            AgentAPIKey.is_active == True,
        )
        .first()
    )

    if not record:
        return None

    if record.expires_at and record.expires_at < datetime.utcnow():
        return None

    record.last_used_at = datetime.utcnow()
    record.usage_count += 1
    db.commit()

    return record


def create_agent_api_key(
    db: Session,
    organization_id: int,
    name: str,
    agent_type: str = "aegis_vanguard",
    scopes: Optional[List[str]] = None,
    expires_in_days: Optional[int] = None,
    created_by_user_id: Optional[int] = None,
) -> Tuple[AgentAPIKey, str]:
    """Create a new agent API key. Returns (record, plaintext_key)."""
    key_id, full_key, key_hash = generate_agent_api_key()

    expires_at = None
    if expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

    record = AgentAPIKey(
        key_id=key_id,
        key_hash=key_hash,
        key_prefix=full_key[:12],
        name=name,
        agent_type=agent_type,
        scopes=scopes or ["ingest:findings", "ingest:heartbeat"],
        organization_id=organization_id,
        created_by_user_id=created_by_user_id,
        expires_at=expires_at,
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return record, full_key
