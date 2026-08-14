"""
Nuclei findings import service.

Maps Nuclei scan results to the Vulnerability model and creates
proper security findings with all relevant metadata.
"""

import logging
import re
from typing import Optional, List
from datetime import datetime
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetType
from app.models.vulnerability import Vulnerability, Severity, VulnerabilityStatus
from app.models.scan import Scan
from app.services.nuclei_service import NucleiResult, NucleiScanResult
from app.services.nuclei_detection import build_nuclei_detection

logger = logging.getLogger(__name__)


# ── Detection confidence ─────────────────────────────────────────────────────
# Mirrors schema.DetectionConfidence in aegis-oracle/pkg/schema/vulnerability.go
DETECTION_CONFIDENCE_EXPLOIT_CONFIRMED  = "exploit_confirmed"
DETECTION_CONFIDENCE_ENDPOINT_CONFIRMED = "endpoint_confirmed"
DETECTION_CONFIDENCE_VERSION_ONLY       = "version_only"
DETECTION_CONFIDENCE_UNKNOWN            = "unknown"

# Template ID path segments / tags that indicate a working exploit was fired.
_EXPLOIT_TEMPLATE_PATTERNS = (
    "/cves/", "/exploits/", "/rce/", "/sqli/", "/ssrf/", "/lfi/", "/rfi/",
    "-rce", "-sqli", "-ssrf", "-blind", "-oast", "-injection",
)
# Template ID path segments / tags that indicate an endpoint probe (no payload).
_ENDPOINT_TEMPLATE_PATTERNS = (
    "detect", "exposure", "misconfiguration", "default-login", "login-panel",
    "config-detect", "status-check", "open-redirect", "directory-listing",
    "backup-files", "spring-actuator", "debug", "phpinfo", "info-disclosure",
    "service-detect",
)
# Template ID path segments indicating version/banner detection only.
_VERSION_TEMPLATE_PATTERNS = (
    "version", "tech-detect", "fingerprint", "headers", "banner",
)


def classify_nuclei_detection_confidence(
    template_id: str,
    tags: list,
    evidence: str,
    extracted_results: list,
    matcher_name: str = "",
) -> str:
    """
    Classify Nuclei detection confidence from template and result signals.

    Returns one of: exploit_confirmed | endpoint_confirmed | version_only | unknown
    """
    tid = (template_id or "").lower()
    tags_str = " ".join(tags or []).lower()
    evid = (evidence or "").lower()

    # Exploit confirmed — evidence of a working payload (OOB callback, data extraction)
    if extracted_results:
        return DETECTION_CONFIDENCE_EXPLOIT_CONFIRMED
    if any(kw in evid for kw in ("dns callback", "dnslog", "oast", "out-of-band",
                                  "canary token", "data extracted", "blind injection",
                                  "rce confirmed", "reverse shell", "code execution")):
        return DETECTION_CONFIDENCE_EXPLOIT_CONFIRMED
    if any(pat in tid for pat in _EXPLOIT_TEMPLATE_PATTERNS) and evidence:
        return DETECTION_CONFIDENCE_EXPLOIT_CONFIRMED

    # Version / tech detection templates — only indicate presence, not feature reachability
    if any(pat in tid for pat in _VERSION_TEMPLATE_PATTERNS):
        return DETECTION_CONFIDENCE_VERSION_ONLY
    if "tech" in tags_str or "version-detection" in tags_str:
        return DETECTION_CONFIDENCE_VERSION_ONLY

    # Endpoint confirmed — template probed a feature and got a live response
    if any(pat in tid for pat in _ENDPOINT_TEMPLATE_PATTERNS):
        return DETECTION_CONFIDENCE_ENDPOINT_CONFIRMED
    if any(tag in tags_str for tag in ("exposure", "misconfiguration", "default-login", "auth-bypass")):
        return DETECTION_CONFIDENCE_ENDPOINT_CONFIRMED
    if evidence:
        return DETECTION_CONFIDENCE_ENDPOINT_CONFIRMED

    return DETECTION_CONFIDENCE_UNKNOWN


# Map Nuclei severity to our Severity enum
NUCLEI_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


class NucleiFindingsService:
    """
    Service for importing Nuclei scan results into the vulnerabilities table.
    
    Handles:
    - Severity mapping from Nuclei to internal model
    - Asset lookup/creation
    - CVE/CWE extraction
    - Deduplication of findings
    - Label/tag creation on assets
    """
    
    def __init__(self, db: Session):
        """
        Initialize the service.
        
        Args:
            db: SQLAlchemy database session
        """
        self.db = db
    
    def import_scan_results(
        self,
        scan_result: NucleiScanResult,
        organization_id: int,
        scan_id: Optional[int] = None,
        create_assets: bool = True,
        create_labels: bool = True
    ) -> dict:
        """
        Import all findings from a Nuclei scan result.
        
        Args:
            scan_result: Complete Nuclei scan result
            organization_id: Organization to associate findings with
            scan_id: Optional scan record ID
            create_assets: Create assets for unknown hosts
            create_labels: Create technology/CVE labels on assets
            
        Returns:
            Summary of import results
        """
        summary = {
            "findings_created": 0,
            "findings_updated": 0,
            "findings_reactivated": 0,
            "assets_created": 0,
            "labels_created": 0,
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            },
            "cves_found": set(),
            "errors": []
        }
        # Track reactivated vuln IDs for post-commit Jira sync.
        reactivations: list = []  # [(vuln_id, old_status_value), ...]

        for nuclei_result in scan_result.findings:
            try:
                result = self.import_single_finding(
                    nuclei_result=nuclei_result,
                    organization_id=organization_id,
                    scan_id=scan_id,
                    create_assets=create_assets,
                    create_labels=create_labels
                )
                
                if result.get("created"):
                    summary["findings_created"] += 1
                    severity = nuclei_result.severity.lower()
                    if severity in summary["by_severity"]:
                        summary["by_severity"][severity] += 1
                elif result.get("updated"):
                    summary["findings_updated"] += 1

                if result.get("reactivated") and result.get("vulnerability_id"):
                    summary["findings_reactivated"] += 1
                    reactivations.append(
                        (result["vulnerability_id"], result["old_status"])
                    )
                
                if result.get("asset_created"):
                    summary["assets_created"] += 1
                
                if result.get("labels_added"):
                    summary["labels_created"] += result["labels_added"]
                
                if nuclei_result.cve_id:
                    summary["cves_found"].add(nuclei_result.cve_id)
                    
            except Exception as e:
                logger.error(f"Error importing finding {nuclei_result.template_id}: {e}")
                summary["errors"].append(f"{nuclei_result.template_id}: {str(e)}")
                # Postgres aborts the whole transaction on enum/SQL errors —
                # roll back so the next finding can still import.
                try:
                    self.db.rollback()
                except Exception:
                    pass
        
        self.db.commit()

        # After commit, reopen linked Jira tickets for reactivated findings.
        # Each call spawns a self-contained daemon thread with its own DB session.
        if reactivations:
            from app.services.reactivation_service import trigger_jira_reopen_background
            for vuln_id, old_st in reactivations:
                trigger_jira_reopen_background(vuln_id, old_st)
        
        # Convert set to list for JSON serialization
        summary["cves_found"] = list(summary["cves_found"])
        
        logger.info(
            f"Nuclei import complete: {summary['findings_created']} created, "
            f"{summary['findings_updated']} updated, "
            f"{summary['findings_reactivated']} reactivated"
        )
        
        return summary
    
    def import_single_finding(
        self,
        nuclei_result: NucleiResult,
        organization_id: int,
        scan_id: Optional[int] = None,
        create_assets: bool = True,
        create_labels: bool = True
    ) -> dict:
        """
        Import a single Nuclei finding into the vulnerabilities table.
        
        Args:
            nuclei_result: Single Nuclei scan result
            organization_id: Organization ID
            scan_id: Optional scan ID
            create_assets: Create asset if not found
            create_labels: Add labels to asset
            
        Returns:
            Result dict with created/updated status
        """
        result = {
            "created": False,
            "updated": False,
            "reactivated": False,
            "old_status": None,
            "asset_created": False,
            "labels_added": 0,
            "vulnerability_id": None,
        }
        
        # Find or create the asset
        asset = self._find_or_create_asset(
            nuclei_result, organization_id, create_assets
        )
        
        if not asset:
            logger.warning(f"No asset found for {nuclei_result.host}")
            return result
        
        if create_assets and asset.id is None:
            result["asset_created"] = True
        
        # Check for existing finding on this asset (active or closed)
        existing = self._find_existing_vulnerability(asset.id, nuclei_result)
        
        if existing:
            # Reactivate if the finding was previously closed
            from app.services.reactivation_service import reactivate_if_closed
            old_status = existing.status.value
            if reactivate_if_closed(existing):
                result["reactivated"] = True
                result["old_status"] = old_status

            # Refresh timestamps / scan linkage so analysts see it's still present
            self._update_vulnerability(existing, nuclei_result, scan_id=scan_id)
            result["updated"] = True
            result["vulnerability_id"] = existing.id
        else:
            # Check for duplicate on related assets (domain/IP deduplication)
            from app.services.finding_deduplication_service import get_deduplication_service
            dedup_service = get_deduplication_service(self.db)
            
            duplicate = dedup_service.find_duplicate_finding(
                asset=asset,
                template_id=nuclei_result.template_id,
                cve_id=nuclei_result.cve_id,
                include_related_assets=True
            )
            
            if duplicate:
                # Same vulnerability already exists on a related asset (e.g., domain's IP)
                # Merge into existing finding instead of creating a new one
                from app.services.reactivation_service import reactivate_if_closed
                old_status = duplicate.status.value
                if reactivate_if_closed(duplicate):
                    result["reactivated"] = True
                    result["old_status"] = old_status

                dedup_service.merge_finding_into_existing(
                    existing=duplicate,
                    new_asset=asset,
                    new_evidence=nuclei_result.extracted_results,
                    new_matched_at=nuclei_result.matched_at
                )
                # Also refresh last_detected / scan_id / redetection metadata
                self._update_vulnerability(duplicate, nuclei_result, scan_id=scan_id)
                result["updated"] = True
                result["vulnerability_id"] = duplicate.id
                result["deduplicated"] = True
                result["duplicate_asset"] = duplicate.asset.value if duplicate.asset else None
                logger.info(
                    f"Deduplicated finding {nuclei_result.template_id} on {asset.value} - "
                    f"already exists on related asset (finding #{duplicate.id})"
                )
            else:
                # Create new finding
                vulnerability = self._create_vulnerability(
                    asset, nuclei_result, scan_id
                )
                self.db.add(vulnerability)
                self.db.flush()
                result["created"] = True
                result["vulnerability_id"] = vulnerability.id

                # Approved suppression enforcement: if an analyst has approved
                # suppression for this template, auto-mark the new finding as a
                # false positive at ingest (recommend-then-approve, never silent).
                try:
                    from app.services.detection_pattern_service import is_template_suppressed
                    if nuclei_result.template_id and is_template_suppressed(
                        self.db, organization_id, nuclei_result.template_id
                    ):
                        vulnerability.status = VulnerabilityStatus.FALSE_POSITIVE
                        meta = dict(vulnerability.metadata_ or {})
                        meta["auto_suppressed"] = True
                        meta["auto_suppressed_reason"] = "approved_detection_suppression"
                        meta["auto_suppressed_template_id"] = nuclei_result.template_id
                        vulnerability.metadata_ = meta
                        result["auto_suppressed"] = True
                        logger.info(
                            "Auto-suppressed finding %s on %s (approved template suppression)",
                            nuclei_result.template_id, asset.value,
                        )
                except Exception as exc:
                    logger.debug("Suppression check skipped for %s: %s", nuclei_result.template_id, exc)

                # Delphi enrichment: attach CISA KEV + EPSS signals for new
                # CVE-backed findings. Best-effort — failures never block scan
                # ingestion. Mirrors the same hook in ingestion_service.
                if nuclei_result.cve_id:
                    try:
                        from app.core.config import settings as _settings
                        if getattr(_settings, "DELPHI_AUTO_ENRICH_ON_INGEST", True):
                            from app.services.delphi_enrichment_service import get_delphi_service
                            get_delphi_service().enrich_vulnerability(vulnerability)
                    except Exception as exc:
                        logger.debug(
                            "Delphi auto-enrich skipped for %s: %s",
                            nuclei_result.cve_id, exc
                        )

                # Oracle enrichment: non-blocking background LLM analysis for
                # all new findings when ORACLE_AUTO_ENRICH_ON_INGEST is enabled.
                if vulnerability.id is not None:
                    try:
                        from app.core.config import settings as _settings
                        if getattr(_settings, "ORACLE_AUTO_ENRICH_ON_INGEST", True):
                            from app.services.oracle_enrichment_service import enqueue_background_enrichment
                            enqueue_background_enrichment(vulnerability.id)
                    except Exception as exc:
                        logger.debug(
                            "Oracle auto-enrich skipped for vuln %s: %s",
                            vulnerability.id, exc
                        )
        
        # Add labels to asset
        if create_labels:
            labels_added = self._add_asset_labels(asset, nuclei_result)
            result["labels_added"] = labels_added
        
        return result
    
    def _find_or_create_asset(
        self,
        nuclei_result: NucleiResult,
        organization_id: int,
        create: bool
    ) -> Optional[Asset]:
        """Find or create asset for the Nuclei finding."""
        # Extract host info
        host = nuclei_result.host
        ip = nuclei_result.ip
        
        # Try to parse URL to get hostname
        if host.startswith(("http://", "https://")):
            parsed = urlparse(host)
            hostname = parsed.netloc.split(":")[0]
        else:
            hostname = host.split(":")[0]
        
        # First, try to find by exact host/value match
        asset = self.db.query(Asset).filter(
            Asset.organization_id == organization_id,
            Asset.value == hostname
        ).first()
        
        # Try by IP if we have one
        if not asset and ip:
            asset = self.db.query(Asset).filter(
                Asset.organization_id == organization_id,
                Asset.value == ip
            ).first()
        
        # Try to find by URL match
        if not asset and host.startswith(("http://", "https://")):
            asset = self.db.query(Asset).filter(
                Asset.organization_id == organization_id,
                Asset.value == host
            ).first()
        
        # Create if requested
        if not asset and create:
            # Determine asset type
            asset_type = self._determine_asset_type(hostname, ip)
            
            asset = Asset(
                organization_id=organization_id,
                name=hostname,
                value=hostname,
                asset_type=asset_type,
                discovery_source="nuclei",
                is_live=True  # Mark as live since we got a response from Nuclei
            )
            self.db.add(asset)
            self.db.flush()
        
        # Mark existing asset as live since Nuclei got a response from it
        if asset and not asset.is_live:
            asset.is_live = True
        
        return asset
    
    def _determine_asset_type(self, hostname: str, ip: Optional[str]) -> AssetType:
        """Determine the asset type from hostname/IP."""
        # Check if it's an IP address
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, hostname):
            return AssetType.IP_ADDRESS
        
        # Check for IPv6
        if ":" in hostname and not hostname.startswith("http"):
            return AssetType.IP_ADDRESS
        
        # Default to domain/subdomain
        if hostname.count(".") > 1:
            return AssetType.SUBDOMAIN
        
        return AssetType.DOMAIN
    
    def _find_existing_vulnerability(
        self,
        asset_id: int,
        nuclei_result: NucleiResult
    ) -> Optional[Vulnerability]:
        """
        Find an existing vulnerability matching this finding.

        Priority order:
          1. Active (OPEN / IN_PROGRESS) match by template_id
          2. Active match by CVE ID
          3. Closed (RESOLVED / ACCEPTED / FALSE_POSITIVE / MITIGATED) match by template_id
          4. Closed match by CVE ID

        Returning a closed record signals to the caller that the finding should
        be reactivated rather than creating a duplicate.
        """
        active_statuses = [VulnerabilityStatus.OPEN, VulnerabilityStatus.IN_PROGRESS]

        # 1. Active match — template_id
        existing = self.db.query(Vulnerability).filter(
            Vulnerability.asset_id == asset_id,
            Vulnerability.template_id == nuclei_result.template_id,
            Vulnerability.status.in_(active_statuses),
        ).first()
        if existing:
            return existing

        # 2. Active match — CVE ID
        if nuclei_result.cve_id:
            existing = self.db.query(Vulnerability).filter(
                Vulnerability.asset_id == asset_id,
                Vulnerability.cve_id == nuclei_result.cve_id,
                Vulnerability.status.in_(active_statuses),
            ).first()
            if existing:
                return existing

        # 3/4. Closed match (redetection of a previously closed finding).
        # MITIGATED may be missing from older Postgres vulnerabilitystatus enums —
        # fall back without it so import still succeeds.
        closed_list = self._closed_statuses_for_query()

        existing = self.db.query(Vulnerability).filter(
            Vulnerability.asset_id == asset_id,
            Vulnerability.template_id == nuclei_result.template_id,
            Vulnerability.status.in_(closed_list),
        ).first()
        if existing:
            return existing

        # 4. Closed match — CVE ID
        if nuclei_result.cve_id:
            existing = self.db.query(Vulnerability).filter(
                Vulnerability.asset_id == asset_id,
                Vulnerability.cve_id == nuclei_result.cve_id,
                Vulnerability.status.in_(closed_list),
            ).first()

        return existing

    def _closed_statuses_for_query(self) -> list:
        """Closed statuses safe to use in SQL against the current DB enum."""
        from app.services.reactivation_service import CLOSED_STATUSES
        from sqlalchemy.exc import DataError, ProgrammingError

        closed_list = list(CLOSED_STATUSES)
        # Probe once per service instance whether MITIGATED exists in PG.
        cached = getattr(self, "_mitigated_in_db", None)
        if cached is False:
            return [s for s in closed_list if s != VulnerabilityStatus.MITIGATED]
        if cached is True:
            return closed_list

        try:
            from sqlalchemy import text
            row = self.db.execute(text(
                "SELECT 1 FROM pg_enum e "
                "JOIN pg_type t ON e.enumtypid = t.oid "
                "WHERE t.typname = 'vulnerabilitystatus' "
                "AND e.enumlabel IN ('MITIGATED', 'mitigated') "
                "LIMIT 1"
            )).first()
            self._mitigated_in_db = bool(row)
        except (ProgrammingError, DataError, Exception):
            try:
                self.db.rollback()
            except Exception:
                pass
            self._mitigated_in_db = False

        if not self._mitigated_in_db:
            logger.warning(
                "Postgres enum vulnerabilitystatus is missing MITIGATED; "
                "closed-finding lookup will omit it. Run: "
                "ALTER TYPE vulnerabilitystatus ADD VALUE IF NOT EXISTS 'MITIGATED';"
            )
            return [s for s in closed_list if s != VulnerabilityStatus.MITIGATED]
        return closed_list
    
    def _create_vulnerability(
        self,
        asset: Asset,
        nuclei_result: NucleiResult,
        scan_id: Optional[int]
    ) -> Vulnerability:
        """Create a new Vulnerability from Nuclei result."""
        # Map severity
        severity = NUCLEI_SEVERITY_MAP.get(
            nuclei_result.severity.lower(),
            Severity.INFO
        )
        
        # Build title
        title = nuclei_result.template_name or nuclei_result.template_id
        if nuclei_result.cve_id:
            title = f"[{nuclei_result.cve_id}] {title}"
        
        # Build description
        description = nuclei_result.description or ""
        if nuclei_result.matched_at:
            description += f"\n\n**Matched at:** {nuclei_result.matched_at}"
        if nuclei_result.extracted_results:
            description += f"\n\n**Extracted data:**\n"
            for extract in nuclei_result.extracted_results[:10]:  # Limit to 10
                description += f"- {extract}\n"
        
        # Build evidence
        evidence = f"Nuclei template {nuclei_result.template_id} matched"
        if nuclei_result.matcher_name:
            evidence += f" (matcher: {nuclei_result.matcher_name})"
        if nuclei_result.curl_command:
            evidence += f"\n\nReproduction:\n```\n{nuclei_result.curl_command}\n```"
        
        # Build tags
        tags = list(nuclei_result.tags) if nuclei_result.tags else []
        tags.append(f"nuclei:{nuclei_result.template_id}")
        if nuclei_result.cve_id:
            tags.append(f"cve:{nuclei_result.cve_id}")
        tags.append(f"severity:{severity.value}")
        
        # Build references
        references = nuclei_result.reference if nuclei_result.reference else []
        if nuclei_result.cve_id:
            references.append(f"https://nvd.nist.gov/vuln/detail/{nuclei_result.cve_id}")
            references.append(f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={nuclei_result.cve_id}")
        
        dc = classify_nuclei_detection_confidence(
            template_id=nuclei_result.template_id,
            tags=nuclei_result.tags or [],
            evidence=evidence,
            extracted_results=nuclei_result.extracted_results or [],
            matcher_name=nuclei_result.matcher_name or "",
        )

        metadata = {
            "nuclei_host": nuclei_result.host,
            "nuclei_ip": nuclei_result.ip,
            "nuclei_matched_at": nuclei_result.matched_at,
            "nuclei_timestamp": nuclei_result.timestamp.isoformat() if nuclei_result.timestamp else None,
            "nuclei_extracted_results": nuclei_result.extracted_results[:10] if nuclei_result.extracted_results else [],
        }
        detection = build_nuclei_detection(nuclei_result)
        if detection:
            metadata["detection"] = detection

        vulnerability = Vulnerability(
            title=title,
            description=description,
            severity=severity,
            cvss_score=nuclei_result.cvss_score,
            cvss_vector=nuclei_result.cvss_vector,
            cve_id=nuclei_result.cve_id,
            cwe_id=nuclei_result.cwe_id,
            references=references,
            asset_id=asset.id,
            scan_id=scan_id,
            detected_by="nuclei",
            template_id=nuclei_result.template_id,
            matcher_name=nuclei_result.matcher_name,
            detection_confidence=dc,
            status=VulnerabilityStatus.OPEN,
            evidence=evidence,
            tags=tags,
            metadata_=metadata,
        )
        
        return vulnerability
    
    def _update_vulnerability(
        self,
        vulnerability: Vulnerability,
        nuclei_result: NucleiResult,
        scan_id: Optional[int] = None,
    ) -> None:
        """Update existing vulnerability when the same bug is redetected.

        Analysts rely on last_detected / latest scan linkage to know the issue
        is still present — always refresh those fields on a hit.
        """
        now = datetime.utcnow()
        vulnerability.last_detected = now
        vulnerability.updated_at = now

        # Point the finding at the scan that most recently confirmed it
        if scan_id is not None:
            vulnerability.scan_id = scan_id

        # Keep matcher/evidence current when Nuclei returns new detail
        if nuclei_result.matcher_name:
            vulnerability.matcher_name = nuclei_result.matcher_name
        if nuclei_result.matched_at or nuclei_result.extracted_results:
            evidence_parts = []
            if nuclei_result.matched_at:
                evidence_parts.append(f"Matched at: {nuclei_result.matched_at}")
            if nuclei_result.extracted_results:
                evidence_parts.append(
                    "Extracted: " + ", ".join(str(x) for x in nuclei_result.extracted_results[:10])
                )
            if evidence_parts:
                vulnerability.evidence = "\n".join(evidence_parts)

        meta = dict(vulnerability.metadata_ or {})
        meta["last_scan_timestamp"] = now.isoformat()
        meta["last_redetected_at"] = now.isoformat()
        meta["redetection_count"] = int(meta.get("redetection_count") or 0) + 1
        if scan_id is not None:
            meta["last_scan_id"] = scan_id
        if nuclei_result.host:
            meta["nuclei_host"] = nuclei_result.host
        if nuclei_result.ip:
            meta["nuclei_ip"] = nuclei_result.ip
        if nuclei_result.matched_at:
            meta["nuclei_matched_at"] = nuclei_result.matched_at
        if nuclei_result.extracted_results:
            meta["nuclei_extracted_results"] = nuclei_result.extracted_results[:10]
        if nuclei_result.timestamp:
            meta["nuclei_timestamp"] = nuclei_result.timestamp.isoformat()
        detection = build_nuclei_detection(nuclei_result)
        if detection:
            existing = meta.get("detection") if isinstance(meta.get("detection"), dict) else {}
            existing.update(detection)
            meta["detection"] = existing
        vulnerability.metadata_ = meta

        # Potentially update severity if it changed (unusual but possible)
        new_severity = NUCLEI_SEVERITY_MAP.get(nuclei_result.severity.lower(), Severity.INFO)
        if new_severity.value != vulnerability.severity.value:
            # Only upgrade severity, never downgrade
            severity_order = ["info", "low", "medium", "high", "critical"]
            if severity_order.index(new_severity.value) > severity_order.index(vulnerability.severity.value):
                vulnerability.severity = new_severity

                # Update tags
                if vulnerability.tags:
                    vulnerability.tags = [t for t in vulnerability.tags if not t.startswith("severity:")]
                    vulnerability.tags.append(f"severity:{new_severity.value}")
    
    def _add_asset_labels(
        self,
        asset: Asset,
        nuclei_result: NucleiResult
    ) -> int:
        """Add labels/tags to asset based on finding."""
        labels_added = 0
        
        # Ensure asset has tags list
        if asset.tags is None:
            asset.tags = []
        
        existing_tags = set(asset.tags)
        new_tags = []
        
        # Add severity label
        severity_label = f"vuln:{nuclei_result.severity.lower()}"
        if severity_label not in existing_tags:
            new_tags.append(severity_label)
        
        # Add CVE label
        if nuclei_result.cve_id:
            cve_label = f"cve:{nuclei_result.cve_id}"
            if cve_label not in existing_tags:
                new_tags.append(cve_label)
        
        # Add technology labels from tags
        tech_tags = ["wordpress", "drupal", "joomla", "magento", "nginx", "apache", 
                     "iis", "tomcat", "jenkins", "gitlab", "aws", "azure", "gcp",
                     "php", "java", "python", "nodejs", "docker", "kubernetes"]
        
        for tag in (nuclei_result.tags or []):
            tag_lower = tag.lower()
            if tag_lower in tech_tags:
                tech_label = f"tech:{tag_lower}"
                if tech_label not in existing_tags:
                    new_tags.append(tech_label)
        
        # Add template category labels
        category_tags = ["rce", "sqli", "xss", "ssrf", "lfi", "xxe", "ssti", 
                        "auth-bypass", "misconfig", "exposure", "default-login"]
        
        for tag in (nuclei_result.tags or []):
            tag_lower = tag.lower()
            if tag_lower in category_tags:
                cat_label = f"vuln-type:{tag_lower}"
                if cat_label not in existing_tags:
                    new_tags.append(cat_label)
        
        # Update asset tags
        if new_tags:
            asset.tags = list(existing_tags) + new_tags
            labels_added = len(new_tags)
        
        return labels_added
    
    def get_findings_summary(
        self,
        organization_id: int,
        scan_id: Optional[int] = None
    ) -> dict:
        """Get summary of Nuclei findings for an organization."""
        query = self.db.query(Vulnerability).filter(
            Vulnerability.detected_by == "nuclei"
        ).join(Asset).filter(
            Asset.organization_id == organization_id
        )
        
        if scan_id:
            query = query.filter(Vulnerability.scan_id == scan_id)
        
        findings = query.all()
        
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        by_template = {}
        cves = set()
        
        for f in findings:
            by_severity[f.severity.value] += 1
            
            if f.template_id:
                by_template[f.template_id] = by_template.get(f.template_id, 0) + 1
            
            if f.cve_id:
                cves.add(f.cve_id)
        
        # Top templates
        top_templates = sorted(
            by_template.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        return {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "unique_cves": len(cves),
            "cves": list(cves)[:50],  # Limit for response size
            "top_templates": [{"template": t, "count": c} for t, c in top_templates],
            "critical_findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "asset": f.asset.value if f.asset else None,
                    "cve": f.cve_id
                }
                for f in findings if f.severity == Severity.CRITICAL
            ][:20]
        }
    
    def close_stale_findings(
        self,
        organization_id: int,
        scan_id: int,
        days_threshold: int = 30
    ) -> int:
        """
        Close findings that haven't been detected in recent scans.
        
        Useful for cleanup after regular scanning.
        
        Args:
            organization_id: Organization ID
            scan_id: Current scan ID
            days_threshold: Close findings not seen in this many days
            
        Returns:
            Number of findings closed
        """
        from datetime import timedelta
        
        threshold_date = datetime.utcnow() - timedelta(days=days_threshold)
        
        stale_findings = self.db.query(Vulnerability).filter(
            Vulnerability.detected_by == "nuclei",
            Vulnerability.status == VulnerabilityStatus.OPEN,
            Vulnerability.last_detected < threshold_date
        ).join(Asset).filter(
            Asset.organization_id == organization_id
        ).all()
        
        closed_count = 0
        for finding in stale_findings:
            finding.status = VulnerabilityStatus.RESOLVED
            finding.resolved_at = datetime.utcnow()
            closed_count += 1
        
        if closed_count:
            self.db.commit()
            logger.info(f"Closed {closed_count} stale Nuclei findings")
        
        return closed_count

















