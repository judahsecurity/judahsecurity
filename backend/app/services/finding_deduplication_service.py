"""
Finding Deduplication Service.

Handles deduplication of security findings across related assets,
particularly for cases where:
- A vulnerability is found on both a domain and its resolved IP
- WAF bypasses where the IP is vulnerable but domain is protected
- Same finding on parent domain and subdomains

The service can either:
1. Link duplicate findings together (keeping both but marking relationship)
2. Merge findings (update one as canonical, mark others as duplicates)
"""

import logging
import re
from typing import Optional, List, Tuple, Set
from datetime import datetime

from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, cast, String

from app.models.asset import Asset, AssetType
from app.models.vulnerability import Vulnerability, VulnerabilityStatus

logger = logging.getLogger(__name__)


class FindingDeduplicationService:
    """
    Service for finding and handling duplicate vulnerabilities across related assets.
    
    Key scenarios:
    1. Domain/IP relationship: example.com resolves to 1.2.3.4, same vuln on both
    2. Subdomain relationship: vuln on www.example.com and example.com
    3. WAF bypass: Domain protected by WAF, IP is not - same underlying issue
    """
    
    def __init__(self, db: Session):
        """Initialize the service."""
        self.db = db
    
    def get_related_assets(self, asset: Asset) -> List[Asset]:
        """
        Get all assets related to the given asset.
        
        For domain/subdomain: Get the IP addresses it resolves to
        For IP address: Get domains that resolve to this IP
        
        Args:
            asset: The asset to find related assets for
            
        Returns:
            List of related Asset objects
        """
        related = []
        org_id = asset.organization_id
        
        if asset.asset_type in [AssetType.DOMAIN, AssetType.SUBDOMAIN]:
            # Get IPs this domain resolves to
            ips = set()
            
            if asset.ip_address:
                ips.add(asset.ip_address)
            
            if asset.ip_addresses:
                ips.update(asset.ip_addresses)
            
            # Find IP assets that match
            if ips:
                ip_assets = self.db.query(Asset).filter(
                    Asset.organization_id == org_id,
                    Asset.asset_type == AssetType.IP_ADDRESS,
                    Asset.value.in_(list(ips))
                ).all()
                related.extend(ip_assets)
            
            # Also find parent domain if this is a subdomain
            if asset.asset_type == AssetType.SUBDOMAIN and asset.root_domain:
                parent = self.db.query(Asset).filter(
                    Asset.organization_id == org_id,
                    Asset.value == asset.root_domain
                ).first()
                if parent:
                    related.append(parent)
        
        elif asset.asset_type == AssetType.IP_ADDRESS:
            # Get domains that resolve to this IP
            ip_value = asset.value
            
            # Find domains with this IP in their ip_address or ip_addresses
            domain_assets = self.db.query(Asset).filter(
                Asset.organization_id == org_id,
                Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
                or_(
                    Asset.ip_address == ip_value,
                    # ip_addresses is a JSON (not JSONB) column, so .contains()
                    # emits a text LIKE that Postgres rejects with
                    # "operator does not exist: json ~~ text". Match against the
                    # JSON-encoded array text instead (values are stored quoted,
                    # e.g. ["1.2.3.4"]).
                    cast(Asset.ip_addresses, String).like(f'%"{ip_value}"%')
                )
            ).all()
            related.extend(domain_assets)
            
            # Also check resolved_from field
            if asset.resolved_from:
                domain = self.db.query(Asset).filter(
                    Asset.organization_id == org_id,
                    Asset.value == asset.resolved_from
                ).first()
                if domain and domain not in related:
                    related.append(domain)
        
        return related
    
    def find_duplicate_finding(
        self,
        asset: Asset,
        template_id: Optional[str] = None,
        title: Optional[str] = None,
        port: Optional[int] = None,
        cve_id: Optional[str] = None,
        include_related_assets: bool = True
    ) -> Optional[Vulnerability]:
        """
        Find an existing duplicate finding for this potential new finding.
        
        Checks both the asset itself and related assets for duplicates.
        
        Args:
            asset: The asset the new finding would be on
            template_id: Nuclei template ID (if applicable)
            title: Finding title pattern
            port: Port number (for port-based findings)
            cve_id: CVE ID if known
            include_related_assets: Check related assets for duplicates
            
        Returns:
            Existing Vulnerability if duplicate found, None otherwise
        """
        # Build list of assets to check
        assets_to_check = [asset]
        if include_related_assets:
            related = self.get_related_assets(asset)
            assets_to_check.extend(related)
        
        asset_ids = [a.id for a in assets_to_check]
        
        # Build query for matching findings
        query = self.db.query(Vulnerability).filter(
            Vulnerability.asset_id.in_(asset_ids),
            Vulnerability.status.in_([
                VulnerabilityStatus.OPEN,
                VulnerabilityStatus.IN_PROGRESS
            ])
        )
        
        # Match by template_id first (most reliable for Nuclei)
        if template_id:
            exact_match = query.filter(
                Vulnerability.template_id == template_id
            ).first()
            if exact_match:
                return exact_match
        
        # Match by CVE (very reliable)
        if cve_id:
            cve_id = cve_id.strip().upper()
            # Also match findings that cover the CVE among several (e.g. a
            # Tenable plugin listing many CVEs keeps all of them in ``cves``).
            cve_match = query.filter(
                or_(
                    Vulnerability.cve_id == cve_id,
                    cast(Vulnerability.cves, String).like(f'%"{cve_id}"%'),
                )
            ).first()
            if cve_match:
                return cve_match
        
        # Match by port (for port-based findings)
        if port:
            port_pattern = f"Port {port}/"
            port_match = query.filter(
                Vulnerability.title.contains(port_pattern)
            ).first()
            if port_match:
                return port_match
        
        # Match by title pattern (less reliable, use cautiously)
        if title and not template_id and not cve_id and not port:
            # Extract the core title without port/host info
            core_title = self._extract_core_title(title)
            if core_title:
                title_match = query.filter(
                    Vulnerability.title.contains(core_title)
                ).first()
                if title_match:
                    return title_match
        
        return None
    
    def _extract_core_title(self, title: str) -> Optional[str]:
        """Extract the core vulnerability title without port/host info."""
        # Remove [Port X/Y] prefix
        title = re.sub(r'^\[Port \d+/\w+\]\s*', '', title)
        # Remove trailing host info
        title = re.sub(r'\s*on\s+[\w\.\-]+$', '', title)
        # Remove common prefixes
        title = re.sub(r'^(Detected|Found|Exposed)\s+', '', title, flags=re.IGNORECASE)
        return title.strip() if len(title.strip()) > 10 else None
    
    def link_duplicate_findings(
        self,
        primary: Vulnerability,
        duplicate: Vulnerability
    ) -> None:
        """
        Link two findings as duplicates.
        
        Keeps both findings but records the relationship in metadata.
        
        Args:
            primary: The primary/canonical finding
            duplicate: The duplicate finding to link
        """
        now = datetime.utcnow().isoformat()
        
        # Update primary's metadata
        primary_meta = primary.metadata_ or {}
        if "linked_findings" not in primary_meta:
            primary_meta["linked_findings"] = []
        
        linked_entry = {
            "finding_id": duplicate.id,
            "asset_id": duplicate.asset_id,
            "linked_at": now,
            "relationship": "same_vulnerability_different_asset"
        }
        
        if linked_entry not in primary_meta["linked_findings"]:
            primary_meta["linked_findings"].append(linked_entry)
            primary.metadata_ = primary_meta
        
        # Update duplicate's metadata
        dup_meta = duplicate.metadata_ or {}
        dup_meta["primary_finding_id"] = primary.id
        dup_meta["is_duplicate"] = True
        dup_meta["duplicate_detected_at"] = now
        dup_meta["duplicate_reason"] = "same_vulnerability_on_related_asset"
        duplicate.metadata_ = dup_meta
        
        # Add a note about the duplicate relationship
        if not duplicate.notes:
            duplicate.notes = ""
        if "Linked to finding" not in duplicate.notes:
            duplicate.notes += f"\n[Auto] Linked to finding #{primary.id} on {primary.asset.value if primary.asset else 'unknown'}"
        
        logger.info(f"Linked finding {duplicate.id} to primary finding {primary.id}")
    
    def merge_finding_into_existing(
        self,
        existing: Vulnerability,
        new_asset: Asset,
        new_evidence: Optional[str] = None,
        new_matched_at: Optional[str] = None
    ) -> Vulnerability:
        """
        Merge a would-be new finding into an existing one.
        
        Updates the existing finding to note it was also found on another asset.
        
        Args:
            existing: The existing finding to update
            new_asset: The asset where the same vuln was also found
            new_evidence: New evidence to add
            new_matched_at: Where the vuln was matched on new asset
            
        Returns:
            The updated existing finding
        """
        now = datetime.utcnow().isoformat()
        
        # Update metadata with additional affected assets
        meta = existing.metadata_ or {}
        if "also_affects" not in meta:
            meta["also_affects"] = []
        
        also_affects_entry = {
            "asset_id": new_asset.id,
            "asset_value": new_asset.value,
            "asset_type": new_asset.asset_type.value,
            "discovered_at": now,
            "matched_at": new_matched_at
        }
        
        # Check if already recorded
        existing_values = [a.get("asset_value") for a in meta["also_affects"]]
        if new_asset.value not in existing_values:
            meta["also_affects"].append(also_affects_entry)
            existing.metadata_ = meta
            
            # Append to evidence
            if new_evidence and existing.evidence:
                existing.evidence += f"\n\nAlso found on {new_asset.value}:\n{new_evidence}"
            elif new_evidence:
                existing.evidence = new_evidence
            
            # Update last detected
            existing.last_detected = datetime.utcnow()
            
            logger.info(f"Merged finding for {new_asset.value} into existing finding {existing.id}")
        
        return existing
    
    def deduplicate_findings_for_organization(
        self,
        organization_id: int,
        dry_run: bool = False
    ) -> dict:
        """
        Find and link duplicate findings across an organization.
        
        This is a bulk operation that can be run to clean up existing duplicates.
        
        Args:
            organization_id: Organization to process
            dry_run: If True, report but don't make changes
            
        Returns:
            Summary of duplicates found/processed
        """
        summary = {
            "total_findings_checked": 0,
            "duplicates_found": 0,
            "findings_linked": 0,
            "duplicate_pairs": [],
            "errors": []
        }
        
        # Get all open findings for the org
        findings = self.db.query(Vulnerability).join(Asset).filter(
            Asset.organization_id == organization_id,
            Vulnerability.status.in_([
                VulnerabilityStatus.OPEN,
                VulnerabilityStatus.IN_PROGRESS
            ])
        ).all()
        
        summary["total_findings_checked"] = len(findings)
        
        # Group findings by template_id
        by_template = {}
        for f in findings:
            if f.template_id:
                if f.template_id not in by_template:
                    by_template[f.template_id] = []
                by_template[f.template_id].append(f)
        
        # Check each group for duplicates
        for template_id, group in by_template.items():
            if len(group) < 2:
                continue
            
            # Check if any are on related assets
            for i, finding1 in enumerate(group):
                if not finding1.asset:
                    continue
                    
                related_assets = self.get_related_assets(finding1.asset)
                related_ids = {a.id for a in related_assets}
                
                for finding2 in group[i+1:]:
                    if not finding2.asset:
                        continue
                    
                    if finding2.asset_id in related_ids:
                        # These are duplicates on related assets
                        summary["duplicates_found"] += 1
                        summary["duplicate_pairs"].append({
                            "template_id": template_id,
                            "finding1": {
                                "id": finding1.id,
                                "asset": finding1.asset.value
                            },
                            "finding2": {
                                "id": finding2.id,
                                "asset": finding2.asset.value
                            },
                            "relationship": self._describe_relationship(
                                finding1.asset, finding2.asset
                            )
                        })
                        
                        if not dry_run:
                            # Link the findings (older one is primary)
                            if finding1.created_at <= finding2.created_at:
                                self.link_duplicate_findings(finding1, finding2)
                            else:
                                self.link_duplicate_findings(finding2, finding1)
                            summary["findings_linked"] += 1
        
        if not dry_run:
            self.db.commit()
        
        return summary
    
    def _describe_relationship(self, asset1: Asset, asset2: Asset) -> str:
        """Describe the relationship between two assets."""
        if asset1.asset_type == AssetType.IP_ADDRESS and \
           asset2.asset_type in [AssetType.DOMAIN, AssetType.SUBDOMAIN]:
            return f"IP {asset1.value} is resolved from {asset2.value}"
        elif asset2.asset_type == AssetType.IP_ADDRESS and \
             asset1.asset_type in [AssetType.DOMAIN, AssetType.SUBDOMAIN]:
            return f"{asset1.value} resolves to IP {asset2.value}"
        elif asset1.root_domain == asset2.value:
            return f"{asset1.value} is subdomain of {asset2.value}"
        elif asset2.root_domain == asset1.value:
            return f"{asset2.value} is subdomain of {asset1.value}"
        else:
            return "related assets"


def get_deduplication_service(db: Session) -> FindingDeduplicationService:
    """Get a deduplication service instance."""
    return FindingDeduplicationService(db)
