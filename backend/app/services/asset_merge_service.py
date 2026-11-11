"""
Asset Merge Service

Merges related assets to follow the canonical model:
- Domain/subdomain is the primary asset
- IP addresses are attributes on the domain, not separate assets
- Findings, ports, and technologies are consolidated to the primary asset

Use cases:
1. Merge IP asset into its parent domain when IP was resolved from domain
2. Merge duplicate assets discovered from multiple sources
3. Clean up orphaned IP assets that belong to known domains

Assets whose cloud or hardware IDs disagree (see app.services.asset_identity)
are different machines and are never merged. Merging moves the duplicate's
identifiers to the survivor, so the next connector sync finds the survivor.
"""

import logging
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.asset import Asset, AssetType, AssetStatus
from app.models.vulnerability import Vulnerability
from app.models.port_service import PortService
from app.models.screenshot import Screenshot

logger = logging.getLogger(__name__)


class AssetMergeService:
    """Service for merging related assets."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def find_mergeable_assets(
        self,
        organization_id: int,
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """
        Find assets that should be merged.
        
        Returns groups of assets that are related and should be merged:
        - IP assets that were resolved from a domain
        - Duplicate domains/subdomains
        """
        results = {
            "ip_to_domain_merges": [],
            "duplicate_domains": [],
            "total_mergeable": 0,
        }
        
        # Find IP assets that have resolved_from pointing to a domain
        ip_assets = self.db.query(Asset).filter(
            Asset.organization_id == organization_id,
            Asset.asset_type == AssetType.IP_ADDRESS,
            Asset.resolved_from.isnot(None),
        ).all()
        
        for ip_asset in ip_assets:
            # Find the parent domain asset
            domain_asset = self.db.query(Asset).filter(
                Asset.organization_id == organization_id,
                Asset.value == ip_asset.resolved_from,
                Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
            ).first()
            
            if domain_asset:
                results["ip_to_domain_merges"].append({
                    "ip_asset_id": ip_asset.id,
                    "ip_value": ip_asset.value,
                    "domain_asset_id": domain_asset.id,
                    "domain_value": domain_asset.value,
                    "ip_vulns_count": len(ip_asset.vulnerabilities),
                    "ip_ports_count": len(ip_asset.port_services),
                })
                results["total_mergeable"] += 1
        
        # Find duplicate domains (same value, different records)
        duplicates = self.db.query(
            Asset.value,
            func.count(Asset.id).label('count')
        ).filter(
            Asset.organization_id == organization_id,
            Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
        ).group_by(Asset.value).having(func.count(Asset.id) > 1).all()
        
        for value, count in duplicates:
            dup_assets = self.db.query(Asset).filter(
                Asset.organization_id == organization_id,
                Asset.value == value,
            ).order_by(Asset.created_at.asc()).all()
            
            results["duplicate_domains"].append({
                "value": value,
                "count": count,
                "asset_ids": [a.id for a in dup_assets],
                "primary_id": dup_assets[0].id if dup_assets else None,
            })
            results["total_mergeable"] += count - 1  # All but primary
        
        return results
    
    # ── Core merge ─────────────────────────────────────────────────────────

    def absorb(self, primary: Asset, dup: Asset) -> Dict[str, int]:
        """Move everything ``dup`` owns onto ``primary`` and delete ``dup``.

        Children are re-parented through their relationship, not just their
        foreign key: ``dup`` deletes its collections on delete, so anything
        left in them would be deleted with it. Does not commit.
        """
        moved = {"vulnerabilities_moved": 0, "ports_moved": 0, "screenshots_moved": 0}
        if dup.id == primary.id:
            return moved

        for vuln in list(dup.vulnerabilities):
            existing = None
            if vuln.template_id or vuln.title:
                existing = self.db.query(Vulnerability).filter(
                    Vulnerability.asset_id == primary.id,
                    Vulnerability.template_id == vuln.template_id,
                    Vulnerability.title == vuln.title,
                ).first()
            if existing is not None:
                if vuln.last_detected and (not existing.last_detected or vuln.last_detected > existing.last_detected):
                    existing.last_detected = vuln.last_detected
                dup.vulnerabilities.remove(vuln)
                self.db.delete(vuln)
            else:
                metadata = dict(vuln.metadata_ or {})
                metadata.setdefault("merged_from_asset_id", dup.id)
                vuln.metadata_ = metadata
                vuln.asset = primary
                moved["vulnerabilities_moved"] += 1

        for port in list(dup.port_services):
            existing = self.db.query(PortService).filter(
                PortService.asset_id == primary.id,
                PortService.port == port.port,
                PortService.protocol == port.protocol,
            ).first()
            if existing is not None:
                if port.last_seen and (not existing.last_seen or port.last_seen > existing.last_seen):
                    existing.last_seen = port.last_seen
                for attr in ("service_name", "banner"):
                    if getattr(port, attr, None) and not getattr(existing, attr, None):
                        setattr(existing, attr, getattr(port, attr))
                dup.port_services.remove(port)
                self.db.delete(port)
            else:
                port.asset = primary
                moved["ports_moved"] += 1

        for screenshot in list(dup.screenshots):
            screenshot.asset = primary
            moved["screenshots_moved"] += 1

        primary_paths = {entry.path_key for entry in primary.sitemap_entries}
        for entry in list(dup.sitemap_entries):
            if entry.path_key in primary_paths:
                dup.sitemap_entries.remove(entry)
                self.db.delete(entry)
            else:
                entry.asset = primary

        for row in list(dup.identifiers):
            row.asset = primary

        for tech in list(dup.technologies):
            if tech not in primary.technologies:
                primary.technologies.append(tech)
        for label in list(dup.labels):
            if label not in primary.labels:
                primary.labels.append(label)
        for child in list(dup.children):
            child.parent = primary

        for ip in dup.ip_addresses or []:
            primary.add_ip_address(ip)
        if not primary.ip_address and dup.ip_address:
            primary.ip_address = dup.ip_address

        primary.tags = sorted(set(primary.tags or []) | set(dup.tags or []))
        sources = [s for s in (primary.discovery_source or "").split(",") if s]
        for source in (dup.discovery_source or "").split(","):
            if source and source not in sources:
                sources.append(source)
        primary.discovery_source = ",".join(sources)[:100] or None

        # Per-source metadata blocks ("wiz", "tenable", ...) are kept side by
        # side; the primary's own values win where both have the same key.
        metadata = dict(dup.metadata_ or {})
        metadata.update(primary.metadata_ or {})
        history = list(metadata.get("merged_assets") or [])
        history.append({
            "asset_id": dup.id,
            "value": dup.value,
            "asset_type": dup.asset_type.value if dup.asset_type else None,
            "merged_at": datetime.utcnow().isoformat(),
        })
        metadata["merged_assets"] = history[-50:]
        primary.metadata_ = metadata

        for attr in (
            "system_type", "operating_system", "device_class", "device_subclass",
            "hosting_type", "hosting_provider", "country", "country_code", "city",
            "region", "isp", "asn", "business_app_id",
        ):
            if getattr(dup, attr, None) and not getattr(primary, attr, None):
                setattr(primary, attr, getattr(dup, attr))
        if dup.first_seen and (not primary.first_seen or dup.first_seen < primary.first_seen):
            primary.first_seen = dup.first_seen
        if dup.last_seen and (not primary.last_seen or dup.last_seen > primary.last_seen):
            primary.last_seen = dup.last_seen
        if dup.latest_screenshot_id and not primary.latest_screenshot_id:
            primary.latest_screenshot_id = dup.latest_screenshot_id

        self.db.delete(dup)
        self.db.flush()
        return moved

    def _identity_conflict(self, a: Asset, b: Asset) -> bool:
        from app.services.asset_identity import AssetIdentityResolver

        return AssetIdentityResolver(self.db, a.organization_id, "merge").assets_conflict(a, b)

    def merge_ip_into_domain(
        self,
        ip_asset_id: int,
        domain_asset_id: int,
        delete_ip_asset: bool = True,
    ) -> Dict[str, Any]:
        """
        Merge an IP asset into its parent domain asset.

        Findings record the IP they were discovered on, ports record the
        scanned IP, and the IP is added to the domain's ``ip_addresses``.
        With ``delete_ip_asset=False`` only the IP attribute is copied.
        """
        ip_asset = self.db.query(Asset).filter(Asset.id == ip_asset_id).first()
        domain_asset = self.db.query(Asset).filter(Asset.id == domain_asset_id).first()

        if not ip_asset or not domain_asset:
            raise ValueError("Asset not found")
        if ip_asset.asset_type != AssetType.IP_ADDRESS:
            raise ValueError(f"Asset {ip_asset_id} is not an IP address")
        if domain_asset.asset_type not in [AssetType.DOMAIN, AssetType.SUBDOMAIN]:
            raise ValueError(f"Asset {domain_asset_id} is not a domain/subdomain")
        if self._identity_conflict(domain_asset, ip_asset):
            raise ValueError("Assets carry different cloud or hardware IDs and are different machines")

        ip_value = ip_asset.value
        result = {
            "ip_asset_id": ip_asset_id,
            "domain_asset_id": domain_asset_id,
            "vulnerabilities_moved": 0,
            "ports_moved": 0,
            "screenshots_moved": 0,
            "ip_added": ip_value not in (domain_asset.ip_addresses or []),
        }
        domain_asset.add_ip_address(ip_value)

        if delete_ip_asset:
            for vuln in ip_asset.vulnerabilities:
                metadata = dict(vuln.metadata_ or {})
                metadata["discovered_on_ip"] = ip_value
                vuln.metadata_ = metadata
            for port in ip_asset.port_services:
                port.scanned_ip = ip_value
            merged_ips = list((domain_asset.metadata_ or {}).get("merged_ips") or [])
            merged_ips.append({
                "ip": ip_value,
                "merged_at": datetime.utcnow().isoformat(),
                "original_asset_id": ip_asset_id,
            })
            result.update(self.absorb(domain_asset, ip_asset))
            metadata = dict(domain_asset.metadata_ or {})
            metadata["merged_ips"] = merged_ips
            domain_asset.metadata_ = metadata
            result["ip_asset_deleted"] = True

        self.db.commit()
        logger.info(f"Merged IP {ip_value} into domain {domain_asset.value}: "
                    f"{result['vulnerabilities_moved']} vulns, {result['ports_moved']} ports")
        return result

    def merge_duplicate_domains(
        self,
        asset_ids: List[int],
    ) -> Dict[str, Any]:
        """
        Merge duplicate assets into one.

        The first ID given is the primary when it exists; otherwise the
        oldest asset is. Assets whose cloud or hardware IDs disagree with the
        primary's are left alone.
        """
        if len(asset_ids) < 2:
            raise ValueError("Need at least 2 assets to merge")

        assets = self.db.query(Asset).filter(
            Asset.id.in_(asset_ids)
        ).order_by(Asset.created_at.asc(), Asset.id.asc()).all()
        if len(assets) < 2:
            raise ValueError("Could not find all assets")

        primary = next((a for a in assets if a.id == asset_ids[0]), assets[0])
        rest = [a for a in assets if a is not primary]
        duplicates = [a for a in rest if not self._identity_conflict(primary, a)]
        skipped = [a.id for a in rest if a not in duplicates]

        result = {
            "primary_id": primary.id,
            "primary_value": primary.value,
            "merged_count": len(duplicates),
            "merged_ids": [a.id for a in duplicates],
            "skipped_conflicting_ids": skipped,
            "vulnerabilities_moved": 0,
            "ports_moved": 0,
        }
        for dup in duplicates:
            moved = self.absorb(primary, dup)
            result["vulnerabilities_moved"] += moved["vulnerabilities_moved"]
            result["ports_moved"] += moved["ports_moved"]

        self.db.commit()
        logger.info(f"Merged {len(duplicates)} duplicates into asset {primary.id} ({primary.value})")
        return result

    def run_full_merge(
        self,
        organization_id: int,
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """
        Run full asset merge for an organization.
        
        1. Merge IP assets into their parent domains
        2. Merge duplicate domain records
        """
        results = {
            "dry_run": dry_run,
            "organization_id": organization_id,
            "ip_merges": [],
            "domain_merges": [],
            "errors": [],
        }
        
        # Find mergeable assets
        mergeable = self.find_mergeable_assets(organization_id, dry_run=True)
        
        if dry_run:
            return {
                "dry_run": True,
                "preview": mergeable,
                "message": "Set dry_run=false to execute merges",
            }
        
        # Execute IP to domain merges
        for merge in mergeable["ip_to_domain_merges"]:
            try:
                result = self.merge_ip_into_domain(
                    merge["ip_asset_id"],
                    merge["domain_asset_id"],
                    delete_ip_asset=True,
                )
                results["ip_merges"].append(result)
            except Exception as e:
                logger.error(f"Error merging IP {merge['ip_asset_id']}: {e}")
                results["errors"].append({
                    "type": "ip_merge",
                    "ip_asset_id": merge["ip_asset_id"],
                    "error": str(e),
                })
        
        # Execute duplicate domain merges
        for dup in mergeable["duplicate_domains"]:
            try:
                result = self.merge_duplicate_domains(dup["asset_ids"])
                results["domain_merges"].append(result)
            except Exception as e:
                logger.error(f"Error merging duplicates for {dup['value']}: {e}")
                results["errors"].append({
                    "type": "domain_merge",
                    "value": dup["value"],
                    "error": str(e),
                })
        
        results["summary"] = {
            "ip_merges_completed": len(results["ip_merges"]),
            "domain_merges_completed": len(results["domain_merges"]),
            "errors": len(results["errors"]),
        }
        
        return results


def get_asset_merge_service(db: Session) -> AssetMergeService:
    """Get an instance of the asset merge service."""
    return AssetMergeService(db)
