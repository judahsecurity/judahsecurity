"""
Discovery orchestration service for attack surface management.

This service coordinates full domain discovery including:
- DNS enumeration
- Subdomain discovery
- HTTP probing
- Technology fingerprinting
"""

import asyncio
import logging
from datetime import datetime
from typing import Optional, Callable
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetType, AssetStatus
from app.models.technology import Technology
from app.models.scan import Scan, ScanType, ScanStatus
from app.services.dns_service import DNSService
from app.services.subdomain_service import SubdomainService
from app.services.http_service import HTTPService
from app.services.wappalyzer_service import WappalyzerService
from app.services.asset_labeling_service import add_tech_to_asset
from app.services.ip_classifier_service import IPClassifierService, IPClassification

logger = logging.getLogger(__name__)


@dataclass
class DiscoveryProgress:
    """Progress tracking for discovery operations."""
    current_step: str = ""
    total_steps: int = 0
    completed_steps: int = 0
    assets_found: int = 0
    technologies_found: int = 0
    errors: list[str] = field(default_factory=list)
    
    @property
    def percentage(self) -> int:
        if self.total_steps == 0:
            return 0
        return int((self.completed_steps / self.total_steps) * 100)


@dataclass
class DiscoveryResult:
    """Result of a discovery operation."""
    domain: str
    success: bool
    assets: list[dict] = field(default_factory=list)
    technologies: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0


class DiscoveryService:
    """
    Orchestration service for full attack surface discovery.
    
    Given a seed domain (e.g., rockwellautomation.com), this service will:
    1. Enumerate DNS records
    2. Discover subdomains via crt.sh and brute-forcing
    3. Resolve all discovered hosts to IP addresses
    4. Probe HTTP/HTTPS endpoints
    5. Fingerprint technologies using Wappalyzer patterns
    6. Store all discovered assets in the database
    """
    
    def __init__(
        self,
        db: Session,
        dns_service: Optional[DNSService] = None,
        subdomain_service: Optional[SubdomainService] = None,
        http_service: Optional[HTTPService] = None,
        wappalyzer_service: Optional[WappalyzerService] = None,
        ip_classifier: Optional[IPClassifierService] = None
    ):
        """
        Initialize discovery service.
        
        Args:
            db: Database session
            dns_service: DNS enumeration service
            subdomain_service: Subdomain discovery service
            http_service: HTTP probing service
            wappalyzer_service: Technology fingerprinting service
            ip_classifier: IP classification service for identifying owned vs cloud IPs
        """
        self.db = db
        self.dns = dns_service or DNSService()
        self.subdomain = subdomain_service or SubdomainService()
        self.http = http_service or HTTPService()
        self.wappalyzer = wappalyzer_service or WappalyzerService()
        self.ip_classifier = ip_classifier or IPClassifierService(db)
    
    async def discover_domain(
        self,
        domain: str,
        organization_id: int,
        scan_id: Optional[int] = None,
        progress_callback: Optional[Callable[[DiscoveryProgress], None]] = None,
        include_technology_scan: bool = True,
        subdomain_wordlist: Optional[list[str]] = None,
        use_tldfinder: bool = False,
    ) -> DiscoveryResult:
        """
        Perform full discovery for a domain.
        
        Args:
            domain: Target domain (e.g., rockwellautomation.com)
            organization_id: Organization ID to associate assets with
            scan_id: Optional scan ID for tracking
            progress_callback: Optional callback for progress updates
            include_technology_scan: Whether to run Wappalyzer detection
            subdomain_wordlist: Optional custom subdomain wordlist
            use_tldfinder: If True, run ProjectDiscovery tldfinder for additional domain coverage
            
        Returns:
            DiscoveryResult with all findings
        """
        start_time = datetime.utcnow()
        progress = DiscoveryProgress()
        result = DiscoveryResult(domain=domain, success=True)
        
        # Update scan status if provided
        if scan_id:
            self._update_scan_status(scan_id, ScanStatus.RUNNING, "Starting discovery")
        
        try:
            # Define discovery steps
            steps = [
                "DNS enumeration",
                "Subdomain discovery",
                "IP resolution",
                "HTTP probing",
            ]
            if include_technology_scan:
                steps.append("Technology fingerprinting")
            
            progress.total_steps = len(steps)
            
            # Step 1: DNS Enumeration
            progress.current_step = "DNS enumeration"
            self._report_progress(progress, progress_callback, scan_id)
            
            logger.info(f"Starting DNS enumeration for {domain}")
            dns_records = self.dns.enumerate_domain(domain)
            
            # Create root domain asset
            root_asset = self._create_or_update_asset(
                organization_id=organization_id,
                asset_type=AssetType.DOMAIN,
                name=domain,
                value=domain,
                discovery_source="seed",
                metadata_={
                    "dns_records": dns_records.to_dict()
                }
            )
            root_ips = list(dict.fromkeys(dns_records.a_records + dns_records.aaaa_records))
            if root_ips:
                root_asset.update_ip_addresses(root_ips)
            result.assets.append(self._asset_to_dict(root_asset))
            progress.assets_found += 1
            
            # Create IP assets from A records with hosting classification
            for ip in dns_records.a_records:
                # Classify the IP to determine if it's owned infrastructure or cloud-hosted
                ip_classification = self.ip_classifier.classify(ip, organization_id)
                
                ip_asset = self._create_or_update_asset(
                    organization_id=organization_id,
                    asset_type=AssetType.IP_ADDRESS,
                    name=ip,
                    value=ip,
                    parent_id=root_asset.id,
                    discovery_source="dns_enumeration",
                    metadata_={
                        "resolved_from": domain,
                        "hosting_type": ip_classification.hosting_type,
                        "hosting_provider": ip_classification.hosting_provider,
                        "is_ephemeral": ip_classification.is_ephemeral,
                        "classification_confidence": ip_classification.confidence,
                        "classification_reason": ip_classification.reason
                    }
                )
                
                # Set hosting classification fields on the asset
                ip_asset.hosting_type = ip_classification.hosting_type
                ip_asset.hosting_provider = ip_classification.hosting_provider
                ip_asset.is_ephemeral_ip = ip_classification.is_ephemeral
                ip_asset.resolved_from = domain
                ip_asset.is_owned = ip_classification.in_owned_cidr
                ip_asset.netblock_id = ip_classification.netblock_id
                
                # Log classification for awareness
                if ip_classification.hosting_type == "cloud":
                    logger.info(
                        f"IP {ip} classified as cloud-hosted ({ip_classification.hosting_provider}) - "
                        f"resolved from {domain}. Scan by hostname only."
                    )
                elif ip_classification.hosting_type == "owned":
                    logger.info(f"IP {ip} classified as owned infrastructure - safe to scan directly")
                
                result.assets.append(self._asset_to_dict(ip_asset))
                progress.assets_found += 1
            
            progress.completed_steps += 1
            self._report_progress(progress, progress_callback, scan_id)
            
            # Step 2: Subdomain Discovery (with recursive multi-level enumeration)
            progress.current_step = "Subdomain discovery"
            self._report_progress(progress, progress_callback, scan_id)
            
            logger.info(f"Starting recursive subdomain enumeration for {domain}")
            
            # Use recursive enumeration to find multi-level subdomains
            # E.g., api.cloud.example.com, portal.cloud.example.com, etc.
            recursive_result = await self.subdomain.enumerate_recursive(
                domain=domain,
                max_depth=2,  # Enumerate up to 3 levels deep
                min_subdomains_for_recursion=2,  # Recurse into subdomains with 2+ children
                use_crtsh=True,
                use_subfinder=True,
                use_chaos=True
            )
            
            # Convert recursive result to list of SubdomainResults
            subdomains = recursive_result.all_subdomains
            
            logger.info(
                f"Recursive enumeration complete: {recursive_result.total_subdomains} subdomains found "
                f"across {len(recursive_result.subdomains_by_depth)} depth levels in {recursive_result.duration_seconds:.2f}s"
            )
            for depth, count in sorted(recursive_result.subdomains_by_depth.items()):
                logger.info(f"  Depth {depth}: {count} subdomains")
            
            subdomain_assets = {}
            for sub_result in subdomains:
                if sub_result.subdomain != domain:
                    sub_asset = self._create_or_update_asset(
                        organization_id=organization_id,
                        asset_type=AssetType.SUBDOMAIN,
                        name=sub_result.subdomain,
                        value=sub_result.subdomain,
                        parent_id=root_asset.id,
                        discovery_source=sub_result.source,
                        status=AssetStatus.VERIFIED if sub_result.is_alive else AssetStatus.UNVERIFIED
                    )
                    if sub_result.ip_addresses:
                        sub_asset.update_ip_addresses(sub_result.ip_addresses)
                    subdomain_assets[sub_result.subdomain] = sub_asset
                    result.assets.append(self._asset_to_dict(sub_asset))
                    progress.assets_found += 1
                    
                    # Create IP assets for this subdomain with hosting classification
                    for ip in sub_result.ip_addresses:
                        # Classify the IP to determine if it's owned or cloud-hosted
                        ip_classification = self.ip_classifier.classify(ip, organization_id)
                        
                        ip_asset = self._create_or_update_asset(
                            organization_id=organization_id,
                            asset_type=AssetType.IP_ADDRESS,
                            name=ip,
                            value=ip,
                            parent_id=sub_asset.id,
                            discovery_source="subdomain_resolution",
                            metadata_={
                                "resolved_from": sub_result.subdomain,
                                "hosting_type": ip_classification.hosting_type,
                                "hosting_provider": ip_classification.hosting_provider,
                                "is_ephemeral": ip_classification.is_ephemeral,
                                "classification_confidence": ip_classification.confidence,
                                "classification_reason": ip_classification.reason
                            }
                        )
                        
                        # Set hosting classification fields
                        ip_asset.hosting_type = ip_classification.hosting_type
                        ip_asset.hosting_provider = ip_classification.hosting_provider
                        ip_asset.is_ephemeral_ip = ip_classification.is_ephemeral
                        ip_asset.resolved_from = sub_result.subdomain
                        ip_asset.is_owned = ip_classification.in_owned_cidr
                        ip_asset.netblock_id = ip_classification.netblock_id
                        # Don't add duplicate IPs to result
            
            progress.completed_steps += 1
            self._report_progress(progress, progress_callback, scan_id)
            
            # Optional: TLD/domain discovery via tldfinder (better coverage for keywords/private TLDs)
            if use_tldfinder:
                try:
                    from app.services.tldfinder_service import TLDFinderService, TLDFINDER_AVAILABLE
                    if TLDFINDER_AVAILABLE:
                        progress.current_step = "TLD/domain discovery (tldfinder)"
                        self._report_progress(progress, progress_callback, scan_id)
                        tldfinder = TLDFinderService(timeout=600)
                        tld_result = await tldfinder.run(domains=[domain], discovery_mode="domain", max_time_minutes=10)
                        if tld_result.domains:
                            tld_added = 0
                            for d in tld_result.domains:
                                d = (d or "").strip().lower()
                                if not d or d == domain or d in subdomain_assets:
                                    continue
                                sub_asset = self._create_or_update_asset(
                                    organization_id=organization_id,
                                    asset_type=AssetType.SUBDOMAIN,
                                    name=d,
                                    value=d,
                                    parent_id=root_asset.id,
                                    discovery_source="tldfinder",
                                )
                                subdomain_assets[d] = sub_asset
                                result.assets.append(self._asset_to_dict(sub_asset))
                                progress.assets_found += 1
                                tld_added += 1
                            if tld_added:
                                logger.info(f"tldfinder added {tld_added} additional domains")
                except Exception as e:
                    logger.warning(f"tldfinder step skipped or failed: {e}")
            
            # Step 3: IP Resolution (already done during subdomain discovery)
            progress.current_step = "IP resolution"
            progress.completed_steps += 1
            self._report_progress(progress, progress_callback, scan_id)
            
            # Step 4: HTTP Probing
            progress.current_step = "HTTP probing"
            self._report_progress(progress, progress_callback, scan_id)
            
            logger.info(f"Probing HTTP endpoints for {domain}")
            
            # Gather all hosts to probe
            hosts_to_probe = [domain] + [s.subdomain for s in subdomains if s.is_alive]
            
            probe_results = await self.http.probe_hosts(hosts_to_probe)
            
            # Update assets with HTTP info
            for probe in probe_results:
                host = probe.url.split("://")[1].split("/")[0].split(":")[0]
                
                # Find the asset for this host
                asset = subdomain_assets.get(host)
                if not asset:
                    # Check if it's the root domain
                    if host == domain:
                        asset = root_asset
                
                if asset:
                    asset.http_status = probe.status_code
                    asset.http_title = probe.title
                    asset.http_headers = probe.headers
                    asset.status = AssetStatus.VERIFIED
                    asset.is_live = True
                    asset.live_url = probe.url  # Store the live URL on the domain/subdomain asset
                    
                    # Store additional metadata
                    if not asset.metadata_:
                        asset.metadata_ = {}
                    asset.metadata_["http_probe"] = {
                        "status_code": probe.status_code,
                        "title": probe.title,
                        "server": probe.server,
                        "response_time_ms": probe.response_time_ms
                    }
                    
                    result.assets.append(self._asset_to_dict(asset))
                    progress.assets_found += 1
            
            self.db.commit()
            progress.completed_steps += 1
            self._report_progress(progress, progress_callback, scan_id)
            
            # Step 5: Technology Fingerprinting
            if include_technology_scan:
                progress.current_step = "Technology fingerprinting"
                self._report_progress(progress, progress_callback, scan_id)
                
                logger.info(f"Running technology fingerprinting for {domain}")
                
                # Get URLs to scan
                urls_to_scan = []
                for probe in probe_results:
                    urls_to_scan.append(probe.url)
                
                # Fan-out: analyse up to 50 URLs concurrently instead of
                # one-after-another. Wappalyzer is network-bound so this is
                # straight wall-clock speedup.
                from urllib.parse import urlparse
                wappalyzer_semaphore = asyncio.Semaphore(10)

                async def _scan_url(url: str):
                    async with wappalyzer_semaphore:
                        try:
                            return url, await self.wappalyzer.analyze_url(url), None
                        except Exception as exc:
                            return url, [], str(exc)

                scan_results = await asyncio.gather(
                    *[_scan_url(u) for u in urls_to_scan[:50]]
                )

                for url, technologies, err in scan_results:
                    if err is not None:
                        logger.warning(f"Technology scan failed for {url}: {err}")
                        progress.errors.append(f"Tech scan failed for {url}: {err}")
                        continue
                    parsed_url = urlparse(url)
                    hostname = parsed_url.netloc.split(':')[0]
                    url_asset = self.db.query(Asset).filter(
                        Asset.organization_id == organization_id,
                        Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
                        Asset.value == hostname,
                    ).first()
                    if not url_asset:
                        continue
                    for tech in technologies:
                        db_tech = self._get_or_create_technology(tech)
                        before_count = len(url_asset.technologies or [])
                        add_tech_to_asset(
                            self.db,
                            organization_id=organization_id,
                            asset=url_asset,
                            tech=db_tech,
                            also_tag_asset=True,
                            tag_parent=True,
                        )
                        after_count = len(url_asset.technologies or [])
                        if after_count > before_count:
                            progress.technologies_found += 1
                        result.technologies.append({
                            "url": url,
                            "technology": tech.name,
                            "version": tech.version,
                            "confidence": tech.confidence,
                            "categories": tech.categories,
                        })
                
                self.db.commit()
                progress.completed_steps += 1
                self._report_progress(progress, progress_callback, scan_id)
            
            # Calculate duration
            result.duration_seconds = (datetime.utcnow() - start_time).total_seconds()
            result.errors = progress.errors
            
            # Update scan with final results
            if scan_id:
                self._update_scan_complete(
                    scan_id,
                    assets_discovered=progress.assets_found,
                    technologies_found=progress.technologies_found,
                    results={
                        "domain": domain,
                        "subdomains_found": len(subdomains),
                        "urls_probed": len(probe_results),
                        "technologies_detected": progress.technologies_found
                    }
                )
            
            logger.info(
                f"Discovery complete for {domain}: "
                f"{progress.assets_found} assets, "
                f"{progress.technologies_found} technologies"
            )
            
        except Exception as e:
            logger.error(f"Discovery failed for {domain}: {e}")
            result.success = False
            result.errors.append(str(e))
            
            if scan_id:
                self._update_scan_failed(scan_id, str(e))
        
        return result

    async def full_discovery(
        self,
        domain: str,
        organization_id: int,
        enable_subdomain_enum: bool = True,
        enable_dns_enum: bool = True,
        enable_http_probe: bool = True,
        enable_tech_detection: bool = True,
        scan_id: Optional[int] = None,
        use_tldfinder: bool = False,
    ) -> dict:
        """
        Backwards-compatible entrypoint used by `workers/scanner_worker.py`.

        Note: The current implementation delegates to `discover_domain()`. The
        enable_* flags are accepted for compatibility; `discover_domain()` always
        performs DNS/subdomain/http steps, and conditionally runs tech detection.
        """
        result = await self.discover_domain(
            domain=domain,
            organization_id=organization_id,
            scan_id=scan_id,
            include_technology_scan=enable_tech_detection,
            use_tldfinder=use_tldfinder,
        )

        # Summaries for worker consumers
        subdomains_found = len([a for a in result.assets if a.get("type") == "subdomain"])
        return {
            "assets_created": len(result.assets),
            "subdomains_found": subdomains_found,
            "technologies_detected": len(result.technologies),
            "success": result.success,
            "errors": result.errors,
        }
    
    def _create_or_update_asset(
        self,
        organization_id: int,
        asset_type: AssetType,
        name: str,
        value: str,
        parent_id: Optional[int] = None,
        discovery_source: Optional[str] = None,
        status: AssetStatus = AssetStatus.DISCOVERED,
        metadata_: Optional[dict] = None
    ) -> Asset:
        """Create or update an asset in the database."""
        # Check if asset already exists
        existing = self.db.query(Asset).filter(
            Asset.organization_id == organization_id,
            Asset.asset_type == asset_type,
            Asset.value == value
        ).first()
        
        if existing:
            existing.last_seen = datetime.utcnow()
            existing.status = status
            if metadata_:
                existing.metadata_ = {**(existing.metadata_ or {}), **metadata_}
            return existing
        
        # Create new asset
        asset = Asset(
            organization_id=organization_id,
            asset_type=asset_type,
            name=name,
            value=value,
            parent_id=parent_id,
            discovery_source=discovery_source,
            status=status,
            metadata_=metadata_ or {}
        )
        self.db.add(asset)
        self.db.flush()  # Get the ID
        
        return asset
    
    def _get_or_create_technology(self, tech) -> Technology:
        """Get or create a technology record."""
        from app.services.wappalyzer_service import slugify
        
        existing = self.db.query(Technology).filter(
            Technology.slug == tech.slug
        ).first()
        
        if existing:
            return existing
        
        db_tech = Technology(
            name=tech.name,
            slug=tech.slug,
            categories=tech.categories,
            website=tech.website,
            icon=tech.icon,
            cpe=tech.cpe
        )
        self.db.add(db_tech)
        self.db.flush()
        
        return db_tech
    
    def _asset_to_dict(self, asset: Asset) -> dict:
        """Convert asset to dictionary."""
        return {
            "id": asset.id,
            "type": asset.asset_type.value,
            "name": asset.name,
            "value": asset.value,
            "status": asset.status.value,
            "discovery_source": asset.discovery_source,
            "parent_id": asset.parent_id
        }
    
    def _report_progress(
        self,
        progress: DiscoveryProgress,
        callback: Optional[Callable],
        scan_id: Optional[int]
    ):
        """Report progress via callback and update scan."""
        if callback:
            callback(progress)
        
        if scan_id:
            scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.progress = progress.percentage
                scan.current_step = progress.current_step
                scan.assets_discovered = progress.assets_found
                scan.technologies_found = progress.technologies_found
                self.db.commit()
    
    def _update_scan_status(self, scan_id: int, status: ScanStatus, step: str):
        """Update scan status."""
        scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = status
            scan.current_step = step
            if status == ScanStatus.RUNNING:
                scan.started_at = datetime.utcnow()
            self.db.commit()
    
    def _update_scan_complete(
        self,
        scan_id: int,
        assets_discovered: int,
        technologies_found: int,
        results: dict
    ):
        """Mark scan as complete."""
        scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.COMPLETED
            scan.progress = 100
            scan.completed_at = datetime.utcnow()
            scan.assets_discovered = assets_discovered
            scan.technologies_found = technologies_found
            scan.results = results
            self.db.commit()
    
    def _update_scan_failed(self, scan_id: int, error: str):
        """Mark scan as failed."""
        scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.FAILED
            scan.completed_at = datetime.utcnow()
            scan.error_message = error
            self.db.commit()
    
    def discover_domain_sync(
        self,
        domain: str,
        organization_id: int,
        scan_id: Optional[int] = None,
        include_technology_scan: bool = True
    ) -> DiscoveryResult:
        """Synchronous wrapper for discover_domain."""
        return asyncio.run(
            self.discover_domain(
                domain=domain,
                organization_id=organization_id,
                scan_id=scan_id,
                include_technology_scan=include_technology_scan
            )
        )

















