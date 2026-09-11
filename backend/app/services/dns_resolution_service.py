"""
DNS Resolution Service - Resolves domains to IP addresses using dnsx.

This service:
1. Takes domains/subdomains and resolves them to IPs
2. Updates asset records with resolved IPs
3. Optionally performs geo-enrichment on resolved IPs
4. Supports batch processing for efficiency
"""

import asyncio
import json
import logging
import subprocess
import tempfile
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetType
from app.services.geolocation_service import (
    GeoLocationService,
    GeoProvider,
    get_geolocation_service_for_org,
)

logger = logging.getLogger(__name__)


@dataclass
class DNSResult:
    """Result of a DNS resolution."""
    hostname: str
    ip_addresses: List[str]
    cname: Optional[str] = None
    mx_records: List[str] = None
    ns_records: List[str] = None
    txt_records: List[str] = None
    a_records: List[str] = None
    aaaa_records: List[str] = None
    error: Optional[str] = None
    
    def __post_init__(self):
        if self.mx_records is None:
            self.mx_records = []
        if self.ns_records is None:
            self.ns_records = []
        if self.txt_records is None:
            self.txt_records = []
        if self.a_records is None:
            self.a_records = []
        if self.aaaa_records is None:
            self.aaaa_records = []


@dataclass
class HTTPProbeResult:
    """Result of an HTTP probe."""
    url: str
    status_code: int
    title: Optional[str] = None
    content_length: Optional[int] = None
    content_type: Optional[str] = None
    technologies: List[str] = None
    webserver: Optional[str] = None
    ip_address: Optional[str] = None
    is_live: bool = True
    
    def __post_init__(self):
        if self.technologies is None:
            self.technologies = []


class DNSResolutionService:
    """Service for resolving domains to IP addresses."""
    
    def __init__(self, db: Optional[Session] = None):
        self.db = db
    
    def _check_dnsx_installed(self) -> bool:
        """Check if dnsx is available."""
        try:
            result = subprocess.run(
                ['dnsx', '-version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _check_httpx_installed(self) -> bool:
        """Check if httpx (ProjectDiscovery) is available."""
        try:
            result = subprocess.run(
                ['httpx', '-version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    async def resolve_domains(
        self,
        domains: List[str],
        include_all_records: bool = False,
        timeout: int = 30,
        retries: int = 2
    ) -> Dict[str, DNSResult]:
        """
        Resolve a list of domains to their IP addresses using dnsx.
        
        Args:
            domains: List of domain names to resolve
            include_all_records: Whether to include MX, NS, TXT records
            timeout: Timeout per domain in seconds
            retries: Number of retries for failed resolutions
            
        Returns:
            Dict mapping hostname to DNSResult
        """
        if not domains:
            return {}
        
        if not self._check_dnsx_installed():
            logger.error("dnsx is not installed")
            return {}
        
        results = {}
        
        # Create temp file with domains
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            for domain in domains:
                f.write(f"{domain.strip()}\n")
            input_file = f.name
        
        try:
            # Build dnsx command
            cmd = [
                'dnsx',
                '-l', input_file,
                '-json',
                '-silent',
                '-retry', str(retries),
                '-a',  # A records (IPv4)
                '-resp',  # Include response data
            ]
            
            if include_all_records:
                cmd.extend(['-aaaa', '-cname', '-mx', '-ns', '-txt'])
            
            logger.info(f"Running dnsx on {len(domains)} domains")
            
            # Run dnsx
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout * len(domains) + 60
            )
            
            # Parse JSON lines output
            for line in stdout.decode().strip().split('\n'):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    hostname = data.get('host', '')
                    
                    # Extract IP addresses from various record types
                    ips = []
                    a_records = data.get('a', [])
                    if a_records:
                        ips.extend(a_records)
                    
                    results[hostname] = DNSResult(
                        hostname=hostname,
                        ip_addresses=ips,
                        a_records=a_records,
                        aaaa_records=data.get('aaaa', []),
                        cname=data.get('cname', [None])[0] if data.get('cname') else None,
                        mx_records=data.get('mx', []),
                        ns_records=data.get('ns', []),
                        txt_records=data.get('txt', []),
                    )
                except json.JSONDecodeError:
                    continue
            
            # Add results for domains that didn't resolve
            for domain in domains:
                domain = domain.strip()
                if domain and domain not in results:
                    results[domain] = DNSResult(
                        hostname=domain,
                        ip_addresses=[],
                        error="No DNS response"
                    )
            
            logger.info(f"Resolved {len([r for r in results.values() if r.ip_addresses])} of {len(domains)} domains")
            
        except asyncio.TimeoutError:
            logger.error(f"DNS resolution timed out after {timeout * len(domains) + 60}s")
        except Exception as e:
            logger.error(f"Error running dnsx: {e}")
        finally:
            # Clean up temp file
            Path(input_file).unlink(missing_ok=True)
        
        return results
    
    async def probe_http(
        self,
        targets: List[str],
        timeout: int = 30,
        follow_redirects: bool = True,
        include_title: bool = True
    ) -> Dict[str, HTTPProbeResult]:
        """
        Probe targets for HTTP/HTTPS services using httpx.
        
        Args:
            targets: List of domains/IPs to probe
            timeout: Timeout per target in seconds
            follow_redirects: Whether to follow redirects
            include_title: Whether to extract page title
            
        Returns:
            Dict mapping target to HTTPProbeResult
        """
        if not targets:
            return {}
        
        if not self._check_httpx_installed():
            logger.error("httpx is not installed")
            return {}
        
        results = {}
        
        # Create temp file with targets
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            for target in targets:
                f.write(f"{target.strip()}\n")
            input_file = f.name
        
        try:
            # Build httpx command
            cmd = [
                'httpx',
                '-l', input_file,
                '-json',
                '-silent',
                '-status-code',
                '-content-length',
                '-content-type',
                '-web-server',
                '-ip',
                '-timeout', str(timeout),
            ]
            
            if include_title:
                cmd.append('-title')
            
            if follow_redirects:
                cmd.extend(['-follow-redirects', '-max-redirects', '10'])
            else:
                cmd.append('-no-follow-redirects')
            
            logger.info(f"Running httpx on {len(targets)} targets")
            
            # Run httpx
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout * len(targets) + 120
            )
            
            # Parse JSON lines output
            for line in stdout.decode().strip().split('\n'):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    url = data.get('url', '')
                    
                    # Extract the host from URL for mapping
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    host = parsed.netloc or parsed.path.split('/')[0]
                    
                    results[host] = HTTPProbeResult(
                        url=url,
                        status_code=data.get('status_code', 0),
                        title=data.get('title', ''),
                        content_length=data.get('content_length'),
                        content_type=data.get('content_type', ''),
                        webserver=data.get('webserver', ''),
                        ip_address=data.get('host', ''),
                        is_live=True
                    )
                except json.JSONDecodeError:
                    continue
            
            logger.info(f"Probed {len(results)} live targets of {len(targets)}")
            
        except asyncio.TimeoutError:
            logger.error(f"HTTP probing timed out")
        except Exception as e:
            logger.error(f"Error running httpx: {e}")
        finally:
            Path(input_file).unlink(missing_ok=True)
        
        return results
    
    async def resolve_and_update_assets(
        self,
        organization_id: int,
        limit: int = 500,
        include_geo: bool = True,
        geo_provider: Optional[GeoProvider] = None
    ) -> Dict[str, Any]:
        """
        Resolve domains/subdomains in the database and update with IPs.
        
        Args:
            organization_id: Organization to process
            limit: Maximum number of assets to process
            include_geo: Whether to geo-enrich resolved IPs
            geo_provider: Specific geo provider to use
            
        Returns:
            Summary of the resolution operation
        """
        if not self.db:
            raise ValueError("Database session required")
        
        summary = {
            "total_assets": 0,
            "resolved": 0,
            "failed": 0,
            "geo_enriched": 0,
            "already_resolved": 0,
            "errors": []
        }
        
        # Get domains/subdomains without IP addresses
        assets = self.db.query(Asset).filter(
            Asset.organization_id == organization_id,
            Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
            (Asset.ip_address == None) | (Asset.ip_address == "")
        ).limit(limit).all()
        
        summary["total_assets"] = len(assets)
        
        if not assets:
            logger.info("No assets need DNS resolution")
            return summary
        
        # Extract hostnames
        hostnames = [a.value for a in assets]
        
        # Resolve all domains
        dns_results = await self.resolve_domains(hostnames)
        
        # Process results and update assets
        ips_to_geo = set()
        
        for asset in assets:
            dns_result = dns_results.get(asset.value)
            
            if not dns_result or not dns_result.ip_addresses:
                summary["failed"] += 1
                continue
            
            # Update asset with all resolved IPs
            asset.update_ip_addresses(dns_result.ip_addresses)
            
            # Store DNS records in metadata
            if not asset.metadata_:
                asset.metadata_ = {}
            asset.metadata_['dns_records'] = {
                'a': dns_result.a_records,
                'aaaa': dns_result.aaaa_records,
                'cname': dns_result.cname,
                'mx': dns_result.mx_records,
                'ns': dns_result.ns_records,
                'resolved_at': datetime.utcnow().isoformat()
            }
            
            asset.last_seen = datetime.utcnow()
            summary["resolved"] += 1
            
            # Collect IPs for geo-enrichment
            for ip in dns_result.ip_addresses:
                ips_to_geo.add(ip)
        
        self.db.commit()
        logger.info(f"Resolved {summary['resolved']} of {summary['total_assets']} assets")
        
        # Geo-enrich IPs
        if include_geo and ips_to_geo:
            geo_service = get_geolocation_service_for_org(
                self.db,
                organization_id,
                preferred_provider=geo_provider,
            )
            geo_results = await self._geo_enrich_ips(
                list(ips_to_geo),
                geo_service,
                geo_provider,
            )
            
            # Update assets with geo data
            for asset in assets:
                if asset.ip_address and asset.ip_address in geo_results:
                    geo = geo_results[asset.ip_address]
                    asset.latitude = geo.get('latitude')
                    asset.longitude = geo.get('longitude')
                    asset.city = geo.get('city')
                    asset.country = geo.get('country')
                    asset.country_code = geo.get('country_code')
                    asset.isp = geo.get('isp')
                    asset.asn = geo.get('asn')
                    summary["geo_enriched"] += 1
            
            self.db.commit()
            logger.info(f"Geo-enriched {summary['geo_enriched']} assets")
        
        return summary
    
    async def _geo_enrich_ips(
        self,
        ips: List[str],
        geo_service: GeoLocationService,
        provider: Optional[GeoProvider] = None,
        rate_limit_delay: float = 0.5
    ) -> Dict[str, Dict[str, Any]]:
        """
        Look up geolocation for a list of IP addresses.
        
        Args:
            ips: List of IP addresses
            provider: Specific provider to use
            rate_limit_delay: Delay between requests (for rate limiting)
            
        Returns:
            Dict mapping IP to geo data
        """
        results = {}
        
        for ip in ips:
            try:
                geo = await geo_service.lookup_ip(ip, provider)
                if geo:
                    results[ip] = geo
                await asyncio.sleep(rate_limit_delay)
            except Exception as e:
                logger.debug(f"Geo lookup failed for {ip}: {e}")
        
        return results
    
    async def probe_and_update_assets(
        self,
        organization_id: int,
        limit: int = 500
    ) -> Dict[str, Any]:
        """
        HTTP probe domains/subdomains/IPs and update with live status, title, etc.
        
        Args:
            organization_id: Organization to process
            limit: Maximum number of assets to process
            
        Returns:
            Summary of the probe operation
        """
        if not self.db:
            raise ValueError("Database session required")
        
        summary = {
            "total_assets": 0,
            "live": 0,
            "not_live": 0,
            "errors": []
        }
        
        # Get domains/subdomains/IPs to probe
        assets = self.db.query(Asset).filter(
            Asset.organization_id == organization_id,
            Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP_ADDRESS]),
        ).limit(limit).all()
        
        summary["total_assets"] = len(assets)
        
        if not assets:
            return summary
        
        # Extract hostnames
        hostnames = [a.value for a in assets]
        
        # Probe all
        probe_results = await self.probe_http(hostnames)
        
        # Update assets
        for asset in assets:
            result = probe_results.get(asset.value)
            
            if result and result.is_live:
                asset.is_live = True
                asset.http_status = result.status_code
                asset.http_title = result.title
                asset.live_url = result.url
                
                # Update IP if discovered
                if result.ip_address:
                    asset.add_ip_address(result.ip_address)
                
                asset.last_seen = datetime.utcnow()
                summary["live"] += 1
            else:
                # Don't mark as not live - it might just be temporarily down
                summary["not_live"] += 1
        
        self.db.commit()
        logger.info(f"Probed {summary['total_assets']} assets: {summary['live']} live, {summary['not_live']} not responding")
        
        return summary


# Singleton instance
_dns_service: Optional[DNSResolutionService] = None


def get_dns_resolution_service(db: Optional[Session] = None) -> DNSResolutionService:
    """Get DNS resolution service instance."""
    global _dns_service
    if _dns_service is None or db is not None:
        _dns_service = DNSResolutionService(db)
    return _dns_service
