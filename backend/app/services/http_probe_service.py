"""
HTTP probe service for checking asset liveness and status codes.

Probes discovered hosts to determine:
- Whether they are live/responding (is_live)
- HTTP status code (http_status)
- Page title (http_title)
- IP address resolution (ip_address)
- Geo-location data (country, city, lat/lon)

Supports batch processing with concurrency limits for probing large numbers
of hosts discovered during external discovery.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from datetime import datetime
from typing import Iterable, List, Optional

import httpx

from sqlalchemy.orm import Session

from app.db.database import SessionLocal
from app.models.asset import Asset, AssetType, AssetStatus
from app.services.geolocation_service import (
    GeoLocationService,
    get_geolocation_service_for_org,
    get_region_from_country,
)

logger = logging.getLogger(__name__)

# Concurrency settings for batch processing
BATCH_SIZE = 20  # How many hosts to probe in parallel
BATCH_DELAY = 0.5  # Seconds to wait between batches
HTTP_TIMEOUT = 10.0  # Timeout for HTTP requests


async def _probe_single_host(
    host: str,
    timeout: float = HTTP_TIMEOUT,
) -> dict:
    """
    Probe a single host for HTTP response.
    
    Returns dict with:
        - host: hostname
        - is_alive: bool
        - status_code: int or None
        - title: str or None
        - final_url: str (after redirects)
        - ip_address: str or None (resolved IP)
        - server: str or None (Server header)
    """
    host = (host or "").strip().lower()
    if not host:
        return {"host": host, "is_alive": False}
    
    result = {
        "host": host,
        "is_alive": False,
        "status_code": None,
        "title": None,
        "final_url": None,
        "ip_address": None,
        "server": None,
    }
    
    # Try to resolve IP address
    try:
        ip = socket.gethostbyname(host)
        result["ip_address"] = ip
    except socket.gaierror:
        pass  # DNS resolution failed
    
    # Try HTTPS first, then HTTP
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        
        try:
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=True,
                verify=False  # Allow self-signed certs
            ) as client:
                response = await client.get(
                    url,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                )
                
                result["is_alive"] = True
                result["status_code"] = response.status_code
                result["final_url"] = str(response.url)
                result["server"] = response.headers.get("server")
                
                # Extract title from HTML
                if "text/html" in response.headers.get("content-type", ""):
                    text = response.text[:10000]  # Limit for performance
                    import re
                    title_match = re.search(r'<title[^>]*>(.*?)</title>', text, re.IGNORECASE | re.DOTALL)
                    if title_match:
                        result["title"] = title_match.group(1).strip()[:500]  # Limit title length
                
                # If we got a response, no need to try the other scheme
                break
                
        except httpx.ConnectTimeout:
            logger.debug(f"Connection timeout for {url}")
        except httpx.ConnectError:
            logger.debug(f"Connection error for {url}")
        except Exception as e:
            logger.debug(f"Error probing {url}: {e}")
    
    return result


async def _probe_hosts_batch(
    hosts: List[str],
    timeout: float = HTTP_TIMEOUT,
) -> List[dict]:
    """Probe a batch of hosts concurrently."""
    tasks = [_probe_single_host(host, timeout) for host in hosts]
    return await asyncio.gather(*tasks, return_exceptions=True)


async def _probe_hosts_async(
    db: Session,
    *,
    organization_id: int,
    hosts: list[str],
    max_hosts: int = 500,
) -> dict:
    """
    Probe hosts for HTTP response and update assets.
    
    Args:
        db: Database session
        organization_id: Organization ID
        hosts: List of hostnames to probe
        max_hosts: Maximum hosts to probe
        
    Returns:
        Summary dict with probe statistics
    """
    hosts_to_probe = [h.strip().lower() for h in hosts[:max_hosts] if h and h.strip()]
    total_hosts = len(hosts_to_probe)
    
    logger.info(f"Starting HTTP probe for {total_hosts} hosts (organization_id={organization_id})")
    
    total_probed = 0
    total_live = 0
    total_resolved = 0
    
    # Process in batches
    for i in range(0, total_hosts, BATCH_SIZE):
        batch = hosts_to_probe[i:i + BATCH_SIZE]
        batch_num = (i // BATCH_SIZE) + 1
        total_batches = (total_hosts + BATCH_SIZE - 1) // BATCH_SIZE
        
        logger.info(f"Probing batch {batch_num}/{total_batches} ({len(batch)} hosts)")
        
        results = await _probe_hosts_batch(batch)
        
        # Process results and update assets
        for result in results:
            if isinstance(result, Exception):
                logger.warning(f"Batch probe error: {result}")
                continue
            
            host = result.get("host")
            if not host:
                continue
            
            total_probed += 1
            
            # Find the asset - include IP_ADDRESS type as well
            asset = db.query(Asset).filter(
                Asset.organization_id == organization_id,
                Asset.value == host,
                Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP_ADDRESS]),
            ).first()
            
            # Also try matching by IP address field for domain/subdomain assets
            if not asset:
                asset = db.query(Asset).filter(
                    Asset.organization_id == organization_id,
                    Asset.ip_address == host,
                ).first()
            
            if not asset:
                continue
            
            # Update asset with probe results
            if result.get("is_alive"):
                asset.is_live = True
                asset.status = AssetStatus.VERIFIED
                total_live += 1
            
            if result.get("status_code"):
                asset.http_status = result["status_code"]
            
            if result.get("title"):
                asset.http_title = result["title"]
            
            if result.get("final_url"):
                asset.live_url = result["final_url"]
            
            if result.get("ip_address"):
                asset.add_ip_address(result["ip_address"])
                total_resolved += 1
            
            if result.get("server"):
                if not asset.http_headers:
                    asset.http_headers = {}
                asset.http_headers["server"] = result["server"]
            
            asset.last_seen = datetime.utcnow()
        
        # Commit after each batch to avoid long transactions
        db.commit()
        
        # Small delay between batches to avoid overwhelming targets
        if i + BATCH_SIZE < total_hosts:
            await asyncio.sleep(BATCH_DELAY)
    
    logger.info(
        f"HTTP probe complete: {total_probed}/{total_hosts} hosts probed, "
        f"{total_live} live, {total_resolved} IPs resolved"
    )
    
    return {
        "total_hosts": total_hosts,
        "hosts_probed": total_probed,
        "hosts_live": total_live,
        "ips_resolved": total_resolved,
    }


def run_http_probe_for_hosts(
    *,
    organization_id: int,
    hosts: Iterable[str],
    max_hosts: int = 500,
) -> dict:
    """
    Synchronous entrypoint (FastAPI BackgroundTasks-friendly).
    Creates its own DB session and runs the async probe.
    
    Args:
        organization_id: Organization ID
        hosts: Iterable of hostnames to probe
        max_hosts: Maximum hosts to probe (default 500)
        
    Returns:
        Summary dict with probe statistics
    """
    db = SessionLocal()
    try:
        logger.info(f"Starting background HTTP probe for organization {organization_id}")
        result = asyncio.run(
            _probe_hosts_async(
                db,
                organization_id=organization_id,
                hosts=list(hosts),
                max_hosts=max_hosts,
            )
        )
        logger.info(f"Background HTTP probe complete: {result}")
        return result
    except Exception as e:
        logger.error(f"HTTP probe failed: {e}")
        return {"error": str(e)}
    finally:
        db.close()


async def _resolve_dns_single(host: str) -> dict:
    """
    Resolve DNS for a single host.
    
    Returns dict with:
        - host: hostname
        - ip_address: str or None
        - success: bool
    """
    host = (host or "").strip().lower()
    if not host:
        return {"host": host, "ip_address": None, "success": False}
    
    try:
        # Use getaddrinfo to resolve DNS
        loop = asyncio.get_event_loop()
        # Run in executor to avoid blocking
        result = await loop.run_in_executor(
            None,
            lambda: socket.gethostbyname(host)
        )
        return {"host": host, "ip_address": result, "success": True}
    except socket.gaierror:
        return {"host": host, "ip_address": None, "success": False}


async def _resolve_dns_batch(hosts: List[str]) -> List[dict]:
    """Resolve DNS for a batch of hosts concurrently."""
    tasks = [_resolve_dns_single(host) for host in hosts]
    return await asyncio.gather(*tasks, return_exceptions=True)


async def _resolve_dns_async(
    db: Session,
    *,
    organization_id: int,
    hosts: list[str],
    max_hosts: int = 500,
) -> dict:
    """
    Resolve DNS for hosts and update assets with IP addresses.
    
    Args:
        db: Database session
        organization_id: Organization ID
        hosts: List of hostnames to resolve
        max_hosts: Maximum hosts to resolve
        
    Returns:
        Summary dict with resolution statistics
    """
    hosts_to_resolve = [h.strip().lower() for h in hosts[:max_hosts] if h and h.strip()]
    total_hosts = len(hosts_to_resolve)
    
    logger.info(f"Starting DNS resolution for {total_hosts} hosts (organization_id={organization_id})")
    
    total_resolved = 0
    
    # Process in larger batches since DNS is faster
    dns_batch_size = 50
    
    for i in range(0, total_hosts, dns_batch_size):
        batch = hosts_to_resolve[i:i + dns_batch_size]
        batch_num = (i // dns_batch_size) + 1
        total_batches = (total_hosts + dns_batch_size - 1) // dns_batch_size
        
        logger.info(f"Resolving DNS batch {batch_num}/{total_batches} ({len(batch)} hosts)")
        
        results = await _resolve_dns_batch(batch)
        
        # Process results and update assets
        for result in results:
            if isinstance(result, Exception):
                logger.warning(f"DNS resolution error: {result}")
                continue
            
            host = result.get("host")
            ip_address = result.get("ip_address")
            
            if not host or not ip_address:
                continue
            
            # Find the asset
            asset = db.query(Asset).filter(
                Asset.organization_id == organization_id,
                Asset.value == host,
                Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
            ).first()
            
            if not asset:
                continue
            
            # Update asset with resolved IP
            asset.add_ip_address(ip_address)
            asset.last_seen = datetime.utcnow()
            total_resolved += 1
        
        # Commit after each batch
        db.commit()
        
        # Small delay between batches
        if i + dns_batch_size < total_hosts:
            await asyncio.sleep(0.1)
    
    logger.info(f"DNS resolution complete: {total_resolved}/{total_hosts} hosts resolved")
    
    return {
        "total_hosts": total_hosts,
        "hosts_resolved": total_resolved,
    }


def run_dns_resolution_for_hosts(
    *,
    organization_id: int,
    hosts: Iterable[str],
    max_hosts: int = 500,
) -> dict:
    """
    Synchronous entrypoint (FastAPI BackgroundTasks-friendly).
    Creates its own DB session and runs the async DNS resolver.
    
    Args:
        organization_id: Organization ID
        hosts: Iterable of hostnames to resolve
        max_hosts: Maximum hosts to resolve (default 500)
        
    Returns:
        Summary dict with resolution statistics
    """
    db = SessionLocal()
    try:
        logger.info(f"Starting background DNS resolution for organization {organization_id}")
        result = asyncio.run(
            _resolve_dns_async(
                db,
                organization_id=organization_id,
                hosts=list(hosts),
                max_hosts=max_hosts,
            )
        )
        logger.info(f"Background DNS resolution complete: {result}")
        return result
    except Exception as e:
        logger.error(f"DNS resolution failed: {e}")
        return {"error": str(e)}
    finally:
        db.close()


# =============================================================================
# Geolocation Enrichment
# =============================================================================

async def _enrich_geo_single(
    ip_address: str,
    geo_service: GeoLocationService,
) -> dict:
    """
    Look up geolocation for a single IP address.
    
    Returns dict with geo data or empty dict if lookup failed.
    """
    if not ip_address:
        return {}
    
    try:
        result = await geo_service.lookup_ip(ip_address)
        return result or {}
    except Exception as e:
        logger.debug(f"Geo lookup failed for {ip_address}: {e}")
        return {}


async def _enrich_geo_batch(
    ip_addresses: List[str],
    geo_service: GeoLocationService,
) -> List[dict]:
    """Enrich geolocation for a batch of IPs concurrently."""
    tasks = [_enrich_geo_single(ip, geo_service) for ip in ip_addresses]
    return await asyncio.gather(*tasks, return_exceptions=True)


async def _enrich_geo_async(
    db: Session,
    *,
    organization_id: int,
    max_assets: int = 500,
    force: bool = False,
) -> dict:
    """
    Enrich assets with geolocation data based on their IP addresses.
    
    Args:
        db: Database session
        organization_id: Organization ID
        max_assets: Maximum assets to enrich
        force: Re-enrich assets that already have geo data
        
    Returns:
        Summary dict with enrichment statistics
    """
    # Find assets with IP addresses but no geo data
    query = db.query(Asset).filter(
        Asset.organization_id == organization_id,
        Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP_ADDRESS]),
        Asset.ip_address.isnot(None),
        Asset.ip_address != '',
    )
    
    if not force:
        query = query.filter(
            (Asset.country.is_(None)) | (Asset.country == '')
        )
    
    assets = query.limit(max_assets).all()
    total_assets = len(assets)
    
    if not assets:
        logger.info(f"No assets to enrich for organization {organization_id}")
        return {"total_assets": 0, "enriched": 0, "message": "No assets need geo enrichment"}
    
    logger.info(f"Starting geo enrichment for {total_assets} assets (organization_id={organization_id})")
    geo_service = get_geolocation_service_for_org(db, organization_id)
    
    # Get unique IPs to look up
    ip_to_assets: dict[str, list[Asset]] = {}
    for asset in assets:
        ip = asset.ip_address
        if ip not in ip_to_assets:
            ip_to_assets[ip] = []
        ip_to_assets[ip].append(asset)
    
    unique_ips = list(ip_to_assets.keys())
    logger.info(f"Looking up {len(unique_ips)} unique IPs")
    
    # Batch geo lookups
    geo_batch_size = 20
    total_enriched = 0
    countries_found: dict[str, int] = {}
    
    for i in range(0, len(unique_ips), geo_batch_size):
        batch = unique_ips[i:i + geo_batch_size]
        batch_num = (i // geo_batch_size) + 1
        total_batches = (len(unique_ips) + geo_batch_size - 1) // geo_batch_size
        
        logger.info(f"Geo lookup batch {batch_num}/{total_batches} ({len(batch)} IPs)")
        
        results = await _enrich_geo_batch(batch, geo_service)
        
        for j, result in enumerate(results):
            if isinstance(result, Exception):
                logger.warning(f"Geo lookup error: {result}")
                continue
            
            if not result:
                continue
            
            ip = batch[j]
            geo_assets = ip_to_assets.get(ip, [])
            
            for asset in geo_assets:
                # Update asset with geo data
                if result.get("latitude"):
                    asset.latitude = str(result["latitude"])
                if result.get("longitude"):
                    asset.longitude = str(result["longitude"])
                if result.get("city"):
                    asset.city = result["city"]
                if result.get("country"):
                    asset.country = result["country"]
                if result.get("country_code"):
                    asset.country_code = result["country_code"]
                    # Also set region from country code
                    region = get_region_from_country(result["country_code"])
                    if region:
                        asset.region = region
                if result.get("isp"):
                    asset.isp = result["isp"]
                if result.get("asn"):
                    asset.asn = result["asn"]
                
                asset.last_seen = datetime.utcnow()
                total_enriched += 1
                
                # Track countries
                country = result.get("country") or result.get("country_code")
                if country:
                    countries_found[country] = countries_found.get(country, 0) + 1
        
        # Commit after each batch
        db.commit()
        
        # Small delay between batches to respect rate limits
        if i + geo_batch_size < len(unique_ips):
            await asyncio.sleep(0.5)
    
    logger.info(f"Geo enrichment complete: {total_enriched}/{total_assets} assets enriched")
    
    return {
        "total_assets": total_assets,
        "unique_ips": len(unique_ips),
        "enriched": total_enriched,
        "countries": countries_found,
    }


def run_geo_enrichment_for_org(
    *,
    organization_id: int,
    max_assets: int = 500,
    force: bool = False,
) -> dict:
    """
    Synchronous entrypoint (FastAPI BackgroundTasks-friendly).
    Creates its own DB session and runs the async geo enricher.
    
    Args:
        organization_id: Organization ID
        max_assets: Maximum assets to enrich (default 500)
        force: Re-enrich assets that already have geo data
        
    Returns:
        Summary dict with enrichment statistics
    """
    db = SessionLocal()
    try:
        logger.info(f"Starting background geo enrichment for organization {organization_id}")
        result = asyncio.run(
            _enrich_geo_async(
                db,
                organization_id=organization_id,
                max_assets=max_assets,
                force=force,
            )
        )
        logger.info(f"Background geo enrichment complete: {result}")
        return result
    except Exception as e:
        logger.error(f"Geo enrichment failed: {e}")
        return {"error": str(e)}
    finally:
        db.close()


async def _enrich_ip_assets_geo_async(
    db: Session,
    *,
    organization_id: int,
    max_assets: int = 500,
) -> dict:
    """
    Enrich IP address assets (from CIDR/netblocks) with geolocation.
    
    This specifically targets IP_ADDRESS type assets that may come from
    WhoisXML netblock discovery.
    
    Args:
        db: Database session
        organization_id: Organization ID
        max_assets: Maximum assets to enrich
        
    Returns:
        Summary dict with enrichment statistics
    """
    # Find IP address assets without geo data
    assets = db.query(Asset).filter(
        Asset.organization_id == organization_id,
        Asset.asset_type == AssetType.IP_ADDRESS,
        (Asset.country.is_(None)) | (Asset.country == ''),
    ).limit(max_assets).all()
    
    total_assets = len(assets)
    
    if not assets:
        logger.info(f"No IP assets to enrich for organization {organization_id}")
        return {"total_assets": 0, "enriched": 0}
    
    logger.info(f"Starting IP asset geo enrichment for {total_assets} IPs")
    geo_service = get_geolocation_service_for_org(db, organization_id)
    
    # Get IPs to look up
    ip_list = [asset.value for asset in assets]
    
    # Batch geo lookups
    geo_batch_size = 20
    total_enriched = 0
    countries_found: dict[str, int] = {}
    
    # Create a map of IP -> asset
    ip_to_asset = {asset.value: asset for asset in assets}
    
    for i in range(0, len(ip_list), geo_batch_size):
        batch = ip_list[i:i + geo_batch_size]
        batch_num = (i // geo_batch_size) + 1
        total_batches = (len(ip_list) + geo_batch_size - 1) // geo_batch_size
        
        logger.info(f"IP geo lookup batch {batch_num}/{total_batches} ({len(batch)} IPs)")
        
        results = await _enrich_geo_batch(batch, geo_service)
        
        for j, result in enumerate(results):
            if isinstance(result, Exception):
                continue
            
            if not result:
                continue
            
            ip = batch[j]
            asset = ip_to_asset.get(ip)
            
            if asset:
                # Update asset with geo data
                asset.ip_address = ip  # Set ip_address to itself for consistency
                if result.get("latitude"):
                    asset.latitude = str(result["latitude"])
                if result.get("longitude"):
                    asset.longitude = str(result["longitude"])
                if result.get("city"):
                    asset.city = result["city"]
                if result.get("country"):
                    asset.country = result["country"]
                if result.get("country_code"):
                    asset.country_code = result["country_code"]
                    region = get_region_from_country(result["country_code"])
                    if region:
                        asset.region = region
                if result.get("isp"):
                    asset.isp = result["isp"]
                if result.get("asn"):
                    asset.asn = result["asn"]
                
                asset.last_seen = datetime.utcnow()
                total_enriched += 1
                
                country = result.get("country") or result.get("country_code")
                if country:
                    countries_found[country] = countries_found.get(country, 0) + 1
        
        db.commit()
        
        if i + geo_batch_size < len(ip_list):
            await asyncio.sleep(0.5)
    
    logger.info(f"IP asset geo enrichment complete: {total_enriched}/{total_assets} IPs enriched")
    
    return {
        "total_assets": total_assets,
        "enriched": total_enriched,
        "countries": countries_found,
    }


def run_ip_assets_geo_enrichment(
    *,
    organization_id: int,
    max_assets: int = 500,
) -> dict:
    """
    Synchronous entrypoint for enriching IP assets with geo data.
    
    Args:
        organization_id: Organization ID
        max_assets: Maximum assets to enrich
        
    Returns:
        Summary dict with enrichment statistics
    """
    db = SessionLocal()
    try:
        logger.info(f"Starting IP assets geo enrichment for organization {organization_id}")
        result = asyncio.run(
            _enrich_ip_assets_geo_async(
                db,
                organization_id=organization_id,
                max_assets=max_assets,
            )
        )
        logger.info(f"IP assets geo enrichment complete: {result}")
        return result
    except Exception as e:
        logger.error(f"IP assets geo enrichment failed: {e}")
        return {"error": str(e)}
    finally:
        db.close()


# =============================================================================
# Netblock-based Geo Enrichment
# =============================================================================

def enrich_assets_from_netblocks(
    db: Session,
    organization_id: int,
    force: bool = False
) -> dict:
    """
    Enrich assets with country/geo data from their associated netblocks.
    
    WhoisXML netblock discovery already has country information.
    This function propagates that country data to all assets that:
    1. Have a netblock_id (already linked to a netblock)
    2. Have an IP address that falls within an owned netblock's CIDR
    
    Args:
        db: Database session
        organization_id: Organization ID
        force: Re-enrich assets that already have country data
        
    Returns:
        Summary dict with enrichment statistics
    """
    from app.models.netblock import Netblock
    import ipaddress
    
    summary = {
        "total_assets": 0,
        "enriched_from_netblock_link": 0,
        "enriched_from_cidr_match": 0,
        "already_had_country": 0,
        "no_netblock_match": 0,
        "countries": {}
    }
    
    # Get all netblocks with country info for this org
    netblocks = db.query(Netblock).filter(
        Netblock.organization_id == organization_id,
        Netblock.country.isnot(None)
    ).all()
    
    if not netblocks:
        logger.info(f"No netblocks with country data found for org {organization_id}")
        return {"message": "No netblocks with country data found", **summary}
    
    logger.info(f"Found {len(netblocks)} netblocks with country data")
    
    # Build CIDR network lookup structures
    cidr_lookup = []
    for nb in netblocks:
        if nb.cidr_notation:
            # CIDR notation may contain multiple CIDRs separated by comma
            for cidr in nb.cidr_notation.split(','):
                cidr = cidr.strip()
                if cidr:
                    try:
                        network = ipaddress.ip_network(cidr, strict=False)
                        cidr_lookup.append({
                            "network": network,
                            "netblock": nb
                        })
                    except ValueError:
                        logger.debug(f"Invalid CIDR: {cidr}")
    
    logger.info(f"Built CIDR lookup with {len(cidr_lookup)} networks")
    
    # Query assets that need enrichment
    query = db.query(Asset).filter(Asset.organization_id == organization_id)
    
    if not force:
        # Only get assets without country data
        query = query.filter(
            (Asset.country.is_(None)) | (Asset.country == '')
        )
    
    assets = query.all()
    summary["total_assets"] = len(assets)
    
    if not assets:
        return {"message": "No assets need geo enrichment from netblocks", **summary}
    
    logger.info(f"Processing {len(assets)} assets for netblock geo enrichment")
    
    for asset in assets:
        # Skip if already has country and not forcing
        if not force and asset.country:
            summary["already_had_country"] += 1
            continue
        
        enriched = False
        
        # Method 1: Use linked netblock if available
        if asset.netblock_id:
            for nb in netblocks:
                if nb.id == asset.netblock_id and nb.country:
                    asset.country = nb.country
                    asset.country_code = nb.country  # Often same as country in netblocks
                    asset.region = nb.region
                    asset.city = nb.city
                    summary["enriched_from_netblock_link"] += 1
                    summary["countries"][nb.country] = summary["countries"].get(nb.country, 0) + 1
                    enriched = True
                    break
        
        # Method 2: Check if asset IP falls within any CIDR
        if not enriched and asset.ip_address:
            try:
                ip_obj = ipaddress.ip_address(asset.ip_address)
                for entry in cidr_lookup:
                    if ip_obj in entry["network"]:
                        nb = entry["netblock"]
                        asset.country = nb.country
                        asset.country_code = nb.country
                        asset.region = nb.region
                        asset.city = nb.city
                        asset.netblock_id = nb.id  # Link asset to netblock
                        summary["enriched_from_cidr_match"] += 1
                        summary["countries"][nb.country] = summary["countries"].get(nb.country, 0) + 1
                        enriched = True
                        break
            except ValueError:
                logger.debug(f"Invalid IP address: {asset.ip_address}")
        
        if not enriched:
            summary["no_netblock_match"] += 1
    
    db.commit()
    
    total_enriched = summary["enriched_from_netblock_link"] + summary["enriched_from_cidr_match"]
    logger.info(f"Netblock geo enrichment: {total_enriched}/{len(assets)} assets enriched")
    
    return summary


async def run_full_geo_enrichment(
    db: Session,
    organization_id: int,
    max_assets: int = 10000,
    force: bool = False,
    progress_callback=None,
) -> dict:
    """
    Run comprehensive geo-enrichment for all assets in an organization.
    
    This is the main function for the GEO_ENRICH scan type. It:
    1. First enriches assets from netblock country data (fast, no API calls)
    2. Then does IP geo-lookup for remaining assets without country data
    
    Args:
        db: Database session
        organization_id: Organization ID
        max_assets: Maximum assets to geo-lookup via API
        force: Re-enrich assets that already have geo data
        progress_callback: Optional callback for progress updates
        
    Returns:
        Comprehensive summary dict
    """
    summary = {
        "total_assets": 0,
        "from_netblocks": 0,
        "from_ip_lookup": 0,
        "already_had_geo": 0,
        "failed_lookup": 0,
        "countries": {},
        "regions": {},
    }
    
    logger.info(f"Starting full geo enrichment for organization {organization_id}")
    
    # Step 1: Enrich from netblocks (fast, no API calls)
    if progress_callback:
        progress_callback(5, "Enriching from netblock country data...")
    
    netblock_result = enrich_assets_from_netblocks(db, organization_id, force=force)
    summary["from_netblocks"] = (
        netblock_result.get("enriched_from_netblock_link", 0) +
        netblock_result.get("enriched_from_cidr_match", 0)
    )
    
    logger.info(f"Netblock enrichment: {summary['from_netblocks']} assets")
    
    if progress_callback:
        progress_callback(20, f"Enriched {summary['from_netblocks']} assets from netblocks")
    
    # Step 2: Get remaining assets without geo data
    query = db.query(Asset).filter(
        Asset.organization_id == organization_id,
        (Asset.country.is_(None)) | (Asset.country == ''),
        Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP_ADDRESS, AssetType.URL])
    )
    
    if not force:
        query = query.filter(
            (Asset.latitude.is_(None)) | (Asset.latitude == '')
        )
    
    assets_to_lookup = query.limit(max_assets).all()
    summary["total_assets"] = len(assets_to_lookup) + summary["from_netblocks"]
    
    if not assets_to_lookup:
        if progress_callback:
            progress_callback(100, "All assets already have geo data")
        logger.info("All assets already have geo data or netblock enrichment covered everything")
        return summary
    
    logger.info(f"Looking up geo for {len(assets_to_lookup)} remaining assets via API")
    
    if progress_callback:
        progress_callback(30, f"Looking up {len(assets_to_lookup)} assets via IP geolocation API...")
    
    # Step 3: IP geo-lookup for remaining assets
    geo_service = get_geolocation_service_for_org(db, organization_id)
    
    batch_size = 20
    processed = 0
    
    for i in range(0, len(assets_to_lookup), batch_size):
        batch = assets_to_lookup[i:i + batch_size]
        batch_num = (i // batch_size) + 1
        total_batches = (len(assets_to_lookup) + batch_size - 1) // batch_size
        
        for asset in batch:
            try:
                geo_data = None
                
                # Determine IP to lookup
                ip_to_lookup = asset.ip_address or asset.value
                
                if asset.asset_type == AssetType.IP_ADDRESS:
                    geo_data = await geo_service.lookup_ip(asset.value)
                elif asset.ip_address:
                    geo_data = await geo_service.lookup_ip(asset.ip_address)
                else:
                    # Resolve hostname first
                    geo_data = await geo_service.lookup_hostname(asset.value)
                
                if geo_data:
                    asset.latitude = geo_data.get("latitude")
                    asset.longitude = geo_data.get("longitude")
                    asset.city = geo_data.get("city")
                    asset.country = geo_data.get("country")
                    asset.country_code = geo_data.get("country_code")
                    asset.isp = geo_data.get("isp")
                    asset.asn = geo_data.get("asn")
                    
                    # Set region from country
                    country_code = geo_data.get("country_code") or geo_data.get("country")
                    if country_code and len(country_code) == 2:
                        region = get_region_from_country(country_code)
                        if region:
                            asset.region = region
                            summary["regions"][region] = summary["regions"].get(region, 0) + 1
                    
                    country = geo_data.get("country") or geo_data.get("country_code")
                    if country:
                        summary["countries"][country] = summary["countries"].get(country, 0) + 1
                    
                    summary["from_ip_lookup"] += 1
                else:
                    summary["failed_lookup"] += 1
                    
            except Exception as e:
                logger.debug(f"Geo lookup failed for {asset.value}: {e}")
                summary["failed_lookup"] += 1
        
        processed += len(batch)
        db.commit()
        
        if progress_callback:
            pct = 30 + int((processed / len(assets_to_lookup)) * 65)
            progress_callback(pct, f"Processed {processed}/{len(assets_to_lookup)} assets")
        
        # Rate limiting
        if i + batch_size < len(assets_to_lookup):
            await asyncio.sleep(0.5)
    
    # Merge country counts from netblock enrichment
    for country, count in netblock_result.get("countries", {}).items():
        summary["countries"][country] = summary["countries"].get(country, 0) + count
    
    total_enriched = summary["from_netblocks"] + summary["from_ip_lookup"]
    logger.info(f"Full geo enrichment complete: {total_enriched} total assets enriched")
    
    if progress_callback:
        progress_callback(100, f"Completed: {total_enriched} assets geo-enriched")
    
    return summary


def run_full_geo_enrichment_sync(
    organization_id: int,
    max_assets: int = 10000,
    force: bool = False,
) -> dict:
    """
    Synchronous entrypoint for full geo enrichment.
    
    Creates its own DB session and runs the async enricher.
    """
    db = SessionLocal()
    try:
        logger.info(f"Starting full geo enrichment for organization {organization_id}")
        result = asyncio.run(
            run_full_geo_enrichment(
                db,
                organization_id=organization_id,
                max_assets=max_assets,
                force=force,
            )
        )
        logger.info(f"Full geo enrichment complete: {result}")
        return result
    except Exception as e:
        logger.error(f"Full geo enrichment failed: {e}")
        return {"error": str(e)}
    finally:
        db.close()
