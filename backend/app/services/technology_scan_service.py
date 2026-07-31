"""
Technology scan service.

Runs Wappalyzer-style detection against hosts/URLs and persists results to:
- `asset_technologies` association
- `labels` / `asset_labels` association (via `tech:<slug>` labels)

Supports batch processing with concurrency limits for scanning large numbers
of hosts discovered during external discovery.

Enhanced with WhatRuns API integration for more comprehensive technology detection.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Iterable, Optional, List, Literal

from sqlalchemy.orm import Session

from app.db.database import SessionLocal
from app.models.asset import Asset, AssetType, AssetStatus
from app.models.technology import Technology
from app.services.asset_labeling_service import add_tech_to_asset
from app.services.chatbot_detection_service import (
    ChatbotDetectionService,
    chatbot_detection_to_metadata,
    chatbot_detections_to_technologies,
)
from app.services.wappalyzer_service import WappalyzerService, DetectedTechnology
from app.services.whatruns_service import WhatRunsService, get_whatruns_service
from app.services.whatweb_service import WhatWebService

logger = logging.getLogger(__name__)

# Concurrency settings for batch processing
BATCH_SIZE = 10  # How many hosts to scan in parallel
BATCH_DELAY = 1.0  # Seconds to wait between batches

# Technology detection sources (whatweb = WhatWeb CLI, 1800+ plugins)
TechSource = Literal["wappalyzer", "whatruns", "whatweb", "both"]


def _get_or_create_technology(db: Session, detected) -> Technology:
    """Get or create a technology record from a DetectedTechnology-like object."""
    existing = db.query(Technology).filter(Technology.slug == detected.slug).first()
    if existing:
        return existing

    db_tech = Technology(
        name=detected.name,
        slug=detected.slug,
        categories=detected.categories,
        website=getattr(detected, "website", None),
        icon=getattr(detected, "icon", None),
        cpe=getattr(detected, "cpe", None),
    )
    db.add(db_tech)
    db.flush()
    return db_tech


def _update_asset_with_url(
    db: Session,
    *,
    asset: Asset,
    url: str,
) -> Asset:
    """
    Update an existing asset with the live URL it responded on.
    Wappalyzer should ENRICH existing assets, not create new ones.
    """
    # Update the asset with the live URL (don't change discovery_source)
    if not asset.live_url:
        asset.live_url = url
    asset.is_live = True
    db.flush()
    return asset


def _wappalyzer_options_from_config(config: Optional[dict]) -> dict:
    """Extract Wappalyzer options from project settings config."""
    if not config:
        return {}
    return {
        "min_confidence": max(0, min(100, int(config.get("min_confidence_threshold", 0)))),
        "require_html": bool(config.get("require_html", False)),
        "detect_chatbots": bool(config.get("detect_chatbots", True)),
        "render_chatbots": bool(config.get("render_chatbots", False)),
    }


async def _scan_single_host(
    wappalyzer: WappalyzerService,
    db: Session,
    organization_id: int,
    host: str,
    source: TechSource = "wappalyzer",
    whatruns: Optional[WhatRunsService] = None,
    whatweb: Optional[WhatWebService] = None,
    wappalyzer_options: Optional[dict] = None,
) -> dict:
    """Scan a single host for technologies. Returns stats dict."""
    host = (host or "").strip().lower()
    if not host:
        return {"host": host, "scanned": False, "techs_found": 0}

    # Look up asset - support DOMAIN, SUBDOMAIN, and IP_ADDRESS types
    host_asset = (
        db.query(Asset)
        .filter(
            Asset.organization_id == organization_id,
            Asset.value == host,
            Asset.asset_type.in_([AssetType.SUBDOMAIN, AssetType.DOMAIN, AssetType.IP_ADDRESS]),
        )
        .first()
    )
    if not host_asset:
        return {"host": host, "scanned": False, "techs_found": 0, "reason": "no_asset"}

    techs_found = 0
    all_detected_techs: List[DetectedTechnology] = []
    chatbot_detections: list[dict] = []
    live_url = None
    
    # Build list of URLs to try
    # Priority: 1) asset.live_url, 2) https://{host}, 3) http://{host}
    urls_to_try = []
    
    # If asset has a live_url from HTTP probe, try that first (most reliable)
    if host_asset.live_url:
        urls_to_try.append(host_asset.live_url)
        # Also extract hostname from live_url for WhatRuns
        try:
            from urllib.parse import urlparse
            parsed = urlparse(host_asset.live_url)
            live_hostname = parsed.netloc.split(':')[0]  # Remove port if present
        except Exception:
            live_hostname = host
    else:
        live_hostname = host
    
    # For IP addresses, we should prefer live_url if available
    # Otherwise construct URLs - for IPs this may not work well with WhatRuns
    is_ip = host_asset.asset_type == AssetType.IP_ADDRESS
    
    # Add constructed URLs if not already covered by live_url
    for scheme in ("https", "http"):
        constructed_url = f"{scheme}://{host}"
        if constructed_url not in urls_to_try:
            urls_to_try.append(constructed_url)
    
    # Try each URL until we get results
    for url in urls_to_try:
        # Wappalyzer detection (works with any URL including IPs)
        if source in ("wappalyzer", "both"):
            try:
                opts = wappalyzer_options or {}
                wappalyzer_techs = await wappalyzer.analyze_url(
                    url,
                    min_confidence=opts.get("min_confidence", 0),
                    require_html=opts.get("require_html", False),
                )
                if wappalyzer_techs:
                    live_url = url
                    all_detected_techs.extend(wappalyzer_techs)
            except Exception as e:
                logger.debug(f"Wappalyzer scan failed for {url}: {e}")
        
        # WhatRuns detection (needs hostname, not IP - use live_hostname)
        # WhatRuns doesn't work well with raw IPs, so only try if we have a hostname
        if source in ("whatruns", "both") and whatruns and not is_ip:
            try:
                whatruns_techs = await whatruns.detect_technologies(live_hostname, url)
                if whatruns_techs:
                    live_url = url
                    # Convert WhatRuns results to DetectedTechnology format
                    for wt in whatruns_techs:
                        all_detected_techs.append(wt.to_detected_technology())
            except Exception as e:
                logger.debug(f"WhatRuns scan failed for {url}: {e}")
        
        # WhatWeb (1800+ plugins) - run when source is whatweb or both
        if source in ("whatweb", "both") and whatweb and whatweb.is_available():
            try:
                ww_result = await whatweb.scan_url(url, aggression=1)
                if ww_result.technologies:
                    live_url = url
                    all_detected_techs.extend(ww_result.technologies)
            except Exception as e:
                logger.debug(f"WhatWeb scan failed for {url}: {e}")

        # Chatbot/live-chat detection runs alongside technology detection. It
        # uses vendor-specific signals plus generic chat-bubble AND message/send
        # correlation to avoid cookie/banner false positives.
        opts = wappalyzer_options or {}
        if opts.get("detect_chatbots", True):
            try:
                chatbot = ChatbotDetectionService()
                chatbot_result = await chatbot.detect_url(
                    url,
                    render=opts.get("render_chatbots", False),
                )
                if chatbot_result.detections:
                    live_url = url
                    all_detected_techs.extend(chatbot_detections_to_technologies(chatbot_result))
                    chatbot_detections.extend(chatbot_detection_to_metadata(chatbot_result))
            except Exception as e:
                logger.debug(f"Chatbot detection failed for {url}: {e}")
        
        # If we got any detections on this URL, break
        if all_detected_techs:
            break

    if not all_detected_techs:
        return {"host": host, "scanned": True, "techs_found": 0}

    # Update the domain/subdomain asset with live_url
    if live_url:
        _update_asset_with_url(db, asset=host_asset, url=live_url)

    # Deduplicate technologies by slug
    seen_slugs = set()
    unique_techs = []
    for dt in all_detected_techs:
        if dt.slug not in seen_slugs:
            seen_slugs.add(dt.slug)
            unique_techs.append(dt)

    # Attach technologies to the primary asset (hostname or IP)
    for dt in unique_techs:
        db_tech = _get_or_create_technology(db, dt)
        add_tech_to_asset(
            db,
            organization_id=organization_id,
            asset=host_asset,
            tech=db_tech,
            also_tag_asset=True,
            tag_parent=False,
        )
        techs_found += 1

    # Propagate technologies to the underlying IP asset(s) so they show up
    # on the IP asset page as well as on the hostname asset page.
    if host_asset.asset_type in (AssetType.SUBDOMAIN, AssetType.DOMAIN):
        # Collect every IP this subdomain resolves to (live_url IP + ip_addresses list)
        ip_values: set[str] = set()
        try:
            if host_asset.ip_address:
                ip_values.add(host_asset.ip_address.strip())
            for ip in (host_asset.ip_addresses or []):
                ip_values.add(str(ip).strip())
            # Also try extracting IP from live_url (in case it was an IP URL)
            if live_url:
                from urllib.parse import urlparse as _urlparse
                _netloc = _urlparse(live_url).netloc.split(":")[0]
                import re as _re
                if _re.match(r"^\d{1,3}(\.\d{1,3}){3}$", _netloc):
                    ip_values.add(_netloc)
        except Exception:
            pass

        for ip_val in ip_values:
            ip_asset = (
                db.query(Asset)
                .filter(
                    Asset.organization_id == organization_id,
                    Asset.value == ip_val,
                    Asset.asset_type == AssetType.IP_ADDRESS,
                )
                .first()
            )
            if ip_asset:
                for dt in unique_techs:
                    db_tech = _get_or_create_technology(db, dt)
                    add_tech_to_asset(
                        db,
                        organization_id=organization_id,
                        asset=ip_asset,
                        tech=db_tech,
                        also_tag_asset=False,
                        tag_parent=False,
                    )
                logger.debug(
                    f"Propagated {len(unique_techs)} technologies from {host} → IP {ip_val}"
                )

    if chatbot_detections:
        metadata = dict(host_asset.metadata_ or {})
        existing = metadata.get("chatbot_detections") or []
        by_slug = {item.get("slug"): item for item in existing if isinstance(item, dict)}
        for item in chatbot_detections:
            by_slug[item.get("slug")] = item
        metadata["chatbot_detections"] = list(by_slug.values())
        host_asset.metadata_ = metadata
        db.flush()

    return {
        "host": host,
        "scanned": True,
        "techs_found": techs_found,
        "chatbots_found": len(chatbot_detections),
    }


async def _scan_hosts_batch(
    wappalyzer: WappalyzerService,
    db: Session,
    organization_id: int,
    hosts: List[str],
    source: TechSource = "wappalyzer",
    whatruns: Optional[WhatRunsService] = None,
    whatweb: Optional[WhatWebService] = None,
    wappalyzer_options: Optional[dict] = None,
) -> List[dict]:
    """Scan a batch of hosts concurrently."""
    tasks = [
        _scan_single_host(
            wappalyzer, db, organization_id, host, source, whatruns,
            whatweb=whatweb,
            wappalyzer_options=wappalyzer_options,
        )
        for host in hosts
    ]
    return await asyncio.gather(*tasks, return_exceptions=True)


async def _scan_hosts_async(
    db: Session,
    *,
    organization_id: int,
    hosts: list[str],
    max_hosts: int = 500,
    source: TechSource = "wappalyzer",
    wappalyzer_config: Optional[dict] = None,
) -> dict:
    """
    Scan hosts for technologies using batch processing.
    
    Args:
        db: Database session
        organization_id: Organization ID
        hosts: List of hostnames to scan
        max_hosts: Maximum hosts to scan
        source: Technology detection source ("wappalyzer", "whatruns", or "both")
        
    Returns:
        Summary dict with scan statistics
    """
    wappalyzer = WappalyzerService()
    whatruns = get_whatruns_service() if source in ("whatruns", "both") else None
    whatweb = WhatWebService() if source in ("whatweb", "both") else None
    
    hosts_to_scan = [h.strip().lower() for h in hosts[:max_hosts] if h and h.strip()]
    total_hosts = len(hosts_to_scan)
    
    logger.info(f"Starting technology scan for {total_hosts} hosts (organization_id={organization_id}, source={source})")
    
    total_scanned = 0
    total_techs_found = 0
    total_chatbots_found = 0
    total_skipped_no_asset = 0
    total_errors = 0
    
    # For WhatRuns, use smaller batch size due to rate limiting
    batch_size = 3 if source == "whatruns" else (5 if source == "both" else BATCH_SIZE)
    batch_delay = 2.0 if source in ("whatruns", "both") else BATCH_DELAY
    
    # Process in batches
    for i in range(0, total_hosts, batch_size):
        batch = hosts_to_scan[i:i + batch_size]
        batch_num = (i // batch_size) + 1
        total_batches = (total_hosts + batch_size - 1) // batch_size
        
        logger.info(f"Scanning batch {batch_num}/{total_batches} ({len(batch)} hosts)")
        
        wappalyzer_options = _wappalyzer_options_from_config(wappalyzer_config)
        results = await _scan_hosts_batch(
            wappalyzer, db, organization_id, batch, source, whatruns,
            whatweb=whatweb,
            wappalyzer_options=wappalyzer_options,
        )
        
        # Process results with detailed logging
        batch_skipped_no_asset = 0
        batch_errors = 0
        for result in results:
            if isinstance(result, Exception):
                logger.warning(f"Batch scan error: {result}")
                batch_errors += 1
                total_errors += 1
                continue
            if result.get("scanned"):
                total_scanned += 1
                total_techs_found += result.get("techs_found", 0)
                total_chatbots_found += result.get("chatbots_found", 0)
                if result.get("techs_found", 0) == 0:
                    logger.debug(f"Host {result.get('host')} scanned but no technologies detected")
            else:
                reason = result.get("reason", "unknown")
                if reason == "no_asset":
                    batch_skipped_no_asset += 1
                    total_skipped_no_asset += 1
                    logger.warning(
                        f"Host '{result.get('host')}' not found as an asset in the database "
                        f"(org={organization_id}). Run a discovery/DNS scan first to add it."
                    )
                else:
                    logger.debug(f"Host {result.get('host')} skipped: {reason}")
        
        if batch_skipped_no_asset > 0 or batch_errors > 0:
            logger.info(
                f"Batch {batch_num}: {batch_skipped_no_asset} hosts skipped (no matching asset), "
                f"{batch_errors} errors"
            )
        
        # Commit after each batch to avoid long transactions
        db.commit()
        
        # Small delay between batches to avoid overwhelming targets
        if i + batch_size < total_hosts:
            await asyncio.sleep(batch_delay)
    
    logger.info(
        f"Technology scan complete: {total_scanned}/{total_hosts} hosts scanned, "
        f"{total_techs_found} technologies detected, {total_chatbots_found} chatbot signals, "
        f"{total_skipped_no_asset} skipped (no asset record)"
    )
    
    return {
        "total_hosts": total_hosts,
        "hosts_scanned": total_scanned,
        "technologies_found": total_techs_found,
        "chatbots_found": total_chatbots_found,
        "skipped_no_asset": total_skipped_no_asset,
        "errors": total_errors,
        "source": source,
    }


def run_technology_scan_for_hosts(
    *,
    organization_id: int,
    hosts: Iterable[str],
    max_hosts: int = 500,
    source: TechSource = "wappalyzer",
    wappalyzer_config: Optional[dict] = None,
) -> dict:
    """
    Synchronous entrypoint (FastAPI BackgroundTasks-friendly).
    Creates its own DB session and runs the async scanner.
    
    Args:
        organization_id: Organization ID
        hosts: Iterable of hostnames to scan
        max_hosts: Maximum hosts to scan (default 500)
        source: Technology detection source ("wappalyzer", "whatruns", or "both")
        wappalyzer_config: Optional project settings for Wappalyzer (min_confidence_threshold, require_html, etc.)
        
    Returns:
        Summary dict with scan statistics
    """
    db = SessionLocal()
    try:
        logger.info(f"Starting background technology scan for organization {organization_id} (source={source})")
        result = asyncio.run(
            _scan_hosts_async(
                db,
                organization_id=organization_id,
                hosts=list(hosts),
                max_hosts=max_hosts,
                source=source,
                wappalyzer_config=wappalyzer_config,
            )
        )
        logger.info(f"Background technology scan complete: {result}")
        return result
    except Exception as e:
        logger.error(f"Technology scan failed: {e}")
        return {"error": str(e)}
    finally:
        db.close()


async def scan_all_org_hosts(
    organization_id: int,
    max_hosts: int = 1000,
    source: TechSource = "wappalyzer",
) -> dict:
    """
    Scan all domains and subdomains in an organization for technologies.
    
    This is useful for running a comprehensive technology scan on the entire
    asset inventory of an organization.
    
    Args:
        organization_id: Organization ID
        max_hosts: Maximum hosts to scan
        source: Technology detection source ("wappalyzer", "whatruns", or "both")
        
    Returns:
        Summary dict with scan statistics
    """
    db = SessionLocal()
    try:
        # Get all domains and subdomains for the organization
        hosts = db.query(Asset.value).filter(
            Asset.organization_id == organization_id,
            Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
        ).limit(max_hosts).all()
        
        host_list = [h[0] for h in hosts]
        
        if not host_list:
            return {"total_hosts": 0, "message": "No domains/subdomains found"}
        
        logger.info(f"Scanning {len(host_list)} hosts for organization {organization_id} (source={source})")
        
        return await _scan_hosts_async(
            db,
            organization_id=organization_id,
            hosts=host_list,
            max_hosts=max_hosts,
            source=source,
        )
    finally:
        db.close()


async def scan_single_host_whatruns(
    hostname: str,
    url: Optional[str] = None,
) -> List[DetectedTechnology]:
    """
    Scan a single host using WhatRuns API only.
    
    This is a convenience function for testing or one-off scans.
    Returns DetectedTechnology objects for compatibility.
    
    Args:
        hostname: The hostname to scan
        url: Optional full URL to scan
        
    Returns:
        List of detected technologies
    """
    whatruns = get_whatruns_service()
    whatruns_techs = await whatruns.detect_technologies(hostname, url)
    return [wt.to_detected_technology() for wt in whatruns_techs]


