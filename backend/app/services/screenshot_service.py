"""
Screenshot Service for automated screenshot capture.

Uses Playwright (Chromium) when available for reliable Docker/headless capture;
falls back to EyeWitness when Playwright is not installed.
"""

import asyncio
import logging
import os
from datetime import datetime
from typing import Iterable, List, Optional
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.db.database import SessionLocal
from app.models.asset import Asset, AssetType
from app.models.screenshot import Screenshot, ScreenshotStatus
from app.services.eyewitness_service import (
    get_eyewitness_service,
    EyeWitnessConfig,
    ScreenshotResult,
)

logger = logging.getLogger(__name__)

# Batch settings
BATCH_SIZE = 20  # How many hosts to screenshot in parallel
BATCH_DELAY = 2.0  # Seconds between batches
SCREENSHOTS_DIR = os.environ.get("SCREENSHOTS_DIR", "/app/data/screenshots")


def _extract_hostname_from_url(url_or_host: str) -> str:
    """
    Extract the hostname from a URL or return the input if it's already a hostname.
    
    Examples:
        'https://example.com/path' -> 'example.com'
        'https://192.168.1.1:8443/login' -> '192.168.1.1'
        'example.com' -> 'example.com'
        '192.168.1.1' -> '192.168.1.1'
    """
    url_or_host = url_or_host.strip()
    
    # If it starts with http:// or https://, parse it
    if url_or_host.startswith('http://') or url_or_host.startswith('https://'):
        parsed = urlparse(url_or_host)
        hostname = parsed.hostname or parsed.netloc
        # Remove port if present
        if ':' in hostname and not hostname.startswith('['):  # Not IPv6
            hostname = hostname.split(':')[0]
        return hostname.lower() if hostname else url_or_host.lower()
    
    # Otherwise it's already a hostname/IP
    return url_or_host.lower()


def _normalize_url(url_or_host: str) -> str:
    """
    Normalize to a full URL, handling cases where input is already a URL.
    
    Examples:
        'example.com' -> 'https://example.com'
        'https://example.com' -> 'https://example.com' (unchanged)
        'http://example.com/path' -> 'http://example.com/path' (unchanged)
    """
    url_or_host = url_or_host.strip()
    
    if url_or_host.startswith('http://') or url_or_host.startswith('https://'):
        return url_or_host
    
    return f"https://{url_or_host}"


def _process_capture_results(
    db: Session,
    results: List[ScreenshotResult],
    organization_id: int,
    url_to_original: dict,
) -> tuple:
    """Process capture results into DB; returns (total_captured, total_failed, assets_updated)."""
    total_captured = 0
    total_failed = 0
    assets_updated = 0
    for result in results:
        result_hostname = _extract_hostname_from_url(result.url)
        original_input = url_to_original.get(result.url)
        asset = db.query(Asset).filter(
            Asset.organization_id == organization_id,
            Asset.value == result_hostname,
            Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP_ADDRESS]),
        ).first()
        if not asset and original_input:
            asset = db.query(Asset).filter(
                Asset.organization_id == organization_id,
                Asset.live_url == original_input,
            ).first()
        if not asset:
            asset = db.query(Asset).filter(
                Asset.organization_id == organization_id,
                Asset.ip_address == result_hostname,
            ).first()
        if not asset:
            asset = db.query(Asset).filter(
                Asset.organization_id == organization_id,
                Asset.ip_addresses.contains([result_hostname]),
            ).first()
        if not asset:
            logger.debug(f"No matching asset found for {result.url} (hostname: {result_hostname})")
            total_failed += 1
            continue
        previous = db.query(Screenshot).filter(
            Screenshot.asset_id == asset.id,
            Screenshot.status == ScreenshotStatus.SUCCESS
        ).order_by(Screenshot.captured_at.desc()).first()
        screenshot = Screenshot(
            asset_id=asset.id,
            url=result.url,
            status=ScreenshotStatus.SUCCESS if result.success else ScreenshotStatus.FAILED,
            file_path=result.file_path,
            thumbnail_path=result.thumbnail_path,
            source_path=result.source_path,
            http_status=result.http_status,
            page_title=result.page_title,
            server_header=result.server_header,
            response_headers=result.response_headers,
            category=result.category,
            default_creds_detected=bool(result.default_creds),
            default_creds_info=result.default_creds,
            width=result.width,
            height=result.height,
            file_size=result.file_size,
            image_hash=result.image_hash,
            error_message=result.error_message,
            captured_at=datetime.utcnow(),
        )
        if previous and result.image_hash and previous.image_hash != result.image_hash:
            screenshot.has_changed = True
            screenshot.previous_screenshot_id = previous.id
        db.add(screenshot)
        db.flush()
        if result.success:
            total_captured += 1
            if screenshot.file_path:
                asset.latest_screenshot_id = screenshot.id
                assets_updated += 1
            try:
                from app.services.sitemap_service import link_screenshot
                link_screenshot(
                    db,
                    asset,
                    result.url,
                    screenshot_id=screenshot.id if result.success else None,
                    http_status=result.http_status,
                    response_title=result.page_title,
                )
            except Exception:
                pass
        else:
            total_failed += 1
    return (total_captured, total_failed, assets_updated)


async def _capture_screenshots_async(
    db: Session,
    *,
    organization_id: int,
    hosts: List[str],
    max_hosts: int = 200,
    timeout: int = 30,
) -> dict:
    """
    Capture screenshots for hosts. Uses Playwright when available (Docker-friendly),
    otherwise EyeWitness.
    """
    hosts_to_scan = [h.strip() for h in hosts[:max_hosts] if h and h.strip()]
    total_hosts = len(hosts_to_scan)
    if not hosts_to_scan:
        return {"hosts_requested": 0, "screenshots_captured": 0, "screenshots_failed": 0, "assets_updated": 0}

    urls = []
    url_to_original = {}
    for host in hosts_to_scan:
        url = _normalize_url(host)
        urls.append(url)
        url_to_original[url] = host

    total_captured = 0
    total_failed = 0
    assets_updated = 0
    capture_error = None

    # Prefer Playwright (works in Docker without display/xvfb)
    try:
        from app.services.playwright_screenshot import (
            capture_screenshots_playwright,
            _check_playwright_available,
        )
        if _check_playwright_available():
            logger.info(f"Using Playwright for screenshot capture ({total_hosts} hosts)")
            results = await capture_screenshots_playwright(
                urls,
                organization_id,
                timeout_ms=timeout * 1000,
                screenshots_dir=SCREENSHOTS_DIR,
            )
            try:
                total_captured, total_failed, assets_updated = _process_capture_results(
                    db, results, organization_id, url_to_original
                )
                db.commit()
            except Exception as e:
                logger.error(f"Screenshot DB error: {e}", exc_info=True)
                db.rollback()
                capture_error = str(e)
            if not capture_error:
                logger.info(f"Screenshot capture complete: {total_captured} captured, {total_failed} failed")
                return {
                    "hosts_requested": total_hosts,
                    "screenshots_captured": total_captured,
                    "screenshots_failed": total_failed,
                    "assets_updated": assets_updated,
                }
    except ImportError:
        pass
    except Exception as e:
        logger.warning(f"Playwright screenshot failed: {e}")

    # Fallback to EyeWitness
    service = get_eyewitness_service()
    install_status = service.check_installation()
    if not install_status.get("installed"):
        err = capture_error or install_status.get("error") or "Screenshot capture unavailable (install Playwright or EyeWitness)"
        logger.warning(err)
        return {
            "error": err,
            "hosts_requested": total_hosts,
            "screenshots_captured": 0,
            "screenshots_failed": total_hosts,
        }
    config = EyeWitnessConfig(timeout=timeout, threads=BATCH_SIZE)
    for i in range(0, len(urls), BATCH_SIZE):
        batch_urls = urls[i:i + BATCH_SIZE]
        logger.info(f"Capturing screenshots batch {i // BATCH_SIZE + 1} ({len(batch_urls)} URLs)")
        try:
            results = await service.capture_screenshots(batch_urls, organization_id, config)
            tc, tf, au = _process_capture_results(db, results, organization_id, url_to_original)
            total_captured += tc
            total_failed += tf
            assets_updated += au
            db.commit()
        except Exception as e:
            logger.error(f"Batch screenshot error: {e}", exc_info=True)
            db.rollback()
            total_failed += len(batch_urls)
        if i + BATCH_SIZE < len(urls):
            await asyncio.sleep(BATCH_DELAY)

    logger.info(f"Screenshot capture complete: {total_captured} captured, {total_failed} failed")
    return {
        "hosts_requested": total_hosts,
        "screenshots_captured": total_captured,
        "screenshots_failed": total_failed,
        "assets_updated": assets_updated,
    }


def run_screenshots_for_hosts(
    *,
    organization_id: int,
    hosts: Iterable[str],
    max_hosts: int = 200,
    timeout: int = 30,
) -> dict:
    """
    Synchronous entrypoint (FastAPI BackgroundTasks-friendly).
    Creates its own DB session and runs the async screenshot capture.
    
    Args:
        organization_id: Organization ID
        hosts: Iterable of hostnames to screenshot
        max_hosts: Maximum hosts to screenshot
        timeout: Timeout per screenshot
        
    Returns:
        Summary dict with capture statistics
    """
    db = SessionLocal()
    try:
        logger.info(f"Starting background screenshot capture for organization {organization_id}")
        result = asyncio.run(
            _capture_screenshots_async(
                db,
                organization_id=organization_id,
                hosts=list(hosts),
                max_hosts=max_hosts,
                timeout=timeout,
            )
        )
        logger.info(f"Background screenshot capture complete: {result}")
        return result
    except Exception as e:
        logger.error(f"Screenshot capture failed: {e}")
        return {"error": str(e)}
    finally:
        db.close()


async def capture_all_org_screenshots(
    organization_id: int,
    max_hosts: int = 500,
    timeout: int = 30,
    live_only: bool = True,
) -> dict:
    """
    Capture screenshots for all web assets in an organization.
    
    Includes domains, subdomains, and IP addresses. Prefers using the live_url
    (from HTTP probe) when available for accurate screenshots of the actual
    responding endpoint.
    
    Args:
        organization_id: Organization ID
        max_hosts: Maximum hosts to screenshot
        timeout: Timeout per screenshot
        live_only: Only include assets marked as live (recommended)
        
    Returns:
        Summary dict with capture statistics
    """
    db = SessionLocal()
    try:
        # Get all web assets for the organization
        # Include DOMAIN, SUBDOMAIN, and IP_ADDRESS types
        query = db.query(Asset).filter(
            Asset.organization_id == organization_id,
            Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP_ADDRESS]),
        )
        
        # Optionally filter to live assets only
        if live_only:
            query = query.filter(Asset.is_live == True)
        
        assets = query.limit(max_hosts).all()
        
        if not assets:
            return {
                "total_hosts": 0, 
                "message": "No assets found" + (" (try with live_only=False)" if live_only else "")
            }
        
        # Build URL list - prefer live_url (from HTTP probe) when available
        # This ensures we screenshot the actual responding endpoint
        # e.g., https://131.200.250.120/global-protect/login.esp instead of just https://131.200.250.120
        url_list = []
        for asset in assets:
            if asset.live_url:
                # Use the actual live URL from HTTP probe
                url_list.append(asset.live_url)
            elif asset.asset_type == AssetType.IP_ADDRESS:
                # For IP assets without live_url, try both HTTP and HTTPS
                url_list.append(f"https://{asset.value}")
            else:
                # For domains/subdomains without live_url
                url_list.append(f"https://{asset.value}")
        
        logger.info(f"Capturing screenshots for {len(url_list)} assets in organization {organization_id}")
        
        return await _capture_screenshots_async(
            db,
            organization_id=organization_id,
            hosts=url_list,
            max_hosts=max_hosts,
            timeout=timeout,
        )
    finally:
        db.close()

