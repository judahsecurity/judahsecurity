"""
API routes for screenshot management using EyeWitness.

Provides endpoints to:
- Capture screenshots of assets
- View screenshot history
- Manage screenshot schedules
- Detect visual changes
"""

import os
from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, Response
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_

from app.api.deps import get_db, get_current_active_user, get_current_user_optional, require_analyst, require_admin
from app.models.user import User
from app.models.asset import Asset, AssetType, AssetStatus
from app.models.scan import Scan, ScanType, ScanStatus
from app.models.screenshot import Screenshot, ScreenshotStatus, ScreenshotSchedule
from app.schemas.screenshot import (
    ScreenshotResponse,
    ScreenshotHistoryResponse,
    BulkScreenshotRequest,
    BulkScreenshotResponse,
    ScreenshotScheduleCreate,
    ScreenshotScheduleUpdate,
    ScreenshotScheduleResponse,
    ScreenshotSummaryResponse,
    ScreenshotChangesResponse,
    ScreenshotChangeReport,
    EyeWitnessStatusResponse,
)
from app.services.eyewitness_service import (
    get_eyewitness_service,
    EyeWitnessConfig,
)

router = APIRouter(prefix="/screenshots", tags=["screenshots"])


def check_org_access(user: User, org_id: int) -> bool:
    """Check if user has access to organization."""
    if user.role.value == "admin":
        return True
    return user.organization_id == org_id


# =============================================================================
# List Screenshots
# =============================================================================

@router.get("/", response_model=List[ScreenshotResponse])
def list_screenshots(
    organization_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List all screenshots with optional filtering."""
    query = db.query(Screenshot).join(Asset)
    
    # Organization filter
    if organization_id:
        if not check_org_access(current_user, organization_id):
            raise HTTPException(status_code=403, detail="Access denied")
        query = query.filter(Asset.organization_id == organization_id)
    elif not current_user.is_superuser:
        if current_user.organization_id:
            query = query.filter(Asset.organization_id == current_user.organization_id)
        else:
            return []
    
    # Asset filter
    if asset_id:
        query = query.filter(Screenshot.asset_id == asset_id)
    
    screenshots = query.order_by(Screenshot.captured_at.desc()).offset(skip).limit(limit).all()
    return screenshots


# =============================================================================
# EyeWitness Status
# =============================================================================

@router.get("/status", response_model=EyeWitnessStatusResponse)
def get_eyewitness_status(
    current_user: User = Depends(get_current_active_user)
):
    """Check screenshot capture health (Playwright preferred, EyeWitness fallback)."""
    service = get_eyewitness_service()
    ew = service.check_installation()
    playwright_available = False
    try:
        from app.services.playwright_screenshot import _check_playwright_available
        playwright_available = bool(_check_playwright_available())
    except Exception:
        playwright_available = False

    screenshots_dir = service.SCREENSHOTS_DIR
    dir_writable = None
    try:
        os.makedirs(screenshots_dir, exist_ok=True)
        dir_writable = os.access(screenshots_dir, os.W_OK)
    except Exception:
        dir_writable = False

    preferred = None
    if playwright_available:
        preferred = "playwright"
    elif ew.get("installed"):
        preferred = "eyewitness"

    return {
        **ew,
        "installed": bool(ew.get("installed") or playwright_available),
        "eyewitness_installed": bool(ew.get("installed")),
        "playwright_available": playwright_available,
        "capture_available": bool(preferred),
        "preferred_engine": preferred,
        "screenshots_dir": screenshots_dir,
        "screenshots_dir_writable": dir_writable,
        "error": None if preferred else ew.get("error") or "No screenshot engine available (install Playwright or EyeWitness)",
    }


# =============================================================================
# Capture Screenshots
# =============================================================================

@router.post("/capture/asset/{asset_id}", response_model=ScreenshotResponse)
async def capture_asset_screenshot(
    asset_id: int,
    timeout: int = Query(default=30, ge=5, le=120),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Capture a screenshot for a single asset.

    Prefers Playwright (Docker/headless-friendly), falls back to EyeWitness.
    The asset must be a web-accessible type (domain, subdomain, URL).
    """
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Check asset type
    web_types = [AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.URL]
    if asset.asset_type not in web_types:
        raise HTTPException(
            status_code=400, 
            detail=f"Asset type {asset.asset_type.value} cannot be screenshotted"
        )
    
    # Prefer live_url from HTTP probe when available (more accurate endpoint)
    if getattr(asset, "live_url", None):
        url = asset.live_url
    elif asset.asset_type in [AssetType.DOMAIN, AssetType.SUBDOMAIN]:
        url = f"https://{asset.value}"
    else:
        url = asset.value

    service = get_eyewitness_service()
    result = None
    capture_error = None

    # Prefer Playwright (same as scanner worker path)
    try:
        from app.services.playwright_screenshot import (
            capture_screenshots_playwright,
            _check_playwright_available,
        )
        if _check_playwright_available():
            pw_results = await capture_screenshots_playwright(
                [url],
                asset.organization_id,
                timeout_ms=timeout * 1000,
            )
            if pw_results and pw_results[0].success:
                result = pw_results[0]
            elif pw_results:
                capture_error = pw_results[0].error_message or "Playwright capture failed"
    except Exception as e:
        capture_error = str(e)

    # Fall back to EyeWitness when Playwright is unavailable or failed
    if result is None:
        install_status = service.check_installation()
        if not install_status.get("installed"):
            raise HTTPException(
                status_code=503,
                detail=(
                    capture_error
                    or install_status.get("error")
                    or "Screenshot capture unavailable (install Playwright or EyeWitness)"
                ),
            )
        config = EyeWitnessConfig(timeout=timeout)
        result = await service.capture_single(url, asset.organization_id, config)
    
    # Get previous screenshot for change detection
    previous_screenshot = db.query(Screenshot).filter(
        Screenshot.asset_id == asset_id,
        Screenshot.status == ScreenshotStatus.SUCCESS
    ).order_by(Screenshot.captured_at.desc()).first()
    
    # Create screenshot record
    screenshot = Screenshot(
        asset_id=asset_id,
        url=url,
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
    
    # Check for changes
    if previous_screenshot and result.image_hash:
        if previous_screenshot.image_hash != result.image_hash:
            screenshot.has_changed = True
            try:
                screenshot.change_percentage = service.calculate_change_percentage(
                    previous_screenshot.image_hash,
                    result.image_hash
                )
            except Exception:
                screenshot.change_percentage = None
            screenshot.previous_screenshot_id = previous_screenshot.id
    
    db.add(screenshot)
    db.commit()
    db.refresh(screenshot)
    
    # Update asset's cached screenshot ID for faster list queries
    if screenshot.status == ScreenshotStatus.SUCCESS and screenshot.file_path:
        asset.latest_screenshot_id = screenshot.id
        db.commit()
    
    return ScreenshotResponse(
        id=screenshot.id,
        asset_id=screenshot.asset_id,
        url=screenshot.url,
        status=screenshot.status.value,
        file_path=screenshot.file_path,
        thumbnail_path=screenshot.thumbnail_path,
        source_path=screenshot.source_path,
        http_status=screenshot.http_status,
        page_title=screenshot.page_title,
        server_header=screenshot.server_header,
        response_headers=screenshot.response_headers,
        default_creds_detected=screenshot.default_creds_detected,
        default_creds_info=screenshot.default_creds_info,
        category=screenshot.category,
        width=screenshot.width,
        height=screenshot.height,
        file_size=screenshot.file_size,
        image_hash=screenshot.image_hash,
        has_changed=screenshot.has_changed,
        change_percentage=screenshot.change_percentage,
        captured_at=screenshot.captured_at,
        error_message=screenshot.error_message,
    )


@router.post("/capture/bulk", response_model=BulkScreenshotResponse)
async def capture_bulk_screenshots(
    request: BulkScreenshotRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Capture screenshots for multiple assets.
    
    Can filter by asset IDs, types, or tags.
    """
    if not check_org_access(current_user, request.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    service = get_eyewitness_service()
    
    # Check installation
    install_status = service.check_installation()
    if not install_status["installed"]:
        raise HTTPException(
            status_code=503,
            detail=f"EyeWitness not available: {install_status.get('error', 'Not installed')}"
        )
    
    # Build asset query
    query = db.query(Asset).filter(
        Asset.organization_id == request.organization_id,
        Asset.status != AssetStatus.ARCHIVED
    )
    
    # Filter by specific IDs
    if request.asset_ids:
        query = query.filter(Asset.id.in_(request.asset_ids))
    
    # Filter by asset types
    if request.asset_types:
        type_enums = [AssetType(t) for t in request.asset_types if t in [e.value for e in AssetType]]
        query = query.filter(Asset.asset_type.in_(type_enums))
    else:
        # Default to web types
        query = query.filter(Asset.asset_type.in_([
            AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.URL
        ]))
    
    # Filter by tags
    if request.include_tags:
        # Assets must have at least one of the include tags
        tag_conditions = [Asset.tags.contains([tag]) for tag in request.include_tags]
        query = query.filter(or_(*tag_conditions))
    
    if request.exclude_tags:
        # Assets must not have any of the exclude tags
        for tag in request.exclude_tags:
            query = query.filter(~Asset.tags.contains([tag]))
    
    assets = query.all()
    
    if not assets:
        raise HTTPException(status_code=404, detail="No matching assets found")
    
    # Create scan record
    scan = Scan(
        name=f"Screenshot Scan: {len(assets)} assets",
        scan_type=ScanType.DISCOVERY,
        organization_id=request.organization_id,
        targets=[a.value for a in assets],
        config={
            "type": "screenshot",
            "timeout": request.timeout,
            "threads": request.threads,
        },
        started_by=current_user.username,
        status=ScanStatus.RUNNING,
        started_at=datetime.utcnow()
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    # Build URLs
    urls = []
    asset_url_map = {}
    for asset in assets:
        url = asset.value
        if asset.asset_type in [AssetType.DOMAIN, AssetType.SUBDOMAIN]:
            url = f"https://{asset.value}"
        urls.append(url)
        asset_url_map[url] = asset
        # Also map without protocol for matching
        asset_url_map[asset.value] = asset
    
    # Capture screenshots
    config = EyeWitnessConfig(
        timeout=request.timeout,
        threads=request.threads,
        delay=request.delay,
        jitter=request.jitter
    )
    
    results = await service.capture_screenshots(urls, request.organization_id, config)
    
    # Process results and create screenshot records
    successful = 0
    failed = 0
    screenshot_responses = []
    
    for result in results:
        # Find matching asset
        asset = asset_url_map.get(result.url) or asset_url_map.get(
            result.url.replace("https://", "").replace("http://", "")
        )
        
        if not asset:
            continue
        
        # Get previous screenshot
        previous_screenshot = db.query(Screenshot).filter(
            Screenshot.asset_id == asset.id,
            Screenshot.status == ScreenshotStatus.SUCCESS
        ).order_by(Screenshot.captured_at.desc()).first()
        
        # Create record
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
            scan_id=scan.id,
        )
        
        # Check for changes
        if previous_screenshot and result.image_hash:
            if previous_screenshot.image_hash != result.image_hash:
                screenshot.has_changed = True
                screenshot.change_percentage = service.calculate_change_percentage(
                    previous_screenshot.image_hash,
                    result.image_hash
                )
                screenshot.previous_screenshot_id = previous_screenshot.id
        
        db.add(screenshot)
        
        if result.success:
            successful += 1
            # Update asset's cached screenshot ID (will be updated after commit with actual ID)
            asset._pending_screenshot = screenshot
        else:
            failed += 1
        
        screenshot_responses.append(ScreenshotResponse(
            id=0,  # Will be set after commit
            asset_id=asset.id,
            url=result.url,
            status="success" if result.success else "failed",
            file_path=result.file_path,
            http_status=result.http_status,
            page_title=result.page_title,
            has_changed=screenshot.has_changed,
            change_percentage=screenshot.change_percentage,
            captured_at=screenshot.captured_at,
            error_message=result.error_message,
        ))
    
    # Update scan
    scan.status = ScanStatus.COMPLETED
    scan.completed_at = datetime.utcnow()
    scan.results = {
        "total": len(results),
        "successful": successful,
        "failed": failed,
    }
    
    db.commit()
    
    # Update assets' cached screenshot IDs (now that we have the actual IDs)
    for asset in assets:
        if hasattr(asset, '_pending_screenshot') and asset._pending_screenshot:
            asset.latest_screenshot_id = asset._pending_screenshot.id
            delattr(asset, '_pending_screenshot')
    db.commit()
    
    return BulkScreenshotResponse(
        scan_id=scan.id,
        total_urls=len(urls),
        successful=successful,
        failed=failed,
        results=screenshot_responses
    )


# =============================================================================
# View Screenshots
# =============================================================================

@router.get("/asset/{asset_id}", response_model=ScreenshotHistoryResponse)
def get_asset_screenshots(
    asset_id: int,
    limit: int = Query(default=10, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get screenshot history for an asset."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    screenshots = db.query(Screenshot).filter(
        Screenshot.asset_id == asset_id
    ).order_by(Screenshot.captured_at.desc()).limit(limit).all()
    
    return ScreenshotHistoryResponse(
        asset_id=asset_id,
        asset_value=asset.value,
        total_screenshots=len(screenshots),
        screenshots=[
            ScreenshotResponse(
                id=s.id,
                asset_id=s.asset_id,
                url=s.url,
                status=s.status.value,
                file_path=s.file_path,
                thumbnail_path=s.thumbnail_path,
                source_path=s.source_path,
                http_status=s.http_status,
                page_title=s.page_title,
                server_header=s.server_header,
                response_headers=s.response_headers,
                default_creds_detected=s.default_creds_detected,
                default_creds_info=s.default_creds_info,
                category=s.category,
                width=s.width,
                height=s.height,
                file_size=s.file_size,
                image_hash=s.image_hash,
                has_changed=s.has_changed,
                change_percentage=s.change_percentage,
                captured_at=s.captured_at,
                error_message=s.error_message,
            )
            for s in screenshots
        ]
    )


@router.get("/latest/{asset_id}", response_model=ScreenshotResponse)
def get_latest_screenshot(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get the latest screenshot for an asset."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    screenshot = db.query(Screenshot).filter(
        Screenshot.asset_id == asset_id,
        Screenshot.status == ScreenshotStatus.SUCCESS
    ).order_by(Screenshot.captured_at.desc()).first()
    
    if not screenshot:
        raise HTTPException(status_code=404, detail="No screenshots found for this asset")
    
    return ScreenshotResponse(
        id=screenshot.id,
        asset_id=screenshot.asset_id,
        url=screenshot.url,
        status=screenshot.status.value,
        file_path=screenshot.file_path,
        thumbnail_path=screenshot.thumbnail_path,
        source_path=screenshot.source_path,
        http_status=screenshot.http_status,
        page_title=screenshot.page_title,
        server_header=screenshot.server_header,
        response_headers=screenshot.response_headers,
        default_creds_detected=screenshot.default_creds_detected,
        default_creds_info=screenshot.default_creds_info,
        category=screenshot.category,
        width=screenshot.width,
        height=screenshot.height,
        file_size=screenshot.file_size,
        image_hash=screenshot.image_hash,
        has_changed=screenshot.has_changed,
        change_percentage=screenshot.change_percentage,
        captured_at=screenshot.captured_at,
        error_message=screenshot.error_message,
    )


@router.get("/image/{screenshot_id}")
def get_screenshot_image(
    screenshot_id: int,
    token: Optional[str] = Query(None, description="JWT token for image access"),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Get the actual screenshot image file.
    
    Supports authentication via:
    - Bearer token in Authorization header
    - token query parameter (for <img> tags)
    """
    # If no user from header, try token from query param
    if not current_user and token:
        from app.core.security import decode_token
        try:
            payload = decode_token(token)
            if payload and "sub" in payload:
                subject = payload["sub"]
                current_user = db.query(User).filter(
                    (User.username == subject) | (User.email == subject)
                ).first()
        except Exception:
            pass
    
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    screenshot = db.query(Screenshot).filter(Screenshot.id == screenshot_id).first()
    if not screenshot:
        raise HTTPException(status_code=404, detail="Screenshot not found")
    
    # Check access via asset
    asset = db.query(Asset).filter(Asset.id == screenshot.asset_id).first()
    if asset and not check_org_access(current_user, asset.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    if not screenshot.file_path:
        raise HTTPException(status_code=404, detail="Screenshot file not available")
    
    service = get_eyewitness_service()
    full_path = service.get_screenshot_path(screenshot.file_path)
    
    if not os.path.exists(full_path):
        raise HTTPException(status_code=404, detail="Screenshot file not found")
    
    return FileResponse(
        full_path,
        media_type="image/png",
        filename=f"screenshot_{screenshot_id}.png"
    )


# =============================================================================
# Summary and Reports
# =============================================================================

@router.get("/summary/{organization_id}", response_model=ScreenshotSummaryResponse)
def get_screenshot_summary(
    organization_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get summary of screenshots for an organization."""
    if not check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Get all screenshots for org's assets
    screenshots = db.query(Screenshot).join(Asset).filter(
        Asset.organization_id == organization_id
    ).all()
    
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = today_start - timedelta(days=7)
    
    # Calculate stats
    total = len(screenshots)
    successful = len([s for s in screenshots if s.status == ScreenshotStatus.SUCCESS])
    failed = len([s for s in screenshots if s.status == ScreenshotStatus.FAILED])
    today = len([s for s in screenshots if s.captured_at and s.captured_at >= today_start])
    this_week = len([s for s in screenshots if s.captured_at and s.captured_at >= week_start])
    with_changes = len([s for s in screenshots if s.has_changed])
    
    # Unique assets with screenshots
    asset_ids = set(s.asset_id for s in screenshots)
    
    # Storage calculation
    total_bytes = sum(s.file_size or 0 for s in screenshots)
    storage_mb = total_bytes / (1024 * 1024)
    
    # Categories
    categories = {}
    for s in screenshots:
        if s.category:
            categories[s.category] = categories.get(s.category, 0) + 1
    
    return ScreenshotSummaryResponse(
        organization_id=organization_id,
        total_screenshots=total,
        total_assets_with_screenshots=len(asset_ids),
        successful_screenshots=successful,
        failed_screenshots=failed,
        screenshots_today=today,
        screenshots_this_week=this_week,
        assets_with_changes=with_changes,
        storage_used_mb=round(storage_mb, 2),
        categories=categories
    )


@router.get("/changes/{organization_id}", response_model=ScreenshotChangesResponse)
def get_screenshot_changes(
    organization_id: int,
    days: int = Query(default=7, ge=1, le=90),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get screenshots that have detected visual changes."""
    if not check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    since = datetime.utcnow() - timedelta(days=days)
    
    # Get screenshots with changes
    screenshots = db.query(Screenshot).join(Asset).filter(
        Asset.organization_id == organization_id,
        Screenshot.has_changed == True,
        Screenshot.captured_at >= since
    ).order_by(Screenshot.captured_at.desc()).all()
    
    changes = []
    for s in screenshots:
        if s.previous_screenshot_id:
            prev = db.query(Screenshot).filter(Screenshot.id == s.previous_screenshot_id).first()
            if prev:
                asset = db.query(Asset).filter(Asset.id == s.asset_id).first()
                changes.append(ScreenshotChangeReport(
                    asset_id=s.asset_id,
                    asset_value=asset.value if asset else "Unknown",
                    previous_screenshot_id=prev.id,
                    current_screenshot_id=s.id,
                    change_percentage=s.change_percentage or 100,
                    previous_captured_at=prev.captured_at,
                    current_captured_at=s.captured_at,
                    previous_file_path=prev.file_path or "",
                    current_file_path=s.file_path or "",
                ))
    
    return ScreenshotChangesResponse(
        organization_id=organization_id,
        since=since,
        total_changes=len(changes),
        changes=changes
    )


# =============================================================================
# Schedules
# =============================================================================

@router.post("/schedules", response_model=ScreenshotScheduleResponse)
def create_schedule(
    schedule: ScreenshotScheduleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Create a new screenshot schedule."""
    if not check_org_access(current_user, schedule.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    db_schedule = ScreenshotSchedule(
        organization_id=schedule.organization_id,
        name=schedule.name,
        description=schedule.description,
        frequency=schedule.frequency,
        cron_expression=schedule.cron_expression,
        asset_types=schedule.asset_types,
        include_tags=schedule.include_tags,
        exclude_tags=schedule.exclude_tags,
        timeout=schedule.timeout,
        threads=schedule.threads,
        delay=schedule.delay,
        jitter=schedule.jitter,
    )
    
    # Calculate next run
    if schedule.frequency == "daily":
        db_schedule.next_run = datetime.utcnow().replace(
            hour=2, minute=0, second=0, microsecond=0
        ) + timedelta(days=1)
    
    db.add(db_schedule)
    db.commit()
    db.refresh(db_schedule)
    
    return ScreenshotScheduleResponse.model_validate(db_schedule)


@router.get("/schedules/{organization_id}", response_model=List[ScreenshotScheduleResponse])
def list_schedules(
    organization_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List all screenshot schedules for an organization."""
    if not check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    schedules = db.query(ScreenshotSchedule).filter(
        ScreenshotSchedule.organization_id == organization_id
    ).all()
    
    return [ScreenshotScheduleResponse.model_validate(s) for s in schedules]


@router.put("/schedules/{schedule_id}", response_model=ScreenshotScheduleResponse)
def update_schedule(
    schedule_id: int,
    updates: ScreenshotScheduleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Update a screenshot schedule."""
    schedule = db.query(ScreenshotSchedule).filter(
        ScreenshotSchedule.id == schedule_id
    ).first()
    
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    
    if not check_org_access(current_user, schedule.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Update fields
    for field, value in updates.model_dump(exclude_unset=True).items():
        setattr(schedule, field, value)
    
    schedule.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(schedule)
    
    return ScreenshotScheduleResponse.model_validate(schedule)


@router.delete("/schedules/{schedule_id}")
def delete_schedule(
    schedule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Delete a screenshot schedule."""
    schedule = db.query(ScreenshotSchedule).filter(
        ScreenshotSchedule.id == schedule_id
    ).first()
    
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    
    if not check_org_access(current_user, schedule.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    db.delete(schedule)
    db.commit()
    
    return {"message": "Schedule deleted successfully"}


@router.post("/schedules/{schedule_id}/run", response_model=BulkScreenshotResponse)
async def run_schedule_now(
    schedule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Manually trigger a screenshot schedule to run now."""
    schedule = db.query(ScreenshotSchedule).filter(
        ScreenshotSchedule.id == schedule_id
    ).first()
    
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    
    if not check_org_access(current_user, schedule.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Build request from schedule config
    request = BulkScreenshotRequest(
        organization_id=schedule.organization_id,
        asset_types=schedule.asset_types,
        include_tags=schedule.include_tags,
        exclude_tags=schedule.exclude_tags,
        timeout=schedule.timeout,
        threads=schedule.threads,
        delay=schedule.delay,
        jitter=schedule.jitter,
    )
    
    # Run the bulk capture
    result = await capture_bulk_screenshots(request, db, current_user)
    
    # Update schedule stats
    schedule.last_run = datetime.utcnow()
    schedule.total_runs += 1
    schedule.successful_captures += result.successful
    schedule.failed_captures += result.failed
    
    db.commit()
    
    return result















