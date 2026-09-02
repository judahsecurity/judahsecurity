"""Asset routes for attack surface management."""

import logging
from typing import Dict, List, Optional, Literal, Any
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from fastapi.responses import Response, JSONResponse
from sqlalchemy.orm import Session, joinedload, selectinload, noload
from sqlalchemy import func, case, inspect as sa_inspect

from app.db.database import get_db
from app.models.asset import Asset, AssetType, AssetStatus
from app.models.port_service import PortService, PortState
from app.models.scan import Scan, ScanType, ScanStatus
from app.models.vulnerability import Vulnerability, VulnerabilityStatus, Severity
from app.models.organization import Organization
from app.models.user import User
from app.schemas.asset import (
    AssetCreate, AssetUpdate, AssetResponse, 
    AssetPortsSummary, PortServiceSummary, PaginatedAssetsResponse
)
from app.api.deps import get_current_active_user, require_analyst
from app.api.routes.scans import send_scan_to_sqs

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/assets", tags=["Assets"])

ASSET_SUMMARY_GROUP_BY = {
    "type",
    "status",
    "country",
    "organization",
    "root_domain",
}


def check_org_access(user: User, org_id: int) -> bool:
    """Check if user has access to organization."""
    if user.is_superuser:
        return True
    return user.organization_id == org_id


def _empty_vuln_counts() -> Dict[str, int]:
    return {
        "vulnerability_count": 0,
        "critical_vuln_count": 0,
        "high_vuln_count": 0,
        "medium_vuln_count": 0,
        "low_vuln_count": 0,
    }


def _batch_vuln_counts(db: Session, asset_ids: List[int]) -> Dict[int, Dict[str, int]]:
    """Aggregate open (non-resolved) vulnerability counts per asset in one query."""
    if not asset_ids:
        return {}

    rows = (
        db.query(
            Vulnerability.asset_id,
            Vulnerability.severity,
            func.count(Vulnerability.id),
        )
        .filter(
            Vulnerability.asset_id.in_(asset_ids),
            Vulnerability.status != VulnerabilityStatus.RESOLVED,
        )
        .group_by(Vulnerability.asset_id, Vulnerability.severity)
        .all()
    )

    counts: Dict[int, Dict[str, int]] = {}
    for asset_id, severity, count in rows:
        bucket = counts.setdefault(asset_id, _empty_vuln_counts())
        bucket["vulnerability_count"] += count
        sev = severity.value.lower() if hasattr(severity, "value") else str(severity).lower()
        if sev == "critical":
            bucket["critical_vuln_count"] += count
        elif sev == "high":
            bucket["high_vuln_count"] += count
        elif sev == "medium":
            bucket["medium_vuln_count"] += count
        elif sev == "low":
            bucket["low_vuln_count"] += count
    return counts


def _org_filter_for_user(current_user: User, organization_id: Optional[int]):
    """Return an Asset org filter clause, or None for unscoped superuser."""
    if current_user.is_superuser:
        if organization_id:
            return Asset.organization_id == organization_id
        return None
    if not current_user.organization_id:
        return False  # sentinel: no access
    return Asset.organization_id == current_user.organization_id


def _close_findings_for_asset(db: Session, asset_id: int) -> int:
    """
    Auto-resolve all open findings on an asset that is being marked out of scope.

    Sets status → ACCEPTED with a standard note so the finding is preserved for
    audit/compliance but no longer surfaces in the active findings queue.

    Returns the number of findings closed.
    """
    open_statuses = [
        VulnerabilityStatus.OPEN,
        VulnerabilityStatus.IN_PROGRESS,
    ]
    findings = db.query(Vulnerability).filter(
        Vulnerability.asset_id == asset_id,
        Vulnerability.status.in_(open_statuses),
    ).all()

    now = datetime.utcnow()
    for f in findings:
        f.status = VulnerabilityStatus.ACCEPTED
        f.resolved_at = now
        f.updated_at = now
        if not f.metadata_:
            f.metadata_ = {}
        f.metadata_["out_of_scope_closed_at"] = now.isoformat()
        f.metadata_["out_of_scope_closed_reason"] = (
            "Asset marked out of scope — finding auto-accepted"
        )

    return len(findings)


def build_asset_response(
    asset: Asset,
    vuln_counts: Optional[Dict[str, int]] = None,
) -> dict:
    """Build asset response with port service information.
    
    Explicitly builds the response dict to avoid SQLAlchemy internal state
    and handle missing database columns gracefully.

    Pass precomputed ``vuln_counts`` from ``_batch_vuln_counts`` for list
    endpoints so we never lazy-load ``asset.vulnerabilities`` (N+1).
    """
    # Build port service summaries
    port_summaries = []
    try:
        for ps in asset.port_services:
            port_summaries.append(PortServiceSummary(
                id=ps.id,
                port=ps.port,
                protocol=ps.protocol.value,
                service=ps.service_name,
                product=ps.service_product,
                version=ps.service_version,
                state=ps.state.value,
                is_ssl=ps.is_ssl,
                is_risky=ps.is_risky,
                port_string=ps.port_string
            ))
    except Exception:
        port_summaries = []
    
    # Build technology summaries
    tech_summaries = []
    try:
        for tech in asset.technologies:
            tech_summaries.append({
                "name": tech.name,
                "slug": tech.slug,
                "categories": tech.categories or [],
                "version": None
            })
    except Exception:
        tech_summaries = []
    
    # Helper to safely get attribute with default
    def safe_get(attr: str, default=None):
        try:
            val = getattr(asset, attr, default)
            return val if val is not None else default
        except Exception:
            return default
    
    # Vulnerability counts — prefer batch counts; never lazy-load the relationship
    if vuln_counts is not None:
        vuln_count = vuln_counts.get("vulnerability_count", 0)
        critical_vulns = vuln_counts.get("critical_vuln_count", 0)
        high_vulns = vuln_counts.get("high_vuln_count", 0)
        medium_vulns = vuln_counts.get("medium_vuln_count", 0)
        low_vulns = vuln_counts.get("low_vuln_count", 0)
    else:
        vuln_count = 0
        critical_vulns = 0
        high_vulns = 0
        medium_vulns = 0
        low_vulns = 0
        try:
            insp = sa_inspect(asset)
            # Only walk the relationship when it is already loaded in this session
            if "vulnerabilities" not in insp.unloaded:
                for vuln in asset.vulnerabilities:
                    if getattr(vuln.status, "value", str(vuln.status)) != "resolved":
                        vuln_count += 1
                        if vuln.severity == Severity.CRITICAL:
                            critical_vulns += 1
                        elif vuln.severity == Severity.HIGH:
                            high_vulns += 1
                        elif vuln.severity == Severity.MEDIUM:
                            medium_vulns += 1
                        elif vuln.severity == Severity.LOW:
                            low_vulns += 1
        except Exception:
            pass
    
    # Get organization name from relationship
    org_name = None
    try:
        if asset.organization:
            org_name = asset.organization.name
    except Exception:
        pass
    
    # Get the latest successful screenshot ID (using cached field for performance)
    screenshot_id = None
    try:
        # First try the cached field (fast - no relationship loading)
        screenshot_id = getattr(asset, 'latest_screenshot_id', None)
        
        # Fallback to relationship if cache not set (for backward compatibility)
        if screenshot_id is None and hasattr(asset, 'screenshots') and asset.screenshots:
            # screenshots are ordered by captured_at desc, so first is most recent
            for screenshot in asset.screenshots:
                if screenshot.status.value == 'success' and screenshot.file_path:
                    screenshot_id = screenshot.id
                    break
    except Exception:
        pass
    
    # Build response explicitly to avoid _sa_instance_state and missing columns
    return {
        "id": asset.id,
        "name": asset.name,
        "asset_type": asset.asset_type,
        "value": asset.value,
        "organization_id": asset.organization_id,
        "organization_name": org_name,
        "parent_id": safe_get("parent_id"),
        "status": asset.status,
        "description": safe_get("description"),
        "tags": safe_get("tags", []),
        "metadata_": safe_get("metadata_", {}),
        "discovery_source": safe_get("discovery_source"),
        "discovery_chain": safe_get("discovery_chain", []),
        "association_reason": safe_get("association_reason"),
        "association_confidence": safe_get("association_confidence", 100),
        "first_seen": safe_get("first_seen"),
        "last_seen": safe_get("last_seen"),
        "risk_score": safe_get("risk_score", 0),
        "criticality": safe_get("criticality", "medium"),
        "is_monitored": safe_get("is_monitored", True),
        # ACS/ARS scoring
        "acs_score": safe_get("acs_score", 5),
        "acs_drivers": safe_get("acs_drivers", {}),
        "ars_score": safe_get("ars_score", 0),
        # Asset classification
        "system_type": safe_get("system_type"),
        "operating_system": safe_get("operating_system"),
        "device_class": safe_get("device_class"),
        "device_subclass": safe_get("device_subclass"),
        "is_public": safe_get("is_public", True),
        "is_licensed": safe_get("is_licensed", True),
        # HTTP info
        "http_status": safe_get("http_status"),
        "http_title": safe_get("http_title"),
        "live_url": safe_get("live_url"),
        "root_domain": safe_get("root_domain"),
        # DNS info
        "dns_records": safe_get("dns_records", {}),
        # IP/Geo info
        "ip_address": safe_get("ip_address"),
        "ip_addresses": safe_get("ip_addresses", []),
        "ip_history": safe_get("ip_history", []),
        "latitude": safe_get("latitude"),
        "longitude": safe_get("longitude"),
        "city": safe_get("city"),
        "country": safe_get("country"),
        "country_code": safe_get("country_code"),
        "region": safe_get("region"),
        "isp": safe_get("isp"),
        "asn": safe_get("asn"),
        # Scope and ownership
        "in_scope": safe_get("in_scope", True),
        "is_owned": safe_get("is_owned", False),
        "is_live": safe_get("is_live", False),
        "has_login_portal": safe_get("has_login_portal", False),
        "login_portals": safe_get("login_portals", []),
        "netblock_id": safe_get("netblock_id"),
        # Scan tracking
        "last_scan_id": safe_get("last_scan_id"),
        "last_scan_name": safe_get("last_scan_name"),
        "last_scan_date": safe_get("last_scan_date"),
        "last_scan_target": safe_get("last_scan_target"),
        "last_authenticated_scan_status": safe_get("last_authenticated_scan_status"),
        # Discovered endpoints
        "endpoints": safe_get("endpoints", []),
        "parameters": safe_get("parameters", []),
        "js_files": safe_get("js_files", []),
        "rest_endpoints": safe_get("rest_endpoints", []),
        "api_specs": safe_get("api_specs", []),
        "created_at": safe_get("created_at"),
        "updated_at": safe_get("updated_at"),
        # Computed fields
        "port_services": port_summaries,
        "technologies": tech_summaries,
        "open_ports_count": len([p for p in port_summaries if hasattr(p, 'state') and p.state == 'open']),
        "risky_ports_count": len([p for p in port_summaries if hasattr(p, 'is_risky') and p.is_risky]),
        # Vulnerability counts
        "vulnerability_count": vuln_count,
        "critical_vuln_count": critical_vulns,
        "high_vuln_count": high_vulns,
        "medium_vuln_count": medium_vulns,
        "low_vuln_count": low_vulns,
        # Latest screenshot
        "screenshot_id": screenshot_id,
    }


@router.get("/", response_model=PaginatedAssetsResponse)
def list_assets(
    organization_id: Optional[int] = None,
    asset_type: Optional[str] = Query(None, description="Asset type (domain, subdomain, ip_address, etc.) - case insensitive"),
    status: Optional[AssetStatus] = None,
    search: Optional[str] = None,
    is_live: Optional[bool] = Query(None, description="Filter by live status (true=live, false=not live)"),
    in_scope: Optional[bool] = Query(None, description="Filter by scope (true=in scope, false=out of scope)"),
    has_open_ports: Optional[bool] = None,
    has_risky_ports: Optional[bool] = None,
    has_geo: Optional[bool] = Query(None, description="Filter for assets with geo data (latitude/longitude)"),
    device_class: Optional[str] = Query(None, description="Filter by device class (e.g. 'Industrial/SCADA') - case insensitive substring"),
    include_cidr: bool = Query(False, description="Include IP_RANGE/CIDR assets (excluded by default)"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100000),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List assets with filtering options. By default excludes IP_RANGE/CIDR blocks (use netblocks endpoint for those)."""
    # Use eager loading to avoid N+1 queries - only load what we need.
    # Explicitly noload vulnerabilities/screenshots so serializers cannot lazy-load them.
    query = db.query(Asset).options(
        selectinload(Asset.port_services),
        selectinload(Asset.technologies),
        selectinload(Asset.organization),
        noload(Asset.vulnerabilities),
        noload(Asset.screenshots),
    )
    
    # Organization filter
    if current_user.is_superuser:
        if organization_id:
            query = query.filter(Asset.organization_id == organization_id)
    else:
        if not current_user.organization_id:
            return PaginatedAssetsResponse(items=[], total=0, skip=skip, limit=limit, has_more=False)
        query = query.filter(Asset.organization_id == current_user.organization_id)
    
    # Apply filters - normalize asset_type to uppercase for case-insensitive matching
    if asset_type:
        normalized_type = asset_type.upper()
        try:
            asset_type_enum = AssetType(normalized_type)
            query = query.filter(Asset.asset_type == asset_type_enum)
        except ValueError:
            # Invalid asset type, return empty
            return PaginatedAssetsResponse(items=[], total=0, skip=skip, limit=limit, has_more=False)
    else:
        # By default, exclude IP_RANGE (CIDR blocks) - these are managed in netblocks
        if not include_cidr:
            query = query.filter(Asset.asset_type != AssetType.IP_RANGE)
    
    if status:
        query = query.filter(Asset.status == status)
    if search:
        # Also match device classification so an operator can search fleet-wide
        # for a vendor/model (e.g. "rockwell", "1769", "PLC").
        query = query.filter(
            (Asset.name.ilike(f"%{search}%")) |
            (Asset.value.ilike(f"%{search}%")) |
            (Asset.system_type.ilike(f"%{search}%")) |
            (Asset.operating_system.ilike(f"%{search}%")) |
            (Asset.device_subclass.ilike(f"%{search}%"))
        )

    # Filter by device class (OT/ICS fleet triage: device_class="Industrial/SCADA")
    if device_class:
        query = query.filter(Asset.device_class.ilike(f"%{device_class}%"))

    # Filter by live status
    if is_live is True:
        query = query.filter(Asset.is_live == True)
    elif is_live is False:
        query = query.filter(Asset.is_live == False)
    
    # Filter by scope
    if in_scope is True:
        query = query.filter(Asset.in_scope == True)
    elif in_scope is False:
        query = query.filter(Asset.in_scope == False)
    
    # Filter for assets with geo data (for map display)
    if has_geo is True:
        query = query.filter(
            Asset.latitude != None,
            Asset.latitude != '',
            Asset.longitude != None,
            Asset.longitude != ''
        )
    elif has_geo is False:
        query = query.filter(
            (Asset.latitude == None) | (Asset.latitude == '')
        )
    
    # Get total count before pagination (using a separate lightweight query)
    count_query = db.query(func.count(Asset.id))
    # Apply the same filters to count query
    if current_user.is_superuser:
        if organization_id:
            count_query = count_query.filter(Asset.organization_id == organization_id)
    else:
        count_query = count_query.filter(Asset.organization_id == current_user.organization_id)
    
    if asset_type:
        try:
            asset_type_enum = AssetType(asset_type.upper())
            count_query = count_query.filter(Asset.asset_type == asset_type_enum)
        except ValueError:
            pass
    elif not include_cidr:
        count_query = count_query.filter(Asset.asset_type != AssetType.IP_RANGE)
    
    if status:
        count_query = count_query.filter(Asset.status == status)
    if search:
        count_query = count_query.filter((Asset.name.ilike(f"%{search}%")) | (Asset.value.ilike(f"%{search}%")))
    if is_live is True:
        count_query = count_query.filter(Asset.is_live == True)
    elif is_live is False:
        count_query = count_query.filter(Asset.is_live == False)
    if in_scope is True:
        count_query = count_query.filter(Asset.in_scope == True)
    elif in_scope is False:
        count_query = count_query.filter(Asset.in_scope == False)
    if has_geo is True:
        count_query = count_query.filter(
            Asset.latitude != None,
            Asset.latitude != '',
            Asset.longitude != None,
            Asset.longitude != ''
        )
    elif has_geo is False:
        count_query = count_query.filter(
            (Asset.latitude == None) | (Asset.latitude == '')
        )
    
    total_count = count_query.scalar() or 0
    
    # Apply pagination
    assets = query.order_by(Asset.created_at.desc()).offset(skip).limit(limit).all()
    
    # Filter by port criteria if specified (note: this affects total count accuracy)
    if has_open_ports is not None or has_risky_ports is not None:
        filtered_assets = []
        for asset in assets:
            open_count = len([p for p in asset.port_services if p.state == PortState.OPEN])
            risky_count = len([p for p in asset.port_services if p.is_risky])
            
            if has_open_ports is not None:
                if has_open_ports and open_count == 0:
                    continue
                if not has_open_ports and open_count > 0:
                    continue
            
            if has_risky_ports is not None:
                if has_risky_ports and risky_count == 0:
                    continue
                if not has_risky_ports and risky_count > 0:
                    continue
            
            filtered_assets.append(asset)
        assets = filtered_assets

    vuln_by_asset = _batch_vuln_counts(db, [a.id for a in assets])
    
    return PaginatedAssetsResponse(
        items=[
            build_asset_response(asset, vuln_counts=vuln_by_asset.get(asset.id, _empty_vuln_counts()))
            for asset in assets
        ],
        total=total_count,
        skip=skip,
        limit=limit,
        has_more=(skip + len(assets)) < total_count
    )


@router.post("/", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
def create_asset(
    asset_data: AssetCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Create a new asset."""
    # Check organization access
    if not check_org_access(current_user, asset_data.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this organization"
        )
    
    # Check for duplicate
    existing = db.query(Asset).filter(
        Asset.organization_id == asset_data.organization_id,
        Asset.asset_type == asset_data.asset_type,
        Asset.value == asset_data.value
    ).first()
    
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Asset with this type and value already exists"
        )
    
    asset_dict = asset_data.model_dump()
    
    # For IP_ADDRESS type assets, auto-populate ip_address and ip_addresses fields
    if asset_data.asset_type == AssetType.IP_ADDRESS:
        if not asset_dict.get('ip_address'):
            asset_dict['ip_address'] = asset_data.value
        if not asset_dict.get('ip_addresses'):
            asset_dict['ip_addresses'] = [asset_data.value]
    
    new_asset = Asset(**asset_dict)
    db.add(new_asset)
    db.commit()
    db.refresh(new_asset)

    # Auto-kick subdomain enumeration when a root domain is onboarded
    if new_asset.asset_type == AssetType.DOMAIN:
        domain_value = new_asset.value.strip().lower()
        subdomain_scan = Scan(
            name=f"Subdomain enumeration: {domain_value}",
            scan_type=ScanType.SUBDOMAIN_ENUM,
            organization_id=new_asset.organization_id,
            targets=[domain_value],
            config={
                "domain": domain_value,
                "triggered_by": "asset_created",
            },
            started_by=current_user.username,
            status=ScanStatus.PENDING,
        )
        db.add(subdomain_scan)
        db.commit()
        db.refresh(subdomain_scan)
        send_scan_to_sqs(subdomain_scan)
        logger.info(
            f"Auto-enqueued SUBDOMAIN_ENUM scan {subdomain_scan.id} for {domain_value}"
        )

    return new_asset


@router.post("/bulk", response_model=List[AssetResponse], status_code=status.HTTP_201_CREATED)
def create_assets_bulk(
    assets_data: List[AssetCreate],
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Create multiple assets at once."""
    created_assets = []
    
    for asset_data in assets_data:
        # Check organization access
        if not check_org_access(current_user, asset_data.organization_id):
            continue
        
        # Check for duplicate
        existing = db.query(Asset).filter(
            Asset.organization_id == asset_data.organization_id,
            Asset.asset_type == asset_data.asset_type,
            Asset.value == asset_data.value
        ).first()
        
        if not existing:
            asset_dict = asset_data.model_dump()
            
            # For IP_ADDRESS type assets, auto-populate ip_address and ip_addresses fields
            if asset_data.asset_type == AssetType.IP_ADDRESS:
                if not asset_dict.get('ip_address'):
                    asset_dict['ip_address'] = asset_data.value
                if not asset_dict.get('ip_addresses'):
                    asset_dict['ip_addresses'] = [asset_data.value]
            
            new_asset = Asset(**asset_dict)
            db.add(new_asset)
            created_assets.append(new_asset)
    
    db.commit()
    for asset in created_assets:
        db.refresh(asset)
    
    return created_assets


@router.get("/geo-stats")
def get_assets_geo_stats_early(
    organization_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get geo-location statistics for assets - used by the map component."""
    from app.services.geolocation_service import get_all_regions

    query = db.query(Asset)

    if current_user.is_superuser:
        if organization_id:
            query = query.filter(Asset.organization_id == organization_id)
    else:
        if not current_user.organization_id:
            return {"total": 0, "with_geo": 0, "without_geo": 0, "by_country": {}, "by_region": {}}
        query = query.filter(Asset.organization_id == current_user.organization_id)

    assets = query.all()

    total = len(assets)
    with_geo = 0
    without_geo = 0
    by_country = {}
    by_city = {}
    by_region = {}

    for asset in assets:
        if asset.latitude and asset.longitude:
            with_geo += 1
            country = asset.country or asset.country_code or "Unknown"
            by_country[country] = by_country.get(country, 0) + 1
            region = asset.region or "Unknown"
            by_region[region] = by_region.get(region, 0) + 1
            if asset.city:
                city_key = asset.city + ", " + country
                by_city[city_key] = by_city.get(city_key, 0) + 1
        else:
            without_geo += 1

    return {
        "total": total,
        "with_geo": with_geo,
        "without_geo": without_geo,
        "by_region": dict(sorted(by_region.items(), key=lambda x: x[1], reverse=True)),
        "by_country": dict(sorted(by_country.items(), key=lambda x: x[1], reverse=True)),
        "by_city": dict(sorted(by_city.items(), key=lambda x: x[1], reverse=True)[:20]),
        "coverage_percent": round(with_geo / total * 100, 1) if total > 0 else 0,
        "available_regions": get_all_regions()
    }


@router.get("/geo")
def list_geo_assets(
    organization_id: Optional[int] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(5000, ge=1, le=20000),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Lean geo payload for the world map.

    Returns only map fields plus SQL-aggregated vuln/port counts — not full
    asset documents. Prefer this over ``GET /assets/?has_geo=true``.
    """
    org_filter = _org_filter_for_user(current_user, organization_id)
    if org_filter is False:
        return {"items": [], "total": 0, "skip": skip, "limit": limit, "has_more": False}

    geo_filter = (
        Asset.latitude.isnot(None),
        Asset.latitude != "",
        Asset.longitude.isnot(None),
        Asset.longitude != "",
        Asset.asset_type != AssetType.IP_RANGE,
    )

    count_q = db.query(func.count(Asset.id)).filter(*geo_filter)
    if org_filter is not None:
        count_q = count_q.filter(org_filter)
    total = count_q.scalar() or 0

    vuln_subq = (
        db.query(
            Vulnerability.asset_id.label("asset_id"),
            func.count(Vulnerability.id).label("vuln_count"),
            func.sum(case((Vulnerability.severity == Severity.CRITICAL, 1), else_=0)).label("critical"),
            func.sum(case((Vulnerability.severity == Severity.HIGH, 1), else_=0)).label("high"),
            func.sum(case((Vulnerability.severity == Severity.MEDIUM, 1), else_=0)).label("medium"),
            func.sum(case((Vulnerability.severity == Severity.LOW, 1), else_=0)).label("low"),
        )
        .filter(Vulnerability.status != VulnerabilityStatus.RESOLVED)
        .group_by(Vulnerability.asset_id)
        .subquery()
    )

    port_subq = (
        db.query(
            PortService.asset_id.label("asset_id"),
            func.sum(case((PortService.state == PortState.OPEN, 1), else_=0)).label("open_ports"),
            func.sum(case((PortService.is_risky == True, 1), else_=0)).label("risky_ports"),
        )
        .group_by(PortService.asset_id)
        .subquery()
    )

    query = (
        db.query(
            Asset.id,
            Asset.name,
            Asset.value,
            Asset.asset_type,
            Asset.latitude,
            Asset.longitude,
            Asset.city,
            Asset.country,
            Asset.country_code,
            Asset.metadata_,
            func.coalesce(vuln_subq.c.vuln_count, 0).label("vuln_count"),
            func.coalesce(vuln_subq.c.critical, 0).label("critical"),
            func.coalesce(vuln_subq.c.high, 0).label("high"),
            func.coalesce(vuln_subq.c.medium, 0).label("medium"),
            func.coalesce(vuln_subq.c.low, 0).label("low"),
            func.coalesce(port_subq.c.open_ports, 0).label("open_ports"),
            func.coalesce(port_subq.c.risky_ports, 0).label("risky_ports"),
        )
        .outerjoin(vuln_subq, Asset.id == vuln_subq.c.asset_id)
        .outerjoin(port_subq, Asset.id == port_subq.c.asset_id)
        .filter(*geo_filter)
    )
    if org_filter is not None:
        query = query.filter(org_filter)

    rows = query.order_by(Asset.id.asc()).offset(skip).limit(limit).all()

    items = []
    for row in rows:
        meta = row.metadata_ or {}
        asset_type = row.asset_type.value if hasattr(row.asset_type, "value") else str(row.asset_type)
        items.append({
            "id": row.id,
            "name": row.name,
            "value": row.value,
            "asset_type": asset_type,
            "latitude": row.latitude,
            "longitude": row.longitude,
            "city": row.city,
            "country": row.country,
            "country_code": row.country_code,
            "vulnerability_count": int(row.vuln_count or 0),
            "critical_vuln_count": int(row.critical or 0),
            "high_vuln_count": int(row.high or 0),
            "medium_vuln_count": int(row.medium or 0),
            "low_vuln_count": int(row.low or 0),
            "open_ports_count": int(row.open_ports or 0),
            "risky_ports_count": int(row.risky_ports or 0),
            "dns_threat": bool(meta.get("dns_threat_listed")),
            "urlhaus_malicious": bool(meta.get("urlhaus_malicious")),
        })

    return {
        "items": items,
        "total": total,
        "skip": skip,
        "limit": limit,
        "has_more": (skip + len(items)) < total,
    }


@router.get("/{asset_id}", response_model=AssetResponse)
def get_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get asset by ID with port services and technologies."""
    asset = (
        db.query(Asset)
        .options(
            selectinload(Asset.port_services),
            selectinload(Asset.technologies),
            selectinload(Asset.vulnerabilities),
        )
        .filter(Asset.id == asset_id)
        .first()
    )

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found"
        )

    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )

    # Build full response with port services and technologies
    return build_asset_response(asset)


@router.get("/{asset_id}/openapi.yaml")
def download_asset_openapi(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Download discovered OpenAPI YAML for this asset (View Spec / Download)."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    from app.services.rest_inventory_service import to_openapi_yaml

    yaml_text = to_openapi_yaml(asset)
    if not yaml_text:
        raise HTTPException(status_code=404, detail="No API spec or REST inventory on this asset")
    filename = f"{asset.value.replace('.', '_')}-openapi.yaml"
    return Response(
        content=yaml_text,
        media_type="application/yaml",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{asset_id}/api-specs")
def get_asset_api_specs(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Return stored swagger/openapi documents (without huge bodies unless requested)."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    specs = []
    for spec in asset.api_specs or []:
        if not isinstance(spec, dict):
            continue
        item = {k: v for k, v in spec.items() if k != "spec"}
        item["has_spec"] = bool(spec.get("spec"))
        specs.append(item)
    return {"specs": specs, "rest_endpoints": asset.rest_endpoints or []}


@router.get("/{asset_id}/api-specs/{spec_index}")
def get_asset_api_spec_body(
    asset_id: int,
    spec_index: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """View a stored OpenAPI/Swagger document."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    specs = [s for s in (asset.api_specs or []) if isinstance(s, dict)]
    if spec_index < 0 or spec_index >= len(specs):
        raise HTTPException(status_code=404, detail="Spec not found")
    spec = specs[spec_index]
    body = spec.get("spec")
    if not body:
        raise HTTPException(status_code=404, detail="Spec body was not stored (too large); use the spec URL")
    return JSONResponse(content=body)


@router.get("/{asset_id}/ports", response_model=AssetPortsSummary)
def get_asset_ports(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get detailed port information for an asset."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found"
        )
    
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Build port summaries
    port_summaries = []
    services = set()
    tcp_count = 0
    udp_count = 0
    open_count = 0
    filtered_count = 0
    risky_count = 0
    
    for ps in sorted(asset.port_services, key=lambda x: x.port):
        port_summaries.append(PortServiceSummary(
            id=ps.id,
            port=ps.port,
            protocol=ps.protocol.value,
            service=ps.service_name,
            product=ps.service_product,
            version=ps.service_version,
            state=ps.state.value,
            is_ssl=ps.is_ssl,
            is_risky=ps.is_risky,
            port_string=ps.port_string
        ))
        
        if ps.service_name:
            services.add(ps.service_name)
        
        if ps.protocol.value == "tcp":
            tcp_count += 1
        elif ps.protocol.value == "udp":
            udp_count += 1
        
        if ps.state == PortState.OPEN:
            open_count += 1
        elif ps.state in [PortState.FILTERED, PortState.OPEN_FILTERED]:
            filtered_count += 1
        
        if ps.is_risky:
            risky_count += 1
    
    return AssetPortsSummary(
        asset_id=asset.id,
        asset_value=asset.value,
        total_ports=len(asset.port_services),
        open_ports=open_count,
        filtered_ports=filtered_count,
        risky_ports=risky_count,
        tcp_ports=tcp_count,
        udp_ports=udp_count,
        services=sorted(list(services)),
        ports=port_summaries
    )


@router.put("/{asset_id}", response_model=AssetResponse)
def update_asset(
    asset_id: int,
    asset_data: AssetUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Update asset."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found"
        )
    
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Update fields
    update_data = asset_data.model_dump(exclude_unset=True)
    going_out_of_scope = (
        "in_scope" in update_data
        and update_data["in_scope"] is False
        and asset.in_scope is True
    )
    for field, value in update_data.items():
        setattr(asset, field, value)

    asset.last_seen = datetime.utcnow()

    # Auto-close open findings when the asset is being removed from scope
    if going_out_of_scope:
        _close_findings_for_asset(db, asset.id)

    db.commit()
    db.refresh(asset)

    return asset


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Delete asset."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found"
        )
    
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    db.delete(asset)
    db.commit()
    
    return None


@router.post("/bulk-delete")
def bulk_delete_assets(
    asset_ids: List[int],
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Bulk delete assets by ID.
    
    Only deletes assets the user has access to.
    """
    deleted = 0
    failed = 0
    errors = []
    
    for asset_id in asset_ids:
        try:
            asset = db.query(Asset).filter(Asset.id == asset_id).first()
            if not asset:
                failed += 1
                errors.append(f"Asset {asset_id} not found")
                continue
            
            if not check_org_access(current_user, asset.organization_id):
                failed += 1
                errors.append(f"Asset {asset_id} access denied")
                continue
            
            db.delete(asset)
            deleted += 1
        except Exception as e:
            failed += 1
            errors.append(f"Asset {asset_id}: {str(e)}")
    
    db.commit()
    
    return {
        "deleted": deleted,
        "failed": failed,
        "errors": errors[:10]  # Limit error messages
    }


@router.delete("/out-of-scope")
def delete_out_of_scope_assets(
    organization_id: int = Query(1, ge=1),
    confirm: bool = Query(False, description="Must be true to actually delete"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Delete all out-of-scope assets for an organization.
    
    Pass confirm=true to actually delete. Without it, just returns count.
    """
    if not check_org_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Find out-of-scope assets
    out_of_scope = db.query(Asset).filter(
        Asset.organization_id == organization_id,
        Asset.in_scope == False
    ).all()
    
    count = len(out_of_scope)
    
    if not confirm:
        return {
            "would_delete": count,
            "message": f"Found {count} out-of-scope assets. Set confirm=true to delete.",
            "preview": [{"id": a.id, "value": a.value, "type": a.asset_type.value if a.asset_type else None} for a in out_of_scope[:20]]
        }
    
    # Actually delete
    for asset in out_of_scope:
        db.delete(asset)
    
    db.commit()
    
    return {
        "deleted": count,
        "message": f"Deleted {count} out-of-scope assets"
    }


@router.get("/stats/summary")
def get_assets_summary(
    organization_id: Optional[int] = None,
    group_by: Optional[str] = Query(
        None,
        description="Optional grouping dimension: type, status, country, organization, root_domain",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get asset statistics summary including port information.
    
    OPTIMIZED: Uses SQL aggregations instead of loading all assets into memory.
    Pass ``group_by`` to also return a ``groups`` array for that dimension.
    """
    # Build base filter for organization
    org_filter = _org_filter_for_user(current_user, organization_id)
    if org_filter is False:
        return {
            "total": 0,
            "by_type": {},
            "by_status": {},
            "ports": {},
            "group_by": group_by,
            "groups": [],
        }
    
    # Get total count and aggregated stats in ONE query
    base_query = db.query(
        func.count(Asset.id).label('total'),
        func.sum(case((Asset.is_live == True, 1), else_=0)).label('live_count'),
        func.sum(case((Asset.is_live == False, 1), else_=0)).label('not_live_count'),
        func.sum(case((Asset.is_live == None, 1), else_=0)).label('not_probed_count'),
        func.sum(case((Asset.in_scope == True, 1), else_=0)).label('in_scope_count'),
        func.sum(case((Asset.in_scope == False, 1), else_=0)).label('out_of_scope_count'),
        func.sum(case((Asset.has_login_portal == True, 1), else_=0)).label('with_login_portal'),
    )
    
    if org_filter is not None:
        base_query = base_query.filter(org_filter)
    
    stats = base_query.first()
    
    # Get counts by asset type
    type_query = db.query(
        Asset.asset_type,
        func.count(Asset.id)
    ).group_by(Asset.asset_type)
    
    if org_filter is not None:
        type_query = type_query.filter(org_filter)
    
    by_type = {str(row[0].value): row[1] for row in type_query.all()}
    
    # Get counts by status
    status_query = db.query(
        Asset.status,
        func.count(Asset.id)
    ).group_by(Asset.status)
    
    if org_filter is not None:
        status_query = status_query.filter(org_filter)
    
    by_status = {str(row[0].value): row[1] for row in status_query.all()}
    
    # Get port statistics (separate query for efficiency)
    port_stats_query = db.query(
        func.count(PortService.id).label('total_ports'),
        func.sum(case((PortService.state == PortState.OPEN, 1), else_=0)).label('open_ports'),
        func.sum(case((PortService.is_risky == True, 1), else_=0)).label('risky_ports'),
        func.count(func.distinct(PortService.asset_id)).label('assets_with_ports'),
    ).join(Asset, PortService.asset_id == Asset.id)
    
    if org_filter is not None:
        port_stats_query = port_stats_query.filter(org_filter)
    
    port_stats = port_stats_query.first()
    
    # Count assets with risky ports
    risky_assets_query = db.query(
        func.count(func.distinct(PortService.asset_id))
    ).join(Asset, PortService.asset_id == Asset.id).filter(
        PortService.is_risky == True
    )
    
    if org_filter is not None:
        risky_assets_query = risky_assets_query.filter(org_filter)
    
    assets_with_risky_ports = risky_assets_query.scalar() or 0

    groups: List[Dict[str, Any]] = []
    normalized_group = (group_by or "").strip().lower() or None
    if normalized_group:
        if normalized_group not in ASSET_SUMMARY_GROUP_BY:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid group_by. Allowed: {', '.join(sorted(ASSET_SUMMARY_GROUP_BY))}",
            )
        if normalized_group == "type":
            groups = [
                {"key": k, "label": k, "count": v}
                for k, v in sorted(by_type.items(), key=lambda x: x[1], reverse=True)
            ]
        elif normalized_group == "status":
            groups = [
                {"key": k, "label": k, "count": v}
                for k, v in sorted(by_status.items(), key=lambda x: x[1], reverse=True)
            ]
        elif normalized_group == "country":
            gq = db.query(
                func.coalesce(Asset.country_code, Asset.country, "Unknown").label("key"),
                func.coalesce(Asset.country, Asset.country_code, "Unknown").label("label"),
                func.count(Asset.id),
            ).group_by(
                func.coalesce(Asset.country_code, Asset.country, "Unknown"),
                func.coalesce(Asset.country, Asset.country_code, "Unknown"),
            )
            if org_filter is not None:
                gq = gq.filter(org_filter)
            groups = [
                {"key": str(row[0] or "Unknown"), "label": str(row[1] or "Unknown"), "count": row[2]}
                for row in gq.order_by(func.count(Asset.id).desc()).limit(50).all()
            ]
        elif normalized_group == "organization":
            gq = (
                db.query(Organization.id, Organization.name, func.count(Asset.id))
                .join(Asset, Asset.organization_id == Organization.id)
                .group_by(Organization.id, Organization.name)
            )
            if org_filter is not None:
                gq = gq.filter(org_filter)
            groups = [
                {"key": str(row[0]), "label": row[1], "count": row[2]}
                for row in gq.order_by(func.count(Asset.id).desc()).limit(50).all()
            ]
        elif normalized_group == "root_domain":
            gq = db.query(
                func.coalesce(Asset.root_domain, "Unknown"),
                func.count(Asset.id),
            ).group_by(func.coalesce(Asset.root_domain, "Unknown"))
            if org_filter is not None:
                gq = gq.filter(org_filter)
            groups = [
                {"key": str(row[0]), "label": str(row[0]), "count": row[1]}
                for row in gq.order_by(func.count(Asset.id).desc()).limit(50).all()
            ]
    
    return {
        "total": stats.total or 0,
        "by_type": by_type,
        "by_status": by_status,
        "live": {
            "live": stats.live_count or 0,
            "not_live": stats.not_live_count or 0,
            "not_probed": stats.not_probed_count or 0
        },
        "scope": {
            "in_scope": stats.in_scope_count or 0,
            "out_of_scope": stats.out_of_scope_count or 0
        },
        "login_portals": stats.with_login_portal or 0,
        "ports": {
            "total_ports": port_stats.total_ports or 0 if port_stats else 0,
            "open_ports": port_stats.open_ports or 0 if port_stats else 0,
            "risky_ports": port_stats.risky_ports or 0 if port_stats else 0,
            "assets_with_ports": port_stats.assets_with_ports or 0 if port_stats else 0,
            "assets_with_risky_ports": assets_with_risky_ports
        },
        "group_by": normalized_group,
        "groups": groups,
    }


@router.post("/enrich-geolocation")
async def enrich_assets_geolocation(
    organization_id: Optional[int] = None,
    force: bool = Query(False, description="Re-enrich assets that already have geo data"),
    limit: int = Query(50, ge=1, le=200, description="Maximum assets to enrich"),
    provider: Optional[str] = Query(None, description="Geo provider: ip-api, ipinfo, whoisxml"),
    ipinfo_token: Optional[str] = Query(None, description="IPInfo.io API token"),
    whoisxml_api_key: Optional[str] = Query(None, description="WhoisXML API key"),
    include_ips: bool = Query(True, description="Also enrich IP address assets"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Enrich assets with geo-location data by resolving hostnames and looking up IP locations.
    
    Supported providers:
    - ip-api: Free, no API key required (45 req/min)
    - ipinfo: Free tier 50k/month, optional token for higher limits
    - whoisxml: Requires API key (https://ip-geolocation.whoisxmlapi.com)
    
    Example with WhoisXML:
    POST /api/assets/enrich-geolocation?whoisxml_api_key=at_xxx&provider=whoisxml
    """
    from app.services.geolocation_service import get_geolocation_service, GeoProvider
    
    geo_service = get_geolocation_service()
    
    # Configure API keys if provided
    if ipinfo_token or whoisxml_api_key:
        geo_service.set_api_keys(
            ipinfo_token=ipinfo_token,
            whoisxml_api_key=whoisxml_api_key
        )
    
    # Parse provider
    geo_provider = None
    if provider:
        provider_map = {
            "ip-api": GeoProvider.IP_API,
            "ipinfo": GeoProvider.IPINFO,
            "whoisxml": GeoProvider.WHOISXML,
        }
        geo_provider = provider_map.get(provider.lower())
    
    query = db.query(Asset)
    
    # Organization filter
    if current_user.is_superuser:
        if organization_id:
            query = query.filter(Asset.organization_id == organization_id)
    else:
        if not current_user.organization_id:
            return {"enriched": 0, "total": 0, "message": "No organization access"}
        query = query.filter(Asset.organization_id == current_user.organization_id)
    
    # Include domains, subdomains, and optionally IP addresses
    asset_types = [AssetType.DOMAIN, AssetType.SUBDOMAIN]
    if include_ips:
        asset_types.append(AssetType.IP_ADDRESS)
    query = query.filter(Asset.asset_type.in_(asset_types))
    
    # Optionally skip assets that already have geo data
    if not force:
        query = query.filter(
            (Asset.latitude == None) | (Asset.latitude == "")
        )
    
    assets = query.limit(limit).all()
    
    if not assets:
        return {"enriched": 0, "total": 0, "message": "No assets to enrich"}
    
    enriched_count = 0
    countries_found = {}
    
    for asset in assets:
        try:
            # For IP addresses, look up directly; for hostnames, resolve first
            if asset.asset_type == AssetType.IP_ADDRESS:
                geo_data = await geo_service.lookup_ip(asset.value, geo_provider)
            else:
                geo_data = await geo_service.lookup_hostname(asset.value, geo_provider)
            
            if geo_data:
                from app.services.geolocation_service import get_region_from_country
                
                # Update IP using multi-value method
                if geo_data.get("ip_address"):
                    asset.add_ip_address(geo_data.get("ip_address"))
                asset.latitude = geo_data.get("latitude")
                asset.longitude = geo_data.get("longitude")
                asset.city = geo_data.get("city")
                asset.country = geo_data.get("country")
                asset.country_code = geo_data.get("country_code")
                asset.isp = geo_data.get("isp")
                asset.asn = geo_data.get("asn")
                
                # Auto-assign region from country code
                country_code = geo_data.get("country_code") or geo_data.get("country")
                if country_code:
                    asset.region = get_region_from_country(country_code)
                
                enriched_count += 1
                
                # Track countries
                country = geo_data.get("country") or geo_data.get("country_code")
                if country:
                    countries_found[country] = countries_found.get(country, 0) + 1
        except Exception as e:
            # Log but continue with other assets
            pass
    
    db.commit()
    
    return {
        "enriched": enriched_count,
        "total": len(assets),
        "countries": countries_found,
        "provider_used": provider or "ip-api",
        "message": f"Successfully enriched {enriched_count} of {len(assets)} assets with geo-location data"
    }




@router.post("/enrich-from-netblocks")
def enrich_assets_from_netblocks_endpoint(
    organization_id: Optional[int] = None,
    force: bool = Query(False, description="Re-enrich assets that already have country data"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Enrich assets with country/geo data from their associated netblocks.
    
    WhoisXML netblock discovery already contains country information.
    This endpoint propagates that country data to all assets that:
    1. Have a netblock_id (already linked to a netblock)
    2. Have an IP address that falls within an owned netblock's CIDR
    
    This is fast because it uses existing data from netblocks - no external API calls.
    """
    from app.services.http_probe_service import enrich_assets_from_netblocks
    
    # Get organization ID
    if current_user.is_superuser and organization_id:
        org_id = organization_id
    else:
        org_id = current_user.organization_id
        
    if not org_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization ID required"
        )
    
    result = enrich_assets_from_netblocks(db, org_id, force=force)
    
    return {
        "success": True,
        "organization_id": org_id,
        **result,
        "message": f"Enriched {result.get('enriched_from_netblock_link', 0) + result.get('enriched_from_cidr_match', 0)} assets from netblock country data"
    }


@router.get("/by-country")
def get_assets_by_country(
    country: str = Query(..., description="Country name or code to filter by (e.g., 'United States', 'US', 'CN')"),
    organization_id: Optional[int] = None,
    asset_type: Optional[AssetType] = None,
    in_scope: bool = Query(True, description="Only return in-scope assets"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get assets filtered by country. Useful for understanding geographic exposure
    and identifying assets in specific countries (e.g., for compliance, risk assessment).
    
    Examples:
    - GET /api/assets/by-country?country=CN (assets in China)
    - GET /api/assets/by-country?country=RU (assets in Russia)
    - GET /api/assets/by-country?country=United%20States
    """
    # Filter by country (support both country name and country code)
    query = db.query(Asset).filter(
        (Asset.country.ilike(f"%{country}%")) |
        (Asset.country_code.ilike(f"%{country}%"))
    )
    
    # Organization filter
    if current_user.is_superuser:
        if organization_id:
            query = query.filter(Asset.organization_id == organization_id)
    else:
        if not current_user.organization_id:
            return {"items": [], "total": 0}
        query = query.filter(Asset.organization_id == current_user.organization_id)
    
    if in_scope:
        query = query.filter(Asset.in_scope == True)
    
    if asset_type:
        query = query.filter(Asset.asset_type == asset_type)
    
    total = query.count()
    
    assets = query.order_by(Asset.created_at.desc()).offset(skip).limit(limit).all()
    
    return {
        "items": [
            {
                "id": a.id,
                "name": a.name,
                "value": a.value,
                "asset_type": a.asset_type.value if a.asset_type else None,
                "ip_address": a.ip_address,
                "country": a.country,
                "country_code": a.country_code,
                "city": a.city,
                "region": a.region,
                "latitude": a.latitude,
                "longitude": a.longitude,
                "is_live": a.is_live,
                "in_scope": a.in_scope,
            }
            for a in assets
        ],
        "total": total,
        "skip": skip,
        "limit": limit,
        "country_filter": country
    }


@router.get("/by-region")
def get_assets_by_region(
    region: str = Query(..., description="Region to filter by (e.g., 'North America', 'Europe', 'Asia')"),
    organization_id: Optional[int] = None,
    asset_type: Optional[AssetType] = None,
    in_scope: bool = Query(True, description="Only return in-scope assets"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get assets filtered by geographic region. Useful for regional scanning."""
    query = db.query(Asset).filter(Asset.region == region)
    
    # Organization filter
    if current_user.is_superuser:
        if organization_id:
            query = query.filter(Asset.organization_id == organization_id)
    else:
        if not current_user.organization_id:
            return {"assets": [], "count": 0, "region": region}
        query = query.filter(Asset.organization_id == current_user.organization_id)
    
    if asset_type:
        query = query.filter(Asset.asset_type == asset_type)
    
    if in_scope:
        query = query.filter(Asset.in_scope == True)
    
    assets = query.order_by(Asset.country_code, Asset.value).all()
    
    # Group by country within region
    by_country = {}
    for asset in assets:
        country = asset.country or asset.country_code or "Unknown"
        if country not in by_country:
            by_country[country] = []
        by_country[country].append({
            "id": asset.id,
            "value": asset.value,
            "type": asset.asset_type.value,
            "city": asset.city,
            "is_live": asset.is_live,
            "ip_address": asset.ip_address,
        })
    
    return {
        "region": region,
        "count": len(assets),
        "by_country": by_country,
        "targets": [a.value for a in assets]  # Flat list for scanning
    }


@router.get("/regions")
def get_available_regions(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get list of regions that have assets."""
    from app.services.geolocation_service import get_all_regions
    
    # Get regions that actually have assets
    query = db.query(Asset.region, db.func.count(Asset.id).label('count'))
    
    if not current_user.is_superuser and current_user.organization_id:
        query = query.filter(Asset.organization_id == current_user.organization_id)
    
    query = query.filter(Asset.region.isnot(None))
    results = query.group_by(Asset.region).all()
    
    regions_with_assets = {r.region: r.count for r in results}
    all_regions = get_all_regions()
    
    return {
        "regions": [
            {
                "name": region,
                "asset_count": regions_with_assets.get(region, 0),
                "has_assets": region in regions_with_assets
            }
            for region in all_regions
        ],
        "total_with_region": sum(regions_with_assets.values())
    }


@router.post("/{asset_id}/enrich-geolocation", response_model=AssetResponse)
async def enrich_single_asset_geolocation(
    asset_id: int,
    provider: Optional[str] = Query(None, description="Geo provider: ip-api, ipinfo, whoisxml"),
    ipinfo_token: Optional[str] = Query(None, description="IPInfo.io API token"),
    whoisxml_api_key: Optional[str] = Query(None, description="WhoisXML API key"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Enrich a single asset with geo-location data."""
    from app.services.geolocation_service import get_geolocation_service, GeoProvider
    
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found"
        )
    
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    geo_service = get_geolocation_service()
    
    # Configure API keys if provided
    if ipinfo_token or whoisxml_api_key:
        geo_service.set_api_keys(
            ipinfo_token=ipinfo_token,
            whoisxml_api_key=whoisxml_api_key
        )
    
    # Parse provider
    geo_provider = None
    if provider:
        provider_map = {
            "ip-api": GeoProvider.IP_API,
            "ipinfo": GeoProvider.IPINFO,
            "whoisxml": GeoProvider.WHOISXML,
        }
        geo_provider = provider_map.get(provider.lower())
    
    # For IP addresses, look up directly; for hostnames, resolve first
    if asset.asset_type == AssetType.IP_ADDRESS:
        geo_data = await geo_service.lookup_ip(asset.value, geo_provider)
    else:
        geo_data = await geo_service.lookup_hostname(asset.value, geo_provider)
    
    if geo_data:
        # Update IP using multi-value method
        if geo_data.get("ip_address"):
            asset.add_ip_address(geo_data.get("ip_address"))
        asset.latitude = geo_data.get("latitude")
        asset.longitude = geo_data.get("longitude")
        asset.city = geo_data.get("city")
        asset.country = geo_data.get("country")
        asset.country_code = geo_data.get("country_code")
        asset.isp = geo_data.get("isp")
        asset.asn = geo_data.get("asn")
        db.commit()
        db.refresh(asset)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not resolve geo-location for this asset"
        )
    
    return asset


from pydantic import BaseModel

class HttpxProbeResult(BaseModel):
    """Result from httpx probe."""
    host: str  # e.g. "example.com" or "sub.example.com"
    url: Optional[str] = None  # Full URL if available
    status_code: Optional[int] = None
    title: Optional[str] = None
    webserver: Optional[str] = None  # e.g. "nginx", "IIS:10.0"
    technologies: Optional[List[str]] = None  # e.g. ["Bootstrap", "jQuery"]
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    ip: Optional[str] = None


class HttpxImportRequest(BaseModel):
    """Request to import httpx probe results."""
    organization_id: int
    results: List[HttpxProbeResult]


@router.post("/import-httpx-results")
def import_httpx_results(
    import_data: HttpxImportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Import httpx probe results to update asset http_status, http_title, is_live status,
    and optionally associate technologies.
    
    Example httpx output that can be parsed:
    https://example.com [200] [Example Page] [nginx,Bootstrap,jQuery]
    
    Expected input format:
    {
        "organization_id": 1,
        "results": [
            {"host": "example.com", "status_code": 200, "title": "Example", "technologies": ["nginx"]}
        ]
    }
    """
    if not check_org_access(current_user, import_data.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this organization"
        )
    
    updated_count = 0
    not_found_count = 0
    
    for result in import_data.results:
        # Strip protocol and path to get just the hostname
        hostname = result.host
        if hostname.startswith("https://"):
            hostname = hostname[8:]
        elif hostname.startswith("http://"):
            hostname = hostname[7:]
        hostname = hostname.split("/")[0].split(":")[0]  # Remove path and port
        
        # Find the asset
        asset = db.query(Asset).filter(
            Asset.organization_id == import_data.organization_id,
            Asset.value == hostname
        ).first()
        
        if not asset:
            not_found_count += 1
            continue
        
        # Update asset with probe results
        if result.status_code is not None:
            asset.http_status = result.status_code
            # Mark as live if we got any HTTP response
            asset.is_live = True
        
        if result.title:
            asset.http_title = result.title
        
        if result.ip:
            asset.add_ip_address(result.ip)
        
        # Store additional HTTP info in metadata
        if result.webserver or result.content_type:
            http_info = asset.http_headers or {}
            if result.webserver:
                http_info['server'] = result.webserver
            if result.content_type:
                http_info['content-type'] = result.content_type
            asset.http_headers = http_info
        
        asset.last_seen = datetime.utcnow()
        updated_count += 1
        
        # TODO: Associate technologies if provided
        # This would require looking up or creating Technology records
    
    db.commit()
    
    return {
        "updated": updated_count,
        "not_found": not_found_count,
        "total": len(import_data.results),
        "message": f"Updated {updated_count} assets with HTTP probe results"
    }


@router.post("/probe-live")
async def probe_assets_live(
    organization_id: int,
    asset_type: Optional[AssetType] = Query(None, description="Filter by asset type"),
    limit: int = Query(50, ge=1, le=500, description="Max assets to probe"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Probe assets to check if they're live and get HTTP status.
    Updates is_live, http_status, and http_title fields.
    Uses Python httpx library for reliability.
    """
    import httpx
    import asyncio
    import re
    
    if not check_org_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this organization"
        )
    
    # Get assets to probe
    query = db.query(Asset).filter(Asset.organization_id == organization_id)
    
    if asset_type:
        query = query.filter(Asset.asset_type == asset_type)
    else:
        # Default to domains and subdomains
        query = query.filter(Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]))
    
    assets = query.limit(limit).all()
    
    if not assets:
        return {"probed": 0, "live": 0, "message": "No assets to probe"}
    
    # Probe each asset using Python httpx
    async def probe_single(asset):
        """Probe a single asset for HTTP response."""
        hostname = asset.value
        result = {"asset_id": asset.id, "is_live": False, "status": None, "title": None}
        
        for protocol in ["https", "http"]:
            url = f"{protocol}://{hostname}"
            try:
                async with httpx.AsyncClient(
                    timeout=10.0,
                    follow_redirects=True,
                    verify=False  # Don't fail on self-signed certs
                ) as client:
                    response = await client.get(url)
                    result["is_live"] = True
                    result["status"] = response.status_code
                    
                    # Extract title from HTML
                    content_type = response.headers.get("content-type", "")
                    if "text/html" in content_type:
                        html = response.text[:5000]  # Only look at first 5KB
                        title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
                        if title_match:
                            result["title"] = title_match.group(1).strip()[:200]
                    
                    break  # Success, don't try other protocol
            except Exception:
                continue  # Try next protocol
        
        return result
    
    # Run probes concurrently (limit concurrency to avoid overwhelming)
    semaphore = asyncio.Semaphore(20)  # Max 20 concurrent requests
    
    async def probe_with_limit(asset):
        async with semaphore:
            return await probe_single(asset)
    
    results = await asyncio.gather(*[probe_with_limit(asset) for asset in assets])
    
    # Create lookup map
    results_map = {r["asset_id"]: r for r in results}
    
    # Update assets in database
    live_count = 0
    for asset in assets:
        result = results_map.get(asset.id)
        if result and result["is_live"]:
            asset.is_live = True
            asset.http_status = result["status"]
            asset.http_title = result["title"]
            asset.last_seen = datetime.utcnow()
            live_count += 1
        else:
            # Mark as not live if probe failed
            asset.is_live = False
    
    db.commit()
    
    return {
        "probed": len(assets),
        "live": live_count,
        "message": f"Found {live_count} live assets out of {len(assets)} probed"
    }


@router.post("/resolve-dns")
async def resolve_assets_dns(
    organization_id: int = Query(..., description="Organization ID"),
    asset_type: Optional[AssetType] = Query(None, description="Filter by asset type"),
    limit: int = Query(100, ge=1, le=500, description="Max assets to resolve"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Resolve DNS for domain/subdomain assets to get their IP addresses.
    Updates ip_address and ip_addresses fields on matching assets.
    """
    from app.services.projectdiscovery_service import get_projectdiscovery_service
    
    if not check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Get assets to resolve
    query = db.query(Asset).filter(
        Asset.organization_id == organization_id,
        (Asset.ip_address.is_(None) | (Asset.ip_address == ''))
    )
    
    if asset_type:
        query = query.filter(Asset.asset_type == asset_type)
    else:
        query = query.filter(Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]))
    
    assets = query.limit(limit).all()
    
    if not assets:
        return {"resolved": 0, "message": "No assets to resolve"}
    
    # Get hostnames
    targets = [asset.value for asset in assets]
    
    try:
        # Run dnsx
        pd_service = get_projectdiscovery_service()
        results = await pd_service.run_dnsx(targets, record_types=['A', 'AAAA'])
        
        # Build lookup
        dns_map = {r.host: r for r in results}
        
        # Update assets
        resolved_count = 0
        for asset in assets:
            if asset.value in dns_map:
                dns_result = dns_map[asset.value]
                if dns_result.a_records:
                    all_ips = dns_result.a_records + dns_result.aaaa_records
                    asset.update_ip_addresses(all_ips)
                    asset.last_seen = datetime.utcnow()
                    resolved_count += 1
        
        db.commit()
        
        return {
            "queried": len(assets),
            "resolved": resolved_count,
            "message": f"Resolved {resolved_count} of {len(assets)} assets to IP addresses"
        }
        
    except Exception as e:
        logger.error(f"DNS resolution failed: {e}")
        raise HTTPException(status_code=500, detail=f"DNS resolution failed: {str(e)}")


@router.post("/extract-ssl-certs")
async def extract_ssl_certificates(
    organization_id: int = Query(..., description="Organization ID"),
    limit: int = Query(50, ge=1, le=200, description="Max IPs to scan"),
    create_assets: bool = Query(True, description="Create new assets for discovered domains"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Extract SSL certificates from IP addresses to discover hosted domains.
    
    This scans IP assets and resolved IPs from domain assets, extracts SSL
    certificates, and discovers domains from Common Name and Subject Alternative Names.
    """
    from app.services.ssl_certificate_service import get_ssl_certificate_service
    
    if not check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Get IPs to scan - both IP assets and resolved IPs from domains
    ip_assets = db.query(Asset).filter(
        Asset.organization_id == organization_id,
        Asset.asset_type == AssetType.IP_ADDRESS
    ).limit(limit).all()
    
    # Also get resolved IPs from domain/subdomain assets
    domain_assets = db.query(Asset).filter(
        Asset.organization_id == organization_id,
        Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
        Asset.ip_address.isnot(None),
        Asset.ip_address != ''
    ).limit(limit).all()
    
    # Collect unique IPs
    ips_to_scan = set()
    for asset in ip_assets:
        ips_to_scan.add(asset.value)
    for asset in domain_assets:
        ips_to_scan.add(asset.ip_address)
    
    ips_to_scan = list(ips_to_scan)[:limit]
    
    if not ips_to_scan:
        return {
            "scanned": 0,
            "certificates": 0,
            "domains_found": 0,
            "message": "No IPs to scan. Run DNS resolution first to populate IP addresses."
        }
    
    # Extract SSL certificates
    ssl_service = get_ssl_certificate_service()
    results = await ssl_service.extract_certificates_async(ips_to_scan, port=443)
    
    # Collect all discovered domains
    all_domains_found = set()
    cert_count = 0
    
    for cert in results:
        if not cert.error and cert.domains_found:
            cert_count += 1
            for domain in cert.domains_found:
                # Skip wildcards
                if not domain.startswith('*.'):
                    all_domains_found.add(domain)
    
    # Create assets for new domains if requested
    assets_created = 0
    if create_assets and all_domains_found:
        for domain in all_domains_found:
            # Check if already exists
            existing = db.query(Asset).filter(
                Asset.organization_id == organization_id,
                Asset.value == domain
            ).first()
            
            if not existing:
                # Determine asset type
                parts = domain.split('.')
                if len(parts) == 2:
                    asset_type = AssetType.DOMAIN
                else:
                    asset_type = AssetType.SUBDOMAIN
                
                new_asset = Asset(
                    organization_id=organization_id,
                    name=domain,
                    value=domain,
                    asset_type=asset_type,
                    discovery_source="ssl_certificate",
                    discovery_chain=[{
                        "step": 1,
                        "source": "ssl_certificate",
                        "method": "certificate_extraction",
                        "timestamp": datetime.utcnow().isoformat()
                    }],
                    association_reason="Discovered from SSL certificate on owned IP address"
                )
                db.add(new_asset)
                assets_created += 1
        
        db.commit()
    
    return {
        "ips_scanned": len(ips_to_scan),
        "certificates_found": cert_count,
        "domains_discovered": len(all_domains_found),
        "assets_created": assets_created,
        "domains": sorted(list(all_domains_found)),
        "message": f"Extracted {cert_count} certificates, discovered {len(all_domains_found)} domains, created {assets_created} new assets"
    }


@router.get("/domain-stats")
def get_domain_statistics(
    organization_id: Optional[int] = Query(None, description="Filter by organization"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Get statistics grouped by root domain.
    
    Returns count of subdomains, live assets, and total assets per root domain.
    This allows seeing how many assets belong to each top-level domain.
    """
    from sqlalchemy import func
    
    query = db.query(
        Asset.root_domain,
        func.count(Asset.id).label('total_assets'),
        func.count(Asset.id).filter(Asset.asset_type == AssetType.SUBDOMAIN).label('subdomains'),
        func.count(Asset.id).filter(Asset.is_live == True).label('live_assets'),
    ).filter(
        Asset.root_domain.isnot(None)
    )
    
    if organization_id:
        if not check_org_access(current_user, organization_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this organization"
            )
        query = query.filter(Asset.organization_id == organization_id)
    elif not current_user.is_superuser:
        query = query.filter(Asset.organization_id == current_user.organization_id)
    
    query = query.group_by(Asset.root_domain).order_by(func.count(Asset.id).desc())
    
    results = query.all()
    
    return {
        "domains": [
            {
                "root_domain": r.root_domain,
                "total_assets": r.total_assets,
                "subdomains": r.subdomains,
                "live_assets": r.live_assets
            }
            for r in results
        ],
        "total_domains": len(results)
    }


@router.get("/ip-assets")
def get_ip_assets_for_investigation(
    organization_id: int = Query(..., description="Organization ID"),
    has_open_ports: Optional[bool] = Query(None, description="Filter by whether IP has open ports"),
    has_ssl_cert: Optional[bool] = Query(None, description="Filter by whether IP has SSL certificate"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get IP address assets with their services and associated domains for investigation.
    
    Returns IPs with:
    - Open ports and services
    - Associated domains (via DNS resolution or SSL certs)
    - Live status and other metadata
    
    Use this to investigate what IPs are being used for, even if they don't have domains.
    """
    from app.models.port_service import PortService, PortState
    from sqlalchemy import func
    
    if not check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Query IP assets
    query = db.query(Asset).filter(
        Asset.organization_id == organization_id,
        Asset.asset_type == AssetType.IP_ADDRESS
    )
    
    # Get total count before pagination
    total_count = query.count()
    
    # Apply pagination
    ip_assets = query.order_by(Asset.created_at.desc()).offset(skip).limit(limit).all()
    
    results = []
    for ip_asset in ip_assets:
        # Get port services for this IP
        port_services = db.query(PortService).filter(
            PortService.asset_id == ip_asset.id,
            PortService.state == PortState.OPEN
        ).all()
        
        # Find associated domains (domains that resolve to this IP)
        associated_domains = db.query(Asset).filter(
            Asset.organization_id == organization_id,
            Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
            Asset.ip_address == ip_asset.value
        ).all()
        
        # Build services summary
        services = []
        risky_ports = []
        for ps in port_services:
            service_info = {
                "port": ps.port,
                "protocol": ps.protocol.value if ps.protocol else "tcp",
                "service": ps.service_name,
                "product": ps.service_product,
                "version": ps.service_version,
                "banner": ps.banner[:200] if ps.banner else None,
                "is_risky": ps.is_risky
            }
            services.append(service_info)
            if ps.is_risky:
                risky_ports.append(ps.port)
        
        ip_info = {
            "id": ip_asset.id,
            "ip": ip_asset.value,
            "is_live": ip_asset.is_live,
            "discovery_source": ip_asset.discovery_source,
            "association_reason": ip_asset.association_reason,
            "created_at": ip_asset.created_at.isoformat() if ip_asset.created_at else None,
            "last_seen": ip_asset.last_seen.isoformat() if ip_asset.last_seen else None,
            
            # Geolocation
            "geo": {
                "country": ip_asset.country,
                "country_code": ip_asset.country_code,
                "city": ip_asset.city,
                "region": ip_asset.region,
                "isp": ip_asset.isp,
                "asn": ip_asset.asn,
                "latitude": ip_asset.latitude,
                "longitude": ip_asset.longitude,
            } if ip_asset.country or ip_asset.city else None,
            
            # Services/Ports
            "open_ports_count": len(port_services),
            "risky_ports_count": len(risky_ports),
            "risky_ports": risky_ports,
            "services": services,
            
            # Associated domains
            "associated_domains": [
                {
                    "id": d.id,
                    "value": d.value,
                    "type": d.asset_type.value,
                    "is_live": d.is_live
                }
                for d in associated_domains
            ],
            "has_associated_domain": len(associated_domains) > 0,
            
            # Investigation notes
            "notes": ip_asset.description,
            "tags": ip_asset.tags or [],
            "in_scope": ip_asset.in_scope,
            "is_owned": ip_asset.is_owned,
        }
        
        # Apply filters
        if has_open_ports is not None:
            if has_open_ports and len(port_services) == 0:
                continue
            if not has_open_ports and len(port_services) > 0:
                continue
        
        results.append(ip_info)
    
    # Summary stats
    total_with_ports = sum(1 for r in results if r["open_ports_count"] > 0)
    total_with_domains = sum(1 for r in results if r["has_associated_domain"])
    total_risky = sum(1 for r in results if r["risky_ports_count"] > 0)
    
    return {
        "total": total_count,
        "returned": len(results),
        "skip": skip,
        "limit": limit,
        "summary": {
            "with_open_ports": total_with_ports,
            "with_associated_domains": total_with_domains,
            "with_risky_ports": total_risky,
            "standalone_ips": len(results) - total_with_domains  # IPs without domains
        },
        "ips": results
    }


@router.post("/{asset_id}/investigate")
def update_asset_investigation_notes(
    asset_id: int,
    notes: str = Query(None, description="Investigation notes"),
    purpose: str = Query(None, description="Purpose/use of this asset"),
    tags: List[str] = Query(None, description="Tags to add"),
    in_scope: bool = Query(None, description="Whether asset is in scope"),
    is_owned: bool = Query(None, description="Whether asset is owned by org"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Update investigation notes and metadata for an asset.
    
    Use this to document findings about what an IP/asset is used for.
    """
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Update fields if provided
    if notes is not None:
        asset.description = notes
    
    if purpose is not None:
        if not asset.metadata_:
            asset.metadata_ = {}
        asset.metadata_["purpose"] = purpose
    
    if tags is not None:
        existing_tags = asset.tags or []
        asset.tags = list(set(existing_tags + tags))
    
    if in_scope is not None:
        going_out_of_scope = (in_scope is False and asset.in_scope is True)
        asset.in_scope = in_scope
        if going_out_of_scope:
            _close_findings_for_asset(db, asset.id)

    if is_owned is not None:
        asset.is_owned = is_owned

    asset.updated_at = datetime.utcnow()
    db.commit()
    
    return {
        "id": asset.id,
        "value": asset.value,
        "description": asset.description,
        "purpose": asset.metadata_.get("purpose") if asset.metadata_ else None,
        "tags": asset.tags,
        "in_scope": asset.in_scope,
        "is_owned": asset.is_owned,
        "message": "Investigation notes updated"
    }


# =============================================================================
# Technology Detection Endpoints
# =============================================================================

TechSource = Literal["wappalyzer", "whatruns", "both"]


@router.post("/scan-technologies")
async def scan_assets_technologies(
    organization_id: int = Query(..., description="Organization ID"),
    source: TechSource = Query("both", description="Technology detection source: wappalyzer, whatruns, or both"),
    limit: int = Query(50, ge=1, le=200, description="Maximum assets to scan"),
    only_live: bool = Query(False, description="Only scan assets marked as is_live"),
    background_tasks: BackgroundTasks = None,
    run_in_background: bool = Query(False, description="Run scan in background"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Scan assets for technologies using Wappalyzer, WhatRuns, or both.
    
    Technology detection sources:
    - **wappalyzer**: Local fingerprint matching (fast, limited signatures)
    - **whatruns**: WhatRuns API (comprehensive, includes CMS, JS libs, fonts, analytics, security headers)
    - **both**: Use both sources for maximum coverage (recommended)
    
    The scan will:
    1. Detect technologies on each domain/subdomain
    2. Associate technologies with the asset
    3. Create tech:xxx labels for filtering
    
    Example:
    ```
    POST /api/v1/assets/scan-technologies?organization_id=1&source=both&limit=50
    ```
    """
    from app.services.technology_scan_service import run_technology_scan_for_hosts
    
    if not check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Get assets to scan
    query = db.query(Asset).filter(
        Asset.organization_id == organization_id,
        Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN])
    )
    
    if only_live:
        query = query.filter(Asset.is_live == True)
    
    assets = query.limit(limit).all()
    
    if not assets:
        return {"scanned": 0, "message": "No assets to scan"}
    
    hosts = [asset.value for asset in assets]
    
    if run_in_background and background_tasks:
        # Run in background
        background_tasks.add_task(
            run_technology_scan_for_hosts,
            organization_id=organization_id,
            hosts=hosts,
            max_hosts=limit,
            source=source,
        )
        return {
            "status": "queued",
            "hosts_queued": len(hosts),
            "source": source,
            "message": f"Technology scan queued for {len(hosts)} hosts in background"
        }
    
    # Run synchronously
    result = run_technology_scan_for_hosts(
        organization_id=organization_id,
        hosts=hosts,
        max_hosts=limit,
        source=source,
    )
    
    return result


@router.post("/{asset_id}/scan-technologies")
async def scan_single_asset_technologies(
    asset_id: int,
    source: TechSource = Query("both", description="Technology detection source"),
    url: Optional[str] = Query(None, description="Specific URL to scan (defaults to https://{asset})"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Scan a single asset for technologies.
    
    Use this to manually trigger technology detection for a specific asset.
    
    Returns the list of detected technologies.
    """
    from app.services.wappalyzer_service import WappalyzerService
    from app.services.whatruns_service import get_whatruns_service
    from app.services.technology_scan_service import _get_or_create_technology
    from app.services.asset_labeling_service import add_tech_to_asset
    
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    if asset.asset_type not in [AssetType.DOMAIN, AssetType.SUBDOMAIN]:
        raise HTTPException(
            status_code=400, 
            detail="Technology scanning is only available for domain and subdomain assets"
        )
    
    hostname = asset.value
    scan_url = url or f"https://{hostname}/"
    
    all_techs = []
    
    # Wappalyzer detection
    if source in ("wappalyzer", "both"):
        try:
            wappalyzer = WappalyzerService()
            wap_techs = await wappalyzer.analyze_url(scan_url)
            if wap_techs:
                all_techs.extend(wap_techs)
                logger.info(f"Wappalyzer found {len(wap_techs)} technologies for {hostname}")
        except Exception as e:
            logger.warning(f"Wappalyzer scan failed for {hostname}: {e}")
    
    # WhatRuns detection
    if source in ("whatruns", "both"):
        try:
            whatruns = get_whatruns_service()
            wr_techs = await whatruns.detect_technologies(hostname, scan_url)
            if wr_techs:
                # Convert to DetectedTechnology format
                for wt in wr_techs:
                    all_techs.append(wt.to_detected_technology())
                logger.info(f"WhatRuns found {len(wr_techs)} technologies for {hostname}")
        except Exception as e:
            logger.warning(f"WhatRuns scan failed for {hostname}: {e}")
    
    if not all_techs:
        return {
            "asset_id": asset_id,
            "hostname": hostname,
            "technologies": [],
            "count": 0,
            "message": "No technologies detected"
        }
    
    # Deduplicate by slug
    seen_slugs = set()
    unique_techs = []
    for dt in all_techs:
        if dt.slug not in seen_slugs:
            seen_slugs.add(dt.slug)
            unique_techs.append(dt)
    
    # Save technologies to database
    saved_techs = []
    for dt in unique_techs:
        db_tech = _get_or_create_technology(db, dt)
        add_tech_to_asset(
            db,
            organization_id=asset.organization_id,
            asset=asset,
            tech=db_tech,
            also_tag_asset=True,
            tag_parent=False,
        )
        saved_techs.append({
            "name": dt.name,
            "slug": dt.slug,
            "categories": dt.categories,
            "confidence": dt.confidence,
            "version": dt.version,
            "website": dt.website,
        })
    
    # Update asset live_url
    asset.live_url = scan_url
    asset.is_live = True
    
    db.commit()
    
    return {
        "asset_id": asset_id,
        "hostname": hostname,
        "url_scanned": scan_url,
        "source": source,
        "technologies": saved_techs,
        "count": len(saved_techs),
        "message": f"Detected {len(saved_techs)} technologies"
    }


@router.get("/{asset_id}/technologies")
def get_asset_technologies(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get all technologies associated with an asset.
    
    Returns the list of detected technologies with their categories and metadata.
    """
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Get technologies through the relationship
    technologies = []
    for tech in asset.technologies:
        technologies.append({
            "id": tech.id,
            "name": tech.name,
            "slug": tech.slug,
            "categories": tech.categories or [],
            "website": tech.website,
            "icon": tech.icon,
            "cpe": tech.cpe,
        })
    
    # Group by category
    by_category = {}
    for tech in technologies:
        for cat in tech.get("categories", ["Other"]):
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(tech["name"])
    
    return {
        "asset_id": asset_id,
        "hostname": asset.value,
        "technologies": technologies,
        "by_category": by_category,
        "count": len(technologies)
    }


@router.post("/whatruns-test")
async def test_whatruns_api(
    hostname: str = Query(..., description="Hostname to test (e.g., example.com)"),
    url: Optional[str] = Query(None, description="Specific URL to scan"),
    current_user: User = Depends(require_analyst)
):
    """
    Test the WhatRuns API with a specific hostname.
    
    This is useful for testing WhatRuns integration without saving results to database.
    
    Example:
    ```
    POST /api/v1/assets/whatruns-test?hostname=plex.my.site.com&url=https://plex.my.site.com/community/s/login/
    ```
    """
    from app.services.whatruns_service import get_whatruns_service
    
    whatruns = get_whatruns_service()
    
    try:
        techs = await whatruns.detect_technologies(hostname, url)
        
        # Group by category
        by_category = {}
        results = []
        
        for tech in techs:
            results.append({
                "name": tech.name,
                "category": tech.category,
                "website": tech.website,
                "icon": tech.icon,
                "is_theme": tech.is_theme,
                "is_plugin": tech.is_plugin,
            })
            
            cat = tech.category
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(tech.name)
        
        return {
            "hostname": hostname,
            "url": url or f"https://{hostname}/",
            "technologies": results,
            "by_category": by_category,
            "count": len(techs),
            "status": "success"
        }
        
    except Exception as e:
        logger.error(f"WhatRuns test failed for {hostname}: {e}")
        return {
            "hostname": hostname,
            "url": url,
            "technologies": [],
            "count": 0,
            "status": "error",
            "error": str(e)
        }


@router.get("/technology-stats")
def get_technology_statistics(
    organization_id: Optional[int] = Query(None, description="Filter by organization"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get technology statistics across assets.
    
    Returns counts of technologies grouped by category and name.
    """
    from sqlalchemy import func
    from app.models.technology import Technology, asset_technologies
    
    # Build query based on organization access
    if organization_id:
        if not check_org_access(current_user, organization_id):
            raise HTTPException(status_code=403, detail="Access denied")
        org_filter = Asset.organization_id == organization_id
    elif not current_user.is_superuser:
        org_filter = Asset.organization_id == current_user.organization_id
    else:
        org_filter = True
    
    # Get all assets with technologies for this org
    assets_with_tech = db.query(Asset).filter(
        org_filter,
        Asset.technologies.any()
    ).all()
    
    # Count technologies
    tech_counts = {}
    category_counts = {}
    
    for asset in assets_with_tech:
        for tech in asset.technologies:
            # Count by tech name
            if tech.name not in tech_counts:
                tech_counts[tech.name] = {"count": 0, "slug": tech.slug, "categories": tech.categories or []}
            tech_counts[tech.name]["count"] += 1
            
            # Count by category
            for cat in (tech.categories or ["Other"]):
                if cat not in category_counts:
                    category_counts[cat] = 0
                category_counts[cat] += 1
    
    # Sort by count
    sorted_techs = sorted(tech_counts.items(), key=lambda x: x[1]["count"], reverse=True)
    sorted_categories = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)
    
    return {
        "total_assets_with_technology": len(assets_with_tech),
        "unique_technologies": len(tech_counts),
        "technologies": [
            {"name": name, **data}
            for name, data in sorted_techs[:50]  # Top 50
        ],
        "by_category": dict(sorted_categories),
    }


# =============================================================================
# Cascading Scope Management
# =============================================================================

@router.post("/{asset_id}/set-scope")
def set_asset_scope_with_cascade(
    asset_id: int,
    in_scope: bool = Query(..., description="Whether to mark asset as in-scope or out-of-scope"),
    cascade_to_subdomains: bool = Query(True, description="Also update all subdomains of this domain"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Set scope for a domain and optionally cascade to all its subdomains.
    
    When a domain is marked out-of-scope, its subdomains should typically also
    be removed from scope since they belong to a domain no longer owned/tracked.
    
    The cascade uses the `root_domain` field to find related subdomains.
    
    Example:
    ```
    POST /api/v1/assets/123/set-scope?in_scope=false&cascade_to_subdomains=true
    ```
    """
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Update the main asset
    asset.in_scope = in_scope
    asset.updated_at = datetime.utcnow()

    cascaded_count = 0
    cascaded_assets = []
    findings_closed = 0

    # Auto-close open findings when going out of scope
    if not in_scope:
        findings_closed += _close_findings_for_asset(db, asset.id)

    # If this is a domain and cascade is enabled, update subdomains too
    if cascade_to_subdomains and asset.asset_type == AssetType.DOMAIN:
        subdomains = db.query(Asset).filter(
            Asset.organization_id == asset.organization_id,
            Asset.asset_type == AssetType.SUBDOMAIN,
            Asset.root_domain == asset.value
        ).all()

        for sub in subdomains:
            sub.in_scope = in_scope
            sub.updated_at = datetime.utcnow()
            cascaded_count += 1
            cascaded_assets.append({"id": sub.id, "value": sub.value})
            if not in_scope:
                findings_closed += _close_findings_for_asset(db, sub.id)

    db.commit()

    return {
        "id": asset.id,
        "value": asset.value,
        "in_scope": asset.in_scope,
        "cascaded_to_subdomains": cascade_to_subdomains,
        "subdomains_updated": cascaded_count,
        "findings_closed": findings_closed,
        "updated_subdomains": cascaded_assets[:20],
        "message": (
            f"Updated scope for {asset.value}"
            + (f" and {cascaded_count} subdomains" if cascaded_count else "")
            + (f"; {findings_closed} finding(s) auto-accepted" if findings_closed else "")
        ),
    }


@router.delete("/{asset_id}/with-subdomains")
def delete_asset_with_subdomains(
    asset_id: int,
    confirm: bool = Query(False, description="Must be true to actually delete"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Delete a domain and all its subdomains.
    
    This is useful when a domain is no longer owned and should be completely
    removed from the attack surface along with all its subdomains.
    
    Pass confirm=true to actually delete. Without it, returns a preview of what would be deleted.
    
    Example:
    ```
    DELETE /api/v1/assets/123/with-subdomains?confirm=true
    ```
    """
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Find all subdomains that belong to this root domain
    subdomains = []
    if asset.asset_type == AssetType.DOMAIN:
        subdomains = db.query(Asset).filter(
            Asset.organization_id == asset.organization_id,
            Asset.asset_type == AssetType.SUBDOMAIN,
            Asset.root_domain == asset.value
        ).all()
    
    total_to_delete = 1 + len(subdomains)
    
    if not confirm:
        return {
            "would_delete": total_to_delete,
            "domain": {"id": asset.id, "value": asset.value},
            "subdomains": [{"id": s.id, "value": s.value} for s in subdomains[:50]],
            "subdomains_count": len(subdomains),
            "message": f"Would delete {asset.value} and {len(subdomains)} subdomains. Set confirm=true to proceed."
        }
    
    # Delete subdomains first
    for sub in subdomains:
        db.delete(sub)
    
    # Delete the main asset
    db.delete(asset)
    
    db.commit()
    
    return {
        "deleted": total_to_delete,
        "domain": asset.value,
        "subdomains_deleted": len(subdomains),
        "message": f"Deleted {asset.value} and {len(subdomains)} subdomains"
    }


@router.post("/bulk-set-scope")
def bulk_set_scope_with_cascade(
    asset_ids: List[int],
    in_scope: bool = Query(..., description="Whether to mark assets as in-scope or out-of-scope"),
    cascade_to_subdomains: bool = Query(True, description="Also update subdomains of any domains in the list"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Bulk update scope for multiple assets with optional cascade to subdomains.
    
    For each DOMAIN asset in the list, if cascade_to_subdomains is true,
    all subdomains matching that root_domain will also be updated.
    
    Example:
    ```
    POST /api/v1/assets/bulk-set-scope?in_scope=false&cascade_to_subdomains=true
    Body: [1, 2, 3]
    ```
    """
    updated_count = 0
    cascaded_count = 0
    findings_closed = 0
    errors = []
    
    # Get all requested assets
    assets = db.query(Asset).filter(Asset.id.in_(asset_ids)).all()
    
    # Build lookup for access checking
    asset_map = {a.id: a for a in assets}
    
    for asset_id in asset_ids:
        asset = asset_map.get(asset_id)
        if not asset:
            errors.append(f"Asset {asset_id} not found")
            continue
        
        if not check_org_access(current_user, asset.organization_id):
            errors.append(f"Asset {asset_id} access denied")
            continue
        
        # Update the asset
        asset.in_scope = in_scope
        asset.updated_at = datetime.utcnow()
        updated_count += 1

        # Auto-close open findings when going out of scope
        if not in_scope:
            findings_closed += _close_findings_for_asset(db, asset.id)

        # Cascade to subdomains if this is a domain
        if cascade_to_subdomains and asset.asset_type == AssetType.DOMAIN:
            subdomains = db.query(Asset).filter(
                Asset.organization_id == asset.organization_id,
                Asset.asset_type == AssetType.SUBDOMAIN,
                Asset.root_domain == asset.value,
            ).all()
            for sub in subdomains:
                sub.in_scope = in_scope
                sub.updated_at = datetime.utcnow()
                cascaded_count += 1
                if not in_scope:
                    findings_closed += _close_findings_for_asset(db, sub.id)

    db.commit()

    return {
        "updated": updated_count,
        "cascaded_subdomains": cascaded_count,
        "findings_closed": findings_closed,
        "total_affected": updated_count + cascaded_count,
        "in_scope": in_scope,
        "errors": errors[:10] if errors else [],
        "message": (
            f"Updated {updated_count} assets"
            + (f" and {cascaded_count} subdomains" if cascaded_count else "")
            + (f"; {findings_closed} finding(s) auto-accepted" if findings_closed else "")
        ),
    }


# =============================================================================
# Risk Driver Endpoints
# =============================================================================

@router.post("/{asset_id}/calculate-risk-drivers")
async def calculate_asset_risk_drivers(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Calculate and update risk drivers for a single asset.
    
    Risk drivers are calculated based on:
    - Login portal detection
    - High-risk technologies (SAP, databases, admin panels, etc.)
    - Risky open ports
    - Vulnerability count and severity
    - Public accessibility
    - Hosting classification
    
    The results are stored in the asset's acs_drivers field.
    """
    from app.services.risk_driver_service import get_risk_driver_service
    
    asset = db.query(Asset).options(
        selectinload(Asset.technologies),
        selectinload(Asset.port_services),
        selectinload(Asset.vulnerabilities)
    ).filter(Asset.id == asset_id).first()
    
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    service = get_risk_driver_service(db)
    drivers = service.update_asset_risk_drivers(asset)
    
    return {
        "asset_id": asset_id,
        "value": asset.value,
        "acs_score": asset.acs_score,
        "risk_drivers": drivers
    }


@router.post("/calculate-risk-drivers")
async def calculate_all_risk_drivers(
    organization_id: Optional[int] = Query(None, description="Filter by organization"),
    limit: int = Query(500, ge=1, le=5000, description="Maximum assets to process"),
    background_tasks: BackgroundTasks = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Calculate and update risk drivers for multiple assets.
    
    This analyzes each asset's:
    - Login portals
    - Technologies
    - Risky ports
    - Vulnerabilities
    - Public accessibility
    
    And populates the acs_drivers field with meaningful risk factors.
    """
    from app.services.risk_driver_service import get_risk_driver_service
    
    # Validate org access if specified
    if organization_id and not current_user.is_superuser:
        if current_user.organization_id != organization_id:
            raise HTTPException(status_code=403, detail="Access denied")
    
    # Build query
    query = db.query(Asset).options(
        selectinload(Asset.technologies),
        selectinload(Asset.port_services),
        selectinload(Asset.vulnerabilities)
    )
    
    if organization_id:
        query = query.filter(Asset.organization_id == organization_id)
    elif not current_user.is_superuser:
        query = query.filter(Asset.organization_id == current_user.organization_id)
    
    assets = query.limit(limit).all()
    
    service = get_risk_driver_service(db)
    
    stats = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    
    for asset in assets:
        drivers = service.update_asset_risk_drivers(asset)
        stats["total"] += 1
        
        overall = drivers.get("overall_risk", {})
        risk_level = overall.get("level", "low")
        if risk_level in stats:
            stats[risk_level] += 1
    
    return {
        "message": f"Calculated risk drivers for {stats['total']} assets",
        "statistics": stats
    }


# =============================================================================
# ASSET MERGE ENDPOINTS
# =============================================================================

@router.get("/merge/preview")
def preview_asset_merges(
    organization_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Preview which assets would be merged.
    
    Shows:
    - IP assets that should be merged into their parent domain
    - Duplicate domain/subdomain records
    
    No changes are made - this is a dry run.
    """
    from app.services.asset_merge_service import get_asset_merge_service
    
    # Use org from user if not specified
    if not organization_id and not current_user.is_superuser:
        organization_id = current_user.organization_id
    
    if not organization_id:
        raise HTTPException(status_code=400, detail="organization_id required")
    
    service = get_asset_merge_service(db)
    results = service.find_mergeable_assets(organization_id)
    
    return {
        "organization_id": organization_id,
        "preview": results,
        "message": f"Found {results['total_mergeable']} assets that can be merged",
    }


@router.post("/merge/execute")
def execute_asset_merges(
    organization_id: Optional[int] = None,
    merge_ips: bool = Query(True, description="Merge IP assets into parent domains"),
    merge_duplicates: bool = Query(True, description="Merge duplicate domain records"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Execute asset merges for an organization.
    
    This will:
    1. Merge IP assets into their parent domain assets
       - Move vulnerabilities, ports, and screenshots to the domain
       - Delete the IP asset
    2. Merge duplicate domain records
       - Consolidate to the oldest record
       - Move all findings to the primary
    
    Use /merge/preview first to see what will be merged.
    """
    from app.services.asset_merge_service import get_asset_merge_service
    
    # Use org from user if not specified
    if not organization_id and not current_user.is_superuser:
        organization_id = current_user.organization_id
    
    if not organization_id:
        raise HTTPException(status_code=400, detail="organization_id required")
    
    service = get_asset_merge_service(db)
    
    # Get mergeable assets
    mergeable = service.find_mergeable_assets(organization_id)
    
    results = {
        "organization_id": organization_id,
        "ip_merges": [],
        "domain_merges": [],
        "errors": [],
    }
    
    # Execute IP to domain merges
    if merge_ips:
        for merge in mergeable["ip_to_domain_merges"]:
            try:
                result = service.merge_ip_into_domain(
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
    if merge_duplicates:
        for dup in mergeable["duplicate_domains"]:
            try:
                result = service.merge_duplicate_domains(dup["asset_ids"])
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


@router.post("/merge/specific")
def merge_specific_assets(
    source_asset_id: int = Query(..., description="Asset to merge FROM (will be deleted)"),
    target_asset_id: int = Query(..., description="Asset to merge INTO (will be kept)"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Merge a specific source asset into a target asset.
    
    The source asset's findings, ports, and screenshots are moved to the target.
    The source asset is then deleted.
    
    Use this for manual merges when automatic detection doesn't work.
    """
    from app.services.asset_merge_service import get_asset_merge_service
    
    # Verify both assets exist and user has access
    source = db.query(Asset).filter(Asset.id == source_asset_id).first()
    target = db.query(Asset).filter(Asset.id == target_asset_id).first()
    
    if not source:
        raise HTTPException(status_code=404, detail=f"Source asset {source_asset_id} not found")
    if not target:
        raise HTTPException(status_code=404, detail=f"Target asset {target_asset_id} not found")
    
    if source.organization_id != target.organization_id:
        raise HTTPException(status_code=400, detail="Assets must belong to the same organization")
    
    if not current_user.is_superuser and current_user.organization_id != source.organization_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    service = get_asset_merge_service(db)
    
    # Determine merge type
    if source.asset_type == AssetType.IP_ADDRESS and target.asset_type in [AssetType.DOMAIN, AssetType.SUBDOMAIN]:
        result = service.merge_ip_into_domain(source_asset_id, target_asset_id, delete_ip_asset=True)
    else:
        # Generic merge (treat source as duplicate of target)
        result = service.merge_duplicate_domains([target_asset_id, source_asset_id])
    
    return {
        "success": True,
        "result": result,
        "message": f"Merged asset {source.value} into {target.value}",
    }


@router.post("/fix-ip-fields")
def fix_ip_address_fields(
    organization_id: Optional[int] = Query(None, description="Limit to specific organization"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Fix IP_ADDRESS assets that don't have their ip_address field populated.
    
    For IP_ADDRESS type assets, the value field contains the IP, but the
    ip_address and ip_addresses fields should also be populated for consistency.
    This endpoint fixes any assets where that data is missing.
    """
    from sqlalchemy import or_
    
    # Build query for IP assets with missing ip_address field
    query = db.query(Asset).filter(
        Asset.asset_type == AssetType.IP_ADDRESS,
        or_(
            Asset.ip_address.is_(None),
            Asset.ip_address == ''
        )
    )
    
    if organization_id:
        if not check_org_access(current_user, organization_id):
            raise HTTPException(status_code=403, detail="Access denied to this organization")
        query = query.filter(Asset.organization_id == organization_id)
    elif not current_user.is_superuser:
        query = query.filter(Asset.organization_id == current_user.organization_id)
    
    # Get assets to fix
    assets_to_fix = query.all()
    
    fixed_count = 0
    for asset in assets_to_fix:
        if asset.value:
            asset.ip_address = asset.value
            if not asset.ip_addresses or asset.value not in asset.ip_addresses:
                asset.ip_addresses = [asset.value] if not asset.ip_addresses else asset.ip_addresses + [asset.value]
            fixed_count += 1
    
    db.commit()
    
    return {
        "success": True,
        "fixed_count": fixed_count,
        "message": f"Fixed {fixed_count} IP_ADDRESS assets with missing ip_address field"
    }
