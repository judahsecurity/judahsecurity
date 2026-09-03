"""Port and Service routes for asset reporting."""

import logging
from typing import Optional, List
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, and_
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger(__name__)

from app.db.database import get_db
from app.models.user import User
from app.models.asset import Asset
from app.models.scan import Scan, ScanType, ScanStatus
from app.models.port_service import (
    PortService, Protocol, PortState, 
    RISKY_PORTS, SERVICE_NAMES
)
from app.schemas.port_service import (
    PortServiceCreate,
    PortServiceUpdate,
    PortServiceResponse,
    PortServiceBulkCreate,
    PortServiceSummary,
    PortsByAssetReport,
    PortDistributionReport,
    ServiceDistributionReport,
    RiskyPortsReport,
    ExposedServicesReport,
    PortSearchRequest
)
from app.schemas.port_scanner import (
    PortScanRequest,
    PortScanResultResponse,
    HostResult,
    ImportPortsRequest,
    ImportPortsResponse,
    ScannerStatusResponse
)
from app.schemas.port_findings import (
    GenerateFindingsRequest,
    GenerateFindingsResponse,
    PortRiskSummary
)
from app.services.port_scanner_service import PortScannerService, ScannerType
from app.services.port_findings_service import PortFindingsService, PORT_FINDING_RULES
from app.api.deps import get_current_active_user, require_analyst

router = APIRouter(prefix="/ports", tags=["Ports & Services"])


def check_org_access(user: User, org_id: int) -> bool:
    """Check if user has access to organization."""
    if user.is_superuser:
        return True
    return user.organization_id == org_id


# ==================== CRUD OPERATIONS ====================

@router.get("/", response_model=List[PortServiceResponse])
def list_port_services(
    asset_id: Optional[int] = None,
    organization_id: Optional[int] = None,
    port: Optional[int] = None,
    protocol: Optional[Protocol] = None,
    service: Optional[str] = None,
    state: Optional[PortState] = None,
    is_risky: Optional[bool] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List port services with filtering."""
    query = db.query(PortService).join(Asset)
    
    # Organization filter
    if current_user.is_superuser and organization_id:
        query = query.filter(Asset.organization_id == organization_id)
    elif not current_user.is_superuser:
        if not current_user.organization_id:
            return []
        query = query.filter(Asset.organization_id == current_user.organization_id)
    
    # Apply filters
    if asset_id:
        query = query.filter(PortService.asset_id == asset_id)
    if port:
        query = query.filter(PortService.port == port)
    if protocol:
        query = query.filter(PortService.protocol == protocol)
    if service:
        query = query.filter(PortService.service_name.ilike(f"%{service}%"))
    if state:
        query = query.filter(PortService.state == state)
    if is_risky is not None:
        query = query.filter(PortService.is_risky == is_risky)
    
    ports = query.order_by(PortService.last_seen.desc()).offset(skip).limit(limit).all()
    
    # Add computed fields and asset info
    results = []
    for p in ports:
        # Build response with asset info
        response = PortServiceResponse(
            id=p.id,
            asset_id=p.asset_id,
            port=p.port,
            protocol=p.protocol,
            service_name=p.service_name,
            service_product=p.service_product,
            service_version=p.service_version,
            service_extra_info=p.service_extra_info,
            cpe=p.cpe,
            banner=p.banner,
            state=p.state,
            reason=p.reason,
            discovered_by=p.discovered_by,
            first_seen=p.first_seen or datetime.utcnow(),
            last_seen=p.last_seen or datetime.utcnow(),
            is_ssl=p.is_ssl or False,
            ssl_version=p.ssl_version,
            ssl_cipher=p.ssl_cipher,
            ssl_cert_subject=p.ssl_cert_subject,
            ssl_cert_issuer=p.ssl_cert_issuer,
            ssl_cert_expiry=p.ssl_cert_expiry,
            is_risky=p.is_risky or False,
            risk_reason=p.risk_reason,
            tags=p.tags or [],
            port_string=p.port_string,
            display_name=p.display_name,
            created_at=p.created_at or datetime.utcnow(),
            updated_at=p.updated_at or datetime.utcnow(),
            # Nmap verification
            verified=p.verified or False,
            verified_at=p.verified_at,
            verified_state=p.verified_state,
            verification_scanner=p.verification_scanner,
            scanned_ip=p.scanned_ip,
            # Add asset info
            hostname=p.asset.name if p.asset else None,
            ip_address=p.asset.value if p.asset else None,
            asset_value=p.asset.value if p.asset else None,
        )
        results.append(response)
    
    return results


@router.post("/", response_model=PortServiceResponse, status_code=status.HTTP_201_CREATED)
def create_port_service(
    port_data: PortServiceCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Create a new port service entry."""
    # Verify asset exists and user has access
    asset = db.query(Asset).filter(Asset.id == port_data.asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Check for existing port-protocol combination
    existing = db.query(PortService).filter(
        PortService.asset_id == port_data.asset_id,
        PortService.port == port_data.port,
        PortService.protocol == port_data.protocol
    ).first()
    
    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"Port {port_data.port}/{port_data.protocol.value} already exists for this asset"
        )
    
    # Auto-detect service name if not provided
    if not port_data.service_name and port_data.port in SERVICE_NAMES:
        port_data.service_name = SERVICE_NAMES[port_data.port]
    
    # Auto-flag risky ports
    if port_data.port in RISKY_PORTS and not port_data.is_risky:
        port_data.is_risky = True
        port_data.risk_reason = RISKY_PORTS[port_data.port]
    
    port_service = PortService(**port_data.model_dump(by_alias=True))
    db.add(port_service)
    db.commit()
    db.refresh(port_service)
    
    port_service.port_string = port_service.port_string
    port_service.display_name = port_service.display_name
    
    return port_service


@router.post("/bulk", response_model=List[PortServiceResponse], status_code=status.HTTP_201_CREATED)
def create_port_services_bulk(
    bulk_data: PortServiceBulkCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Create multiple port services for an asset."""
    # Verify asset exists and user has access
    asset = db.query(Asset).filter(Asset.id == bulk_data.asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    created = []
    for port_data in bulk_data.ports:
        # Check for existing
        existing = db.query(PortService).filter(
            PortService.asset_id == bulk_data.asset_id,
            PortService.port == port_data.port,
            PortService.protocol == port_data.protocol
        ).first()
        
        if existing:
            # Update existing
            existing.last_seen = datetime.utcnow()
            existing.state = port_data.state
            if port_data.service_name:
                existing.service_name = port_data.service_name
            created.append(existing)
        else:
            # Auto-detect service name
            if not port_data.service_name and port_data.port in SERVICE_NAMES:
                port_data.service_name = SERVICE_NAMES[port_data.port]
            
            # Auto-flag risky
            if port_data.port in RISKY_PORTS:
                port_data.is_risky = True
                port_data.risk_reason = RISKY_PORTS[port_data.port]
            
            port_data.asset_id = bulk_data.asset_id
            port_service = PortService(**port_data.model_dump(by_alias=True))
            db.add(port_service)
            created.append(port_service)
    
    db.commit()
    
    for p in created:
        db.refresh(p)
        p.port_string = p.port_string
        p.display_name = p.display_name
    
    return created


@router.get("/{port_id}", response_model=PortServiceResponse)
def get_port_service(
    port_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get a specific port service."""
    port_service = db.query(PortService).filter(PortService.id == port_id).first()
    
    if not port_service:
        raise HTTPException(status_code=404, detail="Port service not found")
    
    asset = db.query(Asset).filter(Asset.id == port_service.asset_id).first()
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    port_service.port_string = port_service.port_string
    port_service.display_name = port_service.display_name
    
    return port_service


@router.put("/{port_id}", response_model=PortServiceResponse)
def update_port_service(
    port_id: int,
    port_data: PortServiceUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Update a port service."""
    port_service = db.query(PortService).filter(PortService.id == port_id).first()
    
    if not port_service:
        raise HTTPException(status_code=404, detail="Port service not found")
    
    asset = db.query(Asset).filter(Asset.id == port_service.asset_id).first()
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    update_data = port_data.model_dump(exclude_unset=True, by_alias=True)
    for field, value in update_data.items():
        setattr(port_service, field, value)
    
    db.commit()
    db.refresh(port_service)
    
    port_service.port_string = port_service.port_string
    port_service.display_name = port_service.display_name
    
    return port_service


@router.delete("/{port_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_port_service(
    port_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Delete a port service."""
    port_service = db.query(PortService).filter(PortService.id == port_id).first()
    
    if not port_service:
        raise HTTPException(status_code=404, detail="Port service not found")
    
    asset = db.query(Asset).filter(Asset.id == port_service.asset_id).first()
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    db.delete(port_service)
    db.commit()
    
    return None


@router.post("/{port_id}/create-finding")
def create_finding_from_port(
    port_id: int,
    severity: str = Query("medium", description="Finding severity: critical, high, medium, low, info"),
    title: Optional[str] = None,
    description: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Create a security finding from a specific port.
    
    Allows analysts to manually flag a port as a security issue
    when automated rules don't catch it.
    """
    from app.models.finding import Finding, Severity, FindingStatus
    
    port_service = db.query(PortService).filter(PortService.id == port_id).first()
    
    if not port_service:
        raise HTTPException(status_code=404, detail="Port service not found")
    
    asset = db.query(Asset).filter(Asset.id == port_service.asset_id).first()
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Map severity string to enum
    severity_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    finding_severity = severity_map.get(severity.lower(), Severity.MEDIUM)
    
    # Generate title if not provided
    if not title:
        service_name = port_service.service_name or "Unknown service"
        title = f"Exposed {service_name} on port {port_service.port}/{port_service.protocol.value}"
    
    # Generate description if not provided
    if not description:
        description = f"""An exposed service was manually flagged for review.

**Asset:** {asset.value}
**Port:** {port_service.port}/{port_service.protocol.value}
**Service:** {port_service.service_name or 'Unknown'}
**Product:** {port_service.service_product or 'Unknown'}
**Version:** {port_service.service_version or 'Unknown'}
**State:** {port_service.state.value}

This port was flagged by an analyst as potentially risky and requires review."""
    
    # Check for existing finding for this port
    existing = db.query(Finding).filter(
        Finding.asset_id == asset.id,
        Finding.metadata_.contains({"port": port_service.port}),
        Finding.status != FindingStatus.RESOLVED
    ).first()
    
    if existing:
        return {
            "success": False,
            "message": f"Finding already exists for this port (ID: {existing.id})",
            "finding_id": existing.id,
            "duplicate": True
        }
    
    # Create the finding
    finding = Finding(
        title=title,
        description=description,
        severity=finding_severity,
        status=FindingStatus.OPEN,
        finding_type="exposed_port",
        asset_id=asset.id,
        organization_id=asset.organization_id,
        source="manual",
        metadata_={
            "port": port_service.port,
            "protocol": port_service.protocol.value,
            "service": port_service.service_name,
            "product": port_service.service_product,
            "version": port_service.service_version,
            "port_service_id": port_service.id,
            "created_by": current_user.username,
        },
        remediation=f"Review if port {port_service.port} ({port_service.service_name or 'unknown service'}) should be exposed. If not needed, disable the service or restrict access via firewall rules.",
        cwe_id="CWE-200",
        tags=["exposed-port", "manual-finding"],
    )
    
    db.add(finding)
    
    # Mark the port as risky
    port_service.is_risky = True
    port_service.risk_reason = f"Manually flagged - {severity} severity"
    
    db.commit()
    db.refresh(finding)
    
    return {
        "success": True,
        "message": f"Finding created for port {port_service.port}",
        "finding_id": finding.id,
        "finding_title": finding.title,
        "severity": finding.severity.value,
    }


@router.post("/{port_id}/mark-risky")
def mark_port_as_risky(
    port_id: int,
    reason: str = Query(..., description="Reason why this port is risky"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Mark a port as risky without creating a full finding."""
    port_service = db.query(PortService).filter(PortService.id == port_id).first()
    
    if not port_service:
        raise HTTPException(status_code=404, detail="Port service not found")
    
    asset = db.query(Asset).filter(Asset.id == port_service.asset_id).first()
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    port_service.is_risky = True
    port_service.risk_reason = reason
    
    db.commit()
    
    return {
        "success": True,
        "message": f"Port {port_service.port} marked as risky",
        "port_id": port_id,
        "risk_reason": reason
    }


# ==================== REPORTING ENDPOINTS ====================

@router.get("/report/by-asset/{asset_id}", response_model=PortsByAssetReport)
def get_ports_by_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get all ports for a specific asset."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    ports = db.query(PortService).filter(PortService.asset_id == asset_id).all()
    
    return PortsByAssetReport(
        asset_id=asset.id,
        asset_name=asset.name,
        asset_value=asset.value,
        total_ports=len(ports),
        open_ports=len([p for p in ports if p.state == PortState.OPEN]),
        risky_ports=len([p for p in ports if p.is_risky]),
        ports=[
            PortServiceSummary(
                port=p.port,
                protocol=p.protocol.value,
                service=p.service_name,
                product=p.service_product,
                version=p.service_version,
                state=p.state.value,
                is_ssl=p.is_ssl,
                is_risky=p.is_risky
            )
            for p in sorted(ports, key=lambda x: x.port)
        ]
    )


@router.get("/report/distribution/ports", response_model=List[PortDistributionReport])
def get_port_distribution(
    organization_id: Optional[int] = None,
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get distribution of ports across all assets."""
    query = db.query(
        PortService.port,
        PortService.protocol,
        PortService.service_name,
        func.count(PortService.id).label('count')
    ).join(Asset)
    
    # Organization filter
    if current_user.is_superuser and organization_id:
        query = query.filter(Asset.organization_id == organization_id)
    elif not current_user.is_superuser:
        if not current_user.organization_id:
            return []
        query = query.filter(Asset.organization_id == current_user.organization_id)
    
    results = query.group_by(
        PortService.port, 
        PortService.protocol, 
        PortService.service_name
    ).order_by(func.count(PortService.id).desc()).limit(limit).all()
    
    # Get assets for each port
    distribution = []
    for port, protocol, service, count in results:
        assets_query = db.query(Asset.value).join(PortService).filter(
            PortService.port == port,
            PortService.protocol == protocol
        )
        if not current_user.is_superuser:
            assets_query = assets_query.filter(Asset.organization_id == current_user.organization_id)
        
        asset_values = [a[0] for a in assets_query.limit(10).all()]
        
        distribution.append(PortDistributionReport(
            port=port,
            protocol=protocol.value,
            service=service,
            count=count,
            assets=asset_values
        ))
    
    return distribution


@router.get("/report/distribution/services", response_model=List[ServiceDistributionReport])
def get_service_distribution(
    organization_id: Optional[int] = None,
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get distribution of services across all assets."""
    query = db.query(
        PortService.service_name,
        func.count(PortService.id).label('count')
    ).join(Asset).filter(PortService.service_name.isnot(None))
    
    # Organization filter
    if current_user.is_superuser and organization_id:
        query = query.filter(Asset.organization_id == organization_id)
    elif not current_user.is_superuser:
        if not current_user.organization_id:
            return []
        query = query.filter(Asset.organization_id == current_user.organization_id)
    
    results = query.group_by(PortService.service_name).order_by(
        func.count(PortService.id).desc()
    ).limit(limit).all()
    
    distribution = []
    for service, count in results:
        # Get ports and assets for this service
        ports_query = db.query(PortService.port).filter(
            PortService.service_name == service
        ).distinct()
        ports = [p[0] for p in ports_query.all()]
        
        assets_query = db.query(Asset.value).join(PortService).filter(
            PortService.service_name == service
        )
        if not current_user.is_superuser:
            assets_query = assets_query.filter(Asset.organization_id == current_user.organization_id)
        asset_values = [a[0] for a in assets_query.distinct().limit(10).all()]
        
        distribution.append(ServiceDistributionReport(
            service=service,
            count=count,
            ports=ports,
            assets=asset_values
        ))
    
    return distribution


@router.get("/report/risky", response_model=RiskyPortsReport)
def get_risky_ports_report(
    organization_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get report of risky/dangerous exposed ports."""
    query = db.query(PortService).join(Asset).filter(PortService.is_risky == True)
    
    # Organization filter
    if current_user.is_superuser and organization_id:
        query = query.filter(Asset.organization_id == organization_id)
    elif not current_user.is_superuser:
        if not current_user.organization_id:
            return RiskyPortsReport(total_risky_ports=0, by_risk_type={}, ports=[])
        query = query.filter(Asset.organization_id == current_user.organization_id)
    
    risky_ports = query.all()
    
    # Group by risk reason
    by_risk_type = {}
    ports_list = []
    
    for port in risky_ports:
        reason = port.risk_reason or "Unknown risk"
        by_risk_type[reason] = by_risk_type.get(reason, 0) + 1
        
        ports_list.append({
            "id": port.id,
            "port": port.port,
            "protocol": port.protocol.value,
            "service": port.service_name,
            "asset": port.asset.value if port.asset else None,
            "risk_reason": port.risk_reason,
            "state": port.state.value
        })
    
    return RiskyPortsReport(
        total_risky_ports=len(risky_ports),
        by_risk_type=by_risk_type,
        ports=ports_list
    )


@router.get("/report/summary", response_model=ExposedServicesReport)
def get_exposed_services_summary(
    organization_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get comprehensive summary of all exposed services."""
    base_query = db.query(PortService).join(Asset)
    
    # Organization filter
    if current_user.is_superuser and organization_id:
        base_query = base_query.filter(Asset.organization_id == organization_id)
    elif not current_user.is_superuser:
        if not current_user.organization_id:
            return ExposedServicesReport(
                total_assets=0, total_ports=0, total_services=0, risky_ports_count=0,
                top_ports=[], top_services=[], tcp_ports=0, udp_ports=0,
                open_ports=0, filtered_ports=0, risky_ports=[], 
                ssl_enabled_ports=0, expiring_certs=0
            )
        base_query = base_query.filter(Asset.organization_id == current_user.organization_id)
    
    all_ports = base_query.all()
    
    # Calculate statistics
    unique_assets = len(set(p.asset_id for p in all_ports))
    unique_services = len(set(p.service_name for p in all_ports if p.service_name))
    
    # By protocol
    tcp_count = len([p for p in all_ports if p.protocol == Protocol.TCP])
    udp_count = len([p for p in all_ports if p.protocol == Protocol.UDP])
    
    # By state
    open_count = len([p for p in all_ports if p.state == PortState.OPEN])
    filtered_count = len([p for p in all_ports if p.state in [PortState.FILTERED, PortState.OPEN_FILTERED]])
    
    # Risky
    risky = [p for p in all_ports if p.is_risky]
    
    # SSL stats
    ssl_enabled = len([p for p in all_ports if p.is_ssl])
    expiring_soon = len([p for p in all_ports if p.ssl_cert_expiry and 
                         p.ssl_cert_expiry < datetime.utcnow() + timedelta(days=30)])
    
    # Top ports
    port_counts = {}
    for p in all_ports:
        key = (p.port, p.protocol.value)
        port_counts[key] = port_counts.get(key, 0) + 1
    
    top_ports = [
        {"port": k[0], "protocol": k[1], "count": v}
        for k, v in sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    ]
    
    # Top services
    service_counts = {}
    for p in all_ports:
        if p.service_name:
            service_counts[p.service_name] = service_counts.get(p.service_name, 0) + 1
    
    top_services = [
        {"service": k, "count": v}
        for k, v in sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    ]
    
    # Risky ports list
    risky_ports_list = [
        {
            "port": p.port,
            "protocol": p.protocol.value,
            "service": p.service_name,
            "asset": p.asset.value if p.asset else None,
            "reason": p.risk_reason
        }
        for p in risky[:20]  # Limit to 20
    ]
    
    return ExposedServicesReport(
        total_assets=unique_assets,
        total_ports=len(all_ports),
        total_services=unique_services,
        risky_ports_count=len(risky),
        top_ports=top_ports,
        top_services=top_services,
        tcp_ports=tcp_count,
        udp_ports=udp_count,
        open_ports=open_count,
        filtered_ports=filtered_count,
        risky_ports=risky_ports_list,
        ssl_enabled_ports=ssl_enabled,
        expiring_certs=expiring_soon
    )


@router.post("/search")
def search_ports(
    search: PortSearchRequest,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Search ports with advanced filtering."""
    query = db.query(PortService).join(Asset)
    
    # Organization filter
    if search.organization_id:
        if not current_user.is_superuser and current_user.organization_id != search.organization_id:
            raise HTTPException(status_code=403, detail="Access denied")
        query = query.filter(Asset.organization_id == search.organization_id)
    elif not current_user.is_superuser:
        if not current_user.organization_id:
            return {"total": 0, "results": []}
        query = query.filter(Asset.organization_id == current_user.organization_id)
    
    # Apply filters
    if search.ports:
        query = query.filter(PortService.port.in_(search.ports))
    if search.protocols:
        query = query.filter(PortService.protocol.in_(search.protocols))
    if search.services:
        query = query.filter(PortService.service_name.in_(search.services))
    if search.state:
        query = query.filter(PortService.state == search.state)
    if search.is_risky is not None:
        query = query.filter(PortService.is_risky == search.is_risky)
    if search.is_ssl is not None:
        query = query.filter(PortService.is_ssl == search.is_ssl)
    if search.asset_ids:
        query = query.filter(PortService.asset_id.in_(search.asset_ids))
    
    total = query.count()
    results = query.offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "results": [
            {
                "id": p.id,
                "port": p.port,
                "protocol": p.protocol.value,
                "service": p.service_name,
                "product": p.service_product,
                "version": p.service_version,
                "state": p.state.value,
                "is_ssl": p.is_ssl,
                "is_risky": p.is_risky,
                "asset_id": p.asset_id,
                "asset_value": p.asset.value if p.asset else None
            }
            for p in results
        ]
    }


# ==================== PORT SCANNING ====================

@router.get("/scanners/status", response_model=ScannerStatusResponse)
def get_scanner_status(
    current_user: User = Depends(get_current_active_user)
):
    """
    Check which port scanning tools are available.
    
    Supports:
    - naabu: Fast port scanner from ProjectDiscovery
    - masscan: Mass IP port scanner
    - nmap: Network exploration and security auditing
    """
    scanner_service = PortScannerService()
    status = scanner_service.check_tools()
    
    return ScannerStatusResponse(
        naabu=status.get("naabu", False),
        masscan=status.get("masscan", False),
        nmap=status.get("nmap", False)
    )


@router.get("/scanners/network-test")
async def test_network_connectivity(
    target: str = Query("8.8.8.8", description="Target to test connectivity"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Test network connectivity from the scanner container.
    
    Useful for diagnosing scanning issues like:
    - DNS resolution problems
    - Firewall blocking
    - Network timeouts
    """
    import subprocess
    import socket
    
    results = {
        "target": target,
        "dns_resolution": None,
        "tcp_connectivity": {},
        "ping": None,
        "errors": []
    }
    
    # DNS resolution test
    try:
        resolved_ips = socket.gethostbyname_ex(target)
        results["dns_resolution"] = {
            "success": True,
            "hostname": resolved_ips[0],
            "aliases": resolved_ips[1],
            "ips": resolved_ips[2]
        }
    except socket.gaierror as e:
        results["dns_resolution"] = {"success": False, "error": str(e)}
        results["errors"].append(f"DNS resolution failed: {e}")
    
    # TCP connectivity test on common ports
    test_ports = [80, 443, 22]
    for port in test_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target, port))
            results["tcp_connectivity"][port] = {
                "success": result == 0,
                "state": "open" if result == 0 else "closed/filtered"
            }
            sock.close()
        except Exception as e:
            results["tcp_connectivity"][port] = {"success": False, "error": str(e)}
    
    # Ping test (may not work in all containers)
    try:
        proc = subprocess.run(
            ["ping", "-c", "1", "-W", "3", target],
            capture_output=True,
            text=True,
            timeout=5
        )
        results["ping"] = {
            "success": proc.returncode == 0,
            "output": proc.stdout[:500] if proc.returncode == 0 else proc.stderr[:500]
        }
    except Exception as e:
        results["ping"] = {"success": False, "error": str(e)}
    
    # Quick naabu test
    try:
        proc = subprocess.run(
            ["naabu", "-host", target, "-p", "80,443", "-scan-type", "c", "-silent", "-json"],
            capture_output=True,
            text=True,
            timeout=30
        )
        results["naabu_test"] = {
            "success": proc.returncode == 0,
            "output": proc.stdout[:1000] if proc.stdout else None,
            "errors": proc.stderr[:500] if proc.stderr else None
        }
    except Exception as e:
        results["naabu_test"] = {"success": False, "error": str(e)}
    
    return results


@router.post("/scan", response_model=PortScanResultResponse)
async def run_port_scan(
    request: PortScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Run a port scan using the specified scanner.
    
    Available scanners:
    - **naabu**: Fast port scanner from ProjectDiscovery (default)
    - **masscan**: Mass IP port scanner (fastest, requires root)
    - **nmap**: Most feature-rich with service detection
    
    Results are automatically imported to the database and associated with assets.
    """
    # Check organization access
    if not check_org_access(current_user, request.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this organization"
        )
    
    scanner_service = PortScannerService()
    
    # Check if scanner is available
    tools = scanner_service.check_tools()
    if not tools.get(request.scanner.value, False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"{request.scanner.value} is not installed"
        )
    
    # Create scan record
    scan = Scan(
        name=f"Port Scan ({request.scanner.value}): {len(request.targets)} targets",
        scan_type=ScanType.PORT_SCAN,
        organization_id=request.organization_id,
        targets=request.targets,
        config={
            "scanner": request.scanner.value,
            "ports": request.ports,
            "rate": request.rate,
            **({
                "nmap_scan_type": request.nmap_scan_type,
                "timing": request.timing,
                "service_detection": request.service_detection,
                "os_detection": request.os_detection,
                "nse_scripts": request.nse_scripts,
            } if request.scanner == ScannerType.NMAP else {}),
        },
        started_by=current_user.username,
        status=ScanStatus.RUNNING,
        started_at=datetime.utcnow()
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        # Run scan based on scanner type
        if request.scanner == ScannerType.NAABU:
            result = await scanner_service.scan_with_naabu(
                targets=request.targets,
                ports=request.ports,
                top_ports=request.top_ports,
                rate=request.rate,
                exclude_cdn=request.exclude_cdn
            )
        elif request.scanner == ScannerType.MASSCAN:
            result = await scanner_service.scan_with_masscan(
                targets=request.targets,
                ports=request.ports or "1-65535",
                rate=request.rate
            )
        elif request.scanner == ScannerType.NMAP:
            result = await scanner_service.scan_with_nmap(
                targets=request.targets,
                ports=request.ports,
                scan_type=request.nmap_scan_type,
                service_detection=request.service_detection,
                os_detection=request.os_detection,
                timing=request.timing,
                scripts=request.nse_scripts or None,
            )
        else:
            raise HTTPException(status_code=400, detail=f"Unknown scanner: {request.scanner}")

        # Import results if requested
        import_summary = {"ports_imported": 0, "ports_updated": 0, "assets_created": 0}
        if request.import_results:
            import_summary = scanner_service.import_results_to_assets(
                db=db,
                scan_result=result,
                organization_id=request.organization_id,
                create_assets=request.create_assets
            )
        
        # Build host results from import summary
        host_results = []
        for hr in import_summary.get("host_results", []):
            host_results.append(HostResult(
                host=hr["host"],
                ip=hr["ip"],
                is_live=hr["is_live"],
                open_ports=hr["open_ports"],
                port_count=hr["port_count"],
                asset_id=hr["asset_id"],
                asset_created=hr["asset_created"]
            ))
        
        # Update scan record with full results including host_results
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        scan.assets_discovered = import_summary.get("assets_created", 0)
        scan.results = {
            "ports_found": len(result.ports_found),
            "ports_imported": import_summary.get("ports_imported", 0),
            "ports_updated": import_summary.get("ports_updated", 0),
            "duration": result.duration_seconds,
            "live_hosts": import_summary.get("live_hosts", 0),
            "hosts_processed": import_summary.get("hosts_processed", 0),
            "targets_expanded": result.targets_scanned,
            "host_results": import_summary.get("host_results", [])
        }
        db.commit()
        
        return PortScanResultResponse(
            success=result.success,
            scanner=request.scanner.value,
            targets_scanned=result.targets_scanned,
            ports_found=len(result.ports_found),
            hosts_found=len(host_results),
            live_hosts=import_summary.get("live_hosts", 0),
            duration_seconds=result.duration_seconds,
            errors=result.errors + import_summary.get("errors", []),
            ports_imported=import_summary.get("ports_imported", 0),
            ports_updated=import_summary.get("ports_updated", 0),
            assets_created=import_summary.get("assets_created", 0),
            hosts=host_results
        )
        
    except Exception as e:
        scan.status = ScanStatus.FAILED
        scan.error_message = str(e)
        scan.completed_at = datetime.utcnow()
        db.commit()
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Port scan failed: {str(e)}"
        )


@router.post("/import", response_model=ImportPortsResponse)
def import_port_scan_results(
    request: ImportPortsRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Import port scan results from external tools.
    
    Accepts raw output from:
    - **naabu**: JSON lines format
    - **masscan**: JSON format
    - **nmap**: XML format
    
    Results are parsed and imported to the database.
    """
    # Check organization access
    if not check_org_access(current_user, request.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this organization"
        )
    
    scanner_service = PortScannerService()
    
    # Parse output based on scanner type
    try:
        if request.scanner == ScannerType.NAABU:
            port_results = scanner_service.parse_naabu_output(request.output)
        elif request.scanner == ScannerType.MASSCAN:
            port_results = scanner_service.parse_masscan_output(request.output)
        elif request.scanner == ScannerType.NMAP:
            port_results = scanner_service.parse_nmap_output(request.output)
        else:
            raise HTTPException(status_code=400, detail=f"Unknown scanner: {request.scanner}")
        
        if not port_results:
            return ImportPortsResponse(
                success=True,
                ports_imported=0,
                ports_updated=0,
                assets_created=0,
                errors=["No ports found in the provided output"]
            )
        
        # Create a mock scan result for import
        from app.services.port_scanner_service import ScanResult
        scan_result = ScanResult(
            success=True,
            scanner=request.scanner,
            ports_found=port_results
        )
        
        # Import to database
        import_summary = scanner_service.import_results_to_assets(
            db=db,
            scan_result=scan_result,
            organization_id=request.organization_id,
            create_assets=request.create_assets
        )
        
        return ImportPortsResponse(
            success=True,
            ports_imported=import_summary.get("ports_imported", 0),
            ports_updated=import_summary.get("ports_updated", 0),
            assets_created=import_summary.get("assets_created", 0),
            errors=import_summary.get("errors", [])
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to parse scanner output: {str(e)}"
        )


@router.post("/scan/asset/{asset_id}", response_model=PortScanResultResponse)
async def scan_asset_ports(
    asset_id: int,
    scanner: ScannerType = ScannerType.NAABU,
    ports: Optional[str] = None,
    service_detection: bool = True,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Run a port scan on a specific asset.
    
    Automatically uses the asset's IP or domain as the target.
    """
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Use the asset value as target
    targets = [asset.value]
    
    scanner_service = PortScannerService()
    
    # Check if scanner is available
    tools = scanner_service.check_tools()
    if not tools.get(scanner.value, False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"{scanner.value} is not installed"
        )
    
    try:
        # Run scan
        if scanner == ScannerType.NAABU:
            result = await scanner_service.scan_with_naabu(targets=targets, ports=ports)
        elif scanner == ScannerType.MASSCAN:
            result = await scanner_service.scan_with_masscan(targets=targets, ports=ports or "1-65535")
        elif scanner == ScannerType.NMAP:
            result = await scanner_service.scan_with_nmap(
                targets=targets, 
                ports=ports,
                service_detection=service_detection
            )
        else:
            raise HTTPException(status_code=400, detail=f"Unknown scanner: {scanner}")
        
        # Import results for this specific asset
        import_summary = {"ports_imported": 0, "ports_updated": 0, "errors": []}
        
        for port_result in result.ports_found:
            try:
                existing = db.query(PortService).filter(
                    PortService.asset_id == asset_id,
                    PortService.port == port_result.port,
                    PortService.protocol == Protocol(port_result.protocol.lower())
                ).first()
                
                if existing:
                    existing.last_seen = datetime.utcnow()
                    # Use actual state from scan result
                    state_map = {
                        "open": PortState.OPEN,
                        "closed": PortState.CLOSED,
                        "filtered": PortState.FILTERED,
                        "open|filtered": PortState.OPEN_FILTERED,
                        "closed|filtered": PortState.CLOSED_FILTERED,
                    }
                    existing.state = state_map.get(port_result.state.lower(), PortState.OPEN)
                    if port_result.service_name:
                        existing.service_name = port_result.service_name
                    if port_result.service_product:
                        existing.service_product = port_result.service_product
                    if port_result.service_version:
                        existing.service_version = port_result.service_version
                    import_summary["ports_updated"] += 1
                else:
                    port_data = port_result.to_port_service_dict(asset_id)
                    port_service = PortService(**port_data)
                    db.add(port_service)
                    import_summary["ports_imported"] += 1
                    
            except Exception as e:
                import_summary["errors"].append(f"Error importing port {port_result.port}: {e}")
        
        db.commit()
        
        return PortScanResultResponse(
            success=result.success,
            scanner=scanner.value,
            targets_scanned=1,
            ports_found=len(result.ports_found),
            duration_seconds=result.duration_seconds,
            errors=result.errors + import_summary.get("errors", []),
            ports_imported=import_summary.get("ports_imported", 0),
            ports_updated=import_summary.get("ports_updated", 0),
            assets_created=0
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Port scan failed: {str(e)}"
        )


# ==================== PORT FINDINGS ====================

@router.post("/findings/generate", response_model=GenerateFindingsResponse)
def generate_port_findings(
    request: GenerateFindingsRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Generate security findings from open/filtered ports.
    
    Automatically creates findings for:
    - Critical exposures (databases, RDP, SMB, Docker)
    - High-risk services (SSH, VNC, FTP)
    - Unencrypted protocols (Telnet, HTTP, POP3, IMAP)
    - Filtered ports on critical services
    
    Findings are deduplicated - existing open findings are updated rather than duplicated.
    """
    if not check_org_access(current_user, request.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    findings_service = PortFindingsService()
    
    # Generate findings
    summary = findings_service.create_findings_from_scan(
        db=db,
        organization_id=request.organization_id,
        scan_id=request.scan_id,
        port_ids=request.port_ids
    )
    
    return GenerateFindingsResponse(
        success=True,
        findings_created=summary["findings_created"],
        findings_updated=summary["findings_updated"],
        by_severity=summary["by_severity"],
        findings=summary["findings"]
    )


@router.post("/findings/generate/asset/{asset_id}", response_model=GenerateFindingsResponse)
def generate_findings_for_asset(
    asset_id: int,
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Generate security findings for all ports on a specific asset.
    """
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    findings_service = PortFindingsService()
    findings = findings_service.create_findings_for_asset(db, asset, scan_id)
    
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    finding_summaries = []
    
    for f in findings:
        by_severity[f.severity.value] += 1
        finding_summaries.append({
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value,
            "asset": asset.value,
            "port": f.metadata_.get("port") if f.metadata_ else None
        })
    
    return GenerateFindingsResponse(
        success=True,
        findings_created=len(findings),
        findings_updated=0,
        by_severity=by_severity,
        findings=finding_summaries
    )


@router.get("/findings/risk-summary", response_model=PortRiskSummary)
def get_port_risk_summary(
    organization_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get a summary of port-based security risks for an organization.
    
    Returns:
    - Count of critical, high, and medium risk port exposures
    - List of the most critical exposed services
    - Prioritized remediation recommendations
    """
    if not check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    findings_service = PortFindingsService()
    summary = findings_service.get_risk_summary(db, organization_id)
    
    return PortRiskSummary(**summary)


@router.get("/findings/rules")
def get_finding_rules(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get the list of port finding rules used to generate findings.
    
    Useful for understanding what ports trigger which findings.
    """
    rules = []
    for rule in PORT_FINDING_RULES:
        rules.append({
            "ports": rule.ports,
            "title": rule.title,
            "description": rule.description[:200] + "..." if len(rule.description) > 200 else rule.description,
            "severity": rule.severity.value,
            "tags": rule.tags,
            "cwe_id": rule.cwe_id,
            "states": [s.value for s in rule.states]
        })
    
    return {
        "total_rules": len(rules),
        "rules": rules
    }


@router.post("/scan-and-analyze", response_model=dict)
async def scan_and_generate_findings(
    request: PortScanRequest,
    generate_findings: bool = True,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Run a port scan and automatically generate security findings.
    
    This is a convenience endpoint that combines:
    1. Port scanning (with naabu, masscan, or nmap)
    2. Importing results to database
    3. Generating security findings for risky ports
    
    Ideal for automated security assessments.
    """
    if not check_org_access(current_user, request.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    scanner_service = PortScannerService()
    findings_service = PortFindingsService()
    
    # Check scanner availability
    tools = scanner_service.check_tools()
    if not tools.get(request.scanner.value, False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"{request.scanner.value} is not installed"
        )
    
    # Create scan record
    scan = Scan(
        name=f"Port Scan & Analysis ({request.scanner.value})",
        scan_type=ScanType.PORT_SCAN,
        organization_id=request.organization_id,
        targets=request.targets,
        config={
            "scanner": request.scanner.value,
            "ports": request.ports,
            "generate_findings": generate_findings
        },
        started_by=current_user.username,
        status=ScanStatus.RUNNING,
        started_at=datetime.utcnow()
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    try:
        # Run port scan
        if request.scanner == ScannerType.NAABU:
            result = await scanner_service.scan_with_naabu(
                targets=request.targets,
                ports=request.ports,
                top_ports=request.top_ports,
                rate=request.rate,
                exclude_cdn=request.exclude_cdn
            )
        elif request.scanner == ScannerType.MASSCAN:
            result = await scanner_service.scan_with_masscan(
                targets=request.targets,
                ports=request.ports or "1-65535",
                rate=request.rate
            )
        elif request.scanner == ScannerType.NMAP:
            result = await scanner_service.scan_with_nmap(
                targets=request.targets,
                ports=request.ports,
                scan_type=request.nmap_scan_type,
                service_detection=request.service_detection,
                os_detection=request.os_detection,
                timing=request.timing,
                scripts=request.nse_scripts or None,
            )
        else:
            raise HTTPException(status_code=400, detail=f"Unknown scanner: {request.scanner}")

        # Import results
        import_summary = scanner_service.import_results_to_assets(
            db=db,
            scan_result=result,
            organization_id=request.organization_id,
            create_assets=request.create_assets
        )
        
        # Generate findings if requested
        findings_summary = {"findings_created": 0, "findings_updated": 0, "by_severity": {}}
        if generate_findings:
            findings_summary = findings_service.create_findings_from_scan(
                db=db,
                organization_id=request.organization_id,
                scan_id=scan.id
            )
        
        # Update scan record with full results including host_results
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        scan.vulnerabilities_found = findings_summary.get("findings_created", 0)
        scan.assets_discovered = import_summary.get("assets_created", 0)
        scan.results = {
            "ports_found": len(result.ports_found),
            "ports_imported": import_summary.get("ports_imported", 0),
            "ports_updated": import_summary.get("ports_updated", 0),
            "findings_created": findings_summary.get("findings_created", 0),
            "duration": result.duration_seconds,
            "live_hosts": import_summary.get("live_hosts", 0),
            "hosts_processed": import_summary.get("hosts_processed", 0),
            "targets_expanded": result.targets_scanned,
            "host_results": import_summary.get("host_results", [])
        }
        db.commit()
        
        return {
            "success": True,
            "scan_id": scan.id,
            "scan_results": {
                "scanner": request.scanner.value,
                "targets_scanned": result.targets_scanned,
                "ports_found": len(result.ports_found),
                "live_hosts": import_summary.get("live_hosts", 0),
                "duration_seconds": result.duration_seconds,
                "errors": result.errors
            },
            "import_results": {
                "ports_imported": import_summary.get("ports_imported", 0),
                "ports_updated": import_summary.get("ports_updated", 0),
                "assets_created": import_summary.get("assets_created", 0),
                "host_results": import_summary.get("host_results", [])
            },
            "findings_results": {
                "findings_created": findings_summary.get("findings_created", 0),
                "findings_updated": findings_summary.get("findings_updated", 0),
                "by_severity": findings_summary.get("by_severity", {})
            }
        }
        
    except Exception as e:
        scan.status = ScanStatus.FAILED
        scan.error_message = str(e)
        scan.completed_at = datetime.utcnow()
        db.commit()
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan failed: {str(e)}"
        )


# ==================== PORT VERIFICATION (NMAP) ====================

from pydantic import BaseModel

class PortVerifyRequest(BaseModel):
    """Request to verify a port with nmap."""
    ip: str
    port: int
    protocol: str = "tcp"


class PortVerifyResponse(BaseModel):
    """Response from port verification."""
    ip: str
    port: int
    protocol: str
    state: str  # open, closed, filtered
    service: Optional[str] = None
    version: Optional[str] = None
    verified: bool
    verification_time: datetime
    raw_output: Optional[str] = None


@router.post("/verify", response_model=PortVerifyResponse)
async def verify_port(
    request: PortVerifyRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Verify a specific port using nmap for deeper inspection.
    
    This performs a more thorough check than masscan to determine if a port is:
    - open: Port is accepting connections
    - filtered: Port is blocked by firewall (packets dropped)
    - closed: Port is not accepting connections (RST response)
    
    Also attempts service detection to identify what's running.
    """
    import subprocess
    import re
    
    ip = request.ip
    port = request.port
    protocol = request.protocol.lower()
    
    # Validate inputs
    if not re.match(r'^[\d.]+$', ip) and not re.match(r'^[a-fA-F\d:]+$', ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    if port < 1 or port > 65535:
        raise HTTPException(status_code=400, detail="Port must be between 1 and 65535")
    if protocol not in ["tcp", "udp"]:
        raise HTTPException(status_code=400, detail="Protocol must be tcp or udp")
    
    # Build nmap command
    # -Pn: Skip host discovery (assume host is up)
    # -sT: TCP connect scan (for tcp) or -sU for UDP
    # -sV: Version detection
    # --version-light: Faster version detection
    scan_type = "-sT" if protocol == "tcp" else "-sU"
    cmd = [
        "nmap", "-Pn", scan_type, "-sV", "--version-light",
        "-p", str(port), ip,
        "--max-retries", "2",
        "-T4"  # Aggressive timing
    ]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60  # 60 second timeout
        )
        
        output = result.stdout
        
        # Parse nmap output
        state = "unknown"
        service = None
        version = None
        
        # Look for port state in output
        # Format: "1521/tcp filtered oracle"
        port_pattern = rf'{port}/{protocol}\s+(\w+)\s+(\S+)(?:\s+(.+))?'
        match = re.search(port_pattern, output)
        
        if match:
            state = match.group(1)  # open, closed, filtered
            service = match.group(2) if match.group(2) not in ('unknown', '-') else None
            version = match.group(3).strip() if match.group(3) else None
        
        # Fallback to SERVICE_NAMES mapping if nmap didn't detect service
        if not service and port in SERVICE_NAMES:
            service = SERVICE_NAMES[port]
            logger.info(f"Using SERVICE_NAMES fallback for port {port}: {service}")
        
        # Update the port record in database if it exists (wrap in try/except to avoid 500 on JSON/DB quirks)
        port_record = None
        try:
            port_record = db.query(PortService).join(Asset).filter(
                Asset.value == ip,
                PortService.port == port,
                PortService.protocol == Protocol(protocol)
            ).first()
            
            if not port_record:
                # Try by IP in asset's ip_addresses (JSON array) - can fail on some DB/dialects
                try:
                    asset = db.query(Asset).filter(
                        Asset.ip_addresses.contains([ip])
                    ).first()
                    if asset:
                        port_record = db.query(PortService).filter(
                            PortService.asset_id == asset.id,
                            PortService.port == port,
                            PortService.protocol == Protocol(protocol)
                        ).first()
                except SQLAlchemyError as e:
                    logger.debug("Lookup by ip_addresses.contains skipped: %s", e)
                    db.rollback()
            
            if port_record:
                # Update verification info
                port_record.verified = True
                port_record.verified_at = datetime.utcnow()
                port_record.verified_state = state
                port_record.verification_scanner = "nmap"
                
                # Update service name if detected (use correct field name)
                if service and service not in ('unknown', '-'):
                    port_record.service_name = service
                    logger.info(f"Port {port}/{protocol} on {ip}: detected service '{service}'")
                
                # Update service version if detected (use correct field name)
                if version and version.strip():
                    port_record.service_version = version.strip()
                    # Try to extract product from version string if it contains product info
                    # e.g., "OpenSSH 8.4p1" -> product="OpenSSH", version="8.4p1"
                    version_parts = version.strip().split(' ', 1)
                    if len(version_parts) >= 1:
                        port_record.service_product = version_parts[0]
                    if len(version_parts) >= 2:
                        port_record.service_version = version_parts[1]
                    logger.info(f"Port {port}/{protocol} on {ip}: detected version '{version}'")
                
                # Map nmap state to our PortState enum
                if state == "open":
                    port_record.state = PortState.OPEN
                elif state == "filtered":
                    port_record.state = PortState.FILTERED
                elif state == "closed":
                    port_record.state = PortState.CLOSED
                
                port_record.last_seen = datetime.utcnow()
                db.commit()
                logger.info(f"Updated port {port}/{protocol} on {ip}: state={state}, service={service}")
        except SQLAlchemyError as e:
            logger.warning("Database error during port verification update: %s", e)
            try:
                db.rollback()
            except Exception:
                pass
            # Still return nmap result; we just didn't persist the update
        
        return PortVerifyResponse(
            ip=ip,
            port=port,
            protocol=protocol,
            state=state,
            service=service,
            version=version,
            verified=True,
            verification_time=datetime.utcnow(),
            raw_output=output if len(output) < 2000 else output[:2000] + "..."
        )
        
    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=408,
            detail="Nmap scan timed out after 60 seconds"
        )
    except FileNotFoundError:
        raise HTTPException(
            status_code=500,
            detail="Nmap is not installed on this system"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Verification failed: {str(e)}"
        )


@router.post("/{port_id}/verify", response_model=PortVerifyResponse)
async def verify_port_by_id(
    port_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Verify a port by its database ID.
    
    Looks up the port record and runs nmap verification on it.
    """
    port_record = db.query(PortService).filter(PortService.id == port_id).first()
    
    if not port_record:
        raise HTTPException(status_code=404, detail="Port record not found")
    
    # Get the asset to find the IP
    asset = db.query(Asset).filter(Asset.id == port_record.asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Associated asset not found")
    
    # Check access
    if not current_user.is_superuser and current_user.organization_id != asset.organization_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Get IP address - prefer resolved IP, otherwise use asset value if it's an IP
    ip = None
    if asset.ip_addresses and len(asset.ip_addresses) > 0:
        ip = asset.ip_addresses[0]
    elif asset.value and (asset.value.replace('.', '').isdigit() or ':' in asset.value):
        ip = asset.value
    else:
        raise HTTPException(
            status_code=400, 
            detail="No IP address available for this asset. Run DNS resolution first."
        )
    
    # Call the main verify endpoint
    request = PortVerifyRequest(
        ip=ip,
        port=port_record.port,
        protocol=port_record.protocol.value
    )
    
    return await verify_port(request, db, current_user)


@router.post("/verify-bulk")
async def verify_ports_bulk(
    port_ids: List[int],
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Verify multiple ports in bulk.
    
    Creates a background scan to verify all specified ports.
    Useful for verifying all open ports found by masscan.
    """
    if len(port_ids) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 ports per bulk verification")
    
    # Get all port records with asset joined so we have organization_id
    ports = db.query(PortService).join(Asset).filter(PortService.id.in_(port_ids)).all()
    
    if not ports:
        raise HTTPException(status_code=404, detail="No port records found")
    
    org_id = ports[0].asset.organization_id if ports[0].asset else None
    if org_id is None:
        raise HTTPException(
            status_code=400,
            detail="Could not determine organization for these ports. Ensure each port is linked to an asset."
        )
    if not current_user.is_superuser and current_user.organization_id != org_id:
        raise HTTPException(status_code=403, detail="Access denied to this organization")
    
    # Create a scan record for tracking
    scan = Scan(
        name=f"Bulk Port Verification ({len(ports)} ports)",
        scan_type=ScanType.PORT_SCAN,
        organization_id=org_id,
        targets=[],
        config={
            "verification_mode": True,
            "port_ids": port_ids,
            "scanner": "nmap"
        },
        status=ScanStatus.PENDING
    )
    db.add(scan)
    db.commit()
    
    # Queue for background processing
    # The scanner worker will handle this
    from app.api.routes.scans import send_scan_to_sqs
    send_scan_to_sqs(scan)
    
    return {
        "message": f"Bulk verification queued for {len(ports)} ports",
        "scan_id": scan.id,
        "ports_queued": len(ports)
    }

