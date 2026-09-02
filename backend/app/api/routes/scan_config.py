"""Scan Configuration API routes for managing port lists and scan settings."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from app.db.database import get_db
from app.models.scan_config import (
    ScanConfig,
    DEFAULT_PORT_LISTS,
    DEFAULT_NMAP_PROFILES,
    NMAP_TIMING_TEMPLATES,
    NMAP_NSE_CATALOG,
    seed_default_port_lists,
    seed_default_nmap_profiles,
)
from app.models.user import User
from app.services.port_scanner_service import PortScannerService
from app.api.deps import get_current_active_user, require_analyst

router = APIRouter(prefix="/scan-config", tags=["Scan Configuration"])


# ==================== SCHEMAS ====================

class PortListCreate(BaseModel):
    """Create a new port list."""
    name: str = Field(..., min_length=1, max_length=100, description="Unique name for the port list")
    description: Optional[str] = None
    ports: List[int] = Field(..., description="List of port numbers")
    categories: Optional[dict] = Field(None, description="Optional categorization of ports")


class PortListUpdate(BaseModel):
    """Update an existing port list."""
    description: Optional[str] = None
    ports: Optional[List[int]] = None
    categories: Optional[dict] = None
    is_active: Optional[bool] = None


class PortListResponse(BaseModel):
    """Port list response."""
    id: int
    name: str
    description: Optional[str]
    ports: List[int]
    ports_string: str
    port_count: int
    categories: Optional[dict]
    is_default: bool
    is_active: bool
    
    class Config:
        from_attributes = True


class PortCategoryInfo(BaseModel):
    """Information about a port category."""
    name: str
    ports: List[int]
    port_count: int


# ==================== ENDPOINTS ====================

@router.get("/port-lists", response_model=List[PortListResponse])
def list_port_lists(
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List all available port lists."""
    query = db.query(ScanConfig).filter(ScanConfig.config_type == "port_list")
    
    if not include_inactive:
        query = query.filter(ScanConfig.is_active == True)
    
    configs = query.order_by(ScanConfig.name).all()
    
    results = []
    for config in configs:
        ports = config.config.get("ports", [])
        results.append(PortListResponse(
            id=config.id,
            name=config.name,
            description=config.description,
            ports=ports,
            ports_string=",".join(str(p) for p in ports),
            port_count=len(ports),
            categories=config.config.get("categories"),
            is_default=config.is_default,
            is_active=config.is_active,
        ))
    
    return results


@router.get("/port-lists/{name}", response_model=PortListResponse)
def get_port_list(
    name: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get a specific port list by name."""
    config = db.query(ScanConfig).filter(
        ScanConfig.config_type == "port_list",
        ScanConfig.name == name
    ).first()
    
    if not config:
        raise HTTPException(status_code=404, detail=f"Port list '{name}' not found")
    
    ports = config.config.get("ports", [])
    return PortListResponse(
        id=config.id,
        name=config.name,
        description=config.description,
        ports=ports,
        ports_string=",".join(str(p) for p in ports),
        port_count=len(ports),
        categories=config.config.get("categories"),
        is_default=config.is_default,
        is_active=config.is_active,
    )


@router.post("/port-lists", response_model=PortListResponse, status_code=status.HTTP_201_CREATED)
def create_port_list(
    data: PortListCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Create a new custom port list."""
    # Check for duplicate name
    existing = db.query(ScanConfig).filter(
        ScanConfig.config_type == "port_list",
        ScanConfig.name == data.name
    ).first()
    
    if existing:
        raise HTTPException(status_code=400, detail=f"Port list '{data.name}' already exists")
    
    # Validate ports
    for port in data.ports:
        if not 0 <= port <= 65535:
            raise HTTPException(status_code=400, detail=f"Invalid port number: {port}")
    
    config = ScanConfig(
        config_type="port_list",
        name=data.name,
        description=data.description,
        config={
            "ports": sorted(set(data.ports)),
            "categories": data.categories or {},
        },
        is_default=False,
        is_active=True,
        created_by=current_user.username,
    )
    
    db.add(config)
    db.commit()
    db.refresh(config)
    
    ports = config.config.get("ports", [])
    return PortListResponse(
        id=config.id,
        name=config.name,
        description=config.description,
        ports=ports,
        ports_string=",".join(str(p) for p in ports),
        port_count=len(ports),
        categories=config.config.get("categories"),
        is_default=config.is_default,
        is_active=config.is_active,
    )


@router.put("/port-lists/{name}", response_model=PortListResponse)
def update_port_list(
    name: str,
    data: PortListUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Update an existing port list."""
    config = db.query(ScanConfig).filter(
        ScanConfig.config_type == "port_list",
        ScanConfig.name == name
    ).first()
    
    if not config:
        raise HTTPException(status_code=404, detail=f"Port list '{name}' not found")
    
    if data.description is not None:
        config.description = data.description
    
    if data.ports is not None:
        for port in data.ports:
            if not 0 <= port <= 65535:
                raise HTTPException(status_code=400, detail=f"Invalid port number: {port}")
        config.config["ports"] = sorted(set(data.ports))
    
    if data.categories is not None:
        config.config["categories"] = data.categories
    
    if data.is_active is not None:
        config.is_active = data.is_active
    
    db.commit()
    db.refresh(config)
    
    ports = config.config.get("ports", [])
    return PortListResponse(
        id=config.id,
        name=config.name,
        description=config.description,
        ports=ports,
        ports_string=",".join(str(p) for p in ports),
        port_count=len(ports),
        categories=config.config.get("categories"),
        is_default=config.is_default,
        is_active=config.is_active,
    )


@router.post("/port-lists/{name}/add-ports", response_model=PortListResponse)
def add_ports_to_list(
    name: str,
    ports: List[int],
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Add ports to an existing port list."""
    config = db.query(ScanConfig).filter(
        ScanConfig.config_type == "port_list",
        ScanConfig.name == name
    ).first()
    
    if not config:
        raise HTTPException(status_code=404, detail=f"Port list '{name}' not found")
    
    for port in ports:
        if not 0 <= port <= 65535:
            raise HTTPException(status_code=400, detail=f"Invalid port number: {port}")
    
    existing_ports = set(config.config.get("ports", []))
    existing_ports.update(ports)
    config.config["ports"] = sorted(existing_ports)
    
    db.commit()
    db.refresh(config)
    
    result_ports = config.config.get("ports", [])
    return PortListResponse(
        id=config.id,
        name=config.name,
        description=config.description,
        ports=result_ports,
        ports_string=",".join(str(p) for p in result_ports),
        port_count=len(result_ports),
        categories=config.config.get("categories"),
        is_default=config.is_default,
        is_active=config.is_active,
    )


@router.post("/port-lists/{name}/remove-ports", response_model=PortListResponse)
def remove_ports_from_list(
    name: str,
    ports: List[int],
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Remove ports from an existing port list."""
    config = db.query(ScanConfig).filter(
        ScanConfig.config_type == "port_list",
        ScanConfig.name == name
    ).first()
    
    if not config:
        raise HTTPException(status_code=404, detail=f"Port list '{name}' not found")
    
    existing_ports = set(config.config.get("ports", []))
    existing_ports.difference_update(ports)
    config.config["ports"] = sorted(existing_ports)
    
    db.commit()
    db.refresh(config)
    
    result_ports = config.config.get("ports", [])
    return PortListResponse(
        id=config.id,
        name=config.name,
        description=config.description,
        ports=result_ports,
        ports_string=",".join(str(p) for p in result_ports),
        port_count=len(result_ports),
        categories=config.config.get("categories"),
        is_default=config.is_default,
        is_active=config.is_active,
    )


@router.delete("/port-lists/{name}", status_code=status.HTTP_204_NO_CONTENT)
def delete_port_list(
    name: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Delete a custom port list (cannot delete default lists)."""
    config = db.query(ScanConfig).filter(
        ScanConfig.config_type == "port_list",
        ScanConfig.name == name
    ).first()
    
    if not config:
        raise HTTPException(status_code=404, detail=f"Port list '{name}' not found")
    
    if config.is_default:
        raise HTTPException(status_code=400, detail="Cannot delete default port lists")
    
    db.delete(config)
    db.commit()


@router.post("/seed-defaults")
def seed_default_configs(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Seed the database with default port lists and nmap scan profiles."""
    seed_default_port_lists(db)
    seed_default_nmap_profiles(db)
    return {"success": True, "message": "Default port lists and nmap profiles seeded"}


@router.get("/port-categories")
def get_port_categories(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get all port categories from the 'critical' port list."""
    config = db.query(ScanConfig).filter(
        ScanConfig.config_type == "port_list",
        ScanConfig.name == "critical"
    ).first()
    
    if not config or not config.config.get("categories"):
        # Return from DEFAULT_PORT_LISTS
        categories = DEFAULT_PORT_LISTS.get("critical", {}).get("categories", {})
    else:
        categories = config.config.get("categories", {})
    
    return {
        name: PortCategoryInfo(
            name=name,
            ports=ports,
            port_count=len(ports)
        ).model_dump()
        for name, ports in categories.items()
    }


@router.get("/default-ports")
def get_default_port_lists():
    """Get all default port list configurations (no auth required for reference)."""
    return DEFAULT_PORT_LISTS


# ==================== NMAP SCAN CONFIGURATION ====================


class NmapProfileConfig(BaseModel):
    """A custom nmap scan configuration."""
    nmap_scan_type: str = Field(default="-sT", description="Scan technique flag (e.g. -sT, -sS, -sU)")
    timing: int = Field(default=4, ge=0, le=5, description="Timing template T0-T5")
    service_detection: bool = Field(default=True, description="Enable -sV service/version detection")
    os_detection: bool = Field(default=False, description="Enable -O OS detection")
    nse_scripts: List[str] = Field(default_factory=list, description="NSE scripts/categories to run")
    ports: Optional[str] = Field(default=None, description="Port specification (e.g. '80,443' or '1-1000'); null = defaults")


class NmapProfileCreate(BaseModel):
    """Create/save a reusable nmap scan profile."""
    name: str = Field(..., min_length=1, max_length=100, description="Unique profile name")
    description: Optional[str] = None
    config: NmapProfileConfig


class NmapProfileResponse(BaseModel):
    """Saved nmap scan profile."""
    id: int
    name: str
    description: Optional[str]
    config: NmapProfileConfig
    command_preview: str
    is_default: bool
    is_active: bool

    class Config:
        from_attributes = True


def _nmap_profile_response(config: ScanConfig) -> NmapProfileResponse:
    """Build an nmap profile response, including the equivalent command preview."""
    cfg = config.config or {}
    profile_config = NmapProfileConfig(
        nmap_scan_type=cfg.get("nmap_scan_type", "-sT"),
        timing=cfg.get("timing", 4),
        service_detection=cfg.get("service_detection", True),
        os_detection=cfg.get("os_detection", False),
        nse_scripts=cfg.get("nse_scripts", []) or [],
        ports=cfg.get("ports"),
    )
    preview = PortScannerService.build_nmap_command_preview(
        ports=profile_config.ports,
        scan_type=profile_config.nmap_scan_type,
        service_detection=profile_config.service_detection,
        os_detection=profile_config.os_detection,
        timing=profile_config.timing,
        scripts=profile_config.nse_scripts or None,
    )
    return NmapProfileResponse(
        id=config.id,
        name=config.name,
        description=config.description,
        config=profile_config,
        command_preview=preview,
        is_default=config.is_default,
        is_active=config.is_active,
    )


@router.get("/nmap/options")
def get_nmap_options(
    current_user: User = Depends(get_current_active_user),
):
    """
    Get the catalog of nmap options the scan configuration picker renders:
    scan techniques (allowlisted), timing templates, and the NSE script catalog.
    """
    return {
        "scan_techniques": [
            {"value": flag, "label": flag, "description": desc}
            for flag, desc in PortScannerService.NMAP_SCAN_TECHNIQUES.items()
        ],
        "default_scan_technique": PortScannerService.DEFAULT_NMAP_SCAN_TECHNIQUE,
        "timing_templates": NMAP_TIMING_TEMPLATES,
        "nse_catalog": NMAP_NSE_CATALOG,
    }


@router.post("/nmap/preview")
def preview_nmap_command(
    config: NmapProfileConfig,
    current_user: User = Depends(get_current_active_user),
):
    """Render the nmap command a configuration would run (advisory preview)."""
    preview = PortScannerService.build_nmap_command_preview(
        ports=config.ports,
        scan_type=config.nmap_scan_type,
        service_detection=config.service_detection,
        os_detection=config.os_detection,
        timing=config.timing,
        scripts=config.nse_scripts or None,
    )
    return {"command_preview": preview}


@router.get("/nmap/profiles", response_model=List[NmapProfileResponse])
def list_nmap_profiles(
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List saved nmap scan profiles."""
    query = db.query(ScanConfig).filter(ScanConfig.config_type == "scan_profile")
    if not include_inactive:
        query = query.filter(ScanConfig.is_active == True)
    configs = query.order_by(ScanConfig.name).all()
    return [_nmap_profile_response(c) for c in configs]


@router.post("/nmap/profiles", response_model=NmapProfileResponse, status_code=status.HTTP_201_CREATED)
def create_nmap_profile(
    data: NmapProfileCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Save a new reusable nmap scan profile."""
    existing = db.query(ScanConfig).filter(
        ScanConfig.config_type == "scan_profile",
        ScanConfig.name == data.name
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Scan profile '{data.name}' already exists")

    if data.config.nmap_scan_type not in PortScannerService.NMAP_SCAN_TECHNIQUES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported scan technique '{data.config.nmap_scan_type}'"
        )

    config = ScanConfig(
        config_type="scan_profile",
        name=data.name,
        description=data.description,
        config={"scanner": "nmap", **data.config.model_dump()},
        is_default=False,
        is_active=True,
        created_by=current_user.username,
    )
    db.add(config)
    db.commit()
    db.refresh(config)
    return _nmap_profile_response(config)


@router.put("/nmap/profiles/{name}", response_model=NmapProfileResponse)
def update_nmap_profile(
    name: str,
    data: NmapProfileConfig,
    description: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Update an existing nmap scan profile."""
    config = db.query(ScanConfig).filter(
        ScanConfig.config_type == "scan_profile",
        ScanConfig.name == name
    ).first()
    if not config:
        raise HTTPException(status_code=404, detail=f"Scan profile '{name}' not found")
    if config.is_default:
        raise HTTPException(status_code=400, detail="Cannot modify default scan profiles; save a copy instead")

    if data.nmap_scan_type not in PortScannerService.NMAP_SCAN_TECHNIQUES:
        raise HTTPException(status_code=400, detail=f"Unsupported scan technique '{data.nmap_scan_type}'")

    config.config = {"scanner": "nmap", **data.model_dump()}
    if description is not None:
        config.description = description
    db.commit()
    db.refresh(config)
    return _nmap_profile_response(config)


@router.delete("/nmap/profiles/{name}", status_code=status.HTTP_204_NO_CONTENT)
def delete_nmap_profile(
    name: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Delete a custom nmap scan profile (cannot delete default profiles)."""
    config = db.query(ScanConfig).filter(
        ScanConfig.config_type == "scan_profile",
        ScanConfig.name == name
    ).first()
    if not config:
        raise HTTPException(status_code=404, detail=f"Scan profile '{name}' not found")
    if config.is_default:
        raise HTTPException(status_code=400, detail="Cannot delete default scan profiles")
    db.delete(config)
    db.commit()

