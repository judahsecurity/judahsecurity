"""Organization routes."""

from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from pydantic import BaseModel

from app.db.database import get_db
from app.models.organization import Organization
from app.models.asset import Asset
from app.models.scan import Scan, ScanType, ScanStatus
from app.models.vulnerability import Vulnerability, Severity
from app.models.user import User
from app.models.project_settings import ProjectSettings, ALL_MODULES, get_default_config, MODULE_COMMONCRAWL
from app.schemas.organization import (
    OrganizationCreate,
    OrganizationUpdate,
    OrganizationResponse,
    DiscoverySettingsUpdate,
    DiscoverySettingsResponse,
)
from app.api.deps import get_current_active_user, require_admin
from app.api.routes.scans import send_scan_to_sqs

router = APIRouter(prefix="/organizations", tags=["Organizations"])


def build_org_response(db: Session, org: Organization) -> dict:
    """Build organization response with computed counts."""
    # Get asset count
    asset_count = db.query(func.count(Asset.id)).filter(
        Asset.organization_id == org.id
    ).scalar() or 0
    
    # Get vulnerability counts by severity
    vuln_counts = db.query(
        Vulnerability.severity,
        func.count(Vulnerability.id)
    ).join(Asset).filter(
        Asset.organization_id == org.id
    ).group_by(Vulnerability.severity).all()
    
    counts = {sev: cnt for sev, cnt in vuln_counts}
    
    return {
        **org.__dict__,
        "asset_count": asset_count,
        "vulnerability_count": sum(counts.values()),
        "critical_count": counts.get(Severity.CRITICAL, 0),
        "high_count": counts.get(Severity.HIGH, 0),
        "medium_count": counts.get(Severity.MEDIUM, 0),
        "low_count": counts.get(Severity.LOW, 0),
    }


@router.get("/", response_model=List[OrganizationResponse])
def list_organizations(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List organizations. Superusers see all; everyone else sees only their own."""
    query = db.query(Organization).filter(Organization.is_active == True)

    if not current_user.is_superuser:
        # Org admins, analysts, and viewers are scoped to their own organization only
        if current_user.organization_id:
            query = query.filter(Organization.id == current_user.organization_id)
        else:
            return []

    organizations = query.offset(skip).limit(limit).all()
    return [build_org_response(db, org) for org in organizations]


@router.post("/", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
def create_organization(
    org_data: OrganizationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Create a new organization (superusers only)."""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only platform superusers can create organizations."
        )
    # Check if organization already exists
    existing = db.query(Organization).filter(Organization.name == org_data.name).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization with this name already exists"
        )
    
    new_org = Organization(**org_data.model_dump())
    db.add(new_org)
    db.commit()
    db.refresh(new_org)
    ProjectSettings.ensure_defaults(db, new_org.id)

    # Kick off TLD/domain discovery for the org so we find all domains owned by the organization.
    # After this runs, subdomain enumeration and other processes can use the discovered domains.
    if new_org.domain and new_org.domain.strip():
        domain = new_org.domain.strip().lower()

        tld_scan = Scan(
            name=f"TLD discovery: {domain}",
            scan_type=ScanType.TLDFINDER,
            organization_id=new_org.id,
            targets=[domain],
            config={
                "discovery_mode": "domain",
                "max_time_minutes": 10,
                "triggered_by": "organization_created",
            },
            started_by=current_user.username,
            status=ScanStatus.PENDING,
        )
        db.add(tld_scan)
        db.commit()
        db.refresh(tld_scan)
        send_scan_to_sqs(tld_scan)

        # CommonCrawl CDX enumeration — read per-org settings so operators can
        # tune the year range and dataset count without touching code.
        cc_settings = ProjectSettings.get_config(db, new_org.id, MODULE_COMMONCRAWL)
        cc_scan = Scan(
            name=f"CommonCrawl subdomain discovery: {domain}",
            scan_type=ScanType.COMMONCRAWL_ENUM,
            organization_id=new_org.id,
            targets=[domain],
            config={
                "years": cc_settings.get("years", "last1"),
                "max_per_year": cc_settings.get("max_per_year", 1),
                "timeout": cc_settings.get("timeout", 120),
                "max_results_per_release": cc_settings.get("max_results_per_release", 100000),
                "triggered_by": "organization_created",
            },
            started_by=current_user.username,
            status=ScanStatus.PENDING,
        )
        db.add(cc_scan)
        db.commit()
        db.refresh(cc_scan)
        send_scan_to_sqs(cc_scan)

    return build_org_response(db, new_org)


@router.get("/{org_id}", response_model=OrganizationResponse)
def get_organization(
    org_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get organization by ID."""
    org = db.query(Organization).filter(Organization.id == org_id).first()
    
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )
    
    # Check access
    if not current_user.is_superuser and current_user.organization_id != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    return build_org_response(db, org)


@router.put("/{org_id}", response_model=OrganizationResponse)
def update_organization(
    org_id: int,
    org_data: OrganizationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Update organization. Superusers can update any org; org admins can only update their own."""
    org = db.query(Organization).filter(Organization.id == org_id).first()

    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )

    # Org-level admins may only edit their own organization
    if not current_user.is_superuser and current_user.organization_id != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )

    update_data = org_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(org, field, value)

    db.commit()
    db.refresh(org)
    return org


@router.delete("/{org_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_organization(
    org_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Delete organization (superusers only)."""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only platform superusers can delete organizations."
        )

    org = db.query(Organization).filter(Organization.id == org_id).first()

    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )

    db.delete(org)
    db.commit()
    return None


@router.get("/{org_id}/discovery-settings", response_model=DiscoverySettingsResponse)
def get_discovery_settings(
    org_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get discovery keyword settings for an organization."""
    org = db.query(Organization).filter(Organization.id == org_id).first()
    
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )
    
    # Check access
    if not current_user.is_superuser and current_user.organization_id != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    return DiscoverySettingsResponse(
        organization_id=org.id,
        commoncrawl_org_name=org.commoncrawl_org_name,
        commoncrawl_keywords=org.commoncrawl_keywords or [],
        sni_keywords=org.sni_keywords or [],
    )


@router.put("/{org_id}/discovery-settings", response_model=DiscoverySettingsResponse)
def update_discovery_settings(
    org_id: int,
    settings: DiscoverySettingsUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Update discovery keyword settings for an organization."""
    org = db.query(Organization).filter(Organization.id == org_id).first()
    
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )
    
    # Check access - analysts and admins can update discovery settings
    if not current_user.is_superuser and current_user.organization_id != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Update fields if provided
    if settings.commoncrawl_org_name is not None:
        org.commoncrawl_org_name = settings.commoncrawl_org_name
    if settings.commoncrawl_keywords is not None:
        org.commoncrawl_keywords = settings.commoncrawl_keywords
    if settings.sni_keywords is not None:
        org.sni_keywords = settings.sni_keywords
    
    db.commit()
    db.refresh(org)
    
    return DiscoverySettingsResponse(
        organization_id=org.id,
        commoncrawl_org_name=org.commoncrawl_org_name,
        commoncrawl_keywords=org.commoncrawl_keywords or [],
        sni_keywords=org.sni_keywords or [],
    )


def _check_org_access(db: Session, org_id: int, current_user: User) -> Organization:
    """Return org if exists and user has access."""
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    if not current_user.is_superuser and current_user.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    return org


@router.get("/{org_id}/settings", response_model=Dict[str, Any])
def get_all_project_settings(
    org_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get all project settings for an organization (per-org scan/agent config)."""
    _check_org_access(db, org_id, current_user)
    return {
        module: ProjectSettings.get_config(db, org_id, module)
        for module in ALL_MODULES
    }


@router.get("/{org_id}/settings/{module}", response_model=Dict[str, Any])
def get_project_settings_module(
    org_id: int,
    module: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get one module's project settings."""
    _check_org_access(db, org_id, current_user)
    if module not in ALL_MODULES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unknown module: {module}")
    return ProjectSettings.get_config(db, org_id, module)


class ProjectSettingsUpdate(BaseModel):
    config: Dict[str, Any]


@router.put("/{org_id}/settings/{module}", response_model=Dict[str, Any])
def update_project_settings_module(
    org_id: int,
    module: str,
    body: ProjectSettingsUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Update one module's project settings (partial merge)."""
    _check_org_access(db, org_id, current_user)
    if module not in ALL_MODULES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unknown module: {module}")
    if isinstance(body.config, dict) and body.config.get("llm_base_url"):
        from app.services.agent.llm_factory import UnsupportedProviderError, validate_model_base_url
        try:
            body.config["llm_base_url"] = validate_model_base_url(body.config["llm_base_url"])
        except UnsupportedProviderError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    ProjectSettings.set_config(db, org_id, module, body.config)
    db.commit()
    return ProjectSettings.get_config(db, org_id, module)


@router.post("/{org_id}/settings/ensure-defaults")
def ensure_project_settings_defaults(
    org_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Ensure all module rows exist for this org with defaults."""
    _check_org_access(db, org_id, current_user)
    ProjectSettings.ensure_defaults(db, org_id)
    return {"status": "ok", "message": "Defaults ensured for all modules"}















