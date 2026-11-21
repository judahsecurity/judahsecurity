"""Organization routes."""

from typing import List, Dict, Any
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status
from sqlalchemy.orm import Session
from sqlalchemy import func
from pydantic import BaseModel

from app.db.database import get_db
from app.models.organization import Organization
from app.models.asset import Asset
from app.models.scan import Scan, ScanType, ScanStatus
from app.models.vulnerability import Vulnerability, Severity
from app.models.user import User, UserRole
from app.models.project_settings import (
    ProjectSettings, ALL_MODULES, get_default_config, MODULE_COMMONCRAWL, MODULE_NOTIFICATIONS,
)
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
    from app.services.platform_audit import record as audit

    audit("settings.update", user=current_user, organization_id=org_id, target="discovery",
          detail={"changed": settings.model_dump(exclude_none=True)})
    
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
    response: Response,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get one module's project settings. The ETag header versions the config."""
    _check_org_access(db, org_id, current_user)
    if module not in ALL_MODULES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unknown module: {module}")
    response.headers["ETag"] = ProjectSettings.config_version(db, org_id, module)
    return ProjectSettings.get_config(db, org_id, module)


class ProjectSettingsUpdate(BaseModel):
    config: Dict[str, Any]


@router.put("/{org_id}/settings/{module}", response_model=Dict[str, Any])
def update_project_settings_module(
    org_id: int,
    module: str,
    body: ProjectSettingsUpdate,
    response: Response,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
    if_match: str | None = Header(default=None),
):
    """Update one module's project settings (partial merge).

    Send the ETag from the last GET as ``If-Match``: if someone else saved
    this module since, the save is refused with 409 instead of overwriting
    their change. Saves without ``If-Match`` keep the old last-write-wins
    behavior.
    """
    _check_org_access(db, org_id, current_user)
    if module not in ALL_MODULES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unknown module: {module}")
    if module == MODULE_NOTIFICATIONS:
        _require_org_admin(current_user, target=module)
        _validate_notifications_config(body.config)
    if module == "agent" and any(key.startswith(_APPROVAL_POLICY_PREFIXES) for key in body.config):
        # Approval policy decides what the agent may run without a person.
        _require_org_admin(current_user, target="agent.approval_policy")
        reviewer = body.config.get("tool_confirmation_reviewer")
        if reviewer is not None and reviewer not in ("human", "ai"):
            raise HTTPException(status_code=422, detail="tool_confirmation_reviewer must be 'human' or 'ai'")
    if if_match and if_match.strip() != "*":
        current = ProjectSettings.config_version(db, org_id, module, lock=True)
        expected = {tag.strip() for tag in if_match.split(",")}
        if current not in expected and current.strip('"') not in expected:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=("These settings were changed by someone else since you loaded them. "
                        "Your edits were not saved; reload to see the latest values, then "
                        "reapply your changes."),
                headers={"ETag": current},
            )
    ProjectSettings.set_config(db, org_id, module, body.config)
    db.commit()
    from app.services.platform_audit import record as audit

    audit("settings.update", user=current_user, organization_id=org_id, target=module,
          detail={"changed": body.config})
    response.headers["ETag"] = ProjectSettings.config_version(db, org_id, module)
    return ProjectSettings.get_config(db, org_id, module)


_APPROVAL_POLICY_PREFIXES = ("tool_confirmation", "ai_reviewer", "agent_autonomous_auto_approve")


def _require_org_admin(user: User, target: str = MODULE_NOTIFICATIONS) -> None:
    if not (getattr(user, "is_superuser", False) or getattr(user, "role", None) == UserRole.ADMIN):
        from app.services.platform_audit import record as audit

        audit("settings.update", user=user, target=target, outcome="denied",
              detail={"reason": "admin role required"})
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Only organization admins can change notification settings")


def _validate_notifications_config(config: Dict[str, Any]) -> None:
    from app.services.chat_notifier import SEVERITY_RANK, valid_chat_ids

    if "telegram_chat_ids" in config:
        raw = config["telegram_chat_ids"]
        items = raw if isinstance(raw, list) else str(raw or "").replace(",", " ").split()
        valid = valid_chat_ids(items)
        if len(valid) != len([i for i in items if str(i).strip()]):
            raise HTTPException(status_code=422, detail=(
                "telegram_chat_ids must be numeric chat IDs (groups are negative) or "
                "@channel usernames, at most 10, no duplicates"))
        config["telegram_chat_ids"] = valid
    if "min_severity" in config and str(config["min_severity"]).lower() not in SEVERITY_RANK:
        raise HTTPException(status_code=422, detail="min_severity must be one of "
                            + ", ".join(SEVERITY_RANK))


@router.post("/{org_id}/notifications/test")
def send_test_notification(
    org_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Send a test message to this org's configured chats; returns per-chat results."""
    _check_org_access(db, org_id, current_user)
    _require_org_admin(current_user, target="notifications.test")
    from app.services.chat_notifier import default_notifier, dispatch, valid_chat_ids

    if default_notifier() is None:
        raise HTTPException(status_code=409, detail="TELEGRAM_BOT_TOKEN is not configured on the server")
    config = ProjectSettings.get_config(db, org_id, MODULE_NOTIFICATIONS)
    if not config.get("telegram_enabled") or not valid_chat_ids(config.get("telegram_chat_ids")):
        raise HTTPException(status_code=409, detail="Enable Telegram and add at least one chat ID first")
    results = dispatch(org_id, "test", "Prowl notifications are connected for this organization.",
                       background=False, config={**config, "notify_test": True})
    from app.services.platform_audit import record as audit

    audit("notifications.test", user=current_user, organization_id=org_id, target="telegram",
          detail={"results": results or {}})
    return {"results": results or {}}


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















