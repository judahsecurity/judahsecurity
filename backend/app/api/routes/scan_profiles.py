"""Tenant-aware CRUD API for reusable scan profiles."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user, require_analyst
from app.db.database import get_db
from app.models.organization import Organization
from app.models.scan_profile import ScanProfile
from app.models.user import User
from app.schemas.scan_profile import ScanProfileCreate, ScanProfileResponse, ScanProfileUpdate
from app.services.scan_profiles import profiles_visible_to_organization


router = APIRouter(prefix="/scan-profiles", tags=["Scan Profiles"])


def _resolve_organization_id(current_user: User, requested_id: Optional[int]) -> int:
    if current_user.is_superuser:
        if requested_id is None:
            raise HTTPException(status_code=400, detail="organization_id is required for this operation")
        return requested_id
    if current_user.organization_id is None:
        raise HTTPException(status_code=403, detail="Your account is not assigned to an organization")
    if requested_id is not None and requested_id != current_user.organization_id:
        raise HTTPException(status_code=403, detail="Access denied to this organization")
    return current_user.organization_id


def _managed_profile(db: Session, profile_id: int, current_user: User) -> ScanProfile:
    profile = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Scan profile not found")
    if profile.organization_id is None:
        raise HTTPException(status_code=403, detail="Built-in scan profiles cannot be modified")
    if not current_user.is_superuser and profile.organization_id != current_user.organization_id:
        raise HTTPException(status_code=403, detail="Access denied to this scan profile")
    return profile


def _ensure_unique_name(
    db: Session,
    organization_id: int,
    name: str,
    *,
    exclude_id: Optional[int] = None,
) -> None:
    query = db.query(ScanProfile.id).filter(
        ScanProfile.organization_id == organization_id,
        func.lower(ScanProfile.name) == name.strip().lower(),
    )
    if exclude_id is not None:
        query = query.filter(ScanProfile.id != exclude_id)
    if query.first():
        raise HTTPException(status_code=409, detail="A scan profile with this name already exists")


def _make_default_exclusive(db: Session, profile: ScanProfile) -> None:
    if not profile.is_default:
        return
    db.query(ScanProfile).filter(
        ScanProfile.organization_id == profile.organization_id,
        ScanProfile.profile_type == profile.profile_type,
        ScanProfile.id != profile.id,
    ).update({ScanProfile.is_default: False}, synchronize_session=False)


@router.get("/", response_model=list[ScanProfileResponse])
def list_scan_profiles(
    organization_id: Optional[int] = Query(default=None),
    include_inactive: bool = Query(default=False),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List built-ins and profiles visible to the selected organization."""
    query = db.query(ScanProfile)
    if current_user.is_superuser:
        query = (
            profiles_visible_to_organization(query, organization_id)
            if organization_id is not None
            else query.filter(ScanProfile.organization_id.is_(None))
        )
    else:
        if current_user.organization_id is None:
            return []
        query = profiles_visible_to_organization(query, current_user.organization_id)
    if not include_inactive:
        query = query.filter(ScanProfile.is_active.is_(True))
    return query.order_by(ScanProfile.is_default.desc(), ScanProfile.name.asc()).all()


@router.get("/{profile_id}", response_model=ScanProfileResponse)
def get_scan_profile(
    profile_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    query = db.query(ScanProfile).filter(ScanProfile.id == profile_id)
    if not current_user.is_superuser:
        if current_user.organization_id is None:
            raise HTTPException(status_code=404, detail="Scan profile not found")
        query = profiles_visible_to_organization(query, current_user.organization_id)
    profile = query.first()
    if not profile:
        raise HTTPException(status_code=404, detail="Scan profile not found")
    return profile


@router.post("/", response_model=ScanProfileResponse, status_code=status.HTTP_201_CREATED)
def create_scan_profile(
    payload: ScanProfileCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    organization_id = _resolve_organization_id(current_user, payload.organization_id)
    organization = db.query(Organization.id).filter(
        Organization.id == organization_id,
        Organization.is_active.is_(True),
    ).first()
    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found")
    _ensure_unique_name(db, organization_id, payload.name)

    data = payload.model_dump(exclude={"organization_id"})
    data["name"] = data["name"].strip()
    profile = ScanProfile(**data, organization_id=organization_id, created_by=current_user.username)
    db.add(profile)
    db.flush()
    _make_default_exclusive(db, profile)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="A scan profile with this name already exists") from exc
    db.refresh(profile)
    return profile


@router.put("/{profile_id}", response_model=ScanProfileResponse)
def update_scan_profile(
    profile_id: int,
    payload: ScanProfileUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    profile = _managed_profile(db, profile_id, current_user)
    changes = payload.model_dump(exclude_unset=True)
    if "name" in changes:
        changes["name"] = changes["name"].strip()
        _ensure_unique_name(db, profile.organization_id, changes["name"], exclude_id=profile.id)
    for field, value in changes.items():
        setattr(profile, field, value)
    db.flush()
    _make_default_exclusive(db, profile)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="A scan profile with this name already exists") from exc
    db.refresh(profile)
    return profile


@router.delete("/{profile_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan_profile(
    profile_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    profile = _managed_profile(db, profile_id, current_user)
    db.delete(profile)
    db.commit()
    return None
