"""Attack-path workspace API — Chariot-style campaign graphs per organization."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user
from app.db.database import get_db
from app.models.organization import Organization
from app.models.user import User
from app.services.attack_path_campaign import build_workspace

router = APIRouter(prefix="/attacks", tags=["Attacks"])


def _resolve_org_id(current_user: User, organization_id: Optional[int]) -> int:
    if current_user.is_superuser:
        if organization_id:
            return organization_id
        if current_user.organization_id:
            return current_user.organization_id
        raise HTTPException(status_code=400, detail="Select an organization")
    org_id = current_user.organization_id
    if not org_id:
        raise HTTPException(status_code=400, detail="User must belong to an organization")
    if organization_id and organization_id != org_id:
        raise HTTPException(status_code=403, detail="Access denied")
    return org_id


@router.get("/workspace")
def get_attack_workspace(
    organization_id: Optional[int] = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Named attack-path campaigns, capabilities, signatures, and juicy fruit for an org."""
    org_id = _resolve_org_id(current_user, organization_id)
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return build_workspace(db, org_id)
