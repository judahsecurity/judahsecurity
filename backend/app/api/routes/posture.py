"""Customer-facing external security posture grade."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user
from app.core.config import settings
from app.db.database import get_db
from app.models.organization import Organization
from app.models.user import User
from app.services.posture_score_service import MODEL_VERSION, build_posture_score


router = APIRouter(prefix="/posture", tags=["External Security Posture"])


def _resolve_organization_id(current_user: User, requested_id: Optional[int]) -> int:
    if current_user.is_superuser:
        organization_id = requested_id or current_user.organization_id
        if not organization_id:
            raise HTTPException(status_code=400, detail="Select an organization to calculate its posture grade")
        return organization_id
    if not current_user.organization_id:
        raise HTTPException(status_code=400, detail="User must belong to an organization")
    if requested_id and requested_id != current_user.organization_id:
        raise HTTPException(status_code=403, detail="Access denied")
    return current_user.organization_id


@router.get("/grade")
def get_posture_grade(
    organization_id: Optional[int] = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Calculate the current grade for the caller's organization."""
    if not settings.POSTURE_GRADE_ENABLED:
        return {
            "enabled": False,
            "rating_status": "disabled",
            "model_version": MODEL_VERSION,
        }

    resolved_id = _resolve_organization_id(current_user, organization_id)
    exists = db.query(Organization.id).filter(Organization.id == resolved_id).first()
    if not exists:
        raise HTTPException(status_code=404, detail="Organization not found")
    return build_posture_score(db, resolved_id)
