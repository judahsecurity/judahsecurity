"""Detection suppression routes.

Pattern-based false-positive handling. When false-positive signals for a
detection template span enough distinct hosts, the system raises a suppression
*recommendation*. An analyst reviews it and either:

  - approves  -> future matches of the template are auto-marked false_positive
                 at ingest, or
  - dismisses -> no enforcement.

Analysts can also send a sample of the template's open findings to the Aegis Vanguard
validator agent to gather stronger evidence before deciding.
"""

import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.detection_suppression import DetectionSuppression, SuppressionStatus
from app.models.user import User
from app.api.deps import get_current_active_user, require_analyst
from app.services import detection_pattern_service as patterns

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/detection-suppression", tags=["Detection Suppression"])


def _to_dict(db: Session, s: DetectionSuppression, include_coverage: bool = False) -> dict:
    data = {
        "id": s.id,
        "organization_id": s.organization_id,
        "template_id": s.template_id,
        "detected_by": s.detected_by,
        "status": s.status.value if s.status else None,
        "host_count": s.host_count,
        "threshold": s.threshold,
        "signal_breakdown": s.signal_breakdown or {},
        "first_flagged_at": s.first_flagged_at,
        "last_evaluated_at": s.last_evaluated_at,
        "approved_by_user_id": s.approved_by_user_id,
        "approved_at": s.approved_at,
        "dismissed_by_user_id": s.dismissed_by_user_id,
        "dismissed_at": s.dismissed_at,
        "created_at": s.created_at,
    }
    if include_coverage:
        data["validation_coverage"] = patterns.get_template_validation_coverage(
            db, s.organization_id, s.template_id
        )
    return data


def _get_org_scoped(db: Session, current_user: User, suppression_id: int) -> DetectionSuppression:
    s = db.query(DetectionSuppression).filter(DetectionSuppression.id == suppression_id).first()
    if not s:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Suppression not found")
    if not current_user.is_superuser and s.organization_id != current_user.organization_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    return s


@router.get("")
def list_suppressions(
    status_filter: Optional[str] = Query(None, alias="status", description="recommended|approved|dismissed"),
    template_id: Optional[str] = Query(None),
    include_coverage: bool = Query(True, description="Include validator-agent coverage per template"),
    limit: int = Query(200, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> List[dict]:
    """List detection suppression recommendations/rules for the organization."""
    query = db.query(DetectionSuppression)
    if not current_user.is_superuser:
        query = query.filter(DetectionSuppression.organization_id == current_user.organization_id)
    if status_filter:
        try:
            query = query.filter(DetectionSuppression.status == SuppressionStatus(status_filter))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status_filter}")
    if template_id:
        query = query.filter(DetectionSuppression.template_id == template_id)
    rows = query.order_by(DetectionSuppression.host_count.desc(), DetectionSuppression.last_evaluated_at.desc()).limit(limit).all()
    return [_to_dict(db, s, include_coverage=include_coverage) for s in rows]


@router.post("/evaluate")
def evaluate_patterns(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> dict:
    """Recompute FP patterns across all templates for the organization."""
    org_id = current_user.organization_id
    rows = patterns.evaluate_all(db, org_id)
    return {
        "evaluated": True,
        "recommendations": [_to_dict(db, s) for s in rows if s.status == SuppressionStatus.RECOMMENDED],
        "count": len(rows),
    }


@router.post("/{suppression_id}/approve")
def approve_suppression(
    suppression_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> dict:
    """Approve suppression — future matches of this template are auto-marked FP."""
    s = _get_org_scoped(db, current_user, suppression_id)
    s.status = SuppressionStatus.APPROVED
    s.approved_by_user_id = current_user.id
    s.approved_at = datetime.utcnow()
    s.dismissed_by_user_id = None
    s.dismissed_at = None
    db.commit()
    db.refresh(s)
    logger.info("Suppression %s approved for template %s by user %s", s.id, s.template_id, current_user.id)
    return _to_dict(db, s)


@router.post("/{suppression_id}/dismiss")
def dismiss_suppression(
    suppression_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> dict:
    """Dismiss the recommendation — no enforcement."""
    s = _get_org_scoped(db, current_user, suppression_id)
    s.status = SuppressionStatus.DISMISSED
    s.dismissed_by_user_id = current_user.id
    s.dismissed_at = datetime.utcnow()
    s.approved_by_user_id = None
    s.approved_at = None
    db.commit()
    db.refresh(s)
    logger.info("Suppression %s dismissed for template %s by user %s", s.id, s.template_id, current_user.id)
    return _to_dict(db, s)


@router.post("/{suppression_id}/validate-sample")
def validate_sample(
    suppression_id: int,
    limit: Optional[int] = Query(None, description="Max findings to queue for validation"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> dict:
    """Send a sample of this template's open findings to the validator agent.

    Strengthens the FP evidence before an analyst approves suppression.
    """
    s = _get_org_scoped(db, current_user, suppression_id)
    created_ids = patterns.queue_sample_validations(
        db,
        organization_id=s.organization_id,
        template_id=s.template_id,
        requested_by_user_id=current_user.id,
        limit=limit,
    )
    return {
        "queued": len(created_ids),
        "validation_ids": created_ids,
        "template_id": s.template_id,
        "message": (
            f"Queued {len(created_ids)} finding(s) for validator-agent review."
            if created_ids else
            "No open, unvalidated findings available to queue."
        ),
    }
