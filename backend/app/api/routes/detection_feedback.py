"""Detection feedback routes.

Read access to the template-keyed detection-logic feedback log. Feedback is
created either automatically by the validator agent (via the scanner worker) or
by an analyst through POST /vulnerabilities/{id}/detection-feedback.
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.detection_feedback import DetectionFeedback
from app.models.user import User
from app.api.deps import get_current_active_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/detection-feedback", tags=["Detection Feedback"])


def feedback_to_dict(fb: DetectionFeedback) -> dict:
    return {
        "id": fb.id,
        "organization_id": fb.organization_id,
        "template_id": fb.template_id,
        "detected_by": fb.detected_by,
        "verdict": fb.verdict,
        "logic_issue": fb.logic_issue,
        "upstream_report": fb.upstream_report,
        "example_vulnerability_id": fb.example_vulnerability_id,
        "finding_validation_id": fb.finding_validation_id,
        "source": fb.source,
        "reported_by_user_id": fb.reported_by_user_id,
        "created_at": fb.created_at,
    }


@router.get("")
def list_detection_feedback(
    template_id: Optional[str] = Query(None, description="Filter by detection template id"),
    limit: int = Query(100, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> List[dict]:
    """List detection-logic feedback for the current organization."""
    query = db.query(DetectionFeedback)
    if not current_user.is_superuser:
        query = query.filter(DetectionFeedback.organization_id == current_user.organization_id)
    if template_id:
        query = query.filter(DetectionFeedback.template_id == template_id)
    rows = query.order_by(DetectionFeedback.created_at.desc()).limit(limit).all()
    return [feedback_to_dict(fb) for fb in rows]
