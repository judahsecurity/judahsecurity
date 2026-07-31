"""
Detection Suppression model.

Per-(organization, template) rollup that turns repeated false-positive signals
into an actionable decision. A template is only ever suppressed after an analyst
approves the recommendation — the system never auto-suppresses on a single
false positive.

Lifecycle:
    recommended  -> the FP signal crossed the pattern threshold; awaiting review
    approved     -> analyst approved; future matches of this template are
                    auto-marked false_positive at ingest
    dismissed    -> analyst rejected the recommendation; no enforcement, and it
                    will not be re-recommended
"""

import enum
from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    JSON,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.db.database import Base


class SuppressionStatus(str, enum.Enum):
    RECOMMENDED = "recommended"
    APPROVED = "approved"
    DISMISSED = "dismissed"


class DetectionSuppression(Base):
    """A per-template suppression recommendation / rule."""

    __tablename__ = "detection_suppression"
    __table_args__ = (
        UniqueConstraint("organization_id", "template_id", name="uq_detection_suppression_org_template"),
    )

    id = Column(Integer, primary_key=True, index=True)

    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    organization = relationship("Organization")

    template_id = Column(String(255), nullable=False, index=True)
    detected_by = Column(String(100), nullable=True)  # e.g. nuclei

    status = Column(Enum(SuppressionStatus), default=SuppressionStatus.RECOMMENDED, nullable=False, index=True)

    # Pattern metrics captured at last evaluation
    host_count = Column(Integer, default=0)      # distinct hosts with an FP signal
    threshold = Column(Integer, default=0)       # threshold used when flagged
    # Breakdown of contributing signals, e.g.
    # {"validator": 4, "analyst": 1, "manual": 2, "hosts": ["a.com", ...]}
    signal_breakdown = Column(JSON, default=dict)

    # Provenance / decision
    first_flagged_at = Column(DateTime, default=datetime.utcnow)
    last_evaluated_at = Column(DateTime, default=datetime.utcnow)
    approved_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    dismissed_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    dismissed_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self) -> str:
        return (
            f"<DetectionSuppression {self.id} template={self.template_id} "
            f"status={self.status} hosts={self.host_count}>"
        )
