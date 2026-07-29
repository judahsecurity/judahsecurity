"""
Finding Validation model.

Records each on-demand run of the Aegis Vanguard validator agent against a single
finding. The agent actively re-tests the live target and returns a structured
verdict (confirmed / false_positive / needs_more_evidence) plus the evidence it
gathered. One finding can be validated multiple times; the latest completed
record is surfaced in the UI.
"""

import enum
from datetime import datetime

from sqlalchemy import Column, DateTime, Enum, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship

from app.db.database import Base


class ValidationStatus(str, enum.Enum):
    """Lifecycle of a validation run."""
    QUEUED = "queued"        # Enqueued, worker has not started
    RUNNING = "running"      # Worker is invoking the validator agent
    COMPLETED = "completed"  # Verdict written
    FAILED = "failed"        # Agent invocation errored


class ValidationVerdict(str, enum.Enum):
    """Verdict produced by the validator agent."""
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    NEEDS_MORE_EVIDENCE = "needs_more_evidence"


class FindingValidation(Base):
    """A single validator-agent run against one finding."""

    __tablename__ = "finding_validations"

    id = Column(Integer, primary_key=True, index=True)

    # What is being validated
    vulnerability_id = Column(
        Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    vulnerability = relationship("Vulnerability", back_populates="validations")

    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    # Run lifecycle
    status = Column(Enum(ValidationStatus), default=ValidationStatus.QUEUED, nullable=False, index=True)

    # Verdict (populated on completion)
    verdict = Column(Enum(ValidationVerdict), nullable=True, index=True)
    confidence = Column(String(20), nullable=True)          # high | medium | low
    recommended_severity = Column(String(20), nullable=True)  # critical..info
    reasoning = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    template_logic_issue = Column(Text, nullable=True)      # set when template logic caused a FP
    error = Column(String(255), nullable=True)              # populated on failure/unparseable

    # Full raw agent JSON output (verdict + _meta) for auditing
    raw_output = Column(JSON, default=dict)

    # Who requested it
    requested_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    def __repr__(self) -> str:
        return (
            f"<FindingValidation {self.id} vuln={self.vulnerability_id} "
            f"status={self.status} verdict={self.verdict}>"
        )
