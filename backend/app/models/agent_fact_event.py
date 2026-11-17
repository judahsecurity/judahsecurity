"""Append-only fact stream for worker-recorded assessment facts.

Captures, differentials, credentials, and verified findings are written here as
thin, idempotent, redacted rows so the planner reliably turns them into
hypotheses across turns and restarts — independent of whether the model called
queue_finding_followups. Evidence bytes stay in the evidence store; these rows
carry pointers plus a value-free payload.
"""

from datetime import datetime

from sqlalchemy import BigInteger, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB

from app.db.database import Base

# Recognized fact kinds. A verified_finding is still a lead at consume time; the
# finding gate, not this event, authorizes a reported finding.
FACT_KINDS = ("capture", "differential", "credential", "verified_finding")


class AgentFactEvent(Base):
    """One durable, append-only assessment fact."""

    __tablename__ = "agent_fact_events"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    event_uuid = Column(String(64), nullable=False, unique=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False,
    )
    session_id = Column(String(64), nullable=False, index=True)
    work_id = Column(String(64), nullable=True)
    run_id = Column(String(64), nullable=True)
    kind = Column(String(32), nullable=False)
    target = Column(String(512), nullable=False, default="")
    dedupe_key = Column(String(128), nullable=False)
    scope = Column(JSONB, nullable=False, default=dict)
    evidence_ids = Column(JSONB, nullable=False, default=list)
    payload = Column(JSONB, nullable=False, default=dict)
    consumed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
