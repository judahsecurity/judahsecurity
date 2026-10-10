"""Durable agent run and append-only action receipts."""

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String, Text

from app.db.database import Base


class AgentRunLedger(Base):
    __tablename__ = "agent_run_ledger"

    id = Column(String(64), primary_key=True)
    session_id = Column(String(64), nullable=False, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    objective = Column(Text, nullable=False, default="")
    mode = Column(String(20), nullable=False, default="assist")
    status = Column(String(24), nullable=False, default="running")
    reason = Column(Text, nullable=False, default="")
    started_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    deadline_at = Column(DateTime, nullable=True)
    ended_at = Column(DateTime, nullable=True)


class AgentActionReceipt(Base):
    __tablename__ = "agent_action_receipts"

    id = Column(Integer, primary_key=True)
    run_id = Column(String(64), ForeignKey("agent_run_ledger.id", ondelete="CASCADE"), nullable=False, index=True)
    action_id = Column(String(64), nullable=False, index=True)
    event = Column(String(24), nullable=False)  # started / completed / failed / interrupted / skipped
    tool_name = Column(String(128), nullable=False)
    target = Column(String(512), nullable=False, default="")
    phase = Column(String(32), nullable=False, default="")
    detail = Column(Text, nullable=False, default="")
    evidence_ids = Column(JSON, nullable=False, default=list)
    fingerprint = Column(String(64), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class AgentHypothesisCoverage(Base):
    __tablename__ = "agent_hypothesis_coverage"

    run_id = Column(String(64), ForeignKey("agent_run_ledger.id", ondelete="CASCADE"), primary_key=True)
    hypothesis_id = Column(String(64), primary_key=True)
    title = Column(String(240), nullable=False, default="")
    specialist = Column(String(64), nullable=False, default="")
    status = Column(String(24), nullable=False, default="pending")
    attempts = Column(Integer, nullable=False, default=0)
    blocked_reason = Column(String(300), nullable=False, default="")
    evidence_ids = Column(JSON, nullable=False, default=list)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)
