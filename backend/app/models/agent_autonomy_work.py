"""Persisted scheduled assessment continuation, one target per work item."""

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, JSON, String, Text

from app.db.database import Base


class AgentAutonomyWork(Base):
    __tablename__ = "agent_autonomy_work"

    id = Column(String(64), primary_key=True)
    schedule_id = Column(Integer, ForeignKey("scan_schedules.id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    target = Column(String(512), nullable=False)
    session_id = Column(String(64), nullable=False, unique=True)
    status = Column(String(24), nullable=False, default="queued", index=True)
    prompt = Column(Text, nullable=False, default="")
    revisions = Column(JSON, nullable=False, default=list)
    turns = Column(Integer, nullable=False, default=0)
    max_turns = Column(Integer, nullable=False, default=3)
    price_limit_usd = Column(Float, nullable=False, default=8.0)
    spent_usd = Column(Float, nullable=False, default=0.0)
    max_total_seconds = Column(Integer, nullable=False, default=3600)
    limits = Column(JSON, nullable=False, default=dict)
    lease_owner = Column(String(64), nullable=False, default="")
    lease_until = Column(DateTime, nullable=True)
    turn_started_at = Column(DateTime, nullable=True)
    stop_reason = Column(Text, nullable=False, default="")
    answer = Column(Text, nullable=False, default="")
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    notification_sent = Column(Boolean, nullable=False, default=False)


class AgentRunSnapshot(Base):
    """Redacted scheduled-agent state shared across worker containers."""

    __tablename__ = "agent_run_snapshots"

    session_id = Column(String(64), primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    payload = Column(JSON, nullable=False)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
