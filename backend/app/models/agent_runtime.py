"""Durable control-plane models for agent runs, events, commands, and skills."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)

from app.db.database import Base


class AgentRun(Base):
    __tablename__ = "agent_runs"
    __table_args__ = (
        Index("ix_agent_runs_org_status_updated", "organization_id", "status", "updated_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(64), unique=True, nullable=False, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    status = Column(String(24), nullable=False, default="pending", index=True)
    mode = Column(String(20), nullable=False, default="assist")
    objective = Column(Text, nullable=True)
    current_phase = Column(String(64), nullable=True)
    current_step = Column(String(255), nullable=True)
    iteration_count = Column(Integer, nullable=False, default=0)
    progress = Column(Integer, nullable=False, default=0)
    price_limit_usd = Column(Float, nullable=True)
    cost_usd = Column(Float, nullable=True)
    worker_id = Column(String(255), nullable=True, index=True)
    lease_expires_at = Column(DateTime, nullable=True, index=True)
    heartbeat_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    run_metadata = Column("metadata", JSON, default=dict)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class AgentEventRecord(Base):
    __tablename__ = "agent_events"
    __table_args__ = (
        Index("ix_agent_events_run_created", "run_id", "created_at"),
        Index("ix_agent_events_org_type", "organization_id", "event_type"),
    )

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(64), unique=True, nullable=False, index=True)
    run_id = Column(
        String(64), ForeignKey("agent_runs.session_id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id = Column(String(64), nullable=True)
    event_type = Column(String(64), nullable=False, index=True)
    agent_id = Column(String(128), nullable=True)
    step_id = Column(String(128), nullable=True)
    severity = Column(String(32), nullable=True)
    payload = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)


class AgentCommand(Base):
    __tablename__ = "agent_commands"
    __table_args__ = (
        Index("ix_agent_commands_run_status", "run_id", "status", "created_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    command_id = Column(String(64), unique=True, nullable=False, index=True)
    run_id = Column(
        String(64), ForeignKey("agent_runs.session_id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    command_type = Column(String(32), nullable=False, index=True)
    payload = Column(JSON, default=dict)
    status = Column(String(24), nullable=False, default="queued", index=True)
    issued_by = Column(String(64), nullable=True)
    claimed_by = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    claimed_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)


class AgentCheckpoint(Base):
    __tablename__ = "agent_checkpoints"

    run_id = Column(
        String(64), ForeignKey("agent_runs.session_id", ondelete="CASCADE"), primary_key=True
    )
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    schema_version = Column(Integer, nullable=False, default=1)
    state = Column(JSON, nullable=False, default=dict)
    state_digest = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class AgentSkillVersion(Base):
    __tablename__ = "agent_skill_versions"
    __table_args__ = (
        UniqueConstraint("organization_id", "skill_id", "version", name="uq_agent_skill_version"),
        Index("ix_agent_skills_org_enabled", "organization_id", "enabled"),
        Index(
            "uq_agent_skill_global_version",
            "skill_id",
            "version",
            unique=True,
            postgresql_where=text("organization_id IS NULL"),
            sqlite_where=text("organization_id IS NULL"),
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True
    )
    skill_id = Column(String(64), nullable=False, index=True)
    version = Column(String(64), nullable=False)
    manifest = Column(JSON, nullable=False, default=dict)
    content_hash = Column(String(64), nullable=False, index=True)
    enabled = Column(Boolean, nullable=False, default=False)
    approved_by = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class AgentNotificationEndpoint(Base):
    __tablename__ = "agent_notification_endpoints"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_agent_notification_endpoint_name"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name = Column(String(128), nullable=False)
    channel = Column(String(32), nullable=False)
    config_ref = Column(String(255), nullable=False)
    event_types = Column(JSON, default=list)
    minimum_severity = Column(String(32), nullable=True)
    enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class AgentNotificationDelivery(Base):
    __tablename__ = "agent_notification_deliveries"
    __table_args__ = (
        UniqueConstraint("endpoint_id", "event_id", name="uq_agent_notification_delivery"),
    )

    id = Column(Integer, primary_key=True, index=True)
    endpoint_id = Column(
        Integer, ForeignKey("agent_notification_endpoints.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_id = Column(String(64), nullable=False, index=True)
    status = Column(String(24), nullable=False, default="pending", index=True)
    attempts = Column(Integer, nullable=False, default=0)
    error_message = Column(Text, nullable=True)
    delivered_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
