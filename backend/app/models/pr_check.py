"""Pull-request security check results (source analysis + Prowl handoff)."""

from datetime import datetime

from sqlalchemy import JSON, Column, DateTime, ForeignKey, Integer, String

from app.db.database import Base


class PrCheck(Base):
    __tablename__ = "pr_checks"

    id = Column(String(32), primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True, index=True)
    agent_key_id = Column(String(32), nullable=True)
    repository = Column(String(200), nullable=False, default="")
    pull_request = Column(Integer, nullable=True)
    head_sha = Column(String(64), nullable=False, default="")
    base_sha = Column(String(64), nullable=False, default="")
    conclusion = Column(String(20), nullable=False, default="neutral")  # success | failure | neutral
    fail_on = Column(String(20), nullable=False, default="medium")
    findings = Column(JSON, default=list)
    routes = Column(JSON, default=list)
    summary = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
