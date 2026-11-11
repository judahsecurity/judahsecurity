"""AI-written fix pull requests for independently verified findings."""

from datetime import datetime

from sqlalchemy import JSON, Column, DateTime, ForeignKey, Integer, String, Text

from app.db.database import Base


class FixRequest(Base):
    __tablename__ = "fix_requests"

    id = Column(String(32), primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False, index=True)
    created_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    repository = Column(String(200), nullable=False)
    base_branch = Column(String(200), nullable=False, default="")
    branch = Column(String(200), nullable=False, default="")
    pr_number = Column(Integer, nullable=True)
    pr_url = Column(String(500), nullable=True)
    # pr_open | verified_fixed | fix_ineffective | failed
    status = Column(String(30), nullable=False, default="pr_open", index=True)
    files = Column(JSON, default=list)
    summary = Column(Text, nullable=True)
    preview_origin = Column(String(300), nullable=True)
    verification = Column(JSON, default=dict)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
