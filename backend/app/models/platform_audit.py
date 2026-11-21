"""Who did what on the platform (logins, settings, approvals, exports, users)."""

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, JSON, String

from app.db.database import Base


class PlatformAuditLog(Base):
    __tablename__ = "platform_audit_log"

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"),
                             nullable=True, index=True)
    user_id = Column(Integer, nullable=True, index=True)  # no FK: keep rows after user deletion
    actor = Column(String(255), nullable=False, default="")  # username/email snapshot
    action = Column(String(64), nullable=False, index=True)
    target = Column(String(512), nullable=False, default="")
    outcome = Column(String(16), nullable=False, default="success")  # success|denied|failed
    ip = Column(String(64), nullable=False, default="")
    user_agent = Column(String(255), nullable=False, default="")
    detail = Column(JSON, nullable=False, default=dict)

    __table_args__ = (Index("ix_platform_audit_org_created", "organization_id", "created_at"),)
