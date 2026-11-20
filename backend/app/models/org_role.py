"""Custom per-organization roles (permission subsets of a user's built-in role)."""

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String, UniqueConstraint

from app.db.database import Base


class OrgRole(Base):
    __tablename__ = "org_roles"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"),
                             nullable=False, index=True)
    name = Column(String(80), nullable=False)
    description = Column(String(300), nullable=False, default="")
    permissions = Column(JSON, nullable=False, default=list)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_org_roles_org_name"),)
