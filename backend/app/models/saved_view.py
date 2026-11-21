"""Saved filter views for list pages (assets, findings)."""

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String

from app.db.database import Base


class SavedView(Base):
    __tablename__ = "saved_views"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"),
                             nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    page = Column(String(32), nullable=False, index=True)  # assets | findings
    name = Column(String(80), nullable=False)
    filters = Column(JSON, nullable=False, default=dict)
    shared = Column(Boolean, nullable=False, default=False)  # visible to the whole org
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
