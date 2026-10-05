"""Idempotency receipt for findings published by the PROWL agent."""

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String

from app.db.database import Base


class ProwlPublication(Base):
    __tablename__ = "prowl_publications"

    candidate_id = Column(String(64), primary_key=True)
    run_id = Column(String(64), nullable=False, index=True)
    verification_id = Column(String(64), nullable=False)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False, unique=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
