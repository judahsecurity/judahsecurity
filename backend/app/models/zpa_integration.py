"""ZPA Log Streaming Service receiver configuration and deduplicated evidence."""

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import relationship

from app.db.database import Base


class ZpaIntegration(Base):
    __tablename__ = "zpa_integrations"
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_zpa_org_name"),)

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    token_hash = Column(String(64), nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_ingest_at = Column(DateTime)
    organization = relationship("Organization")
    observations = relationship("ZpaObservation", cascade="all, delete-orphan", passive_deletes=True)


class ZpaObservation(Base):
    """One LSS connection event; no username or raw log payload is retained."""

    __tablename__ = "zpa_observations"
    __table_args__ = (UniqueConstraint("integration_id", "fingerprint", name="uq_zpa_event"),)

    id = Column(Integer, primary_key=True)
    integration_id = Column(Integer, ForeignKey("zpa_integrations.id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    fingerprint = Column(String(64), nullable=False)
    feed = Column(String(32), nullable=False)
    source_key = Column(String(500), nullable=False)
    source_name = Column(String(255))
    destination_asset_id = Column(Integer, ForeignKey("assets.id", ondelete="SET NULL"), index=True)
    destination = Column(String(500), nullable=False)
    destination_port = Column(Integer)
    protocol = Column(String(32))
    action = Column(String(32))
    connected = Column(Boolean, nullable=False)
    occurred_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
