"""Read-only CrowdStrike Falcon Exposure Management connection and source links."""

from datetime import datetime, timedelta

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from app.db.database import Base
from app.models.api_config import get_cipher


class CrowdStrikeIntegration(Base):
    __tablename__ = "crowdstrike_integrations"
    __table_args__ = (UniqueConstraint("organization_id", "connection_name", name="uq_crowdstrike_org_connection"),)

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    connection_name = Column(String(255), nullable=False)
    cloud_region = Column(String(20), nullable=False)
    client_id_encrypted = Column(Text, nullable=False)
    client_secret_encrypted = Column(Text, nullable=False)
    import_external_assets = Column(Boolean, nullable=False, default=True)
    import_hosts = Column(Boolean, nullable=False, default=True)
    import_spotlight = Column(Boolean, nullable=False, default=True)
    is_active = Column(Boolean, nullable=False, default=True)
    continuous_sync_enabled = Column(Boolean, nullable=False, default=True)
    sync_interval_minutes = Column(Integer, nullable=False, default=1440)
    last_tested_at = Column(DateTime)
    last_test_ok = Column(Boolean)
    last_sync_at = Column(DateTime)
    last_sync_ok = Column(Boolean)
    last_sync_stats = Column(JSON, default=dict)
    last_error = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    links = relationship("CrowdStrikeAssetLink", cascade="all, delete-orphan")

    def set_client_id(self, value: str) -> None:
        if value:
            self.client_id_encrypted = get_cipher().encrypt(value.encode()).decode()

    def get_client_id(self) -> str | None:
        return get_cipher().decrypt(self.client_id_encrypted.encode()).decode() if self.client_id_encrypted else None

    def set_client_secret(self, value: str) -> None:
        if value:
            self.client_secret_encrypted = get_cipher().encrypt(value.encode()).decode()

    def get_client_secret(self) -> str | None:
        return get_cipher().decrypt(self.client_secret_encrypted.encode()).decode() if self.client_secret_encrypted else None

    @property
    def next_sync_at(self) -> datetime | None:
        if not self.is_active or not self.continuous_sync_enabled:
            return None
        return (self.last_sync_at or datetime.utcnow()) + (timedelta(minutes=self.sync_interval_minutes) if self.last_sync_at else timedelta())

    def is_sync_due(self, now: datetime | None = None) -> bool:
        due = self.next_sync_at
        return due is not None and (now or datetime.utcnow()) >= due


class CrowdStrikeAssetLink(Base):
    """Stable Falcon ID to Judah asset mapping; avoids merging hosts by shared IP or hostname."""

    __tablename__ = "crowdstrike_asset_links"
    __table_args__ = (UniqueConstraint("integration_id", "source_kind", "source_id", name="uq_crowdstrike_source_link"),)

    id = Column(Integer, primary_key=True)
    integration_id = Column(Integer, ForeignKey("crowdstrike_integrations.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    source_kind = Column(String(20), nullable=False)  # external or host
    source_id = Column(String(255), nullable=False)
    cid = Column(String(100))
    last_seen = Column(DateTime, default=datetime.utcnow)
