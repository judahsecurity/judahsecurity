"""CrowdStrike Falcon Exposure Management integration model."""

from datetime import datetime, timedelta

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from app.db.database import Base
from app.models.api_config import get_cipher

# Falcon cloud region -> API base URL. Only these hosts are ever contacted.
FALCON_CLOUDS = {
    "us-1": "https://api.crowdstrike.com",
    "us-2": "https://api.us-2.crowdstrike.com",
    "eu-1": "https://api.eu-1.crowdstrike.com",
    "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
    "us-gov-2": "https://api.us-gov-2.crowdstrike.mil",
}


class CrowdStrikeIntegration(Base):
    """One read-only Falcon API client connection for an organization."""

    __tablename__ = "crowdstrike_integrations"
    __table_args__ = (
        UniqueConstraint("organization_id", "connection_name", name="uq_crowdstrike_org_connection"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization = relationship("Organization")

    connection_name = Column(String(255), nullable=False)
    cloud = Column(String(20), nullable=False, default="us-1")
    client_id_encrypted = Column(Text, nullable=False)
    client_secret_encrypted = Column(Text, nullable=False)
    member_cid = Column(String(64), nullable=True)  # Flight Control child CID
    asset_filter = Column(Text, nullable=True)  # Extra FQL for external assets

    import_assets = Column(Boolean, nullable=False, default=True)
    import_vulnerabilities = Column(Boolean, nullable=False, default=True)
    import_policies = Column(Boolean, nullable=False, default=True)
    internet_exposed_only = Column(Boolean, nullable=False, default=True)
    is_active = Column(Boolean, nullable=False, default=True)
    continuous_sync_enabled = Column(Boolean, nullable=False, default=True)
    sync_interval_minutes = Column(Integer, nullable=False, default=1440)

    last_tested_at = Column(DateTime, nullable=True)
    last_test_ok = Column(Boolean, nullable=True)
    last_sync_at = Column(DateTime, nullable=True)
    last_sync_ok = Column(Boolean, nullable=True)
    last_sync_stats = Column(JSON, default=dict)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def set_client_id(self, value: str) -> None:
        if value:
            self.client_id_encrypted = get_cipher().encrypt(value.encode()).decode()

    def get_client_id(self) -> str | None:
        if self.client_id_encrypted:
            return get_cipher().decrypt(self.client_id_encrypted.encode()).decode()
        return None

    def set_client_secret(self, value: str) -> None:
        if value:
            self.client_secret_encrypted = get_cipher().encrypt(value.encode()).decode()

    def get_client_secret(self) -> str | None:
        if self.client_secret_encrypted:
            return get_cipher().decrypt(self.client_secret_encrypted.encode()).decode()
        return None

    @property
    def next_sync_at(self) -> datetime | None:
        if not (self.continuous_sync_enabled and self.is_active):
            return None
        if self.last_sync_at is None:
            return datetime.utcnow()
        return self.last_sync_at + timedelta(minutes=self.sync_interval_minutes or 1440)

    def is_sync_due(self, now: datetime | None = None) -> bool:
        next_sync = self.next_sync_at
        return next_sync is not None and (now or datetime.utcnow()) >= next_sync

    def __repr__(self) -> str:
        return f"<CrowdStrikeIntegration org={self.organization_id} name={self.connection_name!r}>"
