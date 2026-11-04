"""CrowdStrike Falcon (Hosts + Spotlight) integration model."""

from datetime import datetime, timedelta

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from app.db.database import Base
from app.models.api_config import get_cipher


class CrowdStrikeIntegration(Base):
    """Stores one read-only CrowdStrike Falcon API client for an organization.

    Hosts (``Hosts: Read``) map Falcon-managed devices into internal assets;
    Spotlight (``Vulnerabilities: Read``) imports open CVEs onto those assets.
    """

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
    cloud_region = Column(String(20), nullable=False, default="us-1")
    client_id_encrypted = Column(Text, nullable=False)
    client_secret_encrypted = Column(Text, nullable=False)

    # Modules
    import_hosts = Column(Boolean, nullable=False, default=True)
    import_spotlight = Column(Boolean, nullable=False, default=True)

    # Spotlight filtering: "prioritized" keeps ExPRT High/Critical with a
    # network attack vector, CISA KEV, and ``extra_cve_ids``; "all" keeps every open CVE.
    spotlight_filter_mode = Column(String(20), nullable=False, default="prioritized")
    extra_cve_ids = Column(JSON, default=list)
    host_lookback_days = Column(Integer, nullable=False, default=7)

    is_active = Column(Boolean, nullable=False, default=True)
    continuous_sync_enabled = Column(Boolean, nullable=False, default=True)
    sync_interval_minutes = Column(Integer, nullable=False, default=1440)

    last_tested_at = Column(DateTime, nullable=True)
    last_test_ok = Column(Boolean, nullable=True)
    last_test_modules = Column(JSON, default=dict)
    last_sync_at = Column(DateTime, nullable=True)
    last_sync_ok = Column(Boolean, nullable=True)
    last_spotlight_sync_at = Column(DateTime, nullable=True)  # last *successful* Spotlight pass
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
