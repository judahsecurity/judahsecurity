"""pfSense integration model.

Stores per-organization connections to a pfSense firewall exposing the
pfSense REST API (v2) package. Read-only: imports firewall alias entries
(host and network aliases) as assets, and never writes configuration back.

Authentication uses an API key sent in the ``X-API-Key`` header.
"""

from datetime import datetime, timedelta

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.db.database import Base
from app.models.api_config import get_cipher


class PfSenseIntegration(Base):
    """Stores a pfSense connection for an organization."""

    __tablename__ = "pfsense_integrations"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "name", name="uq_pfsense_org_name"
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization = relationship("Organization")

    # Human-friendly label (e.g. "Edge pfSense", "Colo-FW").
    name = Column(String(255), nullable=False)

    # Full URL of the pfSense web interface (e.g. https://pfsense.example.com).
    pfsense_host = Column(String(500), nullable=False)

    # pfSense REST API key (encrypted; sent as X-API-Key).
    api_key_encrypted = Column(Text, nullable=False)

    # On-prem pfSense interfaces commonly use self-signed certs.
    verify_ssl = Column(Boolean, default=True, nullable=False)

    is_active = Column(Boolean, default=True, nullable=False)

    continuous_sync_enabled = Column(Boolean, default=False, nullable=False)
    sync_interval_minutes = Column(Integer, default=360, nullable=False)  # 6h default

    last_tested_at = Column(DateTime, nullable=True)
    last_test_ok = Column(Boolean, nullable=True)

    last_sync_at = Column(DateTime, nullable=True)
    last_sync_ok = Column(Boolean, nullable=True)
    last_sync_stats = Column(JSON, default=dict)
    last_error = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def set_api_key(self, key: str) -> None:
        if key:
            self.api_key_encrypted = get_cipher().encrypt(key.encode()).decode()

    def get_api_key(self) -> str | None:
        if self.api_key_encrypted:
            return get_cipher().decrypt(self.api_key_encrypted.encode()).decode()
        return None

    @property
    def next_sync_at(self) -> datetime | None:
        if not (self.continuous_sync_enabled and self.is_active):
            return None
        interval = timedelta(minutes=self.sync_interval_minutes or 360)
        if self.last_sync_at is None:
            return datetime.utcnow()
        return self.last_sync_at + interval

    def is_sync_due(self, now: datetime | None = None) -> bool:
        nxt = self.next_sync_at
        if nxt is None:
            return False
        return (now or datetime.utcnow()) >= nxt

    def __repr__(self) -> str:
        return f"<PfSenseIntegration org={self.organization_id} name={self.name!r}>"
