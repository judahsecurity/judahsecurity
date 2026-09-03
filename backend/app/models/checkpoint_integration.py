"""Check Point integration model.

Stores per-organization connections to a Check Point Security Management
Server (or Multi-Domain Server domain). Read-only: imports network objects
(hosts, networks, address ranges) as assets via the Management Web API and
never publishes changes back to the management server.

Authentication uses management credentials (username + password) exchanged
for a short-lived session id (``sid``) on each sync.
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


class CheckPointIntegration(Base):
    """Stores a Check Point management connection for an organization."""

    __tablename__ = "checkpoint_integrations"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "name", name="uq_checkpoint_org_name"
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization = relationship("Organization")

    # Human-friendly label (e.g. "HQ Management", "SMS-Prod").
    name = Column(String(255), nullable=False)

    # Full URL of the Security Management Server (e.g. https://mgmt.example.com).
    management_host = Column(String(500), nullable=False)

    # Management credentials (encrypted).
    username_encrypted = Column(Text, nullable=False)
    password_encrypted = Column(Text, nullable=False)

    # Optional domain for a Multi-Domain Server (MDS). Blank → single-domain SMS.
    domain = Column(String(255), nullable=True)

    # On-prem management servers commonly use self-signed certs.
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

    def set_username(self, value: str) -> None:
        if value:
            self.username_encrypted = get_cipher().encrypt(value.encode()).decode()

    def get_username(self) -> str | None:
        if self.username_encrypted:
            return get_cipher().decrypt(self.username_encrypted.encode()).decode()
        return None

    def set_password(self, value: str) -> None:
        if value:
            self.password_encrypted = get_cipher().encrypt(value.encode()).decode()

    def get_password(self) -> str | None:
        if self.password_encrypted:
            return get_cipher().decrypt(self.password_encrypted.encode()).decode()
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
        return f"<CheckPointIntegration org={self.organization_id} name={self.name!r}>"
