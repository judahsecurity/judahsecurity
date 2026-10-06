"""Per-organization NetBrain configuration-evidence integration."""

from datetime import datetime, timedelta

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from app.db.database import Base
from app.models.api_config import get_cipher


class NetBrainIntegration(Base):
    """Read-only NetBrain connection used to validate exploit prerequisites."""

    __tablename__ = "netbrain_integrations"
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_netbrain_org_name"),)

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization = relationship("Organization")

    name = Column(String(255), nullable=False)
    base_url = Column(String(500), nullable=False)
    username_encrypted = Column(Text, nullable=False)
    password_encrypted = Column(Text, nullable=False)
    authentication_id = Column(String(255), nullable=True)
    tenant_id = Column(String(128), nullable=False)
    domain_id = Column(String(128), nullable=False)
    verify_ssl = Column(Boolean, default=True, nullable=False)

    is_active = Column(Boolean, default=True, nullable=False)
    continuous_sync_enabled = Column(Boolean, default=False, nullable=False)
    sync_interval_minutes = Column(Integer, default=360, nullable=False)
    max_config_age_hours = Column(Integer, default=24, nullable=False)
    auto_mitigate_enabled = Column(Boolean, default=False, nullable=False)

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
        if not (self.is_active and self.continuous_sync_enabled):
            return None
        if self.last_sync_at is None:
            return datetime.utcnow()
        return self.last_sync_at + timedelta(minutes=self.sync_interval_minutes or 360)

    def is_sync_due(self, now: datetime | None = None) -> bool:
        next_sync = self.next_sync_at
        return bool(next_sync and (now or datetime.utcnow()) >= next_sync)
