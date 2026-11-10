"""SecurityScorecard third-party ratings integration model."""

from datetime import datetime, timedelta

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from app.db.database import Base
from app.models.api_config import get_cipher


class SecurityScorecardIntegration(Base):
    """Stores one read-only SecurityScorecard API connection for an organization."""

    __tablename__ = "securityscorecard_integrations"
    __table_args__ = (
        UniqueConstraint("organization_id", "connection_name", name="uq_securityscorecard_org_connection"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization = relationship("Organization")

    connection_name = Column(String(255), nullable=False)
    # Hidden "username" field from the reference integration; always "securityscorecard".
    username = Column(String(100), nullable=False, default="securityscorecard")
    api_key_encrypted = Column(Text, nullable=False)

    import_risks = Column(Boolean, nullable=False, default=True)
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

    def set_api_key(self, value: str) -> None:
        if value:
            self.api_key_encrypted = get_cipher().encrypt(value.encode()).decode()

    def get_api_key(self) -> str | None:
        if self.api_key_encrypted:
            return get_cipher().decrypt(self.api_key_encrypted.encode()).decode()
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
        return f"<SecurityScorecardIntegration org={self.organization_id} name={self.connection_name!r}>"
