"""Akamai WAF (Application Security) integration model.

Stores per-organization EdgeGrid credentials for read-only import of
Akamai Application Security (Kona Site Defender / App & API Protector)
configurations, policies, and protected hostnames.

Data flows one direction only — from Akamai into the ASM platform.
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


class AkamaiWafIntegration(Base):
    """Stores an Akamai Application Security / WAF connection for an organization."""

    __tablename__ = "akamai_waf_integrations"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "connection_name", name="uq_akamai_org_connection"
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization = relationship("Organization")

    # Human-friendly label (e.g. "Production", "Corp WAF").
    connection_name = Column(String(255), nullable=False)

    # EdgeGrid API host — hostname only, no https:// prefix.
    api_host = Column(String(255), nullable=False)

    # EdgeGrid credentials (encrypted at rest).
    client_token_encrypted = Column(Text, nullable=False)
    client_secret_encrypted = Column(Text, nullable=False)
    access_token_encrypted = Column(Text, nullable=False)

    # Import preferences
    import_configurations = Column(Boolean, default=True, nullable=False)
    import_hostnames = Column(Boolean, default=True, nullable=False)

    is_active = Column(Boolean, default=True, nullable=False)

    # Continuous sync
    continuous_sync_enabled = Column(Boolean, default=False, nullable=False)
    sync_interval_minutes = Column(Integer, default=360, nullable=False)  # 6h default

    # Connection validation tracking
    last_tested_at = Column(DateTime, nullable=True)
    last_test_ok = Column(Boolean, nullable=True)

    # Sync tracking
    last_sync_at = Column(DateTime, nullable=True)
    last_sync_ok = Column(Boolean, nullable=True)
    last_sync_stats = Column(JSON, default=dict)
    last_error = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # ── Credential encryption (Fernet, shared with APIConfig) ────────────────
    def set_client_token(self, value: str) -> None:
        if value:
            self.client_token_encrypted = get_cipher().encrypt(value.encode()).decode()

    def get_client_token(self) -> str | None:
        if self.client_token_encrypted:
            return get_cipher().decrypt(self.client_token_encrypted.encode()).decode()
        return None

    def set_client_secret(self, value: str) -> None:
        if value:
            self.client_secret_encrypted = get_cipher().encrypt(value.encode()).decode()

    def get_client_secret(self) -> str | None:
        if self.client_secret_encrypted:
            return get_cipher().decrypt(self.client_secret_encrypted.encode()).decode()
        return None

    def set_access_token(self, value: str) -> None:
        if value:
            self.access_token_encrypted = get_cipher().encrypt(value.encode()).decode()

    def get_access_token(self) -> str | None:
        if self.access_token_encrypted:
            return get_cipher().decrypt(self.access_token_encrypted.encode()).decode()
        return None

    def set_credentials(
        self,
        *,
        client_token: str | None = None,
        client_secret: str | None = None,
        access_token: str | None = None,
    ) -> None:
        if client_token:
            self.set_client_token(client_token)
        if client_secret:
            self.set_client_secret(client_secret)
        if access_token:
            self.set_access_token(access_token)

    @property
    def next_sync_at(self) -> datetime | None:
        """When the next automatic sync is due (None if continuous sync is off)."""
        if not (self.continuous_sync_enabled and self.is_active):
            return None
        interval = timedelta(minutes=self.sync_interval_minutes or 360)
        if self.last_sync_at is None:
            return datetime.utcnow()
        return self.last_sync_at + interval

    def is_sync_due(self, now: datetime | None = None) -> bool:
        """True if continuous sync is enabled/active and the interval has elapsed."""
        nxt = self.next_sync_at
        if nxt is None:
            return False
        return (now or datetime.utcnow()) >= nxt

    def __repr__(self) -> str:
        return (
            f"<AkamaiWafIntegration org={self.organization_id} "
            f"connection={self.connection_name!r}>"
        )
