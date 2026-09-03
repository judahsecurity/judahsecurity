"""Fortinet FortiGate integration model.

Stores per-organization connections to FortiGate NGFW management interfaces.
Read-only: imports firewall address objects (subnets, IP ranges, FQDNs) as
assets and never modifies configuration, policies, or objects on the FortiGate.

Authentication uses a FortiOS REST API token (a REST API admin's token,
sent as ``Authorization: Bearer <token>``).
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


class FortiGateIntegration(Base):
    """Stores a FortiGate connection for an organization."""

    __tablename__ = "fortigate_integrations"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "name", name="uq_fortigate_org_name"
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization = relationship("Organization")

    # Human-friendly label (e.g. "Perimeter FortiGate", "DC-Edge").
    name = Column(String(255), nullable=False)

    # Full FortiGate management URL including protocol (e.g. https://fw.example.com).
    fortigate_host = Column(String(500), nullable=False)

    # FortiOS REST API token from a REST API admin (encrypted).
    api_token_encrypted = Column(Text, nullable=False)

    # Optional VDOM scope. Blank → the management VDOM (root).
    vdom = Column(String(255), nullable=True)

    # On-prem FortiGate often uses self-signed certs; allow disabling verification.
    verify_ssl = Column(Boolean, default=True, nullable=False)

    is_active = Column(Boolean, default=True, nullable=False)

    # Continuous sync — schedule worker re-syncs when due.
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
    def set_api_token(self, token: str) -> None:
        if token:
            self.api_token_encrypted = get_cipher().encrypt(token.encode()).decode()

    def get_api_token(self) -> str | None:
        if self.api_token_encrypted:
            return get_cipher().decrypt(self.api_token_encrypted.encode()).decode()
        return None

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
        return f"<FortiGateIntegration org={self.organization_id} name={self.name!r}>"
