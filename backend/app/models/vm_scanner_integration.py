"""Vulnerability Management (VM) scanner integration model.

Stores per-organization connections to external vulnerability management
platforms — Tenable Vulnerability Management, Qualys VMDR, Rapid7 InsightVM,
and Tenable Nessus. All four vendors share one table distinguished by the
``provider`` column; provider-specific behavior (auth scheme, API shape)
lives in :mod:`app.services.vm_scanner_service`.

These integrations operate read-only: they pull scanned hosts and vulnerability
detections out of the vendor platform and import them into the ASM inventory.
They never modify anything in the vendor platform.

Credentials differ per vendor (API key pair, username/password, single key),
so they are stored as a single encrypted JSON blob rather than fixed columns.
"""

import json
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


class VmScannerIntegration(Base):
    """Stores a VM scanner (Tenable/Qualys/Rapid7/Nessus) connection for an org."""

    __tablename__ = "vm_scanner_integrations"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "provider", "connection_name",
            name="uq_vm_scanner_org_provider_name",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization = relationship("Organization")

    # One of the keys of vm_scanner_service.PROVIDERS:
    # "tenable" | "qualys" | "rapid7" | "nessus"
    provider = Column(String(50), nullable=False, index=True)

    # Human-friendly label for the connection (e.g. "Corporate Qualys").
    connection_name = Column(String(255), nullable=False)

    # API endpoint. Required for self-hosted platforms (Qualys API server,
    # Nessus scanner, InsightVM region); providers with a fixed cloud URL
    # fall back to their default when this is empty.
    base_url = Column(String(500), nullable=True)

    # Nessus scanners in particular commonly run with self-signed certificates.
    verify_ssl = Column(Boolean, default=True, nullable=False)

    # Provider-specific credentials, encrypted at rest as a JSON object
    # (e.g. {"access_key": ..., "secret_key": ...} or {"username": ..., "password": ...}).
    credentials_encrypted = Column(Text, nullable=False)

    # Import preferences.
    import_vulnerabilities = Column(Boolean, default=True, nullable=False)
    import_assets = Column(Boolean, default=True, nullable=False)

    is_active = Column(Boolean, default=True, nullable=False)

    # Continuous sync — when enabled, the schedule worker re-syncs this
    # connection every ``sync_interval_minutes``.
    continuous_sync_enabled = Column(Boolean, default=False, nullable=False)
    sync_interval_minutes = Column(Integer, default=360, nullable=False)  # 6h default

    # Connection validation tracking
    last_tested_at = Column(DateTime, nullable=True)
    last_test_ok = Column(Boolean, nullable=True)

    # Sync tracking
    last_sync_at = Column(DateTime, nullable=True)
    last_sync_ok = Column(Boolean, nullable=True)
    last_sync_stats = Column(JSON, default=dict)  # {"assets_created": .., "vulns_created": .., ...}
    last_error = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # ── Credential encryption (Fernet, shared with APIConfig) ────────────────
    def set_credentials(self, credentials: dict) -> None:
        if credentials:
            payload = json.dumps(credentials)
            self.credentials_encrypted = get_cipher().encrypt(payload.encode()).decode()

    def get_credentials(self) -> dict:
        if not self.credentials_encrypted:
            return {}
        payload = get_cipher().decrypt(self.credentials_encrypted.encode()).decode()
        try:
            data = json.loads(payload)
        except ValueError:
            return {}
        return data if isinstance(data, dict) else {}

    @property
    def next_sync_at(self) -> datetime | None:
        """When the next automatic sync is due (None if continuous sync is off)."""
        if not (self.continuous_sync_enabled and self.is_active):
            return None
        interval = timedelta(minutes=self.sync_interval_minutes or 360)
        if self.last_sync_at is None:
            return datetime.utcnow()  # never synced -> due now
        return self.last_sync_at + interval

    def is_sync_due(self, now: datetime | None = None) -> bool:
        """True if continuous sync is enabled/active and the interval has elapsed."""
        nxt = self.next_sync_at
        if nxt is None:
            return False
        return (now or datetime.utcnow()) >= nxt

    def __repr__(self) -> str:
        return (
            f"<VmScannerIntegration org={self.organization_id} "
            f"provider={self.provider!r} name={self.connection_name!r}>"
        )
