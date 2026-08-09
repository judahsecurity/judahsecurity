"""Palo Alto Networks Panorama integration model.

Stores per-organization connections to Panorama management servers. Each row
represents a single Panorama scope (live REST API or config-export file).

This integration operates read-only: it imports address objects as assets and
never modifies configuration, policies, or objects in Panorama.

Connection modes:
    api            — pull Objects/Addresses via Panorama REST (X-PAN-KEY)
    config_export  — ingest a scheduled Panorama configuration export (.gz/.tgz/.xml)
                     for air-gapped / internally deployed Panorama servers
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

CONNECTION_MODE_API = "api"
CONNECTION_MODE_CONFIG_EXPORT = "config_export"


class PanoramaIntegration(Base):
    """Stores a Panorama connection for an organization."""

    __tablename__ = "panorama_integrations"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "name", name="uq_panorama_org_name"
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization = relationship("Organization")

    # Human-friendly label for the connection (e.g. "HQ Panorama", "DG-Prod").
    name = Column(String(255), nullable=False)

    # api | config_export
    connection_mode = Column(String(32), nullable=False, default=CONNECTION_MODE_API)

    # Full Panorama URL including protocol (required for api mode).
    panorama_host = Column(String(500), nullable=True)

    # API key from a Panorama admin account (encrypted; required for api mode).
    api_key_encrypted = Column(Text, nullable=True)

    # Optional device-group scope.
    # api mode: blank → shared address space.
    # config_export mode: blank → all scopes found in the export; set → that DG (+ shared).
    device_group = Column(String(255), nullable=True)

    # REST API version path segment (e.g. v11.1). Must match PAN-OS capability.
    api_version = Column(String(32), nullable=False, default="v11.1")

    # On-prem Panorama often uses self-signed certs; allow disabling verification.
    verify_ssl = Column(Boolean, default=True, nullable=False)

    # Config-export file metadata (config_export mode).
    export_file_path = Column(Text, nullable=True)
    export_filename = Column(String(512), nullable=True)
    export_file_size = Column(Integer, nullable=True)
    export_uploaded_at = Column(DateTime, nullable=True)

    is_active = Column(Boolean, default=True, nullable=False)

    # Continuous sync — schedule worker re-syncs when due (api mode, or
    # re-parse of the stored export in config_export mode).
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
    def set_api_key(self, key: str) -> None:
        if key:
            self.api_key_encrypted = get_cipher().encrypt(key.encode()).decode()

    def get_api_key(self) -> str | None:
        if self.api_key_encrypted:
            return get_cipher().decrypt(self.api_key_encrypted.encode()).decode()
        return None

    @property
    def is_config_export(self) -> bool:
        return (self.connection_mode or CONNECTION_MODE_API) == CONNECTION_MODE_CONFIG_EXPORT

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
            f"<PanoramaIntegration org={self.organization_id} "
            f"name={self.name!r} mode={self.connection_mode!r}>"
        )
