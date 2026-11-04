"""Censys ASM integration model.

Stores per-organization connections to Censys Attack Surface Management
workspaces. Each row represents a single Censys ASM workspace (identified by a
workspace-scoped API key). An organization may connect multiple workspaces, so
the connection is keyed by ``(organization_id, workspace_name)`` rather than a
single row per org.

This integration operates read-only: it pulls risks and/or assets that Censys
ASM has attributed to the org and imports them into the ASM platform. It never
modifies anything in Censys.
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


class CensysAsmIntegration(Base):
    """Stores a Censys ASM workspace connection for an organization."""

    __tablename__ = "censys_asm_integrations"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "workspace_name", name="uq_censys_org_workspace"
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization = relationship("Organization")

    # Human-friendly label for the connection (e.g. "Production", "Staging").
    workspace_name = Column(String(255), nullable=False)

    # Workspace-scoped ASM API key (a single token, encrypted at rest).
    api_key_encrypted = Column(Text, nullable=False)

    # Import preferences — mirror the Censys ASM integration options.
    import_vulnerabilities = Column(Boolean, default=True, nullable=False)
    import_assets = Column(Boolean, default=True, nullable=False)

    is_active = Column(Boolean, default=True, nullable=False)

    # Continuous sync — when enabled, the schedule worker re-syncs this
    # workspace every ``sync_interval_minutes``.
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
    # Per-workspace enrichment rules; core identity and org attribution remain fixed.
    field_mappings = Column(JSON, default=list, nullable=False)

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
        return f"<CensysAsmIntegration org={self.organization_id} workspace={self.workspace_name!r}>"
