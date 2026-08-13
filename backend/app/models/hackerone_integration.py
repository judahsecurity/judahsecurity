"""HackerOne bug bounty integration model.

Stores per-organization connections to HackerOne. Each row holds API credentials
(identifier + token) and sync preferences for importing vulnerability reports as
findings and eligible program scopes as assets.

Read-only: the integration never writes back to HackerOne.
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


class HackerOneIntegration(Base):
    """Stores a HackerOne API connection for an organization."""

    __tablename__ = "hackerone_integrations"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "connection_name", name="uq_hackerone_org_connection"
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization = relationship("Organization")

    # Human-friendly label (e.g. "Production", "Public program").
    connection_name = Column(String(255), nullable=False)

    # HackerOne API Identifier (username) — stored in plaintext; not a secret.
    api_identifier = Column(String(255), nullable=False)

    # HackerOne API Token (secret) — encrypted at rest.
    api_token_encrypted = Column(Text, nullable=False)

    # Import preferences
    import_vulnerabilities = Column(Boolean, default=True, nullable=False)
    import_scopes = Column(Boolean, default=True, nullable=False)

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
    last_sync_stats = Column(JSON, default=dict)
    last_error = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    tickets = relationship("HackerOneReportLink", back_populates="integration", cascade="all, delete-orphan")

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
        return (
            f"<HackerOneIntegration org={self.organization_id} "
            f"connection={self.connection_name!r}>"
        )


class HackerOneReportLink(Base):
    """Tracks HackerOne reports linked to ASM vulnerabilities.

    Created either by sync import (``is_associated=False``) or by manually
    linking an existing report to a finding (``is_associated=True``).
    """

    __tablename__ = "hackerone_report_links"
    __table_args__ = (
        UniqueConstraint(
            "vulnerability_id",
            "hackerone_report_id",
            name="uq_hackerone_vuln_report",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    integration_id = Column(
        Integer, ForeignKey("hackerone_integrations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    integration = relationship("HackerOneIntegration", back_populates="tickets")

    vulnerability_id = Column(
        Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    vulnerability = relationship("Vulnerability")

    hackerone_report_id = Column(String(50), nullable=False, index=True)
    hackerone_report_url = Column(String(1000), nullable=False)
    hackerone_program = Column(String(255), nullable=True)
    hackerone_title = Column(String(500), nullable=True)

    # Live status tracking (pulled from HackerOne on associate / refresh / sync)
    hackerone_state = Column(String(100), nullable=True)
    hackerone_severity = Column(String(50), nullable=True)
    hackerone_reporter = Column(String(255), nullable=True)

    # True when manually linked (vs created by sync import)
    is_associated = Column(Boolean, default=True, nullable=False)

    # Soft-unlink; the HackerOne report itself is never modified
    disconnected_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self) -> str:
        return (
            f"<HackerOneReportLink report={self.hackerone_report_id} "
            f"vuln={self.vulnerability_id}>"
        )
