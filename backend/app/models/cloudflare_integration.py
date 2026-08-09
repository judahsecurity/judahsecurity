"""Cloudflare WAF integration model.

Stores per-organization Cloudflare API tokens used to create/update a single
custom WAF skip rule per zone that whitelists Judah Security scanner traffic
(source IP + account-specific header + dedicated user-agent).

Unlike the Akamai WAF integration (read-only import), this integration writes
a narrowly scoped whitelist rule into Cloudflare and re-syncs it on a schedule.
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


class CloudflareWafIntegration(Base):
    """Stores a Cloudflare WAF whitelist connection for an organization."""

    __tablename__ = "cloudflare_waf_integrations"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "connection_name", name="uq_cloudflare_org_connection"
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization = relationship("Organization")

    # Human-friendly label (e.g. "Production", "Corp CDN").
    connection_name = Column(String(255), nullable=False)

    # Cloudflare API token (encrypted at rest).
    api_token_encrypted = Column(Text, nullable=False)

    # Optional zone filter — empty/null means all zones visible to the token.
    # Stored as a JSON list of zone names (e.g. ["example.com", "app.example.com"]).
    zones = Column(JSON, default=list, nullable=False)

    # Optional override of platform egress IPs for this connection.
    # Empty/null → use Settings.ASM_SCANNER_EGRESS_IPS.
    scanner_ips = Column(JSON, default=list, nullable=False)

    # Account-unique scanner identification header (name is public; value encrypted).
    scan_header_name = Column(String(128), nullable=False, default="X-Judah-Scan-Token")
    scan_header_secret_encrypted = Column(Text, nullable=False)

    is_active = Column(Boolean, default=True, nullable=False)

    # Continuous sync — Praetorian runs daily; default matches that cadence.
    continuous_sync_enabled = Column(Boolean, default=True, nullable=False)
    sync_interval_minutes = Column(Integer, default=1440, nullable=False)  # 24h

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

    def set_scan_header_secret(self, secret: str) -> None:
        if secret:
            self.scan_header_secret_encrypted = get_cipher().encrypt(secret.encode()).decode()

    def get_scan_header_secret(self) -> str | None:
        if self.scan_header_secret_encrypted:
            return get_cipher().decrypt(self.scan_header_secret_encrypted.encode()).decode()
        return None

    @property
    def next_sync_at(self) -> datetime | None:
        """When the next automatic sync is due (None if continuous sync is off)."""
        if not (self.continuous_sync_enabled and self.is_active):
            return None
        interval = timedelta(minutes=self.sync_interval_minutes or 1440)
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
            f"<CloudflareWafIntegration org={self.organization_id} "
            f"connection={self.connection_name!r}>"
        )
