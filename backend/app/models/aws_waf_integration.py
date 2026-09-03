"""AWS WAF integration model.

Stores per-organization AWS credentials for read-only import of AWS WAF (WAFv2)
Web ACLs and the hostnames/resources they protect (CloudFront distributions,
Application Load Balancers, API Gateways) into the ASM platform.

Data flows one direction only — from AWS into the ASM platform. The integration
never modifies WAF rules, IP sets, or associations.
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


class AwsWafIntegration(Base):
    """Stores an AWS WAF connection for an organization."""

    __tablename__ = "aws_waf_integrations"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "name", name="uq_aws_waf_org_name"
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization = relationship("Organization")

    # Human-friendly label (e.g. "Prod AWS", "Payments account").
    name = Column(String(255), nullable=False)

    # AWS credentials (encrypted at rest).
    access_key_id_encrypted = Column(Text, nullable=False)
    secret_access_key_encrypted = Column(Text, nullable=False)
    session_token_encrypted = Column(Text, nullable=True)

    # Regions to enumerate REGIONAL Web ACLs in (JSON list of region names).
    regions = Column(JSON, default=list, nullable=False)

    # Scope toggles.
    include_cloudfront = Column(Boolean, default=True, nullable=False)
    include_regional = Column(Boolean, default=True, nullable=False)

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

    # ── Credential encryption (Fernet, shared with APIConfig) ────────────────
    def set_access_key_id(self, value: str) -> None:
        if value:
            self.access_key_id_encrypted = get_cipher().encrypt(value.encode()).decode()

    def get_access_key_id(self) -> str | None:
        if self.access_key_id_encrypted:
            return get_cipher().decrypt(self.access_key_id_encrypted.encode()).decode()
        return None

    def set_secret_access_key(self, value: str) -> None:
        if value:
            self.secret_access_key_encrypted = get_cipher().encrypt(value.encode()).decode()

    def get_secret_access_key(self) -> str | None:
        if self.secret_access_key_encrypted:
            return get_cipher().decrypt(self.secret_access_key_encrypted.encode()).decode()
        return None

    def set_session_token(self, value: str | None) -> None:
        if value:
            self.session_token_encrypted = get_cipher().encrypt(value.encode()).decode()
        else:
            self.session_token_encrypted = None

    def get_session_token(self) -> str | None:
        if self.session_token_encrypted:
            return get_cipher().decrypt(self.session_token_encrypted.encode()).decode()
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
        return f"<AwsWafIntegration org={self.organization_id} name={self.name!r}>"
