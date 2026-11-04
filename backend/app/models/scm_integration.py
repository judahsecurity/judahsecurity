"""Source code manager (SCM) integrations — repository discovery + secret scanning.

One row per connected SCM scope. ``provider`` selects the client; Azure DevOps
Services is the first provider. Repository scanning is read-only: the platform
lists projects/repositories, clones them, and scans them for secrets, but never
writes to the SCM.
"""

from datetime import datetime, timedelta

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from app.db.database import Base
from app.models.api_config import get_cipher

PROVIDER_AZURE_DEVOPS = "azure_devops"
SCM_PROVIDERS = (PROVIDER_AZURE_DEVOPS,)

AUTH_METHOD_PAT = "pat"
AUTH_METHOD_ENTRA_ID = "entra_id"
SCM_AUTH_METHODS = (AUTH_METHOD_ENTRA_ID, AUTH_METHOD_PAT)


def _encrypt(value: str) -> str:
    return get_cipher().encrypt(value.encode()).decode()


def _decrypt(value: str | None) -> str | None:
    if not value:
        return None
    return get_cipher().decrypt(value.encode()).decode()


class SourceCodeManagerIntegration(Base):
    """A read-only connection to a source code manager scope (org or project)."""

    __tablename__ = "scm_integrations"
    __table_args__ = (
        UniqueConstraint("organization_id", "provider", "connection_name", name="uq_scm_org_provider_connection"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization = relationship("Organization")

    provider = Column(String(50), nullable=False, default=PROVIDER_AZURE_DEVOPS, index=True)
    connection_name = Column(String(255), nullable=False)

    # The URL the user entered, plus the parsed scope. ``scm_project`` is NULL
    # for an organization-wide scope.
    scope_url = Column(String(1000), nullable=False)
    scm_organization = Column(String(255), nullable=False)
    scm_project = Column(String(255), nullable=True)

    auth_method = Column(String(32), nullable=False, default=AUTH_METHOD_PAT)
    # PAT authentication
    access_token_encrypted = Column(Text, nullable=True)
    # Entra ID (service principal) authentication
    tenant_id = Column(String(255), nullable=True)
    client_id = Column(String(255), nullable=True)
    client_secret_encrypted = Column(Text, nullable=True)

    secret_scanning_enabled = Column(Boolean, nullable=False, default=True)
    include_unverified_secrets = Column(Boolean, nullable=False, default=False)
    is_active = Column(Boolean, nullable=False, default=True)
    continuous_sync_enabled = Column(Boolean, nullable=False, default=True)
    sync_interval_minutes = Column(Integer, nullable=False, default=1440)

    last_tested_at = Column(DateTime, nullable=True)
    last_test_ok = Column(Boolean, nullable=True)
    last_sync_at = Column(DateTime, nullable=True)
    last_sync_ok = Column(Boolean, nullable=True)
    last_sync_stats = Column(JSON, default=dict)
    last_scan_id = Column(Integer, nullable=True)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # ── Credentials ───────────────────────────────────────────────────────
    def set_access_token(self, value: str) -> None:
        if value:
            self.access_token_encrypted = _encrypt(value)

    def get_access_token(self) -> str | None:
        return _decrypt(self.access_token_encrypted)

    def set_client_secret(self, value: str) -> None:
        if value:
            self.client_secret_encrypted = _encrypt(value)

    def get_client_secret(self) -> str | None:
        return _decrypt(self.client_secret_encrypted)

    @property
    def has_access_token(self) -> bool:
        return bool(self.access_token_encrypted)

    @property
    def has_client_secret(self) -> bool:
        return bool(self.client_secret_encrypted)

    # ── Scheduling ────────────────────────────────────────────────────────
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
        return (
            f"<SourceCodeManagerIntegration org={self.organization_id} "
            f"provider={self.provider} name={self.connection_name!r}>"
        )
