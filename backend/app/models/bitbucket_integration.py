"""Bitbucket Cloud source-code integration model."""

from datetime import datetime, timedelta

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from app.db.database import Base
from app.models.api_config import get_cipher


class BitbucketIntegration(Base):
    """One read-only Bitbucket Cloud workspace connection for an organization.

    Authenticates with a workspace access token (Repository: Read). Each
    non-fork repository in the workspace is imported as a REPOSITORY asset
    and, optionally, scanned for exposed secrets.
    """

    __tablename__ = "bitbucket_integrations"
    __table_args__ = (
        UniqueConstraint("organization_id", "workspace", name="uq_bitbucket_org_workspace"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization = relationship("Organization")

    workspace = Column(String(100), nullable=False)  # Workspace slug from the workspace URL
    workspace_url = Column(String(500), nullable=False)
    access_token_encrypted = Column(Text, nullable=False)

    scan_secrets = Column(Boolean, nullable=False, default=True)
    max_repo_size_mb = Column(Integer, nullable=False, default=500)
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

    def set_access_token(self, value: str) -> None:
        if value:
            self.access_token_encrypted = get_cipher().encrypt(value.encode()).decode()

    def get_access_token(self) -> str | None:
        if self.access_token_encrypted:
            return get_cipher().decrypt(self.access_token_encrypted.encode()).decode()
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
        return f"<BitbucketIntegration org={self.organization_id} workspace={self.workspace!r}>"
