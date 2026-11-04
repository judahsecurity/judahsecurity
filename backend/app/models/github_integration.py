"""GitHub source-code-manager integration models.

Two connection methods are supported:

* ``app`` — the platform's GitHub App is installed on a GitHub organization or
  account. Only the installation ID is stored; short-lived installation access
  tokens are minted on demand with the App's private key.
* ``pat`` — a customer-supplied personal access token, encrypted at rest.
"""

from datetime import datetime, timedelta

from sqlalchemy import (
    BigInteger,
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

AUTH_METHOD_APP = "app"
AUTH_METHOD_PAT = "pat"

# An organization owner must approve a member's install request within this
# window; afterwards the request lapses and the install must be restarted.
INSTALL_REQUEST_TTL = timedelta(days=7)


class GitHubIntegration(Base):
    """One GitHub organization or user account connected to a Judah organization."""

    __tablename__ = "github_integrations"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "auth_method", "account_login", name="uq_github_org_method_account"
        ),
        # An App installation can be linked to exactly one Judah organization.
        UniqueConstraint("installation_id", name="uq_github_installation_id"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization = relationship("Organization")

    auth_method = Column(String(16), nullable=False, default=AUTH_METHOD_APP)
    account_login = Column(String(255), nullable=False)
    account_type = Column(String(32), nullable=False, default="Organization")  # Organization | User
    account_id = Column(BigInteger, nullable=True)

    # GitHub App connection
    installation_id = Column(BigInteger, nullable=True, index=True)
    repository_selection = Column(String(16), nullable=True)  # all | selected
    installed_by_user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    installed_by_github_login = Column(String(255), nullable=True)

    # Personal access token connection
    pat_encrypted = Column(Text, nullable=True)

    import_member_repos = Column(Boolean, nullable=False, default=True)
    scan_secrets = Column(Boolean, nullable=False, default=True)
    # Opening fix pull requests writes to customer repositories: off unless opted in.
    allow_fix_pull_requests = Column(Boolean, nullable=False, default=False)

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

    def set_token(self, value: str) -> None:
        if value:
            self.pat_encrypted = get_cipher().encrypt(value.encode()).decode()

    def get_token(self) -> str | None:
        if self.pat_encrypted:
            return get_cipher().decrypt(self.pat_encrypted.encode()).decode()
        return None

    @property
    def account_url(self) -> str:
        return f"https://github.com/{self.account_login}"

    @property
    def can_open_pull_requests(self) -> bool:
        # The App is read-only today, so only PAT connections can write.
        return self.auth_method == AUTH_METHOD_PAT and bool(self.allow_fix_pull_requests)

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
        return f"<GitHubIntegration org={self.organization_id} {self.auth_method}:{self.account_login!r}>"


class GitHubAppInstallRequest(Base):
    """Tracks one GitHub App install started from the platform.

    The opaque ``state`` handed to GitHub is stored only as a SHA-256 digest.
    Status moves ``started`` → ``linked`` for an owner install, or
    ``started`` → ``requested`` → ``linked`` / ``expired`` when a non-owner
    sends an install request to the organization's owners.
    """

    __tablename__ = "github_app_install_requests"

    id = Column(Integer, primary_key=True, index=True)
    state_digest = Column(String(64), nullable=False, unique=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(16), nullable=False, default="started")
    # Settings chosen in the platform before leaving for GitHub.
    options = Column(JSON, default=dict)
    # Set once GitHub returns: the installation awaiting user authorization, and
    # the requester's GitHub login (needed to attribute an approved request).
    installation_id = Column(BigInteger, nullable=True)
    github_login = Column(String(255), nullable=True)
    integration_id = Column(
        Integer, ForeignKey("github_integrations.id", ondelete="SET NULL"), nullable=True
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    requested_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=False)

    def is_expired(self, now: datetime | None = None) -> bool:
        return (now or datetime.utcnow()) >= self.expires_at
