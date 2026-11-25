"""Workforce identities and leaked-credential exposures.

Identities are ingested read-only from an organization's system of record
(ServiceNow ``sys_user`` today; Workday and SailPoint IIQ later) so that a leaked
credential can be prioritized by who it belongs to and what they can reach.

Only the attributes used for scoring are stored. No salary, address, phone,
national ID or other HR data is ingested.

Exposures never hold a secret. When a provider returns a credential value it is
reduced to ``secret_fingerprint`` (see ``app.services.secret_safety``) so reuse
can be detected across leaks without the platform becoming a credential store.
"""

from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.db.database import Base


# Identity sources
IDENTITY_SOURCE_SERVICENOW = "servicenow"
IDENTITY_SOURCES = (IDENTITY_SOURCE_SERVICENOW,)

# Exposure source types
EXPOSURE_SOURCE_BREACH = "breach"
EXPOSURE_SOURCE_COMBOLIST = "combolist"
EXPOSURE_SOURCE_STEALER_LOG = "stealer_log"
EXPOSURE_SOURCE_PASTE = "paste"
EXPOSURE_SOURCE_CHAT = "chat"

# Credential types, strongest first
CREDENTIAL_SESSION_COOKIE = "session_cookie"
CREDENTIAL_TOKEN = "token"
CREDENTIAL_PASSWORD_PLAINTEXT = "password_plaintext"
CREDENTIAL_PASSWORD = "password"  # password exposed, plaintext vs hash unknown
CREDENTIAL_PASSWORD_HASH = "password_hash"
CREDENTIAL_EMAIL_ONLY = "email_only"

EXPOSURE_STATUSES = ("open", "resolved", "false_positive", "accepted")


class Identity(Base):
    """One person (or service account) from an identity source."""

    __tablename__ = "identities"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "source", "source_id", name="uq_identity_org_source_id"
        ),
        Index("ix_identities_org_email", "organization_id", "email"),
        Index("ix_identities_org_risk", "organization_id", "risk_score"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )

    source = Column(String(30), nullable=False)
    source_id = Column(String(100), nullable=False)  # e.g. ServiceNow sys_id

    # Match keys (all lowercased)
    email = Column(String(320), nullable=True)
    username = Column(String(255), nullable=True)
    aliases = Column(JSON, nullable=False, default=list)

    display_name = Column(String(255), nullable=True)
    employee_number = Column(String(100), nullable=True)
    title = Column(String(255), nullable=True)
    department = Column(String(255), nullable=True)
    manager_name = Column(String(255), nullable=True)
    manager_source_id = Column(String(100), nullable=True)
    worker_type = Column(String(50), nullable=True)  # employee | contractor | service | unknown
    is_active = Column(Boolean, nullable=False, default=True)
    is_vip = Column(Boolean, nullable=False, default=False)
    groups = Column(JSON, nullable=False, default=list)

    is_privileged = Column(Boolean, nullable=False, default=False)
    risk_score = Column(Integer, nullable=False, default=0)  # 0-100
    risk_factors = Column(JSON, nullable=False, default=list)

    last_seen_in_source_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    exposures = relationship("CredentialExposure", back_populates="identity")

    def __repr__(self):
        return f"<Identity org={self.organization_id} {self.source}:{self.email or self.username}>"


class IdentitySourceSync(Base):
    """Sync state for one identity source per organization."""

    __tablename__ = "identity_source_syncs"
    __table_args__ = (
        UniqueConstraint("organization_id", "source", name="uq_identity_sync_org_source"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source = Column(String(30), nullable=False)
    running = Column(Boolean, nullable=False, default=False)
    last_sync_started_at = Column(DateTime, nullable=True)
    last_sync_at = Column(DateTime, nullable=True)
    last_sync_ok = Column(Boolean, nullable=True)
    last_sync_stats = Column(JSON, nullable=True)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class CredentialExposure(Base):
    """A leaked credential (or leaked account identifier) tied to an organization."""

    __tablename__ = "credential_exposures"
    __table_args__ = (
        UniqueConstraint("organization_id", "dedup_key", name="uq_credexp_org_dedup"),
        Index("ix_credexp_org_priority", "organization_id", "priority_score"),
        Index("ix_credexp_org_identifier", "organization_id", "identifier"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    identity_id = Column(
        Integer, ForeignKey("identities.id", ondelete="SET NULL"), nullable=True, index=True
    )
    identity = relationship("Identity", back_populates="exposures")
    asset_id = Column(
        Integer, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )

    dedup_key = Column(String(64), nullable=False)

    identifier = Column(String(320), nullable=False)  # email or username as leaked, lowercased
    identifier_domain = Column(String(255), nullable=True)

    provider = Column(String(50), nullable=False)  # xposedornot | hibp | hudsonrock | ...
    source_type = Column(String(30), nullable=False)
    source_name = Column(String(255), nullable=True)  # breach / channel / log family

    credential_type = Column(String(30), nullable=False, default=CREDENTIAL_EMAIL_ONLY)
    secret_fingerprint = Column(String(40), nullable=True)
    data_classes = Column(JSON, nullable=False, default=list)

    # Stealer logs record the site a credential was saved for
    affected_url = Column(String(2000), nullable=True)
    affected_host = Column(String(255), nullable=True)

    leak_date = Column(DateTime, nullable=True)
    first_seen_at = Column(DateTime, default=datetime.utcnow)
    last_seen_at = Column(DateTime, default=datetime.utcnow)

    priority_score = Column(Integer, nullable=False, default=0)  # 0-100
    severity = Column(String(20), nullable=False, default="info")
    score_factors = Column(JSON, nullable=False, default=list)

    status = Column(String(30), nullable=False, default="open")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<CredentialExposure org={self.organization_id} {self.identifier} {self.source_name}>"


class StealerUrlExposure(Base):
    """A login URL of the organization whose credentials infostealers captured.

    Domain-level signal: Hudson Rock reports how many infected machines saved
    credentials for each URL, split into employees and customers, without
    naming people. Matching the URL's host to an inventory asset turns
    "thousands of infected employees" into "stolen logins for your ADFS".
    """

    __tablename__ = "stealer_url_exposures"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "provider", "url", "audience", name="uq_stealer_url_org"
        ),
        Index("ix_stealer_url_org_priority", "organization_id", "priority_score"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id = Column(
        Integer, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    provider = Column(String(50), nullable=False)
    domain = Column(String(255), nullable=False)
    url = Column(String(2000), nullable=False)
    host = Column(String(255), nullable=True, index=True)
    audience = Column(String(20), nullable=False)  # employee | user | third_party
    occurrence = Column(Integer, nullable=False, default=0)
    login_category = Column(String(30), nullable=True)  # sso | mfa | remote_access | ...
    last_compromised_at = Column(DateTime, nullable=True)

    priority_score = Column(Integer, nullable=False, default=0)
    severity = Column(String(20), nullable=False, default="info")
    score_factors = Column(JSON, nullable=False, default=list)
    status = Column(String(30), nullable=False, default="open")

    first_seen_at = Column(DateTime, default=datetime.utcnow)
    last_seen_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class StealerDomainSummary(Base):
    """Latest provider summary for one of the organization's domains."""

    __tablename__ = "stealer_domain_summaries"
    __table_args__ = (
        UniqueConstraint("organization_id", "provider", "domain", name="uq_stealer_summary_org"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider = Column(String(50), nullable=False)
    domain = Column(String(255), nullable=False)
    summary = Column(JSON, nullable=False, default=dict)
    fetched_at = Column(DateTime, default=datetime.utcnow)


class ExposureScope(Base):
    """An authorized domain for leaked-credential collection and ingest.

    This is the engagement boundary. Only records whose email or affected host
    falls under an authorized domain for the organization may be stored. Every
    row records who authorized it, so the sign-off is explicit and auditable
    rather than inferred from the asset inventory.
    """

    __tablename__ = "exposure_scopes"
    __table_args__ = (
        UniqueConstraint("organization_id", "domain", name="uq_exposure_scope_org_domain"),
        Index("ix_exposure_scopes_domain", "domain"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    domain = Column(String(255), nullable=False)  # authorized apex, e.g. rockwellautomation.com
    include_subdomains = Column(Boolean, nullable=False, default=True)
    # employees | customers | both — who at this domain is in scope
    audience_scope = Column(String(20), nullable=False, default="both")
    is_active = Column(Boolean, nullable=False, default=True)

    authorized_by = Column(String(255), nullable=True)  # user who recorded the sign-off
    authorization_note = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<ExposureScope org={self.organization_id} {self.domain}>"
