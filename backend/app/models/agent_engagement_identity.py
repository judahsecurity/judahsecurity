"""Operator-approved test identities for authenticated assessments.

The restart snapshot deliberately drops live credentials, so a resumed run or an
authz hypothesis would idle waiting for an operator to re-enter working creds.
This durable, org-scoped record lets an operator pre-register an approved
identity once; the autonomy turn re-hydrates it into the in-memory engagement
brain only when the run's limits authorize the identity label and a scope host
matches. The secret is encrypted at rest with the shared Fernet cipher and is
never written back into the snapshot.
"""

from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB

from app.db.database import Base
from app.models.api_config import get_cipher


class AgentEngagementIdentity(Base):
    """A pre-registered, operator-approved engagement test identity."""

    __tablename__ = "agent_engagement_identities"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "schedule_id", "label",
            name="uq_engagement_identity",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    schedule_id = Column(
        Integer, ForeignKey("scan_schedules.id", ondelete="CASCADE"), nullable=True, index=True,
    )
    # Must match an `allowed_identities` entry on the schedule's autonomy config.
    label = Column(String(64), nullable=False)
    username = Column(String(256), nullable=False, default="")
    secret_encrypted = Column(Text, nullable=False, default="")
    secret_type = Column(String(32), nullable=False, default="password")
    # In-scope hosts this identity may authenticate against.
    valid_on = Column(JSONB, nullable=False, default=list)
    login_url = Column(String(512), nullable=False, default="")
    enabled = Column(Boolean, nullable=False, default=True)
    approved_by = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
    )
    notes = Column(Text, nullable=False, default="")
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(
        DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow,
    )

    # ── Secret encryption (Fernet, shared with APIConfig) ────────────────────
    @property
    def secret(self) -> str:
        if not self.secret_encrypted:
            return ""
        return get_cipher().decrypt(self.secret_encrypted.encode()).decode()

    @secret.setter
    def secret(self, value: str) -> None:
        self.secret_encrypted = (
            get_cipher().encrypt((value or "").encode()).decode() if value else ""
        )
