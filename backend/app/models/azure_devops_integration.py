"""Azure DevOps Boards integration models.

One connection per organization (PAT or Entra ID service principal), any number
of routing templates (project + work item type + optional auto-create severity
threshold), and a link table tracking work items created from / associated with
ASM vulnerabilities.
"""

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship

from app.db.database import Base
from app.models.api_config import get_cipher
from app.models.jira_integration import severity_meets_threshold  # noqa: F401 — re-export

__all__ = [
    "AzureDevOpsIntegration",
    "AzureDevOpsTemplate",
    "AzureDevOpsWorkItem",
    "AUTH_METHOD_PAT",
    "AUTH_METHOD_ENTRA",
    "DEFAULT_REMOTE_CLOSED_STATES",
    "severity_meets_threshold",
]

AUTH_METHOD_PAT = "pat"
AUTH_METHOD_ENTRA = "entra_id"

# Work item states that mean "closed" across the Agile / Scrum / CMMI / Basic processes.
DEFAULT_REMOTE_CLOSED_STATES = ["Closed", "Resolved", "Done"]


def _encrypt(value: str | None) -> str | None:
    if not value:
        return None
    return get_cipher().encrypt(value.encode()).decode()


def _decrypt(value: str | None) -> str | None:
    if not value:
        return None
    return get_cipher().decrypt(value.encode()).decode()


class AzureDevOpsIntegration(Base):
    """Azure DevOps organization connection for one ASM organization."""

    __tablename__ = "azure_devops_integrations"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id"), nullable=False, unique=True, index=True
    )
    organization = relationship("Organization")

    # https://dev.azure.com/<org> (legacy *.visualstudio.com URLs are rejected)
    organization_url = Column(String(500), nullable=False)

    # "pat" or "entra_id"
    auth_method = Column(String(20), nullable=False, default=AUTH_METHOD_PAT)

    # PAT auth (encrypted at rest)
    pat_encrypted = Column(Text, nullable=True)

    # Entra ID (Azure AD) service principal — client credentials flow (encrypted secret)
    tenant_id = Column(String(100), nullable=True)
    client_id = Column(String(100), nullable=True)
    client_secret_encrypted = Column(Text, nullable=True)

    # Inbound sync: Azure DevOps → ASM. When a linked work item reaches one of
    # remote_closed_states, the vulnerability is set to accept_close_as.
    sync_enabled = Column(Boolean, default=True, nullable=False)
    remote_closed_states = Column(JSON, default=lambda: list(DEFAULT_REMOTE_CLOSED_STATES))
    accept_close_as = Column(String(30), nullable=False, default="resolved")

    # Outbound sync: ASM → Azure DevOps. Optional state names to set on the work
    # item when the vulnerability is closed / reopened in ASM. Comments are always
    # posted; the state change only happens when these are set.
    close_state = Column(String(100), nullable=True)
    reopen_state = Column(String(100), nullable=True)

    # Post a comment on linked work items when the vulnerability severity changes.
    notify_severity_change = Column(Boolean, default=True, nullable=False)

    is_active = Column(Boolean, default=True, nullable=False)
    last_tested_at = Column(DateTime, nullable=True)
    last_test_ok = Column(Boolean, nullable=True)
    last_pull_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    templates = relationship(
        "AzureDevOpsTemplate", back_populates="integration", cascade="all, delete-orphan"
    )
    work_items = relationship(
        "AzureDevOpsWorkItem", back_populates="integration", cascade="all, delete-orphan"
    )

    # ── credential helpers ──────────────────────────────────────────────────
    def set_pat(self, pat: str | None) -> None:
        if pat:
            self.pat_encrypted = _encrypt(pat)

    def get_pat(self) -> str | None:
        return _decrypt(self.pat_encrypted)

    def set_client_secret(self, secret: str | None) -> None:
        if secret:
            self.client_secret_encrypted = _encrypt(secret)

    def get_client_secret(self) -> str | None:
        return _decrypt(self.client_secret_encrypted)

    @property
    def has_pat(self) -> bool:
        return bool(self.pat_encrypted)

    @property
    def has_client_secret(self) -> bool:
        return bool(self.client_secret_encrypted)

    def __repr__(self):
        return f"<AzureDevOpsIntegration org={self.organization_id} url={self.organization_url}>"


class AzureDevOpsTemplate(Base):
    """Routing template: which project / work item type, and auto-create rules."""

    __tablename__ = "azure_devops_templates"

    id = Column(Integer, primary_key=True, index=True)
    integration_id = Column(
        Integer, ForeignKey("azure_devops_integrations.id"), nullable=False, index=True
    )
    integration = relationship("AzureDevOpsIntegration", back_populates="templates")

    name = Column(String(255), nullable=False)
    project = Column(String(255), nullable=False)          # project name (or id)
    work_item_type = Column(String(100), nullable=False, default="Bug")
    area_path = Column(String(500), nullable=True)
    iteration_path = Column(String(500), nullable=True)
    extra_tags = Column(JSON, default=list)

    auto_create_enabled = Column(Boolean, default=False, nullable=False)
    auto_create_min_severity = Column(String(20), nullable=True, default="high")

    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<AzureDevOpsTemplate {self.name} {self.project}/{self.work_item_type}>"


class AzureDevOpsWorkItem(Base):
    """An Azure DevOps work item linked to an ASM vulnerability."""

    __tablename__ = "azure_devops_work_items"

    id = Column(Integer, primary_key=True, index=True)
    integration_id = Column(
        Integer, ForeignKey("azure_devops_integrations.id"), nullable=False, index=True
    )
    integration = relationship("AzureDevOpsIntegration", back_populates="work_items")

    template_id = Column(
        Integer, ForeignKey("azure_devops_templates.id", ondelete="SET NULL"), nullable=True
    )

    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False, index=True)
    vulnerability = relationship("Vulnerability")

    work_item_id = Column(Integer, nullable=False, index=True)   # Azure DevOps numeric id
    work_item_url = Column(String(1000), nullable=False)
    project = Column(String(255), nullable=True)
    work_item_type = Column(String(100), nullable=True)

    # Live status tracking
    state = Column(String(100), nullable=True)
    assigned_to = Column(String(255), nullable=True)
    last_synced_at = Column(DateTime, nullable=True)

    # Severity the work item was last notified about (for change comments)
    last_notified_severity = Column(String(20), nullable=True)

    is_associated = Column(Boolean, default=False, nullable=False)
    disconnected_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<AzureDevOpsWorkItem #{self.work_item_id} vuln={self.vulnerability_id}>"
