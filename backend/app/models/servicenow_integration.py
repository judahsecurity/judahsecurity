"""ServiceNow ITSM integration models.

Outbound webhook (Praetorian-style) plus Table API bidirectional status sync
and optional close-claim validation via Aegis Vanguard.
"""

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship

from app.db.database import Base
from app.models.api_config import get_cipher
from app.models.jira_integration import severity_meets_threshold  # noqa: F401 — re-export

__all__ = [
    "ServiceNowIntegration",
    "ServiceNowDelivery",
    "severity_meets_threshold",
]


class ServiceNowIntegration(Base):
    """Stores ServiceNow webhook + Table API sync configuration per organization."""

    __tablename__ = "servicenow_integrations"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id"), nullable=False, unique=True, index=True
    )
    organization = relationship("Organization")

    # Full Scripted REST API URL, e.g.
    # https://instance.service-now.com/api/x_1234567_name/pgp_rest_api/notification
    webhook_url = Column(String(1000), nullable=False)

    # Optional Basic Auth (service account). Password encrypted at rest.
    username = Column(String(255), nullable=True)
    password_encrypted = Column(Text, nullable=True)

    # Auto-create: push when a new vuln meets the severity threshold
    auto_create_enabled = Column(Boolean, default=False, nullable=False)
    auto_create_min_severity = Column(String(20), nullable=True, default="high")

    # Bidirectional status sync via Table API (requires sys_id on deliveries)
    sync_enabled = Column(Boolean, default=False, nullable=False)
    table_name = Column(String(100), nullable=False, default="incident")
    # ServiceNow state values (incident defaults: 6=Resolved, 7=Closed, 2=In Progress)
    close_state = Column(String(50), nullable=False, default="6")
    reopen_state = Column(String(50), nullable=False, default="2")
    # States that mean "closed" when pulling from ServiceNow
    remote_closed_states = Column(JSON, default=lambda: ["6", "7"])

    # When ServiceNow marks an incident closed, queue Vanguard validation before
    # accepting the close in ASM. CONFIRMED → reject close; otherwise accept.
    validate_on_remote_close = Column(Boolean, default=True, nullable=False)
    # ASM status to apply when close is accepted after validation
    # (resolved | false_positive | mitigated)
    accept_close_as = Column(String(30), nullable=False, default="resolved")

    is_active = Column(Boolean, default=True, nullable=False)
    last_tested_at = Column(DateTime, nullable=True)
    last_test_ok = Column(Boolean, nullable=True)
    last_delivery_at = Column(DateTime, nullable=True)
    last_pull_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    deliveries = relationship(
        "ServiceNowDelivery",
        back_populates="integration",
        cascade="all, delete-orphan",
    )

    def set_password(self, password: str | None) -> None:
        if password:
            self.password_encrypted = get_cipher().encrypt(password.encode()).decode()

    def get_password(self) -> str | None:
        if self.password_encrypted:
            return get_cipher().decrypt(self.password_encrypted.encode()).decode()
        return None

    def __repr__(self):
        return f"<ServiceNowIntegration org={self.organization_id}>"


class ServiceNowDelivery(Base):
    """Tracks outbound webhook deliveries linked to ASM vulnerabilities."""

    __tablename__ = "servicenow_deliveries"

    id = Column(Integer, primary_key=True, index=True)
    integration_id = Column(
        Integer, ForeignKey("servicenow_integrations.id"), nullable=False, index=True
    )
    integration = relationship("ServiceNowIntegration", back_populates="deliveries")

    vulnerability_id = Column(
        Integer, ForeignKey("vulnerabilities.id"), nullable=False, index=True
    )
    vulnerability = relationship("Vulnerability")

    # Identifiers returned by the customer's Scripted REST handler / Table API
    snow_sys_id = Column(String(100), nullable=True)
    snow_number = Column(String(100), nullable=True)  # e.g. INC0012345
    snow_url = Column(String(1000), nullable=True)

    # Live status tracking (Table API)
    snow_state = Column(String(50), nullable=True)
    snow_state_label = Column(String(100), nullable=True)
    last_synced_at = Column(DateTime, nullable=True)

    # Close-claim validation loop
    pending_close_validation = Column(Boolean, default=False, nullable=False)
    pending_close_validation_id = Column(Integer, nullable=True)
    last_close_validation_verdict = Column(String(50), nullable=True)

    http_status = Column(Integer, nullable=True)
    response_body = Column(Text, nullable=True)

    # Soft-delete: unlink from ASM without deleting the ServiceNow record
    disconnected_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<ServiceNowDelivery vuln={self.vulnerability_id} status={self.http_status}>"
