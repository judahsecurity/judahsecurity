"""Business applications — the organization's application inventory.

Synced from the ServiceNow CMDB Business Application table
(``cmdb_ci_business_app``) so analysts can tie findings to the business
application they affect, and so the severity evaluation can take Business
Impact from the application's business criticality.
"""

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint

from app.db.database import Base


class BusinessApplication(Base):
    __tablename__ = "business_applications"
    __table_args__ = (
        UniqueConstraint("organization_id", "source", "external_id", name="uq_business_app_source_id"),
        Index("ix_business_app_org_name", "organization_id", "name"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)

    # Where the record came from and its id there (ServiceNow sys_id).
    source = Column(String(30), nullable=False, default="servicenow")
    external_id = Column(String(64), nullable=False)
    # The application's unique id analysts reference (ServiceNow "number", e.g. APM0001234).
    app_id = Column(String(64), nullable=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # ServiceNow business_criticality, raw ("1 - most critical") and as 1–4.
    business_criticality = Column(String(50), nullable=True)
    criticality_level = Column(Integer, nullable=True)
    operational_status = Column(String(50), nullable=True)
    lifecycle_stage = Column(String(100), nullable=True)
    owner = Column(String(255), nullable=True)
    it_owner = Column(String(255), nullable=True)
    url = Column(String(500), nullable=True)
    external_url = Column(String(500), nullable=True)  # link to the record in ServiceNow

    raw = Column(JSON, default=dict)
    synced_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<BusinessApplication {self.app_id or self.external_id}: {self.name}>"
