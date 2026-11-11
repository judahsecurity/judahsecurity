"""Application services and the CMDB configuration items that run them.

Synced from the ServiceNow CMDB so an internet-facing asset can be attributed
to what runs it: the application service (``cmdb_ci_service_auto`` and its
child classes), the business application that consumes that service
(``cmdb_ci_business_app``), and through them an owner, support group and
business unit.

``CmdbCiLink`` holds the "what is running it" half: one row per configuration
item (server, IP, DNS name, HTTP entry point) that ServiceNow places in an
application service or business application, with the hostnames and IPs used
to match it to our assets.
"""

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint

from app.db.database import Base


class ApplicationService(Base):
    __tablename__ = "application_services"
    __table_args__ = (
        UniqueConstraint("organization_id", "source", "external_id", name="uq_app_service_source_id"),
        Index("ix_app_service_org_name", "organization_id", "name"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)

    source = Column(String(30), nullable=False, default="servicenow")
    external_id = Column(String(64), nullable=False)  # ServiceNow sys_id
    number = Column(String(64), nullable=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    service_class = Column(String(100), nullable=True)  # sys_class_name, e.g. cmdb_ci_service_discovered

    # Business application that consumes this service (cmdb_rel_ci).
    business_app_id = Column(
        Integer, ForeignKey("business_applications.id", ondelete="SET NULL"), nullable=True, index=True
    )

    business_criticality = Column(String(50), nullable=True)
    criticality_level = Column(Integer, nullable=True)  # 1 (most critical) – 4
    environment = Column(String(50), nullable=True)
    operational_status = Column(String(50), nullable=True)

    owner = Column(String(255), nullable=True)  # owned_by
    managed_by = Column(String(255), nullable=True)
    support_group = Column(String(255), nullable=True)
    change_group = Column(String(255), nullable=True)  # change_control
    business_unit = Column(String(255), nullable=True)
    department = Column(String(255), nullable=True)
    company = Column(String(255), nullable=True)

    external_url = Column(String(500), nullable=True)
    raw = Column(JSON, default=dict)
    synced_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<ApplicationService {self.number or self.external_id}: {self.name}>"


class CmdbCiLink(Base):
    """A configuration item that runs an application service or business app."""

    __tablename__ = "cmdb_ci_links"
    __table_args__ = (
        Index("ix_cmdb_ci_link_org_fqdn", "organization_id", "fqdn"),
        Index("ix_cmdb_ci_link_org_ip", "organization_id", "ip_address"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    app_service_id = Column(
        Integer, ForeignKey("application_services.id", ondelete="CASCADE"), nullable=True, index=True
    )
    business_app_id = Column(
        Integer, ForeignKey("business_applications.id", ondelete="CASCADE"), nullable=True, index=True
    )

    # How ServiceNow ties the CI to the service: entry_point | service_map | relationship
    relation = Column(String(30), nullable=False)
    ci_sys_id = Column(String(64), nullable=True)
    ci_name = Column(String(255), nullable=True)
    ci_class = Column(String(100), nullable=True)
    fqdn = Column(String(255), nullable=True)  # lowercased hostname used for matching
    ip_address = Column(String(64), nullable=True)
    url = Column(String(500), nullable=True)
    synced_at = Column(DateTime, default=datetime.utcnow)
