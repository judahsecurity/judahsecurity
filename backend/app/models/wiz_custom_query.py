"""User-defined Wiz GraphQL pulls and the rows they return."""

from datetime import datetime

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


class WizCustomQuery(Base):
    """A read-only GraphQL query run against a Wiz tenant on its sync schedule.

    Wiz's UI can export any table as a Python script ("Copy as Python"). The
    QUERY and VARIABLES from that script are stored here and paged through with
    the connection's credentials, so new Wiz data (application endpoints,
    attack-surface findings, issues, ...) can be pulled without code changes.
    """

    __tablename__ = "wiz_custom_queries"
    __table_args__ = (
        UniqueConstraint("integration_id", "name", name="uq_wiz_custom_query_name"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    integration_id = Column(
        Integer, ForeignKey("wiz_integrations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    integration = relationship("WizIntegration")

    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    query = Column(Text, nullable=False)
    variables = Column(JSON, default=dict)
    # Dotted path to the paginated connection inside `data`, e.g.
    # "applicationEndpoints". Empty means auto-detect the first {nodes, pageInfo}.
    connection_path = Column(String(255), nullable=True)
    page_size = Column(Integer, nullable=False, default=100)
    max_pages = Column(Integer, nullable=False, default=50)
    # Dotted path inside each row to a hostname or URL, e.g. "host". When set,
    # each row is also upserted as an inventory asset so agents can target it.
    asset_host_field = Column(String(255), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)

    last_run_at = Column(DateTime, nullable=True)
    last_run_ok = Column(Boolean, nullable=True)
    last_run_stats = Column(JSON, default=dict)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<WizCustomQuery integration={self.integration_id} name={self.name!r}>"


class WizCustomQueryRecord(Base):
    """One row (GraphQL node) returned by a custom Wiz query."""

    __tablename__ = "wiz_custom_query_records"
    __table_args__ = (
        UniqueConstraint("query_id", "external_id", name="uq_wiz_custom_query_record"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    query_id = Column(
        Integer, ForeignKey("wiz_custom_queries.id", ondelete="CASCADE"), nullable=False, index=True
    )
    external_id = Column(String(500), nullable=False)
    data = Column(JSON, default=dict)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)
    # False once a later run no longer returns the row (e.g. resolved in Wiz).
    is_present = Column(Boolean, nullable=False, default=True, index=True)
    first_seen_at = Column(DateTime, default=datetime.utcnow)
    last_seen_at = Column(DateTime, default=datetime.utcnow)
