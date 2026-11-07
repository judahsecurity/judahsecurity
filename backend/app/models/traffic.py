"""Recorded HTTP traffic and the bindings that tie it to findings.

Prowl's evidence store is session-scoped and expires. These rows are the
durable, organization-scoped copy an analyst browses after the run: every
agent ``_http_exchange``, plus operator traffic captured by the browser
extension. Bodies and headers are stored redacted and truncated.

Extension-captured rows are discovery hints. They never grant the agent
replay authority (see ``request_capture.py``); only execution-owned evidence
can back a proof.
"""

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, JSON, String, Text

from app.db.database import Base


class TrafficSource:
    AGENT = "agent"
    EXTENSION = "extension"

    ALL = (AGENT, EXTENSION)


class TrafficExchange(Base):
    __tablename__ = "traffic_exchanges"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    source = Column(String(20), nullable=False, default=TrafficSource.AGENT, index=True)

    # Agent provenance: the evidence-store artifact this row mirrors.
    session_id = Column(String(64), nullable=True, index=True)
    artifact_id = Column(String(32), nullable=True, index=True)
    hypothesis_id = Column(String(64), nullable=True)
    identity = Column(String(64), nullable=True)

    # Extension provenance.
    capture_id = Column(String(64), nullable=True, index=True)
    page_url = Column(Text, nullable=True)
    agent_key_id = Column(Integer, nullable=True)  # agent_api_keys.id of the uploading extension

    method = Column(String(16), nullable=False)
    url = Column(Text, nullable=False)
    host = Column(String(255), nullable=False, index=True)
    path = Column(Text, nullable=True)
    status_code = Column(Integer, nullable=True, index=True)

    request_headers = Column(JSON, default=dict)
    request_body = Column(Text, nullable=True)
    response_headers = Column(JSON, default=dict)
    response_body = Column(Text, nullable=True)
    response_length = Column(Integer, nullable=True)
    elapsed_ms = Column(Integer, nullable=True)
    truncated = Column(Integer, nullable=False, default=0)  # bitmask: 1=request body, 2=response body

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    __table_args__ = (
        Index("ix_traffic_org_host_created", "organization_id", "host", "created_at"),
        Index("ix_traffic_org_artifact", "organization_id", "artifact_id"),
    )


class VulnerabilityTrafficRef(Base):
    """One recorded exchange cited as evidence for a finding, in replay order.

    Agent bindings name the evidence ``artifact_id`` (resolved at read time, so
    binding never races the asynchronous recorder); analyst bindings name a
    ``traffic_id`` directly.
    """

    __tablename__ = "vulnerability_traffic_refs"

    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(
        Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    traffic_id = Column(Integer, ForeignKey("traffic_exchanges.id", ondelete="CASCADE"), nullable=True)
    artifact_id = Column(String(32), nullable=True)
    position = Column(Integer, nullable=False, default=0)
    note = Column(String(500), nullable=True)
    bound_by = Column(String(20), nullable=False, default="agent")  # agent | user
    bound_by_user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
