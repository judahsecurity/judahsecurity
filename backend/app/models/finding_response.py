"""Vulnerability response state: triage, SLA, owner communication, and the event log.

``FindingResponse`` is one row per finding that has entered the response
process (analyst triage → owner notice → SLA tracking → close-out).
``FindingEvent`` is the append-only lifecycle log and, at the same time, the
outbox: events whose action is carried out by an external workflow (Blink,
or any webhook consumer) are delivered from here and acknowledged back
through ``POST /finding-response/findings/{id}/actions``.
"""

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship

from app.db.database import Base


class TriageStatus:
    PENDING = "pending_triage"
    APPROVED = "approved"
    REJECTED = "rejected"
    ALL = (PENDING, APPROVED, REJECTED)


class FindingResponse(Base):
    __tablename__ = "finding_responses"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    vulnerability_id = Column(
        Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, unique=True, index=True
    )
    vulnerability = relationship("Vulnerability")

    triage_status = Column(String(20), nullable=False, default=TriageStatus.PENDING, index=True)
    triaged_by = Column(String(255), nullable=True)
    triaged_at = Column(DateTime, nullable=True)
    triage_note = Column(Text, nullable=True)

    # SLA inputs and result, frozen at approval so later policy edits don't
    # silently move a deadline an owner was already given.
    sla_tier = Column(String(20), nullable=True, index=True)  # urgent|critical|high|medium|low|info
    internet_accessible = Column(Boolean, nullable=True)
    sla_days = Column(Integer, nullable=True)
    sla_started_at = Column(DateTime, nullable=True)
    sla_due_at = Column(DateTime, nullable=True, index=True)
    sla_breached = Column(Boolean, nullable=False, default=False, index=True)
    reminders_sent = Column(JSON, default=list)  # thresholds already reminded, e.g. [0.5]

    owner_email = Column(String(320), nullable=True)
    owner_team = Column(String(255), nullable=True)
    # Shown as "Type" in the notice, e.g. "Service or Interface Exposure".
    finding_type = Column(String(100), nullable=True)

    notified_at = Column(DateTime, nullable=True)
    notified_via = Column(String(50), nullable=True)
    ticket_key = Column(String(100), nullable=True)
    ticket_url = Column(String(1000), nullable=True)
    closed_out_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class EventStatus:
    RECORDED = "recorded"      # log only, nothing to carry out
    PENDING = "pending"        # waiting for delivery to the webhook
    DELIVERED = "delivered"    # webhook accepted it; waiting for the executor's callback
    DONE = "done"              # executor reported the action carried out
    QUEUED_NATIVE = "queued_native"  # Judah itself must carry it out
    FAILED = "failed"          # delivery or action failed (see last_error)
    SKIPPED = "skipped"        # executor for this action is "off"


class FindingEvent(Base):
    __tablename__ = "finding_events"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    vulnerability_id = Column(
        Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type = Column(String(50), nullable=False, index=True)  # triaged, sla_warning, sla_breached, resolved, ...
    action = Column(String(50), nullable=True, index=True)       # notify_owner, sla_reminders, close_out, ...
    executor = Column(String(20), nullable=True)                 # judah | webhook | off
    status = Column(String(20), nullable=False, default=EventStatus.RECORDED, index=True)
    actor = Column(String(255), nullable=True)
    payload = Column(JSON, default=dict)
    result = Column(JSON, default=dict)
    attempts = Column(Integer, nullable=False, default=0)
    last_error = Column(Text, nullable=True)
    next_attempt_at = Column(DateTime, nullable=True, index=True)
    delivered_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
