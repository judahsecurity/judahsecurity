"""Vulnerability response: triage gate, SLA tracking, and the action event log.

Flow for one finding:

    open finding ──▶ triage queue ──analyst approves──▶ SLA set, remediation_deadline set
                                                         │
                         event "triaged" + action notify_owner
                                                         │
                 executor = webhook ──▶ signed POST to Blink (or any consumer)
                                        └─ consumer sends the notice, then calls back
                 executor = judah   ──▶ queued for Judah's own sender
                 executor = off     ──▶ recorded as skipped

    SLA sweep (periodic): reminder events at configured fractions of the
    window, a breach event once, and a close-out event when the finding is
    resolved, accepted, mitigated or marked false positive.

Every step is a ``FindingEvent`` row, so the log doubles as the audit trail
and the source for cycle-time metrics.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from app.models.finding_response import EventStatus, FindingEvent, FindingResponse, TriageStatus
from app.models.project_settings import (
    MODULE_FINDING_RESPONSE,
    ProjectSettings,
    default_finding_response_config,
)
from app.models.vulnerability import Vulnerability, VulnerabilityStatus
from app.services import sla_policy

logger = logging.getLogger(__name__)

ACTIONS = ("notify_owner", "open_ticket", "sla_reminders", "close_out")
EXECUTORS = ("judah", "webhook", "off")
_EXECUTOR_ALIASES = {"blink": "webhook"}
CLOSED_STATUSES = (
    VulnerabilityStatus.RESOLVED,
    VulnerabilityStatus.MITIGATED,
    VulnerabilityStatus.ACCEPTED,
    VulnerabilityStatus.FALSE_POSITIVE,
)
EDITABLE_FIELDS = ("title", "description", "impact", "steps_to_reproduce", "remediation", "evidence")
MAX_DELIVERY_ATTEMPTS = 8


class ResponseError(ValueError):
    """A user-correctable problem (bad input, wrong state)."""


# ── Settings ──────────────────────────────────────────────────────────────────


def load_settings(db: Session, organization_id: int) -> Dict[str, Any]:
    """Org response settings with nested defaults filled in."""
    defaults = default_finding_response_config()
    stored = ProjectSettings.get_config(db, organization_id, MODULE_FINDING_RESPONSE) or {}
    merged = {**defaults, **stored}
    merged["executors"] = {**defaults["executors"], **(stored.get("executors") or {})}
    stored_notice = stored.get("notice") or {}
    notice = {**defaults["notice"], **stored_notice}
    for key in ("severity_colors", "labels", "source_names"):
        notice[key] = {**defaults["notice"][key], **(stored_notice.get(key) or {})}
    merged["notice"] = notice
    return merged


def executor_for(settings: Dict[str, Any], action: str) -> str:
    value = str((settings.get("executors") or {}).get(action) or "off").lower()
    value = _EXECUTOR_ALIASES.get(value, value)
    return value if value in EXECUTORS else "off"


def validate_executors(executors: Dict[str, Any]) -> Dict[str, str]:
    clean = {}
    for action, value in (executors or {}).items():
        if action not in ACTIONS:
            raise ResponseError(f"Unknown action {action!r}; expected one of {', '.join(ACTIONS)}")
        value = _EXECUTOR_ALIASES.get(str(value).lower(), str(value).lower())
        if value not in EXECUTORS:
            raise ResponseError(f"Executor for {action} must be one of judah, webhook (blink), off")
        clean[action] = value
    return clean


def validate_webhook_url(url: str) -> str:
    """HTTPS only, no credentials, no literal private/loopback addresses."""
    url = (url or "").strip()
    if not url:
        return ""
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ResponseError("Webhook URL must be an https:// URL")
    if parsed.username or parsed.password:
        raise ResponseError("Webhook URL must not contain credentials")
    host = parsed.hostname.lower()
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".internal"):
        raise ResponseError("Webhook URL must be a public host")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved):
        raise ResponseError("Webhook URL must be a public host")
    return url


def _decrypt(value: str) -> str:
    if not value:
        return ""
    from app.models.api_config import get_cipher

    try:
        return get_cipher().decrypt(value.encode()).decode()
    except Exception:  # wrong key or corrupted value
        logger.warning("Could not decrypt finding-response webhook credential")
        return ""


def encrypt_secret(value: str) -> str:
    if not value:
        return ""
    from app.models.api_config import get_cipher

    return get_cipher().encrypt(value.encode()).decode()


# ── Triage ────────────────────────────────────────────────────────────────────


def get_response(db: Session, vuln: Vulnerability) -> Optional[FindingResponse]:
    return db.query(FindingResponse).filter(FindingResponse.vulnerability_id == vuln.id).first()


def _ensure_response(db: Session, vuln: Vulnerability, organization_id: int) -> FindingResponse:
    response = get_response(db, vuln)
    if response is None:
        response = FindingResponse(
            organization_id=organization_id,
            vulnerability_id=vuln.id,
            triage_status=TriageStatus.PENDING,
            reminders_sent=[],
        )
        db.add(response)
        db.flush()
    return response


def triage_queue(db: Session, organization_id: int, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    """Open findings no analyst has approved or rejected yet, with the SLA the policy proposes."""
    from app.models.asset import Asset

    decided = db.query(FindingResponse.vulnerability_id).filter(
        FindingResponse.organization_id == organization_id,
        FindingResponse.triage_status.in_([TriageStatus.APPROVED, TriageStatus.REJECTED]),
    )
    rows = (
        db.query(Vulnerability)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .filter(
            Asset.organization_id == organization_id,
            Vulnerability.status.in_([VulnerabilityStatus.OPEN, VulnerabilityStatus.IN_PROGRESS]),
            Vulnerability.id.notin_(decided),
        )
        .order_by(Vulnerability.first_detected.desc(), Vulnerability.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    policy = sla_policy.load_policy(db, organization_id)
    out = []
    for vuln in rows:
        proposed = sla_policy.compute_sla(vuln, policy)
        out.append({
            "vulnerability_id": vuln.id,
            "title": vuln.title,
            "severity": getattr(vuln.severity, "value", vuln.severity),
            "asset": vuln.asset.value if vuln.asset else None,
            "detected_by": vuln.detected_by,
            "first_detected": vuln.first_detected.isoformat() if vuln.first_detected else None,
            "sources": sorted({o.source for o in (vuln.observations or [])}) or [vuln.detected_by],
            "proposed_sla": proposed.as_dict(),
        })
    return out


def approve(
    db: Session,
    vuln: Vulnerability,
    organization_id: int,
    actor: str,
    *,
    tier: Optional[str] = None,
    internet_accessible: Optional[bool] = None,
    owner_email: Optional[str] = None,
    owner_team: Optional[str] = None,
    finding_type: Optional[str] = None,
    note: Optional[str] = None,
    edits: Optional[Dict[str, Any]] = None,
    notify: bool = True,
    now: Optional[datetime] = None,
) -> FindingResponse:
    """Approve a finding for owner communication and start its SLA clock.

    Re-approving an already approved finding updates it (new tier, owner,
    text) and recomputes the deadline; it only re-sends the notice when
    ``notify`` is true.
    """
    if vuln.status in CLOSED_STATUSES:
        raise ResponseError(f"Finding is {vuln.status.value}; reopen it before triage")
    now = now or datetime.utcnow()
    settings = load_settings(db, organization_id)
    policy = sla_policy.load_policy(db, organization_id)
    response = _ensure_response(db, vuln, organization_id)
    first_approval = response.triage_status != TriageStatus.APPROVED

    for field, value in (edits or {}).items():
        if field not in EDITABLE_FIELDS:
            raise ResponseError(f"Field {field!r} cannot be edited at triage")
        if value is not None:
            setattr(vuln, field, str(value)[:500] if field == "title" else str(value))

    try:
        sla = sla_policy.compute_sla(
            vuln, policy, tier=tier or (None if first_approval else response.sla_tier),
            internet_accessible=internet_accessible if internet_accessible is not None
            else (None if first_approval else response.internet_accessible),
            # Updating an approved finding keeps its original clock start.
            now=now if first_approval or not response.sla_started_at else response.sla_started_at,
        )
    except sla_policy.PolicyError as exc:
        raise ResponseError(str(exc)) from exc

    response.triage_status = TriageStatus.APPROVED
    response.triaged_by = actor
    response.triaged_at = now
    response.triage_note = note if note is not None else response.triage_note
    response.sla_tier = sla.tier
    response.internet_accessible = sla.internet_accessible
    response.sla_days = sla.days
    response.sla_started_at = sla.started_at
    response.sla_due_at = sla.due_at
    response.sla_breached = bool(sla.due_at and sla.due_at < now)
    if first_approval:
        response.reminders_sent = []
    response.owner_email = (owner_email or response.owner_email or settings.get("default_owner_email") or None)
    response.owner_team = owner_team or response.owner_team
    if finding_type:
        response.finding_type = finding_type.strip()[:100]
    vuln.remediation_deadline = sla.due_at
    db.flush()

    emit(db, vuln, response, "triaged" if first_approval else "triage_updated", actor=actor,
         settings=settings, extra={"sla": sla.as_dict(), "note": note})
    if notify:
        emit(db, vuln, response, "owner_notice", action="notify_owner", actor=actor, settings=settings)
    return response


def reject(
    db: Session,
    vuln: Vulnerability,
    organization_id: int,
    actor: str,
    *,
    note: Optional[str] = None,
    false_positive: bool = False,
) -> FindingResponse:
    """Keep a finding away from owners (duplicate, out of scope, false positive)."""
    response = _ensure_response(db, vuln, organization_id)
    response.triage_status = TriageStatus.REJECTED
    response.triaged_by = actor
    response.triaged_at = datetime.utcnow()
    response.triage_note = note
    if false_positive:
        vuln.status = VulnerabilityStatus.FALSE_POSITIVE
    db.flush()
    emit(db, vuln, response, "triage_rejected", actor=actor,
         extra={"note": note, "false_positive": false_positive})
    return response


# ── Events (log + outbox) ─────────────────────────────────────────────────────


def _base_url(settings: Dict[str, Any]) -> str:
    return str(settings.get("judah_base_url") or "").rstrip("/")


def finding_summary(vuln: Vulnerability, response: Optional[FindingResponse], settings: Dict[str, Any]) -> Dict[str, Any]:
    from app.core.config import settings as app_settings

    base = _base_url(settings)
    api = f"{base}{app_settings.API_PREFIX}/finding-response/findings/{vuln.id}"
    due = response.sla_due_at if response else vuln.remediation_deadline
    return {
        "id": vuln.id,
        "title": vuln.title,
        "severity": getattr(vuln.severity, "value", vuln.severity),
        "sla_tier": response.sla_tier if response else None,
        "internet_accessible": response.internet_accessible if response else None,
        "sla_days": response.sla_days if response else None,
        "remediation_due": due.strftime("%m/%d/%Y") if due else None,
        "remediation_due_iso": due.isoformat() if due else None,
        "asset": vuln.asset.value if vuln.asset else None,
        "affected_component": vuln.affected_component,
        "cve_ids": list(vuln.cves or ([vuln.cve_id] if vuln.cve_id else [])),
        "status": getattr(vuln.status, "value", vuln.status),
        "owner_email": response.owner_email if response else None,
        "owner_team": response.owner_team if response else None,
        "ticket_key": response.ticket_key if response else None,
        "sources": sorted({o.source for o in (vuln.observations or [])}) or [vuln.detected_by],
        "links": {
            "notice_json": f"{api}/notice?format=json",
            "notice_html": f"{api}/notice?format=html",
            "notice_docx": f"{api}/notice?format=docx",
            "notice_pdf": f"{api}/notice?format=pdf",
            "actions_callback": f"{api}/actions",
        },
    }


def emit(
    db: Session,
    vuln: Vulnerability,
    response: Optional[FindingResponse],
    event_type: str,
    *,
    action: Optional[str] = None,
    actor: Optional[str] = None,
    settings: Optional[Dict[str, Any]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> FindingEvent:
    """Record an event; if it carries an action, route it to that action's executor."""
    org_id = response.organization_id if response else vuln.asset.organization_id
    settings = settings or load_settings(db, org_id)
    executor = executor_for(settings, action) if action else None
    if action is None:
        status = EventStatus.RECORDED
    elif executor == "webhook":
        status = EventStatus.PENDING
    elif executor == "judah":
        status = EventStatus.QUEUED_NATIVE
    else:
        status = EventStatus.SKIPPED
    event = FindingEvent(
        organization_id=org_id,
        vulnerability_id=vuln.id,
        event_type=event_type,
        action=action,
        executor=executor,
        status=status,
        actor=actor,
        payload={},
        result={},
        next_attempt_at=datetime.utcnow() if status == EventStatus.PENDING else None,
    )
    db.add(event)
    db.flush()
    event.payload = {
        "event_id": event.id,
        "event_type": event_type,
        "action": action,
        "organization_id": org_id,
        "occurred_at": (event.created_at or datetime.utcnow()).isoformat(),
        "actor": actor,
        "finding": finding_summary(vuln, response, settings),
        **({"details": extra} if extra else {}),
    }
    return event


def record_action_result(
    db: Session,
    vuln: Vulnerability,
    organization_id: int,
    *,
    action: str,
    outcome: str,
    actor: str,
    event_id: Optional[int] = None,
    details: Optional[Dict[str, Any]] = None,
) -> FindingEvent:
    """Executor callback: an action was carried out (``done``) or failed."""
    if action not in ACTIONS:
        raise ResponseError(f"Unknown action {action!r}")
    if outcome not in ("done", "failed"):
        raise ResponseError("outcome must be 'done' or 'failed'")
    details = details or {}
    event = None
    if event_id is not None:
        event = db.query(FindingEvent).filter(
            FindingEvent.id == event_id,
            FindingEvent.vulnerability_id == vuln.id,
            FindingEvent.organization_id == organization_id,
        ).first()
        if event is None:
            raise ResponseError(f"Event {event_id} not found for this finding")
        if event.action != action:
            raise ResponseError(f"Event {event_id} is for {event.action}, not {action}")
    response = get_response(db, vuln)
    if event is None:
        event = emit(db, vuln, response, f"{action}_reported", action=action, actor=actor)
    now = datetime.utcnow()
    event.status = EventStatus.DONE if outcome == "done" else EventStatus.FAILED
    event.result = {**(event.result or {}), **details, "outcome": outcome, "reported_by": actor}
    event.completed_at = now
    if outcome == "failed":
        event.last_error = str(details.get("error") or "executor reported failure")[:2000]
    elif response is not None:
        if action == "notify_owner":
            response.notified_at = now
            response.notified_via = str(details.get("channel") or event.executor or "webhook")[:50]
            if details.get("owner_email"):
                response.owner_email = str(details["owner_email"])[:320]
        elif action == "open_ticket":
            response.ticket_key = str(details.get("ticket_key") or "")[:100] or response.ticket_key
            response.ticket_url = str(details.get("ticket_url") or "")[:1000] or response.ticket_url
        elif action == "close_out":
            response.closed_out_at = now
    db.flush()
    return event


# ── Webhook delivery ──────────────────────────────────────────────────────────


def sign(secret: str, timestamp: str, body: bytes) -> str:
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def _backoff(attempts: int) -> timedelta:
    return timedelta(seconds=min(60 * (2 ** max(attempts - 1, 0)), 6 * 3600))


def deliver_pending(
    db: Session,
    organization_id: Optional[int] = None,
    *,
    limit: int = 50,
    client: Optional[httpx.Client] = None,
    now: Optional[datetime] = None,
) -> Dict[str, int]:
    """POST due webhook events. Safe to run from several workers on Postgres."""
    now = now or datetime.utcnow()
    query = db.query(FindingEvent).filter(
        FindingEvent.status == EventStatus.PENDING,
        FindingEvent.next_attempt_at <= now,
    )
    if organization_id is not None:
        query = query.filter(FindingEvent.organization_id == organization_id)
    events = query.order_by(FindingEvent.id).limit(limit).with_for_update(skip_locked=True).all()
    stats = {"delivered": 0, "retrying": 0, "failed": 0}
    if not events:
        return stats
    own_client = client is None
    client = client or httpx.Client(timeout=15.0, follow_redirects=False)
    settings_cache: Dict[int, Dict[str, Any]] = {}
    try:
        for event in events:
            settings = settings_cache.setdefault(event.organization_id, load_settings(db, event.organization_id))
            event.attempts = (event.attempts or 0) + 1
            error = None
            try:
                url = validate_webhook_url(settings.get("webhook_url") or "")
            except ResponseError as exc:
                url, error = "", str(exc)
            if not url and error is None:
                error = "No webhook URL configured for this organization"
            if error is None:
                body = json.dumps(event.payload, default=str, separators=(",", ":")).encode()
                ts = str(int(time.time()))
                headers = {
                    "Content-Type": "application/json",
                    "User-Agent": "Judah-Finding-Response/1",
                    "X-Judah-Event": event.event_type,
                    "X-Judah-Event-Id": str(event.id),
                    "X-Judah-Timestamp": ts,
                }
                secret = _decrypt(settings.get("webhook_secret_encrypted") or "")
                if secret:
                    headers["X-Judah-Signature"] = sign(secret, ts, body)
                key_header = str(settings.get("webhook_api_key_header") or "").strip()
                key_value = _decrypt(settings.get("webhook_api_key_encrypted") or "")
                if key_header and key_value:
                    headers[key_header] = key_value
                try:
                    resp = client.post(url, content=body, headers=headers)
                    if 200 <= resp.status_code < 300:
                        event.status = EventStatus.DELIVERED
                        event.delivered_at = now
                        event.last_error = None
                        stats["delivered"] += 1
                        continue
                    error = f"Webhook returned HTTP {resp.status_code}"
                except httpx.HTTPError as exc:
                    error = f"Webhook request failed: {exc.__class__.__name__}"
            event.last_error = error
            if event.attempts >= MAX_DELIVERY_ATTEMPTS:
                event.status = EventStatus.FAILED
                stats["failed"] += 1
            else:
                event.next_attempt_at = now + _backoff(event.attempts)
                stats["retrying"] += 1
    finally:
        if own_client:
            client.close()
    db.flush()
    return stats


# ── SLA sweep ─────────────────────────────────────────────────────────────────


def _has_event(db: Session, response: FindingResponse, event_type: str, since: Optional[datetime]) -> bool:
    query = db.query(FindingEvent.id).filter(
        FindingEvent.vulnerability_id == response.vulnerability_id,
        FindingEvent.event_type == event_type,
    )
    if since is not None:
        query = query.filter(FindingEvent.created_at >= since)
    return query.first() is not None


def run_sla_sweep(db: Session, organization_id: int, now: Optional[datetime] = None) -> Dict[str, int]:
    """Emit reminder, breach and close-out events for approved findings."""
    now = now or datetime.utcnow()
    settings = load_settings(db, organization_id)
    policy = sla_policy.load_policy(db, organization_id)
    thresholds = sorted(float(t) for t in (policy.get("reminder_thresholds") or []))
    stats = {"reminders": 0, "breaches": 0, "closed_out": 0}
    responses: Iterable[FindingResponse] = db.query(FindingResponse).filter(
        FindingResponse.organization_id == organization_id,
        FindingResponse.triage_status == TriageStatus.APPROVED,
        FindingResponse.closed_out_at.is_(None),
    ).all()
    for response in responses:
        vuln = response.vulnerability
        if vuln is None:
            continue
        if vuln.status in CLOSED_STATUSES:
            if not _has_event(db, response, "resolved", response.triaged_at):
                emit(db, vuln, response, "resolved", action="close_out", actor="sla_sweep", settings=settings,
                     extra={"final_status": vuln.status.value, "sla_met": not response.sla_breached})
                if executor_for(settings, "close_out") == "off":
                    response.closed_out_at = now
                stats["closed_out"] += 1
            continue
        if not response.sla_due_at or not response.sla_started_at:
            continue
        window = (response.sla_due_at - response.sla_started_at).total_seconds()
        if window <= 0:
            continue
        elapsed = (now - response.sla_started_at).total_seconds() / window
        if elapsed >= 1.0:
            if not response.sla_breached:
                response.sla_breached = True
                emit(db, vuln, response, "sla_breached", action="sla_reminders", actor="sla_sweep",
                     settings=settings, extra={"overdue_days": (now - response.sla_due_at).days})
                stats["breaches"] += 1
            continue
        sent = set(float(t) for t in (response.reminders_sent or []))
        crossed = [t for t in thresholds if elapsed >= t and t not in sent]
        if crossed:
            # Several thresholds crossed at once (e.g. after downtime): remind once.
            highest = max(crossed)
            emit(db, vuln, response, "sla_warning", action="sla_reminders", actor="sla_sweep",
                 settings=settings, extra={"threshold": highest,
                                           "days_left": max((response.sla_due_at - now).days, 0)})
            response.reminders_sent = sorted(sent | set(crossed))
            stats["reminders"] += 1
    db.flush()
    return stats


def active_org_ids(db: Session) -> List[int]:
    """Organizations with approved findings that are not closed out yet."""
    rows = db.query(FindingResponse.organization_id).filter(
        FindingResponse.triage_status == TriageStatus.APPROVED,
        FindingResponse.closed_out_at.is_(None),
    ).distinct().all()
    return [r[0] for r in rows]


def run_cycle(session_factory) -> Dict[str, int]:
    """One sweep + delivery pass for every configured org (background loop).

    Runs in a single transaction guarded by a transaction-level advisory lock
    on Postgres, so several API workers never sweep or deliver concurrently.
    """
    totals = {"reminders": 0, "breaches": 0, "closed_out": 0, "delivered": 0, "retrying": 0, "failed": 0}
    db = session_factory()
    try:
        if not _try_xact_lock(db):
            db.rollback()
            return totals
        for org_id in active_org_ids(db):
            for key, value in run_sla_sweep(db, org_id).items():
                totals[key] += value
        for key, value in deliver_pending(db, limit=200).items():
            totals[key] += value
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Finding response cycle failed")
    finally:
        db.close()
    return totals


_LOCK_KEY = 72_431_901  # arbitrary, stable advisory-lock id for this loop


def _try_xact_lock(db: Session) -> bool:
    """Released automatically at commit/rollback. Always true off Postgres (tests)."""
    bind = db.get_bind()
    if bind is None or bind.dialect.name != "postgresql":
        return True
    from sqlalchemy import text

    return bool(db.execute(text("SELECT pg_try_advisory_xact_lock(:k)"), {"k": _LOCK_KEY}).scalar())
