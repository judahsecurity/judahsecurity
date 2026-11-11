"""Vulnerability response API: SLA policy, triage gate, owner notice, executor callbacks.

Callers are either Judah users (JWT) or an external executor such as a Blink
workflow using an agent API key (``X-API-Key: tfasm_...``). API keys can read
notices, report action results and list the triage queue; approving or
rejecting at triage with a key requires the explicit ``findings:triage`` scope.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_current_user_optional
from app.db.database import get_db
from app.models.asset import Asset
from app.models.finding_response import FindingEvent
from app.models.project_settings import MODULE_FINDING_RESPONSE, MODULE_SLA_POLICY, ProjectSettings
from app.models.user import User, UserRole
from app.models.vulnerability import Vulnerability
from app.services import finding_notice, finding_response as fr, sla_policy

router = APIRouter(prefix="/finding-response", tags=["Finding Response"])

SCOPE_RESPOND = "findings:respond"
SCOPE_TRIAGE = "findings:triage"


# ── Auth ──────────────────────────────────────────────────────────────────────


@dataclass
class Principal:
    organization_id: int
    actor: str
    user: Optional[User] = None
    scopes: Optional[List[str]] = None

    @property
    def is_user(self) -> bool:
        return self.user is not None

    def require_role(self, *roles: UserRole) -> None:
        if not self.is_user:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "This operation needs a signed-in user")
        if self.user.is_superuser or self.user.role in roles:
            return
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Operation not permitted for your role")

    def require_triage(self) -> None:
        if self.is_user:
            self.require_role(UserRole.ADMIN, UserRole.ANALYST)
        elif SCOPE_TRIAGE not in (self.scopes or []):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"API key lacks the {SCOPE_TRIAGE} scope")


def get_principal(
    org_id: Optional[int] = Query(None, description="Superusers only: organization to act on"),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_current_user_optional),
) -> Principal:
    api_key = x_api_key
    if not api_key and authorization and authorization.startswith("Bearer tfasm_"):
        api_key = authorization[7:]
    if api_key:
        from app.services.ingestion_service import verify_agent_api_key

        record = verify_agent_api_key(db, api_key)
        if not record:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired API key")
        scopes = list(record.scopes or [])
        if scopes and SCOPE_RESPOND not in scopes and SCOPE_TRIAGE not in scopes:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"API key lacks the {SCOPE_RESPOND} scope")
        return Principal(record.organization_id, f"api_key:{record.name}", scopes=scopes)
    if user is None or not user.is_active or getattr(user, "must_change_password", False):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated",
                            headers={"WWW-Authenticate": "Bearer"})
    target = user.organization_id
    if org_id is not None and org_id != target:
        if not user.is_superuser:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Access denied")
        target = org_id
    if target is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Pass org_id to choose an organization")
    return Principal(target, user.email or user.username, user=user)


def _finding(db: Session, principal: Principal, vulnerability_id: int) -> Vulnerability:
    vuln = (
        db.query(Vulnerability)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .filter(Vulnerability.id == vulnerability_id, Asset.organization_id == principal.organization_id)
        .first()
    )
    if vuln is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    return vuln


def _bad_request(exc: Exception) -> HTTPException:
    return HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))


# ── Settings ──────────────────────────────────────────────────────────────────


def _public_settings(db: Session, org_id: int) -> Dict[str, Any]:
    settings = fr.load_settings(db, org_id)
    out = {k: v for k, v in settings.items() if not k.endswith("_encrypted")}
    out["webhook_secret_set"] = bool(settings.get("webhook_secret_encrypted"))
    out["webhook_api_key_set"] = bool(settings.get("webhook_api_key_encrypted"))
    return {"response": out, "sla_policy": sla_policy.load_policy(db, org_id)}


@router.get("/settings")
def get_settings(principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    return _public_settings(db, principal.organization_id)


@router.put("/settings/sla-policy")
def update_sla_policy(body: Dict[str, Any], principal: Principal = Depends(get_principal),
                      db: Session = Depends(get_db)):
    """Partial update, e.g. {"internet_accessible": {"high": 21}}. Applies to findings triaged afterwards."""
    principal.require_role(UserRole.ADMIN)
    current = sla_policy.load_policy(db, principal.organization_id)
    try:
        policy = sla_policy.validate_policy(sla_policy.merge_policy(current, body))
    except sla_policy.PolicyError as exc:
        raise _bad_request(exc)
    ProjectSettings.set_config(db, principal.organization_id, MODULE_SLA_POLICY, policy)
    db.commit()
    return sla_policy.load_policy(db, principal.organization_id)


class ResponseSettingsUpdate(BaseModel):
    executors: Optional[Dict[str, str]] = None
    default_owner_email: Optional[str] = None
    judah_base_url: Optional[str] = None
    notice: Optional[Dict[str, Any]] = None


@router.put("/settings/response")
def update_response_settings(body: ResponseSettingsUpdate, principal: Principal = Depends(get_principal),
                             db: Session = Depends(get_db)):
    principal.require_role(UserRole.ADMIN)
    current = fr.load_settings(db, principal.organization_id)
    update: Dict[str, Any] = {}
    try:
        if body.executors is not None:
            update["executors"] = {**current["executors"], **fr.validate_executors(body.executors)}
    except fr.ResponseError as exc:
        raise _bad_request(exc)
    if body.default_owner_email is not None:
        update["default_owner_email"] = body.default_owner_email.strip()[:320]
    if body.judah_base_url is not None:
        base = body.judah_base_url.strip().rstrip("/")
        if base and not base.startswith(("https://", "http://")):
            raise _bad_request(ValueError("judah_base_url must start with https://"))
        update["judah_base_url"] = base
    if body.notice is not None:
        nested = ("severity_colors", "labels", "source_names")
        notice = {**current["notice"], **{k: v for k, v in body.notice.items() if k not in nested}}
        for key in ("labels", "source_names"):
            value = body.notice.get(key) or {}
            if not isinstance(value, dict) or not all(isinstance(v, str) for v in value.values()):
                raise _bad_request(ValueError(f"notice.{key} must map names to text"))
            notice[key] = {**current["notice"][key], **value}
        closing = notice.get("closing_templates")
        if not isinstance(closing, list) or not all(isinstance(t, str) for t in closing):
            raise _bad_request(ValueError("notice.closing_templates must be a list of paragraphs"))
        try:
            datetime(2023, 9, 7).strftime(str(notice.get("date_format") or "%m/%d/%Y"))
        except (ValueError, TypeError):
            raise _bad_request(ValueError("notice.date_format is not a valid date format"))
        colors = {**current["notice"]["severity_colors"], **(body.notice.get("severity_colors") or {})}
        for tier, color in colors.items():
            if not isinstance(color, str) or len(color.lstrip("#")) != 6:
                raise _bad_request(ValueError(f"Color for {tier} must be a 6-digit hex value"))
        notice["severity_colors"] = {k: v.lstrip("#").upper() for k, v in colors.items()}
        update["notice"] = notice
    ProjectSettings.set_config(db, principal.organization_id, MODULE_FINDING_RESPONSE, update)
    db.commit()
    return _public_settings(db, principal.organization_id)


class WebhookUpdate(BaseModel):
    url: str = ""
    secret: Optional[str] = Field(None, description="HMAC signing secret; omit to keep, empty string to clear")
    api_key_header: Optional[str] = Field(None, description="e.g. BLINK-API-KEY for a Blink webhook trigger")
    api_key: Optional[str] = Field(None, description="Value for api_key_header; omit to keep, empty to clear")


@router.put("/settings/webhook")
def update_webhook(body: WebhookUpdate, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    principal.require_role(UserRole.ADMIN)
    try:
        update: Dict[str, Any] = {"webhook_url": fr.validate_webhook_url(body.url)}
    except fr.ResponseError as exc:
        raise _bad_request(exc)
    if body.secret is not None:
        update["webhook_secret_encrypted"] = fr.encrypt_secret(body.secret)
    if body.api_key_header is not None:
        header = body.api_key_header.strip()
        if header and not header.replace("-", "").replace("_", "").isalnum():
            raise _bad_request(ValueError("api_key_header must be a plain header name"))
        update["webhook_api_key_header"] = header
    if body.api_key is not None:
        update["webhook_api_key_encrypted"] = fr.encrypt_secret(body.api_key)
    ProjectSettings.set_config(db, principal.organization_id, MODULE_FINDING_RESPONSE, update)
    db.commit()
    return _public_settings(db, principal.organization_id)["response"]


@router.post("/run")
def run_now(principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    """Run the SLA sweep and webhook delivery for this organization now."""
    principal.require_role(UserRole.ADMIN, UserRole.ANALYST)
    sweep = fr.run_sla_sweep(db, principal.organization_id)
    delivery = fr.deliver_pending(db, principal.organization_id)
    db.commit()
    return {**sweep, **delivery}


# ── Triage ────────────────────────────────────────────────────────────────────


@router.get("/triage-queue")
def get_triage_queue(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
                     principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    return {"items": fr.triage_queue(db, principal.organization_id, limit=limit, offset=offset)}


class TriageRequest(BaseModel):
    decision: Literal["approve", "reject"] = "approve"
    sla_tier: Optional[Literal["urgent", "critical", "high", "medium", "low", "info"]] = None
    internet_accessible: Optional[bool] = None
    owner_email: Optional[str] = None
    owner_team: Optional[str] = None
    finding_type: Optional[str] = Field(None, description='Notice "Type", e.g. Service or Interface Exposure')
    note: Optional[str] = None
    notify: Optional[bool] = Field(None, description="Send the owner notice (default: on first approval only)")
    false_positive: bool = False
    edits: Dict[str, Optional[str]] = Field(
        default_factory=dict,
        description="Notice text to set at triage: title, description, impact, steps_to_reproduce, remediation, evidence",
    )


@router.post("/findings/{vulnerability_id}/triage")
def triage(vulnerability_id: int, body: TriageRequest, principal: Principal = Depends(get_principal),
           db: Session = Depends(get_db)):
    principal.require_triage()
    vuln = _finding(db, principal, vulnerability_id)
    try:
        if body.decision == "reject":
            response = fr.reject(db, vuln, principal.organization_id, principal.actor,
                                 note=body.note, false_positive=body.false_positive)
        else:
            existing = fr.get_response(db, vuln)
            first = existing is None or existing.triage_status != "approved"
            response = fr.approve(
                db, vuln, principal.organization_id, principal.actor,
                tier=body.sla_tier, internet_accessible=body.internet_accessible,
                owner_email=body.owner_email, owner_team=body.owner_team,
                finding_type=body.finding_type, note=body.note,
                edits=body.edits, notify=first if body.notify is None else body.notify,
            )
    except fr.ResponseError as exc:
        db.rollback()
        raise _bad_request(exc)
    db.commit()
    return _detail(db, vuln, response)


def _detail(db: Session, vuln: Vulnerability, response) -> Dict[str, Any]:
    events = (
        db.query(FindingEvent)
        .filter(FindingEvent.vulnerability_id == vuln.id)
        .order_by(FindingEvent.id.desc())
        .limit(100)
        .all()
    )
    settings = fr.load_settings(db, vuln.asset.organization_id)
    return {
        "finding": fr.finding_summary(vuln, response, settings),
        "response": None if response is None else {
            "triage_status": response.triage_status,
            "triaged_by": response.triaged_by,
            "triaged_at": response.triaged_at,
            "triage_note": response.triage_note,
            "sla_tier": response.sla_tier,
            "internet_accessible": response.internet_accessible,
            "sla_days": response.sla_days,
            "sla_started_at": response.sla_started_at,
            "sla_due_at": response.sla_due_at,
            "sla_breached": response.sla_breached,
            "owner_email": response.owner_email,
            "owner_team": response.owner_team,
            "notified_at": response.notified_at,
            "ticket_key": response.ticket_key,
            "ticket_url": response.ticket_url,
            "closed_out_at": response.closed_out_at,
        },
        "events": [
            {
                "id": e.id, "event_type": e.event_type, "action": e.action, "executor": e.executor,
                "status": e.status, "actor": e.actor, "attempts": e.attempts, "last_error": e.last_error,
                "result": e.result, "created_at": e.created_at, "completed_at": e.completed_at,
            }
            for e in events
        ],
    }


@router.get("/findings/{vulnerability_id}")
def get_finding_response(vulnerability_id: int, principal: Principal = Depends(get_principal),
                         db: Session = Depends(get_db)):
    vuln = _finding(db, principal, vulnerability_id)
    return _detail(db, vuln, fr.get_response(db, vuln))


# ── Notice ────────────────────────────────────────────────────────────────────


@router.get("/findings/{vulnerability_id}/notice")
def get_notice(
    vulnerability_id: int,
    format: Literal["json", "html", "text", "docx", "pdf"] = "json",
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
):
    """The owner notice in the requested format. ``json`` bundles subject, fields, html and text."""
    vuln = _finding(db, principal, vulnerability_id)
    settings = fr.load_settings(db, principal.organization_id)
    fields = finding_notice.build_fields(vuln, fr.get_response(db, vuln), settings)
    if format == "json":
        return {
            "subject": fields["subject"],
            "to": fields["owner_email"],
            "fields": fields,
            "html": finding_notice.render_html(fields),
            "text": finding_notice.render_text(fields),
        }
    if format == "html":
        return Response(finding_notice.render_html(fields), media_type="text/html; charset=utf-8")
    if format == "text":
        return Response(finding_notice.render_text(fields), media_type="text/plain; charset=utf-8")
    if format == "docx":
        return Response(
            finding_notice.render_docx(fields),
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": f'attachment; filename="{finding_notice.filename(fields, "docx")}"'},
        )
    try:
        pdf = finding_notice.render_pdf(fields)
    except finding_notice.NoticeUnavailable as exc:
        raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, str(exc))
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{finding_notice.filename(fields, "pdf")}"'})


# ── Executor callback ─────────────────────────────────────────────────────────


class ActionReport(BaseModel):
    action: Literal["notify_owner", "open_ticket", "sla_reminders", "close_out"]
    outcome: Literal["done", "failed"] = "done"
    event_id: Optional[int] = Field(None, description="The event_id from the webhook payload, when there was one")
    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="e.g. channel, owner_email, message_id, ticket_key, ticket_url, error",
    )


@router.post("/findings/{vulnerability_id}/actions")
def report_action(vulnerability_id: int, body: ActionReport, principal: Principal = Depends(get_principal),
                  db: Session = Depends(get_db)):
    """An executor (Blink, Judah, a person) reports that it carried out an action."""
    vuln = _finding(db, principal, vulnerability_id)
    details = {k: v for k, v in body.details.items() if isinstance(k, str)}
    try:
        event = fr.record_action_result(
            db, vuln, principal.organization_id, action=body.action, outcome=body.outcome,
            actor=principal.actor, event_id=body.event_id, details=details,
        )
    except fr.ResponseError as exc:
        db.rollback()
        raise _bad_request(exc)
    db.commit()
    return {"event_id": event.id, "status": event.status}
