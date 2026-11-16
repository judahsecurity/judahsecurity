"""
Rules of Engagement routes.

All routes are scoped to an organization and require ``analyst`` role (GET)
or ``admin`` role (POST/PUT) to modify.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import require_admin, require_analyst
from app.db.database import get_db
from app.models.user import User
from app.models.project_settings import MODULE_RULES_OF_ENGAGEMENT, ProjectSettings
from app.services import agent_denylist, roe_service

router = APIRouter(prefix="/roe", tags=["rules-of-engagement"])


class RoEPayload(BaseModel):
    """Full or partial RoE update."""

    enabled: bool = True
    document_name: Optional[str] = Field(default=None)
    document_text: Optional[str] = Field(default=None)
    scope_in: Optional[list[str]] = None
    scope_out: Optional[list[str]] = None
    allowed_scan_types: Optional[list[str]] = None
    restricted_scan_types: Optional[list[str]] = None
    max_rps_global: Optional[int] = None
    max_concurrency: Optional[int] = None
    requires_agent_confirmation: Optional[bool] = None
    contacts: Optional[list[str]] = None
    notes: Optional[str] = None


class RoECheckRequest(BaseModel):
    organization_id: int
    targets: list[str]
    scan_type: Optional[str] = None


def _check_org_access(user: User, org_id: int) -> bool:
    if user.is_superuser:
        return True
    return user.organization_id == org_id


@router.get("/{organization_id}")
def get_roe(
    organization_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    if not _check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    return roe_service.load_roe(db, organization_id)


@router.put("/{organization_id}", status_code=status.HTTP_200_OK)
def update_roe(
    organization_id: int,
    payload: RoEPayload,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    if not _check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")

    updated = roe_service.accept_roe(
        db,
        organization_id=organization_id,
        actor_email=current_user.email or current_user.username or "",
        document_text=payload.document_text or "",
        document_name=payload.document_name or "",
        scope_in=payload.scope_in,
        scope_out=payload.scope_out,
        allowed_scan_types=payload.allowed_scan_types,
        restricted_scan_types=payload.restricted_scan_types,
        max_rps_global=payload.max_rps_global,
        max_concurrency=payload.max_concurrency,
        requires_agent_confirmation=payload.requires_agent_confirmation,
        contacts=payload.contacts,
        notes=payload.notes,
        enabled=payload.enabled,
    )
    agent_denylist.invalidate(organization_id)
    return updated


@router.post("/{organization_id}/upload", status_code=status.HTTP_200_OK)
async def upload_roe(
    organization_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Upload a markdown RoE document. The server will best-effort parse scope
    sections and pre-populate ``scope_in`` / ``scope_out`` / ``contacts``.
    The user can then review and call ``PUT /roe/{org}`` to finalize.
    """
    if not _check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")

    raw = await file.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File is not UTF-8 text")

    parsed = roe_service.ingest_markdown(text)

    updated = roe_service.accept_roe(
        db,
        organization_id=organization_id,
        actor_email=current_user.email or current_user.username or "",
        document_text=text,
        document_name=file.filename or "roe.md",
        scope_in=parsed.get("scope_in"),
        scope_out=parsed.get("scope_out"),
        contacts=parsed.get("contacts"),
        notes=parsed.get("notes"),
        enabled=True,
    )
    agent_denylist.invalidate(organization_id)
    return {
        "parsed": parsed,
        "config": updated,
    }


@router.post("/check")
def check_roe(
    payload: RoECheckRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Dry-run RoE guardrail for a list of targets."""
    if not _check_org_access(current_user, payload.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")

    ok, reason, rejected = roe_service.check_targets(
        db, payload.organization_id, payload.targets, scan_type=payload.scan_type
    )
    return {
        "allowed": ok,
        "reason": reason,
        "rejected_targets": rejected,
    }


# ---------------------------------------------------------------------------
# Agent never-touch denylist (enforced on every agent tool call, RoE on or off)
# ---------------------------------------------------------------------------


class DenylistPayload(BaseModel):
    scope_out: Optional[list[str]] = None
    deny_patterns: Optional[list[str]] = None
    deny_dry_run: Optional[bool] = None


class DenylistPreviewRequest(DenylistPayload):
    targets: list[str] = Field(..., min_length=1, max_length=100)


def _denylist_view(roe: dict) -> dict:
    from aegis_praetorium.denylist import DEFAULT_DENY_RULES

    policy = agent_denylist.policy_from_roe(roe)
    return {
        "scope_out": roe.get("scope_out") or [],
        "deny_patterns": roe.get("deny_patterns") or [],
        "deny_dry_run": bool(roe.get("deny_dry_run")),
        "default_rules": [r.pattern for r in DEFAULT_DENY_RULES],
        "default_overrides": list(policy.allow_hosts),
    }


def _validate_patterns(patterns: Optional[list[str]]) -> Optional[list[str]]:
    from aegis_praetorium.denylist import compile_pattern

    if patterns is None:
        return None
    cleaned = [p for p in (str(x).strip() for x in patterns) if p]
    for p in cleaned:
        try:
            compile_pattern(p)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    return list(dict.fromkeys(cleaned))


@router.get("/{organization_id}/denylist")
def get_denylist(
    organization_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    if not _check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    return _denylist_view(roe_service.load_roe(db, organization_id))


@router.put("/{organization_id}/denylist")
def update_denylist(
    organization_id: int,
    payload: DenylistPayload,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Edit never-touch rules without re-accepting the RoE document."""
    if not _check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    changes: dict = {}
    patterns = _validate_patterns(payload.deny_patterns)
    if patterns is not None:
        changes["deny_patterns"] = patterns
    if payload.scope_out is not None:
        changes["scope_out"] = list(dict.fromkeys(s.strip() for s in payload.scope_out if s.strip()))
    if payload.deny_dry_run is not None:
        changes["deny_dry_run"] = payload.deny_dry_run
    if changes:
        ProjectSettings.set_config(db, organization_id, MODULE_RULES_OF_ENGAGEMENT, changes)
        db.commit()
        agent_denylist.invalidate(organization_id)
    return _denylist_view(roe_service.load_roe(db, organization_id))


@router.post("/{organization_id}/denylist/preview")
def preview_denylist(
    organization_id: int,
    payload: DenylistPreviewRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Show which sample targets would be blocked, optionally with unsaved edits."""
    if not _check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    roe = dict(roe_service.load_roe(db, organization_id))
    patterns = _validate_patterns(payload.deny_patterns)
    if patterns is not None:
        roe["deny_patterns"] = patterns
    if payload.scope_out is not None:
        roe["scope_out"] = payload.scope_out
    if payload.deny_dry_run is not None:
        roe["deny_dry_run"] = payload.deny_dry_run
    return agent_denylist.preview(payload.targets, roe)
