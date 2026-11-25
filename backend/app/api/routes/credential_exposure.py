"""Leaked-credential exposures prioritized by workforce identity.

Every route is scoped to the caller's organization. Identity data comes from
HR and IT systems, so reads require the analyst role, not just a login.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.api.deps import require_analyst
from app.db.database import get_db
from app.models.identity import (
    EXPOSURE_STATUSES,
    IDENTITY_SOURCE_SERVICENOW,
    CredentialExposure,
    Identity,
    IdentitySourceSync,
)
from app.models.servicenow_integration import ServiceNowIntegration
from app.models.user import User
from app.services import identity_sync_service
from app.services.credential_exposure_service import rescore_organization

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/credential-exposure", tags=["Credential Exposure"])


def _org_id(user: User) -> int:
    if not user.organization_id:
        raise HTTPException(status_code=400, detail="User has no associated organization.")
    return user.organization_id


# ── Schemas ──────────────────────────────────────────────────────────────────

class ScoreFactorOut(BaseModel):
    key: str
    points: int
    detail: str


class IdentityOut(BaseModel):
    id: int
    source: str
    email: Optional[str] = None
    username: Optional[str] = None
    display_name: Optional[str] = None
    title: Optional[str] = None
    department: Optional[str] = None
    manager_name: Optional[str] = None
    is_active: bool
    is_vip: bool
    is_privileged: bool
    groups: List[str] = Field(default_factory=list)
    risk_score: int
    risk_factors: List[ScoreFactorOut] = Field(default_factory=list)
    exposure_count: int = 0
    last_seen_in_source_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class ExposureIdentityOut(BaseModel):
    id: int
    display_name: Optional[str] = None
    title: Optional[str] = None
    department: Optional[str] = None
    is_active: bool
    is_privileged: bool
    risk_score: int


class ExposureOut(BaseModel):
    id: int
    identifier: str
    provider: str
    source_type: str
    source_name: Optional[str] = None
    credential_type: str
    data_classes: List[str] = Field(default_factory=list)
    affected_url: Optional[str] = None
    affected_host: Optional[str] = None
    asset_id: Optional[int] = None
    leak_date: Optional[datetime] = None
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    priority_score: int
    severity: str
    score_factors: List[ScoreFactorOut] = Field(default_factory=list)
    status: str
    identity: Optional[ExposureIdentityOut] = None


class Page(BaseModel):
    total: int
    items: List[Any]


class ExposureStatusUpdate(BaseModel):
    status: str


class SyncStatusOut(BaseModel):
    source: str
    configured: bool
    running: bool = False
    last_sync_started_at: Optional[datetime] = None
    last_sync_at: Optional[datetime] = None
    last_sync_ok: Optional[bool] = None
    last_sync_stats: Optional[dict] = None
    last_error: Optional[str] = None


def _exposure_out(e: CredentialExposure) -> ExposureOut:
    ident = e.identity
    return ExposureOut(
        id=e.id,
        identifier=e.identifier,
        provider=e.provider,
        source_type=e.source_type,
        source_name=e.source_name,
        credential_type=e.credential_type,
        data_classes=e.data_classes or [],
        affected_url=e.affected_url,
        affected_host=e.affected_host,
        asset_id=e.asset_id,
        leak_date=e.leak_date,
        first_seen_at=e.first_seen_at,
        last_seen_at=e.last_seen_at,
        priority_score=e.priority_score,
        severity=e.severity,
        score_factors=e.score_factors or [],
        status=e.status,
        identity=ExposureIdentityOut(
            id=ident.id,
            display_name=ident.display_name,
            title=ident.title,
            department=ident.department,
            is_active=ident.is_active,
            is_privileged=ident.is_privileged,
            risk_score=ident.risk_score,
        ) if ident is not None else None,
    )


# ── Exposures ────────────────────────────────────────────────────────────────

@router.get("/exposures", response_model=Page)
def list_exposures(
    severity: Optional[str] = Query(None),
    status_filter: Optional[str] = Query("open", alias="status"),
    matched_only: bool = Query(False, description="Only exposures tied to a known identity"),
    q: Optional[str] = Query(None, max_length=200),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Exposures ordered by priority, highest first."""
    query = db.query(CredentialExposure).filter(
        CredentialExposure.organization_id == _org_id(current_user)
    )
    if severity:
        query = query.filter(CredentialExposure.severity == severity.lower())
    if status_filter:
        query = query.filter(CredentialExposure.status == status_filter)
    if matched_only:
        query = query.filter(CredentialExposure.identity_id.isnot(None))
    if q:
        like = f"%{q.lower()}%"
        query = query.filter(or_(
            CredentialExposure.identifier.like(like),
            CredentialExposure.source_name.ilike(like),
        ))
    total = query.count()
    rows = (
        query.order_by(CredentialExposure.priority_score.desc(), CredentialExposure.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return Page(total=total, items=[_exposure_out(e) for e in rows])


@router.patch("/exposures/{exposure_id}", response_model=ExposureOut)
def update_exposure_status(
    exposure_id: int,
    payload: ExposureStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    if payload.status not in EXPOSURE_STATUSES:
        raise HTTPException(
            status_code=422, detail=f"status must be one of: {', '.join(EXPOSURE_STATUSES)}"
        )
    exposure = (
        db.query(CredentialExposure)
        .filter(
            CredentialExposure.id == exposure_id,
            CredentialExposure.organization_id == _org_id(current_user),
        )
        .first()
    )
    if exposure is None:
        raise HTTPException(status_code=404, detail="Exposure not found.")
    exposure.status = payload.status
    db.commit()
    db.refresh(exposure)
    return _exposure_out(exposure)


@router.post("/rescore")
def rescore(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    count = rescore_organization(db, _org_id(current_user))
    db.commit()
    return {"rescored": count}


# ── Identities ───────────────────────────────────────────────────────────────

@router.get("/identities", response_model=Page)
def list_identities(
    min_score: int = Query(0, ge=0, le=100),
    privileged_only: bool = Query(False),
    exposed_only: bool = Query(False),
    q: Optional[str] = Query(None, max_length=200),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _org_id(current_user)
    query = db.query(Identity).filter(
        Identity.organization_id == org_id, Identity.risk_score >= min_score
    )
    if privileged_only:
        query = query.filter(Identity.is_privileged.is_(True))
    if exposed_only:
        query = query.filter(Identity.exposures.any())
    if q:
        like = f"%{q.lower()}%"
        query = query.filter(or_(
            Identity.email.like(like),
            Identity.username.like(like),
            Identity.display_name.ilike(like),
            Identity.title.ilike(like),
        ))
    total = query.count()
    rows = (
        query.order_by(Identity.risk_score.desc(), Identity.id)
        .offset(offset)
        .limit(limit)
        .all()
    )
    counts = dict(
        db.query(CredentialExposure.identity_id, func.count(CredentialExposure.id))
        .filter(
            CredentialExposure.organization_id == org_id,
            CredentialExposure.identity_id.in_([r.id for r in rows] or [-1]),
        )
        .group_by(CredentialExposure.identity_id)
        .all()
    )
    items = []
    for r in rows:
        out = IdentityOut.model_validate(r)
        out.exposure_count = int(counts.get(r.id, 0))
        items.append(out)
    return Page(total=total, items=items)


@router.get("/identities/sync", response_model=List[SyncStatusOut])
def identity_sync_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _org_id(current_user)
    configured = (
        db.query(ServiceNowIntegration)
        .filter(ServiceNowIntegration.organization_id == org_id)
        .first()
        is not None
    )
    row = (
        db.query(IdentitySourceSync)
        .filter(
            IdentitySourceSync.organization_id == org_id,
            IdentitySourceSync.source == IDENTITY_SOURCE_SERVICENOW,
        )
        .first()
    )
    out = SyncStatusOut(source=IDENTITY_SOURCE_SERVICENOW, configured=configured)
    if row is not None:
        for field in ("running", "last_sync_started_at", "last_sync_at", "last_sync_ok",
                      "last_sync_stats", "last_error"):
            setattr(out, field, getattr(row, field))
    return [out]


@router.post("/identities/sync/servicenow", status_code=status.HTTP_202_ACCEPTED)
def start_servicenow_identity_sync(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Pull ServiceNow sys_user in the background; poll GET /identities/sync."""
    org_id = _org_id(current_user)
    integration = (
        db.query(ServiceNowIntegration)
        .filter(ServiceNowIntegration.organization_id == org_id)
        .first()
    )
    if integration is None or not integration.is_active:
        raise HTTPException(status_code=400, detail="No active ServiceNow integration is configured.")
    if not identity_sync_service.claim_sync(db, org_id, IDENTITY_SOURCE_SERVICENOW):
        raise HTTPException(status_code=409, detail="An identity sync is already running.")
    background_tasks.add_task(_bg_servicenow_sync, org_id)
    return {"started": True}


async def _bg_servicenow_sync(organization_id: int) -> None:
    from app.db.database import SessionLocal

    db = SessionLocal()
    try:
        await identity_sync_service.sync_servicenow_identities(db, organization_id)
    except Exception as exc:  # noqa: BLE001 — recorded on the sync row
        logger.error("ServiceNow identity sync failed for org %s: %s", organization_id, exc)
    finally:
        db.close()
