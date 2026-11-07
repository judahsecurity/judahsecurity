"""Recorded traffic: search, detail, extension ingest, and finding bindings."""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user, require_analyst
from app.api.routes.ingestion import require_scope
from app.db.database import get_db
from app.models.agent_api_key import AgentAPIKey
from app.models.asset import Asset
from app.models.traffic import TrafficExchange, VulnerabilityTrafficRef
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.services import traffic_recorder

router = APIRouter(tags=["Traffic"])


def _org_id(user: User, organization_id: Optional[int]) -> int:
    if organization_id is not None and user.is_superuser:
        return organization_id
    if not user.organization_id:
        raise HTTPException(status_code=400, detail="User has no organization")
    return user.organization_id


def _vuln_for_user(db: Session, vuln_id: int, user: User) -> tuple[Vulnerability, int]:
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    asset = db.query(Asset).filter(Asset.id == vuln.asset_id).first()
    org_id = asset.organization_id if asset else None
    if not org_id or (not user.is_superuser and user.organization_id != org_id):
        raise HTTPException(status_code=403, detail="Access denied")
    return vuln, org_id


@router.get("/traffic")
def list_traffic(
    q: str = Query("", max_length=200),
    host: str = Query("", max_length=255),
    method: str = Query("", max_length=16),
    status_code: Optional[int] = None,
    source: str = Query("", pattern="^(|agent|extension)$"),
    session_id: str = Query("", max_length=64),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    organization_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    org_id = _org_id(current_user, organization_id)
    total, rows = traffic_recorder.search(
        db, org_id, q=q, host=host, method=method, status_code=status_code,
        source=source, session_id=session_id, limit=limit, offset=offset,
    )
    return {"total": total, "items": [traffic_recorder.summary(r) for r in rows]}


@router.get("/traffic/{traffic_id}")
def get_traffic(
    traffic_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    row = db.query(TrafficExchange).filter(TrafficExchange.id == traffic_id).first()
    if not row or (not current_user.is_superuser and row.organization_id != current_user.organization_id):
        raise HTTPException(status_code=404, detail="Exchange not found")
    return traffic_recorder.detail(row)


class ExtensionEntry(BaseModel):
    method: str = Field("GET", max_length=16)
    url: str = Field(..., max_length=8000)
    status: Optional[int] = None
    request_headers: Optional[object] = None
    request_body: Optional[str] = None
    response_headers: Optional[object] = None
    response_body: Optional[str] = None
    elapsed_ms: Optional[int] = None
    page_url: Optional[str] = Field(None, max_length=8000)


class ExtensionBatch(BaseModel):
    capture_id: str = Field(..., min_length=8, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    entries: List[ExtensionEntry] = Field(..., max_length=traffic_recorder.MAX_EXTENSION_BATCH)


@router.post("/traffic/ingest")
def ingest_extension_traffic(
    batch: ExtensionBatch,
    agent_key: AgentAPIKey = Depends(require_scope("ingest:traffic")),
    db: Session = Depends(get_db),
):
    """Browser-extension upload. Out-of-scope hosts are rejected per entry."""
    return traffic_recorder.ingest_extension_batch(
        db,
        organization_id=agent_key.organization_id,
        agent_key_id=agent_key.id,
        capture_id=batch.capture_id,
        entries=[e.model_dump() for e in batch.entries],
    )


@router.get("/vulnerabilities/{vuln_id}/traffic")
def list_vulnerability_traffic(
    vuln_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    _, org_id = _vuln_for_user(db, vuln_id, current_user)
    return {"items": traffic_recorder.traffic_for_vulnerability(db, vuln_id, org_id)}


class BindRequest(BaseModel):
    traffic_id: int
    note: Optional[str] = Field(None, max_length=500)


@router.post("/vulnerabilities/{vuln_id}/traffic", status_code=status.HTTP_201_CREATED)
def bind_vulnerability_traffic(
    vuln_id: int,
    body: BindRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    _, org_id = _vuln_for_user(db, vuln_id, current_user)
    row = db.query(TrafficExchange).filter(
        TrafficExchange.id == body.traffic_id, TrafficExchange.organization_id == org_id,
    ).first()
    if not row:
        raise HTTPException(status_code=404, detail="Exchange not found")
    duplicate = db.query(VulnerabilityTrafficRef).filter(
        VulnerabilityTrafficRef.vulnerability_id == vuln_id,
        VulnerabilityTrafficRef.traffic_id == row.id,
    ).first()
    if duplicate:
        return {"ref_id": duplicate.id}
    last = db.query(VulnerabilityTrafficRef.position).filter(
        VulnerabilityTrafficRef.vulnerability_id == vuln_id,
    ).order_by(VulnerabilityTrafficRef.position.desc()).first()
    ref = VulnerabilityTrafficRef(
        vulnerability_id=vuln_id, organization_id=org_id, traffic_id=row.id,
        artifact_id=row.artifact_id, position=(last[0] + 1) if last else 0,
        note=body.note, bound_by="user", bound_by_user_id=current_user.id,
    )
    db.add(ref)
    db.commit()
    return {"ref_id": ref.id}


@router.delete("/vulnerabilities/{vuln_id}/traffic/{ref_id}", status_code=status.HTTP_204_NO_CONTENT)
def unbind_vulnerability_traffic(
    vuln_id: int,
    ref_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    _vuln_for_user(db, vuln_id, current_user)
    ref = db.query(VulnerabilityTrafficRef).filter(
        VulnerabilityTrafficRef.id == ref_id, VulnerabilityTrafficRef.vulnerability_id == vuln_id,
    ).first()
    if not ref:
        raise HTTPException(status_code=404, detail="Binding not found")
    db.delete(ref)
    db.commit()
