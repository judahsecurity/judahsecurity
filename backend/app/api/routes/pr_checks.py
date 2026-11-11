"""Pull-request security checks called from CI with an org agent API key."""

from __future__ import annotations

import uuid
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user
from app.api.routes.ingestion import get_agent_key
from app.db.database import get_db
from app.models.agent_api_key import AgentAPIKey
from app.models.asset import Asset
from app.models.pr_check import PrCheck
from app.models.user import User

router = APIRouter(prefix="/pr-checks", tags=["PR checks"])

PR_CHECK_SCOPE = "pr:check"


class ChangedFileIn(BaseModel):
    path: str = Field(min_length=1, max_length=300)
    content: str = Field(max_length=300_000)
    patch: Optional[str] = Field(default=None, max_length=600_000)


class PrCheckRequest(BaseModel):
    repository: str = Field(default="", max_length=200)
    pull_request: Optional[int] = Field(default=None, ge=1)
    head_sha: str = Field(default="", max_length=64)
    base_sha: str = Field(default="", max_length=64)
    asset_id: Optional[int] = Field(default=None, ge=1,
                                    description="Asset whose live origin Prowl should test with these routes")
    fail_on: Literal["info", "low", "medium", "high", "critical", "never"] = "medium"
    files: List[ChangedFileIn] = Field(default_factory=list, max_length=400)


def require_pr_check_key(agent_key: AgentAPIKey = Depends(get_agent_key)) -> AgentAPIKey:
    """Unlike ingestion keys, an empty scope list does not grant PR checks."""
    if PR_CHECK_SCOPE not in (agent_key.scopes or []):
        raise HTTPException(status_code=403, detail=f"API key lacks required scope: {PR_CHECK_SCOPE}")
    return agent_key


def _serialize(check: PrCheck, *, include_detail: bool = True) -> dict:
    out = {
        "id": check.id, "repository": check.repository, "pull_request": check.pull_request,
        "head_sha": check.head_sha, "base_sha": check.base_sha, "asset_id": check.asset_id,
        "conclusion": check.conclusion, "fail_on": check.fail_on, "summary": check.summary or {},
        "created_at": check.created_at.isoformat() if check.created_at else None,
    }
    if include_detail:
        out["findings"] = check.findings or []
        out["routes"] = check.routes or []
    return out


@router.post("", status_code=201)
def create_pr_check(
    request: PrCheckRequest,
    agent_key: AgentAPIKey = Depends(require_pr_check_key),
    db: Session = Depends(get_db),
):
    """Analyze changed files; return advisory findings, routes and a CI conclusion.

    Sends no traffic to any target. With ``asset_id`` the extracted routes are
    stored for Prowl's ``import_source_routes`` live handoff.
    """
    from app.services.pr_check_service import analyze

    org_id = agent_key.organization_id
    if request.asset_id is not None:
        asset = db.query(Asset).filter(Asset.id == request.asset_id,
                                       Asset.organization_id == org_id).first()
        if asset is None:
            raise HTTPException(status_code=404, detail="Asset not found for this key's organization")
    result = analyze([f.model_dump() for f in request.files])
    conclusion = result.conclusion(request.fail_on)
    check = PrCheck(
        id=uuid.uuid4().hex, organization_id=org_id, asset_id=request.asset_id,
        agent_key_id=agent_key.key_id, repository=request.repository,
        pull_request=request.pull_request, head_sha=request.head_sha,
        base_sha=request.base_sha, conclusion=conclusion, fail_on=request.fail_on,
        findings=result.findings, routes=result.routes,
        summary={**result.summary(), "skipped": result.skipped_files[:50]},
    )
    db.add(check)
    db.commit()
    body = _serialize(check)
    body["next_step"] = (
        "In a Prowl session on this asset, call import_source_routes to test these routes live."
        if request.asset_id else
        "Pass asset_id to hand these routes to Prowl for live testing."
    )
    return body


@router.get("")
def list_pr_checks(
    asset_id: Optional[int] = None,
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    org_id = getattr(current_user, "organization_id", None)
    if not org_id:
        raise HTTPException(status_code=400, detail="User must belong to an organization")
    query = db.query(PrCheck).filter(PrCheck.organization_id == org_id)
    if asset_id:
        query = query.filter(PrCheck.asset_id == asset_id)
    rows = query.order_by(PrCheck.created_at.desc()).limit(limit).all()
    return {"checks": [_serialize(row, include_detail=False) for row in rows]}


@router.get("/{check_id}")
def get_pr_check(
    check_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    check = db.query(PrCheck).filter(PrCheck.id == check_id).first()
    if check is None or check.organization_id != getattr(current_user, "organization_id", None):
        raise HTTPException(status_code=404, detail="PR check not found")
    return _serialize(check)
