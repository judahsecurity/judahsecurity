"""Fix pull requests for independently verified findings."""

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user, require_analyst
from app.db.database import get_db
from app.models.asset import Asset
from app.models.fix_request import FixRequest
from app.models.user import User
from app.models.vulnerability import Vulnerability

router = APIRouter(tags=["Fix PRs"])


class FixPrRequest(BaseModel):
    repository: str = Field(min_length=3, max_length=200, description="owner/name")
    base_branch: str = Field(default="", max_length=200)
    file_paths: List[str] = Field(default_factory=list, max_length=5,
                                  description="Source files to fix; defaults to files linked by PR checks")


class FixPreviewUpdate(BaseModel):
    preview_origin: str = Field(min_length=8, max_length=300)


def _user_org(user: User) -> Optional[int]:
    return getattr(user, "organization_id", None)


def _vulnerability_for(db: Session, vuln_id: int, user: User) -> tuple:
    vulnerability = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    asset = db.query(Asset).filter(Asset.id == vulnerability.asset_id).first() if vulnerability else None
    if not vulnerability or not asset:
        raise HTTPException(status_code=404, detail="Finding not found")
    if not getattr(user, "is_superuser", False) and asset.organization_id != _user_org(user):
        raise HTTPException(status_code=404, detail="Finding not found")
    return vulnerability, asset


def _fix_for(db: Session, fix_id: str, user: User) -> FixRequest:
    fix = db.query(FixRequest).filter(FixRequest.id == fix_id).first()
    if not fix or (not getattr(user, "is_superuser", False) and fix.organization_id != _user_org(user)):
        raise HTTPException(status_code=404, detail="Fix request not found")
    return fix


def serialize_fix(fix: FixRequest) -> dict:
    return {
        "id": fix.id, "vulnerability_id": fix.vulnerability_id, "repository": fix.repository,
        "base_branch": fix.base_branch, "branch": fix.branch, "pr_number": fix.pr_number,
        "pr_url": fix.pr_url, "status": fix.status, "files": fix.files or [],
        "summary": fix.summary, "preview_origin": fix.preview_origin,
        "verification": fix.verification or {},
        "created_at": fix.created_at.isoformat() if fix.created_at else None,
    }


@router.post("/vulnerabilities/{vuln_id}/fix-pr", status_code=201)
async def create_fix_pr(
    vuln_id: int,
    request: FixPrRequest,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    """Ask the fixer model for a minimal patch and open it as a draft PR."""
    from app.core.config import settings
    from app.models.pr_check import PrCheck
    from app.services.agent.model_router import LLMTask, get_llm_for_task
    from app.services.fix_pr_service import FixError, is_eligible, open_fix_pr, resolve_github_token
    from app.services.github_client import GitHubClient, GitHubError

    vulnerability, asset = _vulnerability_for(db, vuln_id, current_user)
    reason = is_eligible(vulnerability)
    if reason:
        raise HTTPException(status_code=409, detail=reason)
    token = resolve_github_token(db, asset.organization_id)
    if not token:
        raise HTTPException(status_code=400, detail="Add a GitHub token (service 'github') in Settings first")
    checks = (db.query(PrCheck).filter(PrCheck.organization_id == asset.organization_id,
                                       PrCheck.asset_id == asset.id)
              .order_by(PrCheck.created_at.desc()).limit(10).all())
    llm = get_llm_for_task(db, asset.organization_id, LLMTask.REASONING, max_tokens=16000)
    try:
        async with GitHubClient(token, api_url=settings.GITHUB_API_URL) as github:
            fix = await open_fix_pr(
                db=db, vulnerability=vulnerability, organization_id=asset.organization_id,
                user_id=current_user.id, repository=request.repository, llm=llm, github=github,
                base_branch=request.base_branch, file_paths=request.file_paths, pr_checks=checks,
            )
    except FixError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc))
    except GitHubError as exc:
        db.rollback()
        raise HTTPException(status_code=502, detail=str(exc))
    return serialize_fix(fix)


@router.get("/fix-requests")
def list_fix_requests(
    vulnerability_id: Optional[int] = None,
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    query = db.query(FixRequest).filter(FixRequest.organization_id == _user_org(current_user))
    if vulnerability_id:
        query = query.filter(FixRequest.vulnerability_id == vulnerability_id)
    return {"fix_requests": [serialize_fix(f) for f in
                             query.order_by(FixRequest.created_at.desc()).limit(limit).all()]}


@router.get("/fix-requests/{fix_id}")
def get_fix_request(fix_id: str, current_user: User = Depends(get_current_active_user),
                    db: Session = Depends(get_db)):
    return serialize_fix(_fix_for(db, fix_id, current_user))


@router.put("/fix-requests/{fix_id}/preview")
def set_fix_preview(
    fix_id: str,
    body: FixPreviewUpdate,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    """Record the PR's preview deployment; Prowl re-runs the proof there."""
    from app.services.api_spec_import import normalize_origin

    fix = _fix_for(db, fix_id, current_user)
    origin = normalize_origin(body.preview_origin)
    if not origin:
        raise HTTPException(status_code=400, detail="preview_origin must be an exact http(s) origin")
    fix.preview_origin = origin
    if fix.status in ("verified_fixed", "fix_ineffective"):
        fix.status, fix.verification = "pr_open", {}
    db.commit()
    return {**serialize_fix(fix),
            "next_step": "Start a Prowl session on the preview origin (add it to the RoE) and call verify_fix"}
