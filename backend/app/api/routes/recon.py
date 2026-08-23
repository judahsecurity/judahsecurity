"""
Recon bridge API.

Lets out-of-harness Interceptor workers (Mac desktop / Ubuntu browser host)
POST normalised crawl results and claim jobs from a queue. Completion builds a
capability_map (+ optional auth_session) and pushes live WS updates into the
agent session when ``session_id`` is present.

Also keeps the legacy one-shot ingest endpoint for ``interceptor_recon --post``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from urllib.parse import urlparse

from app.db.database import get_db
from app.models.user import User
from app.models.organization import Organization
from app.models.agent_knowledge import AgentKnowledge
from app.api.deps import require_analyst, get_current_user_optional
from app.services import recon_jobs_service as jobs

router = APIRouter(tags=["Recon"])


class ReconIngest(BaseModel):
    """Normalised recon result from an external driver (Interceptor or deep_crawl)."""
    organization_id: Optional[int] = Field(
        None, description="Org to attach the recon to (None = global; superuser only)"
    )
    session_id: Optional[str] = Field(
        None, description="Live agent session to push capability_map updates into"
    )
    recon: Dict[str, Any] = Field(..., description="Normalised recon contract")
    auth_session: Optional[Dict[str, Any]] = None


class ReconIngestResponse(BaseModel):
    knowledge_id: int
    organization_id: Optional[int]
    title: str
    endpoints_ingested: int
    js_files_ingested: int
    capability_map: Optional[Dict[str, Any]] = None


class CreateReconJob(BaseModel):
    url: str
    organization_id: Optional[int] = None
    session_id: Optional[str] = None
    scope: Optional[str] = None
    max_pages: int = 20
    interact: bool = True
    prefer: Optional[List[str]] = Field(default=None, description='["mac","ubuntu"]')
    opts: Optional[Dict[str, Any]] = None


class WorkerHeartbeat(BaseModel):
    worker_id: str
    worker_kind: str  # mac | ubuntu
    hostname: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None


class CompleteJobBody(BaseModel):
    success: bool = True
    recon: Optional[Dict[str, Any]] = None
    auth_session: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    # Allow workers to send a pre-built envelope
    result: Optional[Dict[str, Any]] = None


def _check_org_access(current_user: User, org_id: Optional[int], db: Session) -> None:
    if org_id is None:
        if not getattr(current_user, "is_superuser", False):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only superusers can ingest global recon",
            )
        return
    if not current_user.is_superuser and getattr(current_user, "organization_id", None) != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized for this organization",
        )
    if not db.query(Organization).filter(Organization.id == org_id).first():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")


def _require_worker(
    authorization: Optional[str],
    x_worker_token: Optional[str],
    current_user: Optional[User],
) -> None:
    token = jobs.get_worker_token_from_header(authorization, x_worker_token)
    if jobs.worker_token_ok(token):
        return
    if current_user is not None:
        role = getattr(current_user, "role", None)
        role_val = getattr(role, "value", role)
        if getattr(current_user, "is_superuser", False) or role_val in ("admin", "analyst"):
            return
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid Interceptor worker token (set INTERCEPTOR_WORKER_TOKEN / X-Worker-Token)",
    )


def _format_recon(d: Dict[str, Any]) -> str:
    """Render the normalised recon contract into an agent-readable document."""
    lines: List[str] = []
    target = d.get("target", "")
    scope = d.get("scope", "")
    engine = d.get("engine", "unknown")
    lines.append(f"# Recon surface for {target}")
    lines.append(f"Engine: {engine}  |  Scope: {scope}")

    pages = d.get("pages_visited") or []
    lines.append(f"\n## Pages visited ({len(pages)})")
    lines += [f"- {p}" for p in pages[:40]]

    api_calls = d.get("api_calls") or {}
    total = sum(len(v) for v in api_calls.values())
    if api_calls:
        lines.append(f"\n## First-party API / XHR endpoints ({total})")
        for host in sorted(api_calls):
            lines.append(f"### {host}")
            for key in list(api_calls[host])[:150]:
                lines.append(f"- {key}")

    for label, keyname, cap in (
        ("WebSocket channels", "websockets", 40),
        ("SSE streams", "sse", 40),
        ("JavaScript files", "js_files", 120),
        ("Source maps exposed", "source_maps", 40),
        ("Endpoints from JS", "endpoints_from_js", 200),
        ("Third-party hosts", "third_party", 60),
    ):
        vals = d.get(keyname) or []
        if vals:
            lines.append(f"\n## {label} ({len(vals)})")
            lines += [f"- {v}" for v in vals[:cap]]

    auth_headers = d.get("auth_headers") or []
    if auth_headers:
        lines.append(f"\n## Auth / CSRF header surface\n- {', '.join(auth_headers)}")

    return "\n".join(lines)


def _persist_knowledge(
    db: Session,
    *,
    organization_id: Optional[int],
    recon: Dict[str, Any],
) -> AgentKnowledge:
    target = str(recon.get("target") or "").strip()
    host = urlparse(target).netloc or target
    engine = str(recon.get("engine") or "recon")
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    title = f"Recon: {host} ({engine}) {ts}"[:512]
    doc = AgentKnowledge(
        organization_id=organization_id,
        title=title,
        content=_format_recon(recon),
        tags=["recon", engine, host],
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)
    try:
        from app.services.agent.palace_memory import mine_knowledge_doc

        mine_knowledge_doc(
            organization_id=doc.organization_id,
            title=doc.title,
            content=doc.content,
            tags=doc.tags or [],
            doc_id=doc.id,
        )
    except Exception:
        pass
    return doc


@router.post("/recon/ingest", response_model=ReconIngestResponse)
async def ingest_recon(
    body: ReconIngest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Ingest a normalised recon result and persist it as agent knowledge."""
    _check_org_access(current_user, body.organization_id, db)

    recon = body.recon or {}
    target = str(recon.get("target") or "").strip()
    if not target:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="recon.target is required")

    doc = _persist_knowledge(db, organization_id=body.organization_id, recon=recon)
    api_calls = recon.get("api_calls") or {}
    endpoints_ingested = sum(len(v) for v in api_calls.values()) + len(recon.get("endpoints_from_js") or [])
    js_files_ingested = len(recon.get("js_files") or [])

    envelope = jobs.envelope_from_normalized(recon, auth_session=body.auth_session)
    await jobs.push_map_updates(body.session_id, envelope)
    try:
        from app.services.sitemap_service import persist_capability_map_safe
        persist_capability_map_safe(
            body.organization_id,
            envelope.get("capability_map"),
            source="interceptor",
            db=db,
        )
        db.commit()
    except Exception:
        pass

    return ReconIngestResponse(
        knowledge_id=doc.id,
        organization_id=doc.organization_id,
        title=doc.title,
        endpoints_ingested=endpoints_ingested,
        js_files_ingested=js_files_ingested,
        capability_map=envelope.get("capability_map"),
    )


@router.post("/recon/jobs")
def create_recon_job(
    body: CreateReconJob,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Create a crawl job for Mac/Ubuntu Interceptor workers."""
    url = (body.url or "").strip()
    if not url:
        raise HTTPException(status_code=422, detail="url is required")
    if body.organization_id is not None:
        _check_org_access(current_user, body.organization_id, db)
    view = jobs.create_job(
        url=url,
        organization_id=body.organization_id or getattr(current_user, "organization_id", None),
        session_id=body.session_id,
        scope=body.scope,
        max_pages=body.max_pages,
        interact=body.interact,
        prefer=body.prefer,
        opts=body.opts,
        created_by_user_id=getattr(current_user, "id", None),
    )
    return view.to_dict()


@router.get("/recon/jobs/next")
def next_recon_job(
    worker: str = Query(..., description="mac | ubuntu"),
    worker_id: str = Query(..., description="stable worker instance id"),
    authorization: Optional[str] = Header(None),
    x_worker_token: Optional[str] = Header(None, alias="X-Worker-Token"),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """Claim the next queued job for this worker kind (preference-aware)."""
    _require_worker(authorization, x_worker_token, current_user)
    try:
        view = jobs.claim_next_job(worker_kind=worker, worker_id=worker_id)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    if not view:
        return {"job": None}
    jobs.mark_running(view.id)
    refreshed = jobs.get_job(view.id)
    return {"job": (refreshed or view).to_dict()}


@router.get("/recon/jobs/{job_id}")
def get_recon_job(
    job_id: str,
    current_user: User = Depends(require_analyst),
):
    view = jobs.get_job(job_id)
    if not view:
        raise HTTPException(status_code=404, detail="job not found")
    return view.to_dict()


@router.post("/recon/jobs/{job_id}/complete")
async def complete_recon_job(
    job_id: str,
    body: CompleteJobBody,
    db: Session = Depends(get_db),
    authorization: Optional[str] = Header(None),
    x_worker_token: Optional[str] = Header(None, alias="X-Worker-Token"),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """Worker posts crawl results; builds capability_map and notifies the agent session."""
    _require_worker(authorization, x_worker_token, current_user)
    existing = jobs.get_job(job_id)
    if not existing:
        raise HTTPException(status_code=404, detail="job not found")

    if body.result and isinstance(body.result, dict) and body.result.get("capability_map"):
        envelope = body.result
    elif body.recon:
        envelope = jobs.envelope_from_normalized(body.recon, auth_session=body.auth_session)
    elif body.success:
        raise HTTPException(status_code=422, detail="recon or result required on success")
    else:
        envelope = {
            "success": False,
            "output": body.error or "worker reported failure",
            "error": body.error or "failed",
            "exit_code": 1,
            "capability_map": None,
            "auth_session": None,
        }

    view = jobs.complete_job(
        job_id,
        success=bool(body.success and envelope.get("success", True)),
        result=envelope,
        error=body.error or envelope.get("error"),
    )
    if not view:
        raise HTTPException(status_code=404, detail="job not found")

    recon = body.recon or (envelope.get("normalized") if isinstance(envelope.get("normalized"), dict) else None)
    if recon and body.success:
        try:
            _persist_knowledge(db, organization_id=existing.organization_id, recon=recon)
        except Exception:
            pass
        try:
            from app.services.sitemap_service import persist_capability_map_safe
            persist_capability_map_safe(
                existing.organization_id,
                envelope.get("capability_map"),
                source="interceptor",
                db=db,
            )
            db.commit()
        except Exception:
            pass

    await jobs.push_map_updates(existing.session_id, envelope)
    if existing.session_id:
        await jobs.notify_session_ws(existing.session_id, {
            "type": "thinking",
            "content": f"Interceptor worker finished job {job_id[:8]}… "
                       f"(status={view.status}, pages="
                       f"{len((recon or {}).get('pages_visited') or [])})",
        })

    return {"job": view.to_dict(), "capability_map": envelope.get("capability_map")}


@router.post("/recon/workers/heartbeat")
def worker_heartbeat(
    body: WorkerHeartbeat,
    authorization: Optional[str] = Header(None),
    x_worker_token: Optional[str] = Header(None, alias="X-Worker-Token"),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    _require_worker(authorization, x_worker_token, current_user)
    try:
        return jobs.record_heartbeat(
            worker_id=body.worker_id,
            worker_kind=body.worker_kind,
            hostname=body.hostname,
            meta=body.meta,
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e


@router.get("/recon/workers")
def list_workers(current_user: User = Depends(require_analyst)):
    workers = jobs.list_online_workers()
    return {
        "workers": workers,
        "online_kinds": jobs.online_kinds(),
        "prefer_order": list(jobs.DEFAULT_PREFER),
    }
