"""
Recon job queue + worker presence for dual Interceptor (Mac + Ubuntu).

Preference order for execute_interceptor:
  1. Online Mac worker
  2. Online Ubuntu worker
  3. Local interceptor binary (if present)
  4. Playwright deep_crawl fallback

Jobs are persisted in Postgres (recon_jobs) with an in-memory index for
fast claim/wait within a single API worker process.
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from app.db.database import SessionLocal
from app.models.recon_job import ReconJob, ReconWorkerHeartbeat

logger = logging.getLogger(__name__)

WORKER_KINDS = ("mac", "ubuntu")
DEFAULT_PREFER = ["mac", "ubuntu"]
HEARTBEAT_TTL_SEC = int(os.environ.get("INTERCEPTOR_WORKER_HEARTBEAT_TTL_SEC", "90"))
JOB_TIMEOUT_SEC = int(os.environ.get("RECON_JOB_TIMEOUT_SEC", "900"))
WORKER_TOKEN_ENV = "INTERCEPTOR_WORKER_TOKEN"

_lock = threading.RLock()
_waiters: Dict[str, List[asyncio.Future]] = {}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def worker_token_ok(token: Optional[str]) -> bool:
    expected = (os.environ.get(WORKER_TOKEN_ENV) or "").strip()
    if not expected:
        # No shared worker secret configured — rely on analyst JWT instead.
        return False
    return (token or "").strip() == expected


def get_worker_token_from_header(authorization: Optional[str], x_worker_token: Optional[str]) -> Optional[str]:
    if x_worker_token and x_worker_token.strip():
        return x_worker_token.strip()
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return None


@dataclass
class JobView:
    id: str
    url: str
    status: str
    organization_id: Optional[int] = None
    session_id: Optional[str] = None
    scope: Optional[str] = None
    max_pages: int = 20
    interact: bool = True
    prefer: List[str] = field(default_factory=lambda: list(DEFAULT_PREFER))
    opts: Dict[str, Any] = field(default_factory=dict)
    worker_kind: Optional[str] = None
    worker_id: Optional[str] = None
    error: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    created_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "url": self.url,
            "status": self.status,
            "organization_id": self.organization_id,
            "session_id": self.session_id,
            "scope": self.scope,
            "max_pages": self.max_pages,
            "interact": self.interact,
            "prefer": self.prefer,
            "opts": self.opts,
            "worker_kind": self.worker_kind,
            "worker_id": self.worker_id,
            "error": self.error,
            "result": self.result,
            "created_at": self.created_at,
        }


def _row_to_view(row: ReconJob) -> JobView:
    return JobView(
        id=row.id,
        url=row.url,
        status=row.status or "queued",
        organization_id=row.organization_id,
        session_id=row.session_id,
        scope=row.scope,
        max_pages=int(row.max_pages or 20),
        interact=bool(row.interact),
        prefer=list(row.prefer or DEFAULT_PREFER),
        opts=dict(row.opts or {}),
        worker_kind=row.worker_kind,
        worker_id=row.worker_id,
        error=row.error,
        result=row.result if isinstance(row.result, dict) else None,
        created_at=row.created_at.isoformat() + "Z" if row.created_at else None,
    )


def create_job(
    *,
    url: str,
    organization_id: Optional[int] = None,
    session_id: Optional[str] = None,
    scope: Optional[str] = None,
    max_pages: int = 20,
    interact: bool = True,
    prefer: Optional[Sequence[str]] = None,
    opts: Optional[Dict[str, Any]] = None,
    created_by_user_id: Optional[int] = None,
) -> JobView:
    prefer_list = [p for p in (prefer or DEFAULT_PREFER) if p in WORKER_KINDS]
    if not prefer_list:
        prefer_list = list(DEFAULT_PREFER)
    job_id = str(uuid.uuid4())
    db = SessionLocal()
    try:
        row = ReconJob(
            id=job_id,
            organization_id=organization_id,
            session_id=session_id,
            url=url,
            scope=scope,
            max_pages=max_pages,
            interact=1 if interact else 0,
            prefer=prefer_list,
            opts=opts or {},
            status="queued",
            created_by_user_id=created_by_user_id,
            created_at=_utcnow(),
            updated_at=_utcnow(),
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return _row_to_view(row)
    finally:
        db.close()


def get_job(job_id: str) -> Optional[JobView]:
    db = SessionLocal()
    try:
        row = db.query(ReconJob).filter(ReconJob.id == job_id).first()
        return _row_to_view(row) if row else None
    finally:
        db.close()


def record_heartbeat(
    *,
    worker_id: str,
    worker_kind: str,
    hostname: Optional[str] = None,
    meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if worker_kind not in WORKER_KINDS:
        raise ValueError(f"worker_kind must be one of {WORKER_KINDS}")
    db = SessionLocal()
    try:
        row = db.query(ReconWorkerHeartbeat).filter(
            ReconWorkerHeartbeat.worker_id == worker_id
        ).first()
        now = _utcnow()
        if row:
            row.worker_kind = worker_kind
            row.hostname = hostname
            row.meta = meta or {}
            row.last_seen = now
        else:
            row = ReconWorkerHeartbeat(
                worker_id=worker_id,
                worker_kind=worker_kind,
                hostname=hostname,
                meta=meta or {},
                last_seen=now,
                created_at=now,
            )
            db.add(row)
        db.commit()
        return {
            "worker_id": worker_id,
            "worker_kind": worker_kind,
            "hostname": hostname,
            "last_seen": now.isoformat() + "Z",
            "online": True,
        }
    finally:
        db.close()


def list_online_workers(ttl_sec: int = HEARTBEAT_TTL_SEC) -> List[Dict[str, Any]]:
    cutoff = time.time() - ttl_sec
    db = SessionLocal()
    try:
        rows = db.query(ReconWorkerHeartbeat).all()
        out = []
        for r in rows:
            ts = r.last_seen.timestamp() if r.last_seen else 0
            online = ts >= cutoff
            out.append({
                "worker_id": r.worker_id,
                "worker_kind": r.worker_kind,
                "hostname": r.hostname,
                "meta": r.meta or {},
                "last_seen": r.last_seen.isoformat() + "Z" if r.last_seen else None,
                "online": online,
            })
        return out
    finally:
        db.close()


def online_kinds(ttl_sec: int = HEARTBEAT_TTL_SEC) -> List[str]:
    kinds = []
    for w in list_online_workers(ttl_sec):
        if w.get("online") and w.get("worker_kind") in WORKER_KINDS:
            if w["worker_kind"] not in kinds:
                kinds.append(w["worker_kind"])
    # Stable preference: mac before ubuntu
    return [k for k in DEFAULT_PREFER if k in kinds]


def claim_next_job(
    *,
    worker_kind: str,
    worker_id: str,
) -> Optional[JobView]:
    if worker_kind not in WORKER_KINDS:
        raise ValueError(f"worker_kind must be one of {WORKER_KINDS}")
    db = SessionLocal()
    try:
        # Prefer jobs that list this kind first in prefer order.
        candidates = (
            db.query(ReconJob)
            .filter(ReconJob.status == "queued")
            .order_by(ReconJob.created_at.asc())
            .limit(50)
            .all()
        )
        online = online_kinds()
        chosen = None
        for row in candidates:
            prefer = list(row.prefer or DEFAULT_PREFER)
            if worker_kind not in prefer:
                continue
            # Leave the job for a higher-preference online worker when present.
            top_online = next((p for p in prefer if p in online), None)
            if top_online is not None and top_online != worker_kind:
                continue
            chosen = row
            break
        if not chosen:
            return None
        chosen.status = "claimed"
        chosen.worker_kind = worker_kind
        chosen.worker_id = worker_id
        chosen.claimed_at = _utcnow()
        chosen.updated_at = _utcnow()
        db.commit()
        db.refresh(chosen)
        return _row_to_view(chosen)
    finally:
        db.close()


def mark_running(job_id: str) -> Optional[JobView]:
    db = SessionLocal()
    try:
        row = db.query(ReconJob).filter(ReconJob.id == job_id).first()
        if not row:
            return None
        row.status = "running"
        row.updated_at = _utcnow()
        db.commit()
        db.refresh(row)
        _notify_waiters(job_id)
        return _row_to_view(row)
    finally:
        db.close()


def complete_job(
    job_id: str,
    *,
    success: bool,
    result: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
) -> Optional[JobView]:
    db = SessionLocal()
    try:
        row = db.query(ReconJob).filter(ReconJob.id == job_id).first()
        if not row:
            return None
        row.status = "completed" if success else "failed"
        row.result = result or {}
        row.error = error
        row.completed_at = _utcnow()
        row.updated_at = _utcnow()
        db.commit()
        db.refresh(row)
        view = _row_to_view(row)
        _notify_waiters(job_id)
        return view
    finally:
        db.close()


def _notify_waiters(job_id: str) -> None:
    with _lock:
        futs = _waiters.pop(job_id, [])
    for fut in futs:
        if not fut.done():
            try:
                loop = fut.get_loop()
                loop.call_soon_threadsafe(fut.set_result, True)
            except Exception:
                try:
                    fut.set_result(True)
                except Exception:
                    pass


async def wait_for_job(
    job_id: str,
    *,
    timeout_sec: float = JOB_TIMEOUT_SEC,
    poll_sec: float = 2.0,
    on_progress: Optional[Any] = None,
) -> JobView:
    """Block until job completes/fails or timeout. Optionally call on_progress(view)."""
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        view = get_job(job_id)
        if not view:
            raise KeyError(f"job {job_id} not found")
        if on_progress:
            try:
                maybe = on_progress(view)
                if asyncio.iscoroutine(maybe):
                    await maybe
            except Exception:
                pass
        if view.status in ("completed", "failed", "cancelled"):
            return view
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        with _lock:
            _waiters.setdefault(job_id, []).append(fut)
        try:
            await asyncio.wait_for(fut, timeout=poll_sec)
        except asyncio.TimeoutError:
            pass
        finally:
            with _lock:
                lst = _waiters.get(job_id) or []
                if fut in lst:
                    lst.remove(fut)
                if not lst and job_id in _waiters:
                    del _waiters[job_id]
    view = get_job(job_id)
    if view and view.status in ("completed", "failed", "cancelled"):
        return view
    # Timeout — mark failed so workers don't keep it forever if still queued
    complete_job(job_id, success=False, error="job_timeout", result={"error": "job_timeout"})
    raise TimeoutError(f"recon job {job_id} timed out after {timeout_sec}s")


def envelope_from_normalized(
    normalized: Dict[str, Any],
    *,
    auth_session: Optional[Dict[str, Any]] = None,
    note: Optional[str] = None,
) -> Dict[str, Any]:
    """Build the agent tool envelope (capability_map + auth_session) from normalised recon."""
    from app.services.recon_envelope import envelope_from_normalized as _build

    return _build(normalized, auth_session=auth_session, note=note)


async def notify_session_ws(session_id: Optional[str], message: Dict[str, Any]) -> None:
    if not session_id:
        return
    try:
        from app.api.routes.agent import ws_manager

        await ws_manager.send_message(session_id, message)
    except Exception as e:
        logger.debug("ws notify failed: %s", e)


async def push_map_updates(
    session_id: Optional[str],
    envelope: Dict[str, Any],
) -> None:
    """Push capability_map / auth_session WS events for a live agent session."""
    if not session_id:
        return
    cmap = envelope.get("capability_map") or {}
    if cmap:
        await notify_session_ws(session_id, {
            "type": "capability_map_update",
            "quality_score": cmap.get("quality_score"),
            "ready_for_attack": cmap.get("ready_for_attack"),
            "capabilities": cmap.get("capabilities", []),
            "ranked_hunt_queue": (cmap.get("ranked_hunt_queue") or [])[:8],
            "authenticated": cmap.get("authenticated"),
            "api_sample_count": len(cmap.get("api_samples") or []),
        })
    auth = envelope.get("auth_session")
    if isinstance(auth, dict):
        await notify_session_ws(session_id, {
            "type": "auth_session_update",
            "authenticated": auth.get("authenticated"),
            "cookie_count": len(auth.get("cookies") or []),
            "target": auth.get("target"),
        })
