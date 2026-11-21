"""Platform audit log: list and CSV export (org admins; superusers across orgs)."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.db.database import get_db
from app.models.platform_audit import PlatformAuditLog
from app.models.user import User

router = APIRouter(prefix="/audit", tags=["Audit"])

EXPORT_LIMIT = 50_000


def _query(db: Session, user: User, *, organization_id: Optional[int], action: Optional[str],
           actor: Optional[str], outcome: Optional[str], since: Optional[datetime],
           until: Optional[datetime]):
    query = db.query(PlatformAuditLog)
    if user.is_superuser:
        if organization_id is not None:
            query = query.filter(PlatformAuditLog.organization_id == organization_id)
    else:
        if not user.organization_id:
            raise HTTPException(status_code=403, detail="No organization")
        if organization_id is not None and organization_id != user.organization_id:
            raise HTTPException(status_code=403, detail="Access denied")
        query = query.filter(PlatformAuditLog.organization_id == user.organization_id)
    if action:
        query = query.filter(PlatformAuditLog.action.like(action.rstrip("*") + "%"))
    if actor:
        query = query.filter(PlatformAuditLog.actor.ilike(f"%{actor}%"))
    if outcome:
        query = query.filter(PlatformAuditLog.outcome == outcome)
    if since:
        query = query.filter(PlatformAuditLog.created_at >= since)
    if until:
        query = query.filter(PlatformAuditLog.created_at <= until)
    return query.order_by(PlatformAuditLog.created_at.desc(), PlatformAuditLog.id.desc())


def _row(entry: PlatformAuditLog) -> dict:
    return {
        "id": entry.id,
        "created_at": entry.created_at.isoformat() + "Z" if entry.created_at else "",
        "organization_id": entry.organization_id,
        "user_id": entry.user_id,
        "actor": entry.actor,
        "action": entry.action,
        "target": entry.target,
        "outcome": entry.outcome,
        "ip": entry.ip,
        "user_agent": entry.user_agent,
        "detail": entry.detail or {},
    }


@router.get("/logs")
def list_audit_logs(
    organization_id: Optional[int] = None,
    action: Optional[str] = Query(None, description="Exact action or prefix with *, e.g. auth.*"),
    actor: Optional[str] = None,
    outcome: Optional[str] = Query(None, pattern="^(success|denied|failed)$"),
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    query = _query(db, current_user, organization_id=organization_id, action=action,
                   actor=actor, outcome=outcome, since=since, until=until)
    return {"total": query.count(), "items": [_row(e) for e in query.offset(offset).limit(limit)]}


@router.get("/logs/export")
def export_audit_logs(
    organization_id: Optional[int] = None,
    action: Optional[str] = None,
    actor: Optional[str] = None,
    outcome: Optional[str] = Query(None, pattern="^(success|denied|failed)$"),
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    query = _query(db, current_user, organization_id=organization_id, action=action,
                   actor=actor, outcome=outcome, since=since, until=until)
    rows = [_row(e) for e in query.limit(EXPORT_LIMIT)]
    from app.services.platform_audit import record as audit

    audit("audit.export", user=current_user, target="platform_audit_log",
          detail={"rows": len(rows), "action": action, "since": str(since or "")})
    buffer = io.StringIO()
    fields = ["created_at", "organization_id", "actor", "action", "target", "outcome", "ip",
              "user_agent", "detail"]
    writer = csv.DictWriter(buffer, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        row = {**row, "detail": json.dumps(row["detail"], default=str)}
        # Neutralize spreadsheet formulas in exported text cells.
        for key in ("actor", "target", "user_agent", "detail"):
            if str(row[key]).startswith(("=", "+", "-", "@")):
                row[key] = "'" + str(row[key])
        writer.writerow(row)
    return StreamingResponse(
        iter([buffer.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="audit_log.csv"'},
    )
