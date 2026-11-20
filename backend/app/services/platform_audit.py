"""Platform audit log: record people's actions, never break the caller.

The agent's own actions are in ``action_ledger``; this log answers "who
logged in, changed settings, approved a tool call, exported a report or
managed users". Details are redacted (secret-looking keys and values) and
capped; rows older than ``AUDIT_RETENTION_DAYS`` are pruned.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

MAX_DETAIL_BYTES = 8192
_PRUNE_EVERY_SECONDS = 3600
_last_prune = 0.0
_prune_lock = threading.Lock()


def _actor(user: Any) -> str:
    if user is None:
        return ""
    return str(getattr(user, "email", "") or getattr(user, "username", "") or "")[:255]


def _client(request: Any) -> tuple:
    if request is None:
        return "", ""
    ip = ""
    try:
        forwarded = request.headers.get("x-forwarded-for") or ""
        ip = forwarded.split(",")[0].strip() or (request.client.host if request.client else "")
    except Exception:
        pass
    try:
        agent = request.headers.get("user-agent") or ""
    except Exception:
        agent = ""
    return ip[:64], agent[:255]


def _safe_detail(detail: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not detail:
        return {}
    from app.services.agent.observability import redact_value

    redacted = redact_value(detail)
    encoded = json.dumps(redacted, default=str)
    if len(encoded) > MAX_DETAIL_BYTES:
        return {"truncated": True, "preview": encoded[:MAX_DETAIL_BYTES - 200]}
    return json.loads(encoded)


def record(
    action: str,
    *,
    user: Any = None,
    organization_id: Optional[int] = None,
    target: str = "",
    outcome: str = "success",
    request: Any = None,
    detail: Optional[Dict[str, Any]] = None,
    actor: Optional[str] = None,
    db_factory=None,
) -> None:
    """Write one audit row in its own transaction. Never raises."""
    try:
        from app.core.config import settings

        if not getattr(settings, "AUDIT_ENABLED", True):
            return
        from app.models.platform_audit import PlatformAuditLog

        if db_factory is None:
            from app.db.database import SessionLocal as db_factory  # noqa: N813
        ip, agent = _client(request)
        org = organization_id if organization_id is not None else getattr(user, "organization_id", None)
        with db_factory() as db:
            db.add(PlatformAuditLog(
                organization_id=org,
                user_id=getattr(user, "id", None),
                actor=(actor if actor is not None else _actor(user))[:255],
                action=action[:64],
                target=str(target or "")[:512],
                outcome=outcome[:16],
                ip=ip,
                user_agent=agent,
                detail=_safe_detail(detail),
            ))
            db.commit()
        _maybe_prune(db_factory)
    except Exception:
        logger.exception("Audit record failed for %s", action)


def _maybe_prune(db_factory) -> None:
    global _last_prune
    now = time.monotonic()
    if now - _last_prune < _PRUNE_EVERY_SECONDS:
        return
    with _prune_lock:
        if now - _last_prune < _PRUNE_EVERY_SECONDS:
            return
        _last_prune = now
    prune(db_factory)


def prune(db_factory=None) -> int:
    from app.core.config import settings
    from app.models.platform_audit import PlatformAuditLog

    days = int(getattr(settings, "AUDIT_RETENTION_DAYS", 365) or 0)
    if days <= 0:
        return 0
    if db_factory is None:
        from app.db.database import SessionLocal as db_factory  # noqa: N813
    cutoff = datetime.utcnow() - timedelta(days=days)
    with db_factory() as db:
        removed = db.query(PlatformAuditLog).filter(
            PlatformAuditLog.created_at < cutoff).delete(synchronize_session=False)
        db.commit()
    return int(removed or 0)
