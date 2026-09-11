"""SQL-backed agent control plane.

All functions are best-effort at integration boundaries so an unavailable
telemetry table never hides a completed assessment. Explicit API operations use
the ``RuntimeStore`` methods directly and may surface database errors.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import socket
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any, Iterable, Iterator, Optional

from sqlalchemy.orm import Session

from app.db.database import SessionLocal
from app.models.agent_runtime import (
    AgentCheckpoint,
    AgentCommand,
    AgentEventRecord,
    AgentRun,
)

logger = logging.getLogger(__name__)
_MAX_EVENT_PAYLOAD_BYTES = 200_000


def worker_identity() -> str:
    return f"{socket.gethostname()}:{os.getpid()}"


@contextmanager
def _session() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _as_user_id(value: Any) -> Optional[int]:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def ensure_run(
    *,
    session_id: str,
    organization_id: int,
    user_id: Any = None,
    mode: str = "assist",
    objective: str = "",
    price_limit_usd: Optional[float] = None,
    db: Optional[Session] = None,
) -> AgentRun:
    owns = db is None
    context = _session() if owns else _borrowed(db)
    with context as session:
        run = session.query(AgentRun).filter(AgentRun.session_id == session_id).first()
        now = datetime.utcnow()
        if run is None:
            run = AgentRun(
                session_id=session_id,
                organization_id=int(organization_id),
                user_id=_as_user_id(user_id),
                status="running",
                mode=mode or "assist",
                objective=(objective or "")[:10000] or None,
                price_limit_usd=price_limit_usd,
                worker_id=worker_identity(),
                heartbeat_at=now,
                lease_expires_at=now + timedelta(seconds=90),
                started_at=now,
            )
            session.add(run)
            session.flush()
        else:
            if run.organization_id != int(organization_id):
                raise ValueError("session_id belongs to a different organization")
            requested_user = _as_user_id(user_id)
            if run.user_id is not None and requested_user is not None and run.user_id != requested_user:
                raise ValueError("session_id belongs to a different user")
            run.status = "running"
            run.worker_id = worker_identity()
            run.heartbeat_at = now
            run.lease_expires_at = now + timedelta(seconds=90)
            run.completed_at = None
            if objective:
                run.objective = objective[:10000]
            if price_limit_usd is not None:
                run.price_limit_usd = float(price_limit_usd)
            run.updated_at = now
        return run


@contextmanager
def _borrowed(db: Session) -> Iterator[Session]:
    yield db


def update_run(
    session_id: str,
    *,
    status: Optional[str] = None,
    current_phase: Optional[str] = None,
    current_step: Optional[str] = None,
    iteration_count: Optional[int] = None,
    progress: Optional[int] = None,
    cost_usd: Optional[float] = None,
    error_message: Optional[str] = None,
    completed: bool = False,
) -> bool:
    with _session() as db:
        run = db.query(AgentRun).filter(AgentRun.session_id == session_id).first()
        if run is None:
            return False
        if status is not None:
            run.status = status
        if current_phase is not None:
            run.current_phase = current_phase[:64]
        if current_step is not None:
            run.current_step = current_step[:255]
        if iteration_count is not None:
            run.iteration_count = max(0, int(iteration_count))
        if progress is not None:
            run.progress = min(100, max(0, int(progress)))
        if cost_usd is not None:
            run.cost_usd = max(0.0, float(cost_usd))
        if error_message is not None:
            run.error_message = error_message[:4000]
        run.heartbeat_at = datetime.utcnow()
        if completed:
            run.completed_at = datetime.utcnow()
            run.lease_expires_at = None
            run.worker_id = None
        return True


def append_event(event: Any) -> Optional[int]:
    """Persist an ``aegis_runtime.AgentEvent`` or equivalent mapping."""
    raw = event.to_dict() if hasattr(event, "to_dict") else dict(event)
    from app.services.agent.observability import redact_value

    payload = redact_value(dict(raw.get("payload") or {}))
    encoded_payload = json.dumps(payload, separators=(",", ":"), default=str)
    if len(encoded_payload.encode("utf-8")) > _MAX_EVENT_PAYLOAD_BYTES:
        payload = {
            "payload_truncated": True,
            "preview": encoded_payload[:_MAX_EVENT_PAYLOAD_BYTES],
        }
    created = _parse_datetime(raw.get("created_at")) or datetime.utcnow()
    with _session() as db:
        run = db.query(AgentRun).filter(AgentRun.session_id == str(raw["run_id"])).first()
        if run is None or run.organization_id != int(raw["organization_id"]):
            raise ValueError("event run/organization does not match")
        if db.query(AgentEventRecord.id).filter(
            AgentEventRecord.event_id == str(raw["event_id"])
        ).first():
            return None
        record = AgentEventRecord(
            event_id=str(raw["event_id"]),
            run_id=str(raw["run_id"]),
            organization_id=int(raw["organization_id"]),
            user_id=_text(raw.get("user_id"), 64),
            event_type=_text(raw.get("event_type"), 64) or "run.progress",
            agent_id=_text(raw.get("agent_id"), 128),
            step_id=_text(raw.get("step_id"), 128),
            severity=_text(raw.get("severity"), 32),
            payload=payload,
            created_at=created,
        )
        db.add(record)
        db.flush()
        return record.id


def queue_command(
    session_id: str,
    command_type: str,
    payload: Optional[dict[str, Any]] = None,
    *,
    issued_by: Any = None,
) -> Optional[str]:
    with _session() as db:
        run = db.query(AgentRun).filter(AgentRun.session_id == session_id).first()
        if run is None:
            return None
        command_id = str(uuid.uuid4())
        db.add(
            AgentCommand(
                command_id=command_id,
                run_id=session_id,
                organization_id=run.organization_id,
                command_type=command_type[:32],
                payload=dict(payload or {}),
                status="queued",
                issued_by=_text(issued_by, 64),
            )
        )
        db.add(
            AgentEventRecord(
                event_id=str(uuid.uuid4()),
                run_id=session_id,
                organization_id=run.organization_id,
                user_id=_text(issued_by, 64),
                event_type="command.queued",
                payload={"command_id": command_id, "command_type": command_type[:32]},
            )
        )
        return command_id


def has_queued_command(session_id: str, command_type: str) -> bool:
    with _session() as db:
        return bool(
            db.query(AgentCommand.id)
            .filter(
                AgentCommand.run_id == session_id,
                AgentCommand.command_type == command_type,
                AgentCommand.status == "queued",
            )
            .first()
        )


def consume_commands(
    session_id: str,
    command_types: Iterable[str],
    *,
    consumer: Optional[str] = None,
) -> list[dict[str, Any]]:
    kinds = tuple({str(item) for item in command_types if item})
    if not kinds:
        return []
    claimed_by = consumer or worker_identity()
    now = datetime.utcnow()
    with _session() as db:
        rows = (
            db.query(AgentCommand)
            .filter(
                AgentCommand.run_id == session_id,
                AgentCommand.command_type.in_(kinds),
                AgentCommand.status == "queued",
            )
            .order_by(AgentCommand.id.asc())
            .all()
        )
        result = []
        for row in rows:
            row.status = "completed"
            row.claimed_by = claimed_by
            row.claimed_at = now
            row.completed_at = now
            result.append(
                {
                    "command_id": row.command_id,
                    "command_type": row.command_type,
                    "payload": dict(row.payload or {}),
                    "issued_by": row.issued_by,
                }
            )
            db.add(
                AgentEventRecord(
                    event_id=str(uuid.uuid4()),
                    run_id=session_id,
                    organization_id=row.organization_id,
                    event_type="command.consumed",
                    payload={"command_id": row.command_id, "command_type": row.command_type},
                )
            )
        return result


def save_checkpoint(
    organization_id: int,
    session_id: str,
    state: dict[str, Any],
    *,
    schema_version: int = 1,
) -> str:
    encoded = json.dumps(state, sort_keys=True, separators=(",", ":"), default=str)
    serializable = json.loads(encoded)
    digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    with _session() as db:
        row = db.query(AgentCheckpoint).filter(AgentCheckpoint.run_id == session_id).first()
        if row is None:
            row = AgentCheckpoint(
                run_id=session_id,
                organization_id=int(organization_id),
                schema_version=int(schema_version),
                state=serializable,
                state_digest=digest,
            )
            db.add(row)
        else:
            if row.organization_id != int(organization_id):
                raise ValueError("checkpoint run/organization does not match")
            row.organization_id = int(organization_id)
            row.schema_version = int(schema_version)
            row.state = serializable
            row.state_digest = digest
            row.updated_at = datetime.utcnow()
    return digest


def load_checkpoint(organization_id: int, session_id: str) -> dict[str, Any]:
    with _session() as db:
        row = (
            db.query(AgentCheckpoint)
            .filter(
                AgentCheckpoint.run_id == session_id,
                AgentCheckpoint.organization_id == int(organization_id),
            )
            .first()
        )
        return dict(row.state or {}) if row else {}


def get_run(session_id: str, organization_id: Optional[int] = None) -> Optional[dict[str, Any]]:
    with _session() as db:
        q = db.query(AgentRun).filter(AgentRun.session_id == session_id)
        if organization_id is not None:
            q = q.filter(AgentRun.organization_id == int(organization_id))
        row = q.first()
        return _run_dict(row) if row else None


def list_runs(
    organization_id: int,
    *,
    user_id: Optional[int] = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    with _session() as db:
        q = db.query(AgentRun).filter(AgentRun.organization_id == int(organization_id))
        if user_id is not None:
            q = q.filter(AgentRun.user_id == int(user_id))
        rows = q.order_by(AgentRun.updated_at.desc()).limit(min(max(limit, 1), 200)).all()
        return [_run_dict(row) for row in rows]


def list_events(
    session_id: str,
    organization_id: int,
    *,
    after_id: int = 0,
    limit: int = 200,
) -> list[dict[str, Any]]:
    with _session() as db:
        rows = (
            db.query(AgentEventRecord)
            .filter(
                AgentEventRecord.run_id == session_id,
                AgentEventRecord.organization_id == int(organization_id),
                AgentEventRecord.id > max(0, int(after_id)),
            )
            .order_by(AgentEventRecord.id.asc())
            .limit(min(max(limit, 1), 1000))
            .all()
        )
        return [
            {
                "id": row.id,
                "event_id": row.event_id,
                "run_id": row.run_id,
                "event_type": row.event_type,
                "agent_id": row.agent_id,
                "step_id": row.step_id,
                "severity": row.severity,
                "payload": row.payload or {},
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in rows
        ]


def safe_call(name: str, *args: Any, **kwargs: Any) -> Any:
    """Call a runtime-store function without making assessment execution brittle."""
    try:
        return globals()[name](*args, **kwargs)
    except Exception:
        logger.debug("agent runtime store %s skipped", name, exc_info=True)
        return None


def _run_dict(row: AgentRun) -> dict[str, Any]:
    return {
        "session_id": row.session_id,
        "organization_id": row.organization_id,
        "user_id": row.user_id,
        "status": row.status,
        "mode": row.mode,
        "objective": row.objective,
        "current_phase": row.current_phase,
        "current_step": row.current_step,
        "iteration_count": row.iteration_count,
        "progress": row.progress,
        "price_limit_usd": row.price_limit_usd,
        "cost_usd": row.cost_usd,
        "worker_id": row.worker_id,
        "heartbeat_at": row.heartbeat_at.isoformat() if row.heartbeat_at else None,
        "error_message": row.error_message,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        "completed_at": row.completed_at.isoformat() if row.completed_at else None,
    }


def _text(value: Any, limit: int) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text[:limit] or None


def _parse_datetime(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value.replace(tzinfo=None) if value.tzinfo else value
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.replace(tzinfo=None) if parsed.tzinfo else parsed
        except ValueError:
            return None
    return None
