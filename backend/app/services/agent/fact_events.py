"""Durable, append-only fact stream and its planner-facing consumer.

Worker-recorded facts (captures, differentials, credentials, verified findings)
are appended here idempotently so the planner reliably turns them into
hypotheses across turns and restarts — not only when the model remembers to call
queue_finding_followups. Payloads are value-free; secrets never land here (a
``credential`` fact is the *signal* that creds exist for a host, pointing at
evidence, not the secret itself — re-hydration stays with pre-registered
identities and in-session brain memory).
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

from app.services.agent.action_ledger import safe_target
from app.services.agent.recon_observation_adapter import _allowed, _host

# Imported lazily where needed to avoid a heavy import at module load.


def fact_dedupe_key(organization_id: int, kind: str, target: str, *parts: str) -> str:
    """Stable key so the same fact is enqueued at most once per organization."""
    raw = "|".join([str(organization_id), str(kind), safe_target(target), *[str(p) for p in parts]])
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def append_fact_event(
    *,
    organization_id: int,
    session_id: str,
    kind: str,
    target: str = "",
    dedupe_parts: Iterable[str] = (),
    evidence_ids: Iterable[str] | None = None,
    scope_hosts: Iterable[str] = (),
    payload: dict[str, Any] | None = None,
    work_id: str | None = None,
    run_id: str | None = None,
) -> str | None:
    """Idempotently append one fact. Returns its event_uuid, or None if a dup.

    Owns its own session (like action_ledger). The ``(organization_id,
    dedupe_key)`` unique constraint plus a pre-check make a worker retry or a
    restart a no-op rather than a double hypothesis.
    """
    from app.db.database import SessionLocal
    from app.models.agent_fact_event import FACT_KINDS, AgentFactEvent
    from app.services.agent.observability import redact_value

    if not organization_id or not session_id or kind not in FACT_KINDS:
        return None
    dedupe_key = fact_dedupe_key(organization_id, kind, target, *dedupe_parts)
    event_uuid = uuid.uuid4().hex
    scope = {"allowed_hosts": sorted({str(h).lower().rstrip(".") for h in (scope_hosts or ()) if h})[:100]}
    clean_payload = redact_value(dict(payload or {}))
    with SessionLocal() as db:
        exists = db.query(AgentFactEvent.id).filter(
            AgentFactEvent.organization_id == organization_id,
            AgentFactEvent.dedupe_key == dedupe_key,
        ).first()
        if exists:
            return None
        db.add(AgentFactEvent(
            event_uuid=event_uuid, organization_id=organization_id,
            session_id=session_id[:64], work_id=(work_id or None), run_id=(run_id or None),
            kind=kind, target=safe_target(target)[:512], dedupe_key=dedupe_key,
            scope=scope,
            evidence_ids=[str(e)[:64] for e in (evidence_ids or [])][:16],
            payload=clean_payload,
        ))
        try:
            db.commit()
        except Exception:
            db.rollback()
            return None
    return event_uuid


def _fact_to_observation(row: Any, scope_hosts: list[str]) -> dict[str, Any] | None:
    """Turn an in-scope fact into a value-free observation for planner review."""
    target = str(getattr(row, "target", "") or "")
    host = _host(target)
    if not host or not _allowed(host, scope_hosts):
        return None
    key = str(getattr(row, "dedupe_key", "") or "")
    if not key:
        return None
    payload = getattr(row, "payload", None) or {}
    return {
        "id": key, "dedupe_key": key, "kind": f"fact_{getattr(row, 'kind', '')}",
        "target": target, "host": host,
        "value": str(payload.get("summary") or getattr(row, "kind", ""))[:256],
        "source": "fact_event",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "evidence_ref": (list(getattr(row, "evidence_ids", None) or [""])[:1] or [""])[0] or f"fact:{key}",
        "scope": {"allowed_hosts": sorted(set(scope_hosts))[:100]},
    }


def consume_fact_events_into_brain(
    brain: Any, rows: Iterable[Any], scope_hosts: Iterable[str],
) -> tuple[int, list[int]]:
    """Ingest unconsumed facts into the brain's observation surface (pure).

    Returns ``(ingested, consumed_ids)``. An out-of-scope fact is consumed
    (dropped) rather than left to re-process every turn — the RoE says it is not
    actionable for this engagement. A fact already present is consumed without a
    duplicate. Only an ingest adds a reviewable observation; the next planner
    pass turns it into a hypothesis.
    """
    scope = [str(h) for h in (scope_hosts or ()) if h]
    existing = {
        str(obs.get("dedupe_key") or obs.get("id") or "")
        for obs in (getattr(brain, "recon_observations", None) or [])
    }
    ingested = 0
    consumed: list[int] = []
    for row in rows:
        row_id = getattr(row, "id", None)
        observation = _fact_to_observation(row, scope) if scope else None
        if observation is None:
            if row_id is not None:
                consumed.append(row_id)  # out of scope -> not actionable
            continue
        key = observation["dedupe_key"]
        if key not in existing:
            brain.recon_observations.append(observation)
            brain.recon_observations = brain.recon_observations[-200:]
            existing.add(key)
            ingested += 1
        if row_id is not None:
            consumed.append(row_id)
    return ingested, consumed


def drain_fact_events_into_brain(
    brain: Any, *, organization_id: int, session_id: str,
    scope_hosts: Iterable[str], limit: int = 100,
) -> int:
    """Read unconsumed facts for this session, ingest them, mark consumed.

    Returns the number of observations newly added to the brain. Owns its own
    session; safe to call at turn start.
    """
    from app.db.database import SessionLocal
    from app.models.agent_fact_event import AgentFactEvent

    if not organization_id or not session_id:
        return 0
    with SessionLocal() as db:
        rows = db.query(AgentFactEvent).filter(
            AgentFactEvent.organization_id == organization_id,
            AgentFactEvent.session_id == session_id,
            AgentFactEvent.consumed_at.is_(None),
        ).order_by(AgentFactEvent.id.asc()).limit(limit).all()
        if not rows:
            return 0
        ingested, consumed_ids = consume_fact_events_into_brain(brain, rows, scope_hosts)
        if consumed_ids:
            now = datetime.utcnow()
            db.query(AgentFactEvent).filter(
                AgentFactEvent.id.in_(consumed_ids),
            ).update({AgentFactEvent.consumed_at: now}, synchronize_session=False)
            db.commit()
    return ingested
