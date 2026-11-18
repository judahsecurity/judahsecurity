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


# Per-kind specialist cards. A fact becomes assignable work, not just a visible
# observation. `capture` stays observation-only (context, not its own card) to
# avoid flooding the graph; the high-signal kinds each seed one bounded card.
_FACT_CARDS: dict[str, dict[str, str]] = {
    "credential": {
        "specialist": "api_authz", "priority": "high",
        "title": "Authenticated access review",
        "assumption": "Recorded working credentials may reach another user's or tenant's data or a privileged function.",
        "test": "Replay the credential against in-scope authenticated endpoints and compare authorized test identities with compare_requests.",
        "pass_criteria": "Authenticated access reveals cross-user/tenant data or a function the identity should not reach.",
        "kill_criteria": "Credential rejected, or access is consistent with the identity's expected scope.",
    },
    "differential": {
        "specialist": "api_authz", "priority": "high",
        "title": "Confirm response differential",
        "assumption": "An observed response differential suggests an access-control or tenant-isolation gap.",
        "test": "Reproduce against a matched negative control via compare_requests.",
        "pass_criteria": "LIKELY_IMPACT: another identity's or tenant's data is returned.",
        "kill_criteria": "NO_MATERIAL_DIFF, or the mutation is denied.",
    },
    "verified_finding": {
        "specialist": "business_logic", "priority": "high",
        "title": "Chain follow-up from a confirmed weakness",
        "assumption": "A confirmed weakness may chain to adjacent objects or escalate privileges.",
        "test": "Test write/export variants and adjacent object families on the same surface; do not re-prove the original finding.",
        "pass_criteria": "An adjacent object or escalation is independently demonstrated.",
        "kill_criteria": "No adjacent impact; the surface is isolated.",
    },
}


def _fact_hypothesis(observation: dict[str, Any], kind: str) -> Any | None:
    """Build one bounded specialist card for an in-scope fact, or None.

    Mirrors the recon observation adapter: the card is value-free, linked to the
    fact's observation, and deduped by a stable id so repeated drains do not
    duplicate it.
    """
    template = _FACT_CARDS.get(kind)
    if not template:
        return None
    from app.services.agent.engagement_brain import Hypothesis

    key = observation["dedupe_key"]
    host = observation.get("host") or ""
    hid = hashlib.sha256(f"fact|{key}|{template['specialist']}".encode()).hexdigest()[:12]
    return Hypothesis(
        id=hid,
        title=f"{template['title']} on {host}" if host else template["title"],
        assumption=template["assumption"],
        test=template["test"],
        pass_criteria=template["pass_criteria"],
        kill_criteria=template["kill_criteria"],
        specialist=template["specialist"],
        status="open",
        priority=template["priority"],
        target=observation["target"],
        evidence=f"{observation.get('evidence_ref') or ''}: {kind}",
        source="chain",
        observation_id=key,
    )


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
    open_hyp_ids = {h.id for h in (getattr(brain, "hypotheses", None) or [])}
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
            # Turn the fact into one bounded, claimable specialist card so the
            # planner assigns it, not just records it.
            card = _fact_hypothesis(observation, str(getattr(row, "kind", "") or ""))
            if card is not None and card.id not in open_hyp_ids:
                brain.hypotheses.append(card)
                open_hyp_ids.add(card.id)
        if row_id is not None:
            consumed.append(row_id)
    return ingested, consumed


def prior_fact_summaries(
    rows: Iterable[Any], scope_hosts: Iterable[str], limit: int = 20,
) -> list[dict[str, Any]]:
    """Value-free, in-scope summaries of prior-engagement facts (pure).

    Cross-session memory: a credential or verified finding seen on an in-scope
    host in an earlier run becomes context for this one. RoE is enforced by the
    host-scope filter; secrets never appear (payloads are already value-free).
    """
    scope = [str(h) for h in (scope_hosts or ()) if h]
    if not scope:
        return []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        host = _host(str(getattr(row, "target", "") or ""))
        if not host or not _allowed(host, scope):
            continue
        key = str(getattr(row, "dedupe_key", "") or "")
        if not key or key in seen:
            continue
        seen.add(key)
        payload = getattr(row, "payload", None) or {}
        out.append({
            "kind": str(getattr(row, "kind", "") or ""),
            "host": host,
            "summary": str(payload.get("summary") or getattr(row, "kind", ""))[:160],
            "dedupe_key": key,
        })
        if len(out) >= limit:
            break
    return out


def search_prior_facts(
    organization_id: int,
    scope_hosts: Iterable[str],
    *,
    kinds: Iterable[str] | None = None,
    exclude_session_id: str = "",
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Cross-session fact search for an organization, filtered to in-scope hosts.

    Read-only. Returns value-free summaries, newest first. This is the shared,
    durable memory an ARTEX-style later worker reads: prior captures, credentials
    and verified findings on hosts this engagement is already authorized for.
    """
    from app.db.database import SessionLocal
    from app.models.agent_fact_event import AgentFactEvent

    if not organization_id:
        return []
    with SessionLocal() as db:
        query = db.query(AgentFactEvent).filter(
            AgentFactEvent.organization_id == organization_id,
        )
        if exclude_session_id:
            query = query.filter(AgentFactEvent.session_id != exclude_session_id)
        if kinds:
            query = query.filter(AgentFactEvent.kind.in_(list(kinds)))
        rows = query.order_by(AgentFactEvent.id.desc()).limit(max(1, limit) * 5).all()
    return prior_fact_summaries(rows, scope_hosts, limit=limit)


def prune_consumed_fact_events(older_than_days: int = 14) -> int:
    """Delete consumed facts older than a cutoff. Unconsumed rows are kept.

    The ledger is append-only; this bounds its growth. Evidence bytes live in the
    evidence store, so a pruned event loses only a thin, already-consumed pointer.
    Owns its own session. Returns the number of rows deleted.
    """
    from datetime import timedelta

    from app.db.database import SessionLocal
    from app.models.agent_fact_event import AgentFactEvent

    cutoff = datetime.utcnow() - timedelta(days=max(1, older_than_days))
    with SessionLocal() as db:
        deleted = db.query(AgentFactEvent).filter(
            AgentFactEvent.consumed_at.isnot(None),
            AgentFactEvent.consumed_at < cutoff,
        ).delete(synchronize_session=False)
        db.commit()
    return int(deleted or 0)


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
