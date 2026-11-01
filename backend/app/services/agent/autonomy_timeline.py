"""Operator-safe timeline for one scheduled assessment work item."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable

from app.services.agent.action_ledger import safe_target
from app.services.agent.observability import redact_string


def _candidate_receipt(candidate: dict, receipts: dict) -> dict:
    return next((
        row for row in receipts.values()
        if isinstance(row, dict) and row.get("candidate_id") == candidate.get("id")
    ), {})


def verified_candidate(candidate: dict, receipts: dict) -> bool:
    receipt = _candidate_receipt(candidate, receipts)
    return bool(
        candidate.get("status") == "confirmed"
        and receipt.get("verdict") == "confirmed"
        and receipt.get("run_id") == candidate.get("verifier_run_id")
        and receipt.get("revision") == candidate.get("revision")
        and receipt.get("nonce") == candidate.get("nonce")
        and receipt.get("nonce_observed") is True
        and receipt.get("evidence_ids")
    )


def _at(value: Any) -> str:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
    return value.isoformat() if isinstance(value, datetime) else str(value or "")


def _sort_key(event: dict) -> datetime:
    try:
        value = datetime.fromisoformat(event.get("at") or "")
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def build_timeline(
    work: Any, snapshot: dict, runs: Iterable[Any], actions: Iterable[Any],
    coverage: Iterable[Any],
) -> dict[str, Any]:
    brain = snapshot.get("engagement_brain") or {}
    events: list[dict[str, Any]] = []
    observations = [row for row in (brain.get("recon_observations") or [])[:200] if isinstance(row, dict)]
    for row in observations:
        events.append({
            "kind": "observation", "at": _at(row.get("observed_at")),
            "id": row.get("id"), "observation_kind": row.get("kind"),
            "target": safe_target(row.get("target")), "value": redact_string(str(row.get("value") or ""))[:256],
            "source": row.get("source"), "evidence_ref": row.get("evidence_ref"),
            "scope": row.get("scope") or {},
        })
    latest_coverage = {}
    for row in coverage:
        key = str(getattr(row, "hypothesis_id", "") or "")
        if key and (key not in latest_coverage or row.updated_at > latest_coverage[key].updated_at):
            latest_coverage[key] = row
    graph_nodes = (brain.get("task_graph") or {}).get("nodes") or {}
    for row in (brain.get("hypotheses") or [])[:300]:
        if not isinstance(row, dict):
            continue
        hid = str(row.get("id") or "")
        node = graph_nodes.get(hid) or {}
        audit = latest_coverage.get(hid)
        events.append({
            "kind": "hypothesis", "at": _at(row.get("created_at")),
            "id": hid, "observation_id": row.get("observation_id") or None,
            "title": redact_string(str(row.get("title") or ""))[:240],
            "target": safe_target(row.get("target")), "specialist": row.get("specialist"),
            "status": node.get("status") or row.get("status"),
            "verdict": row.get("status"),
            "attempts": getattr(audit, "attempts", 0),
            "stop_reason": redact_string(str(node.get("blocked_reason") or getattr(audit, "blocked_reason", "") or ""))[:300],
            "evidence_ids": list(getattr(audit, "evidence_ids", []) or [])[:16],
        })
    attempts: dict[tuple[str, str], dict] = {}
    for row in list(actions)[:1000]:
        key = (str(row.run_id), str(row.action_id))
        event = attempts.setdefault(key, {
            "kind": "tool_attempt", "at": _at(row.created_at),
            "run_id": row.run_id, "action_id": row.action_id,
            "tool": row.tool_name, "target": safe_target(row.target),
            "specialist": row.phase or (row.tool_name.split(":", 1)[1] if row.tool_name.startswith("specialist:") else ""),
            "status": "started", "stop_reason": "", "evidence_ids": [],
        })
        if row.event != "started":
            event.update(
                status=row.event,
                stop_reason=redact_string(str(row.detail or ""))[:300],
                evidence_ids=list(row.evidence_ids or [])[:16],
            )
    events.extend(attempts.values())
    receipts = brain.get("verification_receipts") or {}
    candidates = [row for row in (brain.get("candidates") or [])[:100] if isinstance(row, dict)]
    for row in candidates:
        verified = verified_candidate(row, receipts)
        receipt = _candidate_receipt(row, receipts) if verified else {}
        events.append({
            "kind": "candidate", "at": _at(row.get("verified_at") or snapshot.get("saved_at")),
            "id": row.get("id"), "hypothesis_id": row.get("hypothesis_id"),
            "verdict": "verified" if verified else "lead",
            "status": row.get("status"),
            "evidence_ids": list(receipt.get("evidence_ids") or row.get("evidence_ids") or [])[:16],
        })
    for run in runs:
        events.append({
            "kind": "run", "at": _at(run.started_at), "run_id": run.id,
            "status": run.status, "stop_reason": redact_string(str(run.reason or ""))[:300],
            "ended_at": _at(run.ended_at),
        })
    events.append({
        "kind": "work", "at": _at(work.finished_at or work.updated_at),
        "status": work.status, "stop_reason": redact_string(str(work.stop_reason or ""))[:500],
        "turns": work.turns, "cost_usd": work.spent_usd,
    })
    events.sort(key=_sort_key)
    return {
        "work_id": work.id, "status": work.status,
        "lead_count": len(observations),
        "verified_count": sum(verified_candidate(row, receipts) for row in candidates),
        "cost_usd": work.spent_usd, "events": events,
    }
