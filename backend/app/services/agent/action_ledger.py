"""Write-through, tenant-scoped receipts for agent work.

Each receipt commits independently of LangGraph checkpoints and chat persistence.
Tool arguments and raw output are deliberately excluded from this audit surface.
"""

from __future__ import annotations

import logging
import uuid
from contextvars import ContextVar
from datetime import datetime, timedelta
from urllib.parse import urlsplit

from app.db.database import SessionLocal
from app.models.agent_run_ledger import (
    AgentActionReceipt, AgentHypothesisCoverage, AgentRunLedger,
)

logger = logging.getLogger(__name__)
active_run_id: ContextVar[str | None] = ContextVar("active_agent_run_id", default=None)


def safe_target(value: str | None) -> str:
    """Keep only an origin or hostname; URL queries can hold credentials."""
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = urlsplit(text if "://" in text else f"https://{text}")
        host = parsed.hostname or ""
    except ValueError:
        return ""
    if not host or any(char.isspace() for char in host):
        return ""
    try:
        port = f":{parsed.port}" if parsed.port else ""
    except ValueError:
        port = ""
    return f"{parsed.scheme}://{host.lower()}{port}" if "://" in text else f"{host.lower()}{port}"


def start_run(*, session_id: str, organization_id: int, user_id: int,
              objective: str, mode: str, budget_seconds: int) -> str:
    run_id = uuid.uuid4().hex
    now = datetime.utcnow()
    with SessionLocal() as db:
        db.add(AgentRunLedger(
            id=run_id, session_id=session_id, organization_id=organization_id,
            user_id=user_id, objective=safe_target(objective), mode=mode,
            started_at=now, deadline_at=now + timedelta(seconds=budget_seconds),
        ))
        db.commit()
    return run_id


def append_action(run_id: str | None, action_id: str, event: str, tool_name: str,
                  *, target: str = "", phase: str = "", detail: str = "",
                  evidence_ids: list[str] | None = None,
                  fingerprint: str = "") -> None:
    if not run_id:
        return
    from app.services.agent.observability import redact_string

    with SessionLocal() as db:
        run = db.query(AgentRunLedger).filter(
            AgentRunLedger.id == run_id,
        ).with_for_update().one_or_none()
        if run is None or run.ended_at is not None:
            return
        db.add(AgentActionReceipt(
            run_id=run_id, action_id=action_id, event=event,
            tool_name=tool_name[:128], target=safe_target(target), phase=phase[:32],
            detail=redact_string(detail or "")[:300],
            evidence_ids=[str(item)[:64] for item in (evidence_ids or [])[:16]],
            fingerprint=fingerprint if len(fingerprint) == 64 else None,
        ))
        db.commit()


def finish_run(run_id: str | None, status: str, reason: str = "") -> None:
    if not run_id:
        return
    with SessionLocal() as db:
        row = db.query(AgentRunLedger).filter(
            AgentRunLedger.id == run_id,
        ).with_for_update().one_or_none()
        if row is None or row.ended_at is not None:
            return
        started = db.query(AgentActionReceipt).filter(
            AgentActionReceipt.run_id == run_id,
            AgentActionReceipt.event == "started",
        ).all()
        terminal_ids = {item.action_id for item in db.query(AgentActionReceipt).filter(
            AgentActionReceipt.run_id == run_id,
            AgentActionReceipt.event != "started",
        ).all()}
        for item in started:
            if item.action_id not in terminal_ids:
                db.add(AgentActionReceipt(
                    run_id=run_id, action_id=item.action_id,
                    event="interrupted", tool_name=item.tool_name,
                    target=item.target, phase=item.phase,
                    detail="Run ended before this action returned",
                    fingerprint=item.fingerprint,
                ))
        row.status = status
        row.reason = reason[:500]
        row.ended_at = datetime.utcnow()
        db.commit()


def record_hypotheses(run_id: str | None, snapshot: dict) -> None:
    """Checkpoint scheduler coverage independently of the final model report."""
    if not run_id or not isinstance(snapshot, dict):
        return
    from app.services.agent.observability import redact_string

    items = [item for bucket in snapshot.values() if isinstance(bucket, list)
             for item in bucket if isinstance(item, dict) and item.get("id")][:300]
    if not items:
        return
    ids = [str(item["id"])[:64] for item in items]
    with SessionLocal() as db:
        run = db.query(AgentRunLedger).filter(
            AgentRunLedger.id == run_id,
        ).with_for_update().one_or_none()
        if run is None or run.ended_at is not None:
            return
        existing = {row.hypothesis_id: row for row in db.query(AgentHypothesisCoverage).filter(
            AgentHypothesisCoverage.run_id == run_id,
            AgentHypothesisCoverage.hypothesis_id.in_(ids),
        ).all()}
        for item in items:
            hypothesis_id = str(item["id"])[:64]
            row = existing.get(hypothesis_id)
            if row is None:
                row = AgentHypothesisCoverage(run_id=run_id, hypothesis_id=hypothesis_id)
                db.add(row)
                existing[hypothesis_id] = row
            row.title = redact_string(str(item.get("title") or ""))[:240]
            row.specialist = str(item.get("specialist") or "")[:64]
            row.status = str(item.get("status") or "pending")[:24]
            row.attempts = max(0, int(item.get("attempts") or 0))
            row.blocked_reason = redact_string(str(item.get("blocked_reason") or ""))[:300]
            refs = item.get("evidence_ids") or []
            row.evidence_ids = [str(ref)[:64] for ref in refs[:16]] if isinstance(refs, list) else []
            row.updated_at = datetime.utcnow()
        db.commit()


def latest_run(db, *, session_id: str, organization_id: int, user_id: int,
               run_id: str | None = None) -> dict | None:
    query = db.query(AgentRunLedger).filter(
        AgentRunLedger.session_id == session_id,
        AgentRunLedger.organization_id == organization_id,
        AgentRunLedger.user_id == user_id,
    )
    if run_id:
        query = query.filter(AgentRunLedger.id == run_id)
    row = query.order_by(AgentRunLedger.started_at.desc()).first()
    if row is None:
        return None
    events = db.query(AgentActionReceipt).filter(
        AgentActionReceipt.run_id == row.id,
    ).order_by(AgentActionReceipt.id).all()
    hypotheses = db.query(AgentHypothesisCoverage).filter(
        AgentHypothesisCoverage.run_id == row.id,
    ).order_by(AgentHypothesisCoverage.updated_at.desc()).all()
    actions: dict[str, dict] = {}
    fingerprints: dict[str, str] = {}
    for event in events:
        if event.fingerprint:
            fingerprints[event.action_id] = event.fingerprint
        item = actions.setdefault(event.action_id, {
            "id": event.action_id, "tool_name": event.tool_name,
            "target": event.target, "phase": event.phase,
            "started_at": event.created_at.isoformat(),
            "status": "running", "detail": "", "evidence_ids": [],
        })
        if event.event != "started":
            item.update(status=event.event, detail=event.detail,
                        evidence_ids=event.evidence_ids or [],
                        ended_at=event.created_at.isoformat())
    now = datetime.utcnow()
    deadline_passed = bool(row.status == "running" and row.deadline_at and now > row.deadline_at)
    last_event_at = events[-1].created_at if events else row.started_at
    from app.core.config import settings

    idle_limit = max(720, int(getattr(settings, "AGENT_TOOL_HARD_TIMEOUT_SECONDS", 600)) + 120)
    stalled = bool(row.status == "running" and not deadline_passed
                   and (now - last_event_at).total_seconds() > idle_limit)
    partial_status = row.status in ("partial", "timeout", "cancelled", "error") or deadline_passed
    hypothesis_rows = []
    hypothesis_counts: dict[str, int] = {}
    for hypothesis in hypotheses:
        if hypothesis.status == "proven":
            coverage_state = "proven_with_evidence" if hypothesis.evidence_ids else "proven_unverified"
        elif hypothesis.status == "killed":
            coverage_state = "negative_with_evidence" if hypothesis.evidence_ids else "tested_no_evidence"
        elif hypothesis.status == "blocked":
            coverage_state = "blocked"
        elif hypothesis.status == "running":
            coverage_state = "interrupted" if partial_status else "in_progress"
        elif hypothesis.status in ("ready", "pending"):
            coverage_state = "skipped_by_budget" if partial_status and "budget" in (row.reason or "").lower() else "not_attempted"
        else:
            coverage_state = "incomplete"
        hypothesis_counts[coverage_state] = hypothesis_counts.get(coverage_state, 0) + 1
        hypothesis_rows.append({
            "id": hypothesis.hypothesis_id, "title": hypothesis.title,
            "specialist": hypothesis.specialist, "state": coverage_state,
            "attempts": hypothesis.attempts,
            "blocked_reason": hypothesis.blocked_reason,
            "evidence_ids": hypothesis.evidence_ids or [],
        })
    if deadline_passed:
        for item in actions.values():
            if item["status"] == "running":
                item["status"] = "interrupted"
                item["detail"] = "Run deadline passed without a terminal receipt"
    counts: dict[str, int] = {}
    repeated: dict[tuple[str, str], int] = {}
    exact: dict[str, int] = {}
    stages: dict[str, int] = {name: 0 for name in (
        "discovery", "surface_mapping", "logic_testing", "scanner_coverage", "http_requests",
    )}
    for item in actions.values():
        counts[item["status"]] = counts.get(item["status"], 0) + 1
        fingerprint = fingerprints.get(item["id"])
        if fingerprint and item["status"] != "skipped":
            exact[fingerprint] = exact.get(fingerprint, 0) + 1
        tool = item["tool_name"]
        if tool != "http_exchange" and not tool.startswith("agent_"):
            key = (tool, item["target"])
            repeated[key] = repeated.get(key, 0) + 1
        if tool == "http_exchange":
            stage = "http_requests"
        elif tool in ("recon_worker:katana_urls", "recon_worker:ferox_dirs",
                      "recon_worker:archive_params",
                      "execute_interceptor", "execute_deep_crawl", "execute_browser",
                      "execute_katana", "execute_feroxbuster", "fingerprint_api",
                      "probe_pilot_ports",
                      "fetch_lazy_chunks", "extract_js_endpoints", "discover_parameters",
                      "parameter_discovery", "parameter_reflection_check",
                      "execute_arjun", "ingest_urls_into_map"):
            stage = "surface_mapping"
        elif tool in ("assessment_kickoff", "spawn_recon_workers") or tool.startswith("recon_worker:"):
            stage = "discovery"
        elif tool.startswith("specialist:") or tool in (
                      "compare_requests", "test_authorization_boundary",
                      "replay_http_request", "independent_verify", "run_assessment_workflow",
                      "mutate_captured_request", "run_intruder_batch", "browser_xss_check",
                      "scoped_assessment_probe_assigned", "scoped_query_probe",
                      "scoped_numeric_sqli", "scoped_string_sqli", "scoped_body_probe"):
            stage = "logic_testing"
        elif tool in ("execute_nuclei", "execute_nikto", "execute_ffuf", "execute_wpscan"):
            stage = "scanner_coverage"
        else:
            stage = ""
        if stage and item["status"] == "completed":
            stages[stage] += 1
    return {
        "run_id": row.id, "session_id": row.session_id,
        "status": "interrupted" if deadline_passed else "stalled" if stalled else row.status,
        "reason": "Run deadline passed" if deadline_passed else
                  f"No saved action for over {idle_limit // 60} minutes" if stalled else row.reason,
        "objective": row.objective, "mode": row.mode,
        "started_at": row.started_at.isoformat(),
        "deadline_at": row.deadline_at.isoformat() if row.deadline_at else None,
        "ended_at": row.ended_at.isoformat() if row.ended_at else None,
        "coverage": {"actions": len(actions), "by_status": counts,
                     "duration_seconds": round(((row.ended_at or datetime.utcnow()) - row.started_at).total_seconds(), 1),
                     "repeated_tool_target_actions": sum(max(0, n - 1) for n in repeated.values()),
                     "fingerprinted_tool_calls": sum(exact.values()),
                     "exact_repeated_tool_calls": sum(max(0, n - 1) for n in exact.values()),
                     "model_calls": sum(1 for item in actions.values()
                                        if item["tool_name"].startswith("agent_")),
                     "test_actions": sum(1 for item in actions.values()
                                         if item["status"] != "skipped"
                                         and item["tool_name"] in (
                                             "compare_requests", "test_authorization_boundary",
                                             "replay_http_request", "independent_verify",
                                             "run_assessment_workflow", "mutate_captured_request",
                                             "run_intruder_batch", "execute_nuclei", "execute_nikto",
                                             "execute_wpscan", "execute_sqlmap",
                                             "scoped_assessment_probe_assigned", "scoped_query_probe",
                                             "scoped_numeric_sqli", "scoped_string_sqli", "scoped_body_probe",
                                         )),
                     "completed_by_stage": stages,
                     "hypotheses_by_state": hypothesis_counts,
                     "untested_stages": [name for name, count in stages.items()
                                         if not count and name != "http_requests"],
                     "published_findings": sum(1 for item in actions.values()
                                               if item["tool_name"] == "create_finding"
                                               and item["status"] == "completed"
                                               and item["detail"] == "finding_published")},
        "actions": list(actions.values()),
        "hypotheses": hypothesis_rows,
    }


def partial_report(run_id: str | None, reason: str) -> str:
    """Deterministic final text when the report model is unavailable or slow."""
    if not run_id:
        return f"Assessment ended: {reason}. No durable run receipt is available."
    with SessionLocal() as db:
        row = db.get(AgentRunLedger, run_id)
        report = latest_run(
            db, session_id=row.session_id,
            organization_id=row.organization_id, user_id=row.user_id, run_id=run_id,
        ) if row else None
    if not report:
        return f"Assessment ended: {reason}. The run receipt could not be loaded."
    counts = report["coverage"]["by_status"]
    action_names = [item["tool_name"] for item in report["actions"]]
    actions = ", ".join(action_names[-15:]) or "none recorded"
    return (
        f"Assessment stopped: {reason}. Run {run_id}. "
        f"Recorded {report['coverage']['actions']} actions "
        f"({counts.get('completed', 0)} completed, {counts.get('failed', 0)} failed, "
        f"{counts.get('interrupted', 0)} interrupted, {counts.get('skipped', 0)} skipped). "
        f"Recent actions: {actions}. "
        f"Published findings: {report['coverage']['published_findings']}. "
        "Open Work performed for individual receipts. Untested surfaces remain unknown."
    )
