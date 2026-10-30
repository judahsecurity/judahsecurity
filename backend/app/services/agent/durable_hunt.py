"""Postgres-backed continuation for opted-in scheduled tester assessments.

One claimed work item performs one agent turn. The next turn is committed as
queued work before it is run, so a process restart can continue from a stable
boundary. Expired in-flight turns are blocked for ledger reconciliation because
their spend and target-side effects cannot safely be guessed.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import math
import time
import uuid
from datetime import datetime, timedelta
from typing import Any

from app.db.database import SessionLocal
from app.models.agent_autonomy_work import AgentAutonomyWork, AgentRunSnapshot
from app.models.scan_schedule import ScanSchedule
from app.models.user import User, UserRole
from app.services.agent.scheduled_hunt import continuation_plan, notify_emails

logger = logging.getLogger(__name__)
_LEASE_SECONDS = 120


def work_identity(schedule_id: int, due_at: datetime, target: str, organization_id: int) -> tuple[str, str]:
    seed = f"{schedule_id}:{due_at.isoformat()}"
    digest = hashlib.sha256(f"{seed}:{target}".encode()).hexdigest()
    return digest[:40], f"sched-{organization_id}-{digest[:24]}"


def enqueue_scheduled_hunts(
    db: Any, schedule: ScanSchedule, targets: list[str], *, user_id: int,
) -> int:
    """Create at-most-once work items for one schedule tick."""
    from app.services.agent.playbooks import build_initial_objective
    from app.services.agent.autonomy_limits import limits_from_config

    config = schedule.config or {}
    due_at = schedule.next_run_at or datetime.utcnow()
    created = 0
    for target in targets:
        active = db.query(AgentAutonomyWork.id).filter(
            AgentAutonomyWork.schedule_id == schedule.id,
            AgentAutonomyWork.target == target,
            AgentAutonomyWork.status.in_(("queued", "running")),
        ).first()
        if active:
            continue
        work_id, session_id = work_identity(
            schedule.id, due_at, target, schedule.organization_id,
        )
        if db.get(AgentAutonomyWork, work_id) is not None:
            continue
        objective, _ = build_initial_objective("tester_process", target)
        db.add(AgentAutonomyWork(
            id=work_id,
            schedule_id=schedule.id,
            organization_id=schedule.organization_id,
            user_id=int(user_id),
            target=target,
            session_id=session_id,
            status="queued",
            prompt=objective or f"Run tester-process on {target}",
            revisions=[],
            max_turns=max(1, min(int(config.get("max_turns") or 3), 4)),
            price_limit_usd=max(0.01, float(config.get("price_limit_usd") or 8.0)),
            max_total_seconds=max(300, min(int(config.get("max_total_seconds") or 3600), 7200)),
            limits=limits_from_config(config).__dict__,
        ))
        created += 1
    return created


def recover_expired(db: Any, *, now: datetime | None = None) -> int:
    """Quarantine an interrupted turn; no unknown action or spend is replayed."""
    now = now or datetime.utcnow()
    rows = db.query(AgentAutonomyWork).filter(
        AgentAutonomyWork.status == "running",
        AgentAutonomyWork.lease_until < now,
    ).with_for_update(skip_locked=True).all()
    for row in rows:
        row.status = "blocked"
        row.stop_reason = "Execution lease expired; reconcile the action ledger and spend before retrying"
        row.lease_owner = ""
        row.lease_until = None
        row.finished_at = now
    if rows:
        db.commit()
    return len(rows)


def claim_next(db: Any, *, owner: str, now: datetime | None = None) -> str | None:
    """Atomically claim one queued turn across worker replicas."""
    now = now or datetime.utcnow()
    row = db.query(AgentAutonomyWork).filter(
        AgentAutonomyWork.status == "queued",
    ).order_by(AgentAutonomyWork.created_at, AgentAutonomyWork.id).with_for_update(
        skip_locked=True,
    ).first()
    if row is None:
        return None
    row.status = "running"
    row.lease_owner = owner
    row.lease_until = now + timedelta(seconds=_LEASE_SECONDS)
    row.updated_at = now
    work_id = row.id
    db.commit()
    return work_id


def _authorized(db: Any, row: AgentAutonomyWork) -> tuple[bool, str]:
    schedule = db.get(ScanSchedule, row.schedule_id)
    user = db.get(User, row.user_id)
    if not schedule or not schedule.is_enabled or schedule.scan_type != "tester_process":
        return False, "Schedule was disabled or removed"
    if (schedule.config or {}).get("autonomous_followup") is not True:
        return False, "Autonomous follow-up was disabled"
    if schedule.organization_id != row.organization_id:
        return False, "Schedule organization changed"
    if (not user or not user.is_active or user.role not in {UserRole.ADMIN, UserRole.ANALYST}
            or not (user.is_superuser or user.organization_id == row.organization_id)):
        return False, "Schedule creator no longer has analyst access"
    try:
        from app.services.scan_guardrails import validate_rules_of_engagement
        validate_rules_of_engagement(db, row.organization_id, [row.target], "tester_process")
    except Exception as exc:
        return False, f"Rules of engagement no longer permit this target: {str(exc)[:180]}"
    return True, ""


def _update_owned(work_id: str, owner: str, **values: Any) -> bool:
    with SessionLocal() as db:
        row = db.get(AgentAutonomyWork, work_id)
        if not row or row.status != "running" or row.lease_owner != owner:
            return False
        for key, value in values.items():
            setattr(row, key, value)
        row.updated_at = datetime.utcnow()
        db.commit()
        return True


async def _heartbeat(work_id: str, owner: str, stop: asyncio.Event) -> None:
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=30)
        except asyncio.TimeoutError:
            try:
                renewed = _update_owned(
                    work_id, owner,
                    lease_until=datetime.utcnow() + timedelta(seconds=_LEASE_SECONDS),
                )
            except Exception:
                logger.exception("Autonomy lease heartbeat failed for %s", work_id)
                return
            if not renewed:
                return


def _finish(work_id: str, owner: str, *, status: str, reason: str, answer: str = "",
            cost_usd: float = 0.0, revision: str = "", prompt: str = "",
            count_turn: bool = True) -> dict[str, Any]:
    with SessionLocal() as db:
        row = db.get(AgentAutonomyWork, work_id)
        if not row or row.status != "running" or row.lease_owner != owner:
            return {"id": work_id, "status": "lost_lease"}
        if count_turn:
            row.turns += 1
        row.spent_usd = round(float(row.spent_usd or 0) + cost_usd, 6)
        row.status = status
        row.stop_reason = reason[:500]
        row.answer = answer[:800]
        row.lease_owner = ""
        row.lease_until = None
        if status == "queued":
            row.prompt = prompt
            row.revisions = [*(row.revisions or []), revision][-10:]
        else:
            row.finished_at = datetime.utcnow()
        db.commit()
        return {
            "id": work_id, "status": status, "turns": row.turns,
            "spent_usd": row.spent_usd, "stop_reason": row.stop_reason,
        }


async def process_claimed(work_id: str, owner: str) -> dict[str, Any]:
    """Run one bounded turn and persist the next safe continuation."""
    from app.services.agent.action_ledger import latest_run
    from app.services.agent.orchestrator import get_agent_orchestrator
    from app.services.agent.playbooks import build_initial_objective
    from app.services.agent.run_snapshot import load_run_snapshot

    with SessionLocal() as db:
        row = db.get(AgentAutonomyWork, work_id)
        if not row or row.status != "running" or row.lease_owner != owner:
            return {"id": work_id, "status": "lost_lease"}
        authorized, reason = _authorized(db, row)
        remaining_seconds = row.max_total_seconds - (datetime.utcnow() - row.created_at).total_seconds()
        remaining_usd = row.price_limit_usd - row.spent_usd
        target, prompt, session_id = row.target, row.prompt, row.session_id
        organization_id, user_id, turns = row.organization_id, row.user_id, row.turns
        max_turns = row.max_turns
        limits_config = dict(row.limits or {})
    if not authorized:
        return _finish(work_id, owner, status="blocked", reason=reason, count_turn=False)
    if remaining_seconds <= 0 or remaining_usd <= 0 or turns >= max_turns:
        return _finish(
            work_id, owner, status="blocked", reason="Assessment budget exhausted",
            count_turn=False,
        )

    _, todos = build_initial_objective("tester_process", target)
    stop = asyncio.Event()
    heartbeat = asyncio.create_task(_heartbeat(work_id, owner, stop))
    try:
        orchestrator = await get_agent_orchestrator()
        from app.services.agent.autonomy_limits import current_autonomy_limits, limits_from_config

        token = current_autonomy_limits.set(limits_from_config(limits_config))
        try:
            turn_started_at = time.time()
            response = await asyncio.wait_for(orchestrator.invoke(
                question=prompt,
                user_id=str(user_id),
                organization_id=int(organization_id),
                session_id=session_id,
                initial_todos=todos if turns == 0 else None,
                mode="agent",
                max_iterations=30,
                price_limit_usd=remaining_usd,
            ), timeout=max(1.0, remaining_seconds))
        finally:
            current_autonomy_limits.reset(token)
        if response.error or getattr(response, "awaiting_question", False) or getattr(response, "awaiting_approval", False):
            return _finish(
                work_id, owner, status="blocked", reason="Agent error or operator input required",
                answer=str(getattr(response, "answer", "") or ""),
            )
        raw_cost = getattr(response, "cost_usd", None)
        if not isinstance(raw_cost, (int, float)) or not math.isfinite(raw_cost) or raw_cost < 0:
            return _finish(work_id, owner, status="blocked", reason="Agent spend could not be measured")
        cost = float(raw_cost)
        with SessionLocal() as db:
            run = latest_run(
                db, session_id=session_id, organization_id=int(organization_id), user_id=int(user_id),
            )
            row = db.get(AgentAutonomyWork, work_id)
            prior_revisions = set(row.revisions or []) if row else set()
            saved = db.get(AgentRunSnapshot, session_id)
            fresh_snapshot = bool(
                saved and saved.organization_id == int(organization_id)
                and isinstance(saved.payload, dict)
                and float(saved.payload.get("saved_at") or 0) >= turn_started_at
            )
        if not fresh_snapshot:
            return _finish(
                work_id, owner, status="blocked",
                reason="This turn has no durable database snapshot; reconcile before resuming",
                answer=str(response.answer or ""), cost_usd=cost,
            )
        plan = continuation_plan(load_run_snapshot(organization_id, session_id), run, target)
        if plan and turns + 1 < max_turns and cost < remaining_usd:
            revision, next_prompt = plan
            if revision not in prior_revisions:
                return _finish(
                    work_id, owner, status="queued", reason="", answer=str(response.answer or ""),
                    cost_usd=cost, revision=revision, prompt=next_prompt,
                )
        complete = bool(response.task_complete and run and run.get("status") == "completed")
        reason = "" if complete else (
            "No new hypothesis or coverage progress" if plan and plan[0] in prior_revisions else
            "Assessment turn or spend budget reached" if plan else
            "No schedulable work in the saved assessment"
        )
        return _finish(
            work_id, owner, status="completed" if complete else "blocked",
            reason=reason, answer=str(response.answer or ""), cost_usd=cost,
        )
    except asyncio.TimeoutError:
        return _finish(work_id, owner, status="blocked", reason="Assessment time budget reached")
    except asyncio.CancelledError:
        raise  # The lease expires and the next worker quarantines this turn.
    except Exception as exc:
        logger.exception("Durable scheduled assessment %s failed", work_id)
        return _finish(work_id, owner, status="blocked", reason=f"Agent failed: {str(exc)[:300]}")
    finally:
        stop.set()
        await heartbeat


def send_terminal_notification(work_id: str) -> None:
    """Claim one terminal digest at most once, even across worker restarts."""
    with SessionLocal() as db:
        row = db.query(AgentAutonomyWork).filter(
            AgentAutonomyWork.id == work_id,
        ).with_for_update(skip_locked=True).first()
        if not row or row.status not in {"completed", "blocked"} or row.notification_sent:
            return
        schedule = db.get(ScanSchedule, row.schedule_id)
        if not schedule or not (schedule.notify_on_completion or schedule.notify_on_findings):
            row.notification_sent = True
            db.commit()
            return
        addresses = list(schedule.notification_emails or [])
        subject = f"[Judah] tester-process: {schedule.name}"
        body = (
            f"Scheduled assessment: {row.target}\n"
            f"status={row.status} turns={row.turns} cost_usd={row.spent_usd:.4f}\n"
            f"reason={row.stop_reason or '-'}\n{row.answer[:500]}"
        )
        row.notification_sent = True
        db.commit()
    notify_emails(addresses, subject, body)


async def run_worker_once() -> dict[str, Any] | None:
    owner = uuid.uuid4().hex
    with SessionLocal() as db:
        recover_expired(db)
        terminal_ids = [row.id for row in db.query(AgentAutonomyWork).filter(
            AgentAutonomyWork.status.in_(("completed", "blocked")),
            AgentAutonomyWork.notification_sent == False,
        ).limit(20).all()]
        work_id = claim_next(db, owner=owner)
    for terminal_id in terminal_ids:
        send_terminal_notification(terminal_id)
    if not work_id:
        return None
    result = await process_claimed(work_id, owner)
    if result.get("status") in {"completed", "blocked"}:
        send_terminal_notification(work_id)
    return result
