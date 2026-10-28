"""Scheduled /skill tester-process hunts (ScanSchedule scan_type=tester_process)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import smtplib
import time
import uuid
from email.message import EmailMessage
from typing import Any, Iterable, List
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def _as_url(raw: str) -> str:
    text = (raw or "").strip()
    if not text:
        return ""
    if text.startswith("http://") or text.startswith("https://"):
        return text.split()[0]
    parsed = urlparse("https://" + text.split()[0])
    if parsed.netloc and "." in parsed.netloc:
        return f"https://{parsed.netloc}"
    return ""


def web_targets(raw: Iterable[str], *, limit: int = 3) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in raw or []:
        url = _as_url(str(item))
        if not url or url in seen:
            continue
        seen.add(url)
        out.append(url)
        if len(out) >= limit:
            break
    return out


def notify_emails(addresses: Iterable[str], subject: str, body: str) -> bool:
    addrs = [a.strip() for a in (addresses or []) if a and "@" in str(a)]
    if not addrs:
        return False
    host = (os.environ.get("SMTP_HOST") or "").strip()
    if not host:
        logger.info("tester-process digest (no SMTP_HOST): %s\n%s", subject, body[:2000])
        return False
    port = int(os.environ.get("SMTP_PORT") or 587)
    user = os.environ.get("SMTP_USER") or ""
    password = os.environ.get("SMTP_PASSWORD") or ""
    sender = os.environ.get("SMTP_FROM") or user or addrs[0]
    msg = EmailMessage()
    msg["Subject"] = subject[:180]
    msg["From"] = sender
    msg["To"] = ", ".join(addrs)
    msg.set_content(body[:12000])
    try:
        with smtplib.SMTP(host, port, timeout=20) as smtp:
            smtp.starttls()
            if user:
                smtp.login(user, password)
            smtp.send_message(msg)
        return True
    except Exception:
        logger.warning("tester-process email failed", exc_info=True)
        return False


def continuation_plan(snapshot: dict, run: dict | None, target: str) -> tuple[str, str] | None:
    """Return a value-free work revision and prompt for an unfinished assessment."""
    if not run or run.get("status") not in {"partial", "paused"}:
        return None
    if not snapshot or snapshot.get("reauthentication_required"):
        return None
    from app.services.agent.tools import same_assessment_target

    cmap = snapshot.get("capability_map") or {}
    if not same_assessment_target(str(cmap.get("target") or ""), target):
        return None
    brain = snapshot.get("engagement_brain") or {}
    from app.services.agent.engagement_brain import engagement_brain_from_dict
    from app.services.agent.penetration_task_graph import (
        NODE_READY, sync_graph_from_brain,
    )

    graph = sync_graph_from_brain(engagement_brain_from_dict(brain))
    ready = sorted(
        (node.id, node.attempts, node.specialist)
        for node in graph.nodes.values() if node.status == NODE_READY
    )
    cells = sorted(
        (str(cell.get("id") or ""), str(cell.get("status") or ""),
         int(cell.get("first_pass_attempts") or 0))
        for cell in (brain.get("coverage_cells") or [])
        if isinstance(cell, dict) and cell.get("status") in {"untested", "in_focus"}
    )
    candidates = sorted(
        (str(row.get("id") or ""), int(row.get("revision") or 1))
        for row in (brain.get("candidates") or [])
        if isinstance(row, dict) and row.get("status") == "pending"
    )
    if not (ready or cells or candidates):
        if not brain.get("hypotheses"):
            # A turn may end after mapping but before the task graph was seeded.
            # Give that observed map one bounded follow-up, then the unchanged
            # revision guard stops further empty retries.
            map_revision = hashlib.sha256(json.dumps(cmap, sort_keys=True, default=str).encode()).hexdigest()[:16]
            return map_revision, (
                f"Continue the authorized assessment of {target} from its saved map. "
                "Sync the engagement brain, then dispatch ready specialists. "
                "Do not repeat completed probes or expand scope."
            )
        return None
    revision = hashlib.sha256(json.dumps(
        [ready, cells, candidates], separators=(",", ":")
    ).encode()).hexdigest()[:16]
    kinds = []
    if ready:
        kinds.append(f"{len(ready)} ready hypotheses")
    if cells:
        kinds.append(f"{len(cells)} open coverage cells")
    if candidates:
        kinds.append(f"{len(candidates)} pending candidates")
    prompt = (
        f"Continue the authorized assessment of {target} from saved evidence. "
        f"Remaining work: {', '.join(kinds)}. Dispatch ready specialists and "
        "run the bounded checks required by the task graph. Verify candidates "
        "independently. Do not repeat completed probes or expand scope."
    )
    return revision, prompt


async def run_tester_process_targets(
    *,
    organization_id: int,
    user_id: str,
    targets: List[str],
    price_limit_usd: float = 8.0,
    schedule_name: str = "",
    run_key: str = "",
    max_turns: int = 3,
    max_total_seconds: int = 3600,
) -> dict[str, Any]:
    from app.services.agent.orchestrator import get_agent_orchestrator
    from app.services.agent.playbooks import build_initial_objective
    from app.services.agent.run_snapshot import load_run_snapshot
    from app.services.agent.action_ledger import latest_run
    from app.db.database import SessionLocal

    orch = await get_agent_orchestrator()
    results = []
    for target in targets:
        objective, todos = build_initial_objective("tester_process", target)
        seed = run_key or uuid.uuid4().hex
        target_hash = hashlib.sha256(f"{seed}:{target}".encode()).hexdigest()[:24]
        session_id = f"sched-{organization_id}-{target_hash}"
        started = time.monotonic()
        spent = 0.0
        revisions: set[str] = set()
        turns = 0
        prompt = objective or f"Run tester-process on {target}"
        last_response = None
        last_run_status = ""
        stop_reason = ""
        try:
            for turn in range(max(1, min(int(max_turns), 4))):
                remaining_seconds = max_total_seconds - (time.monotonic() - started)
                remaining_usd = price_limit_usd - spent
                if remaining_seconds <= 0 or remaining_usd <= 0:
                    stop_reason = "assessment time or spend budget reached"
                    break
                resp = await asyncio.wait_for(orch.invoke(
                    question=prompt,
                    user_id=str(user_id),
                    organization_id=int(organization_id),
                    session_id=session_id,
                    initial_todos=todos if turn == 0 else None,
                    mode="agent",
                    max_iterations=30,
                    price_limit_usd=remaining_usd,
                ), timeout=remaining_seconds)
                turns += 1
                last_response = resp
                if resp.error or getattr(resp, "awaiting_question", False) or getattr(resp, "awaiting_approval", False):
                    stop_reason = "agent error or operator input required"
                    break
                if not isinstance(resp.cost_usd, (int, float)):
                    stop_reason = "agent spend could not be measured"
                    break
                spent += max(0.0, float(resp.cost_usd))
                with SessionLocal() as db:
                    run = latest_run(
                        db, session_id=session_id,
                        organization_id=int(organization_id), user_id=int(user_id),
                    )
                last_run_status = str((run or {}).get("status") or "")
                plan = continuation_plan(
                    load_run_snapshot(organization_id, session_id), run, target,
                )
                if not plan:
                    if last_run_status != "completed":
                        stop_reason = "no schedulable work in the saved assessment"
                    break
                revision, prompt = plan
                if revision in revisions:
                    stop_reason = "no new hypothesis or coverage progress"
                    break
                revisions.add(revision)
            else:
                stop_reason = "scheduled assessment turn budget reached"
            results.append({
                "target": target,
                "session_id": session_id, "turns": turns,
                "error": getattr(last_response, "error", None),
                "complete": bool(last_response and last_response.task_complete
                                 and last_run_status == "completed" and not stop_reason),
                "cost_usd": round(spent, 4),
                "stop_reason": stop_reason,
                "answer": (getattr(last_response, "answer", None) or "")[:800],
            })
        except asyncio.TimeoutError:
            results.append({"target": target, "session_id": session_id,
                            "turns": turns, "complete": False,
                            "cost_usd": round(spent, 4),
                            "stop_reason": "assessment time budget reached"})
        except Exception as exc:
            logger.exception("scheduled tester-process failed for %s", target)
            results.append({"target": target, "error": str(exc)[:400]})
    body_lines = [f"Scheduled hunt: {schedule_name or 'tester_process'}"]
    for row in results:
        body_lines.append(
            f"- {row.get('target')}: complete={row.get('complete')} "
            f"turns={row.get('turns', 0)} cost={row.get('cost_usd')} "
            f"status={row.get('stop_reason') or '-'} err={row.get('error') or '-'}"
        )
        if row.get("answer"):
            body_lines.append(str(row["answer"])[:500])
    return {"results": results, "digest": "\n".join(body_lines)}
