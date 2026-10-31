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
    autonomous_followup: bool = False,
    max_turns: int = 3,
    max_total_seconds: int = 3600,
    extra_instructions: str = "",
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
        if extra_instructions:
            # Advisory focus only (e.g. a PR's changed areas). Scope enforcement
            # still comes from the assessment scope/authorization engines.
            prompt = f"{prompt}\n\n{str(extra_instructions).strip()[:2000]}"
        last_response = None
        last_run_status = ""
        stop_reason = ""
        try:
            turn_limit = max(1, min(int(max_turns), 4)) if autonomous_followup else 1
            for turn in range(turn_limit):
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
                    max_iterations=30 if autonomous_followup else None,
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
                if not autonomous_followup:
                    break
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


# ---------------------------------------------------------------------------
# CI gate — run a bounded hunt and fail a pipeline only on CONFIRMED findings
# ---------------------------------------------------------------------------

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def finding_severity_counts(findings: Iterable[dict], session_id: str) -> dict:
    """Count one session's findings by severity (ignores other sessions' rows)."""
    counts: dict[str, int] = {}
    for row in findings or []:
        if str(row.get("session_id") or "") != session_id:
            continue
        sev = str(row.get("severity") or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def ci_gate_exit_code(counts: dict, fail_on: str = "medium") -> int:
    """Non-zero only when a confirmed finding meets/exceeds the fail-on severity.

    A clean or quiet run returns 0. Because every persisted finding has already
    cleared the independent-verify publish gate, a non-zero code is trustworthy
    enough to block a pipeline on.
    """
    threshold = _SEVERITY_RANK.get(str(fail_on or "medium").lower(), 2)
    for sev, n in (counts or {}).items():
        if int(n or 0) > 0 and _SEVERITY_RANK.get(str(sev).lower(), 0) >= threshold:
            return 1
    return 0


def collect_confirmed_findings(organization_id: int, session_id: str, since) -> list[dict]:
    """Persisted agent findings for one hunt session created at/after ``since``.

    Findings are tagged with ``agent_detection.session_id`` and joined to their
    asset for org scoping. JSON filtering is done in Python so the query stays
    portable across SQLite/Postgres. Every row returned already passed the
    publish gate, so it is a confirmed finding, not a raw lead.
    """
    from app.db.database import SessionLocal
    from app.models.asset import Asset
    from app.models.vulnerability import Vulnerability

    out: list[dict] = []
    with SessionLocal() as db:
        rows = (
            db.query(Vulnerability)
            .join(Asset, Vulnerability.asset_id == Asset.id)
            .filter(Asset.organization_id == organization_id)
            .filter(Vulnerability.created_at >= since)
            .all()
        )
        for v in rows:
            meta = v.metadata_ if isinstance(v.metadata_, dict) else {}
            detection = meta.get("agent_detection") if isinstance(meta, dict) else {}
            sid = detection.get("session_id") if isinstance(detection, dict) else ""
            if str(sid or "") != session_id:
                continue
            sev = v.severity.value if hasattr(v.severity, "value") else str(v.severity or "info")
            out.append({
                "id": v.id,
                "title": v.title,
                "severity": str(sev).lower(),
                "session_id": session_id,
            })
    return out


async def run_ci_gate(
    *,
    organization_id: int,
    user_id: str,
    targets: List[str],
    fail_on: str = "medium",
    scope_note: str = "",
    **hunt_kwargs: Any,
) -> dict[str, Any]:
    """Run a bounded tester-process hunt and gate CI on *confirmed* findings only.

    Returns the hunt digest plus an ``exit_code`` that is non-zero only when a
    persisted (independently verified, publish-gated) finding meets or exceeds
    ``fail_on``. ``scope_note`` is woven into the objective as advisory focus
    (e.g. a PR's changed areas); it never widens or enforces scope. A quiet run
    exits 0 — the per-run coverage statement says what was actually tested, so
    0 is not mistaken for "nothing to find".
    """
    from datetime import datetime

    started_at = datetime.utcnow()
    hunt = await run_tester_process_targets(
        organization_id=organization_id,
        user_id=user_id,
        targets=targets,
        extra_instructions=scope_note,
        **hunt_kwargs,
    )
    exit_code = 0
    gate_rows: list[dict] = []
    for row in hunt.get("results", []):
        session_id = str(row.get("session_id") or "")
        counts: dict = {}
        if session_id:
            try:
                findings = collect_confirmed_findings(organization_id, session_id, started_at)
                counts = finding_severity_counts(findings, session_id)
            except Exception:
                logger.warning("CI gate finding lookup failed for %s", session_id, exc_info=True)
        code = ci_gate_exit_code(counts, fail_on)
        exit_code = max(exit_code, code)
        gate_rows.append({**row, "confirmed_findings": counts,
                          "gate": "fail" if code else "pass"})
    digest = hunt.get("digest", "") + f"\n\nCI gate: {'FAIL' if exit_code else 'PASS'} (fail_on={fail_on})"
    return {"results": gate_rows, "exit_code": exit_code,
            "gate": "fail" if exit_code else "pass", "digest": digest}
