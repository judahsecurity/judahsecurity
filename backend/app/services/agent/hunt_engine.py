"""Event-driven hunt engine: an LLM planner and parallel specialist workers.

Modelled on AntiFox's planner/worker split. The deterministic first pass
(observed_input_batch, streaming_first_pass) tests every input cheaply; this
engine spends model reasoning only on what those passes surfaced.

- The planner is the only producer of work. Each wake-up is a fresh,
  short LLM session over a compact overview of the engagement brain
  (signals, candidates and verifier verdicts, finished intents). It emits
  0..MAX_INTENTS_PER_ROUND intents, may cancel running ones, or declare done.
  Zero intents is a valid answer.
- Workers claim intents from a queue and run one specialist each
  (fireteam_service._run_specialist) through the normal tool path, so scope,
  method policy, the request ceiling and the publication gate still apply.
- A finished worker wakes the planner. Wake-ups are debounced so a burst of
  results costs one planning round.
- Every intent is checked against the session scope and deduplicated.

Nothing here publishes: workers submit candidates, and the independent
verifier decides true or false positive as before.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

MAX_INTENTS_PER_ROUND = 4
DEFAULT_WORKERS = 3
DEFAULT_MAX_ROUNDS = 8
DEFAULT_MAX_INTENTS = 24
DEBOUNCE_SECONDS = 0.8
PLANNER_TIMEOUT_SECONDS = 90
WORKER_TIMEOUT_SECONDS = 600

PLANNER_PROMPT = """You plan follow-up testing for an authorized web assessment. You do not run
tools; you decide which focused tasks the specialist workers run next.

Rules:
- Ground every task in a concrete signal below (a first-pass result, a candidate, a
  finished task's result). No generic checklist tasks.
- Do not repeat a task that is queued, running or finished unless it names a
  genuinely different technique.
- Keep two or three distinct attack routes alive; do not pile every task on one input.
- At most {max_intents} new tasks. Zero tasks is a valid answer when nothing deserves
  more work. Set "done": true when the remaining signals are exhausted.
- Targets must be URLs inside: {scope}.
- specialist must be one of: {specialists}.
- To stop a running task that is no longer worth it, list its id in "cancel".

Return ONLY JSON:
{{"done": false, "cancel": [], "intents": [{{"title": str, "specialist": str,
  "target": "in-scope URL", "parameter": str, "objective": "what to establish and how"}}]}}

Assessment objective: {objective}

Current state:
{overview}
"""


@dataclass
class Intent:
    id: str
    title: str
    specialist: str
    target: str
    parameter: str
    objective: str
    round: int
    status: str = "queued"          # queued | running | done | cancelled | failed
    verdict: str = ""
    summary: str = ""
    key_findings: List[str] = field(default_factory=list)
    started_at: float = 0.0
    finished_at: float = 0.0

    def key(self) -> tuple:
        return (self.specialist, self.target.split("#")[0], self.parameter.strip().lower())

    def brief(self) -> Dict[str, Any]:
        row = {"id": self.id, "title": self.title, "specialist": self.specialist,
               "target": self.target, "parameter": self.parameter, "status": self.status}
        if self.verdict:
            row["verdict"] = self.verdict
        if self.summary:
            row["result"] = self.summary[:300]
        return row


def parse_plan(text: str) -> Dict[str, Any]:
    """Extract the planner's JSON object; anything malformed means 'no new work'."""
    match = re.search(r"\{.*\}", text or "", re.DOTALL)
    if not match:
        return {"done": False, "cancel": [], "intents": []}
    try:
        data = json.loads(match.group(0))
    except (TypeError, ValueError):
        return {"done": False, "cancel": [], "intents": []}
    if not isinstance(data, dict):
        return {"done": False, "cancel": [], "intents": []}
    intents = [row for row in data.get("intents") or [] if isinstance(row, dict)]
    cancel = [str(x) for x in data.get("cancel") or [] if isinstance(x, (str, int))]
    return {"done": bool(data.get("done")), "cancel": cancel,
            "intents": intents[:MAX_INTENTS_PER_ROUND]}


def brain_overview(brain: Any, intents: List[Intent], budget: Optional[Dict[str, int]] = None,
                   max_rows: int = 30) -> str:
    """Compact, model-facing view of what the deterministic passes and workers found."""
    brain = brain if isinstance(brain, dict) else {}
    signals = []
    for cell in brain.get("coverage_cells") or []:
        if not isinstance(cell, dict):
            continue
        outcome = cell.get("first_pass_outcome")
        if outcome in ("proof_signal", "inconclusive") or cell.get("triage_pending"):
            signals.append({
                "path": cell.get("path"), "method": cell.get("method"),
                "parameter": cell.get("parameter"), "test_type": cell.get("test_type"),
                "outcome": outcome or "lead", "reason": str(cell.get("first_pass_reason") or "")[:160],
            })
    tested_clean = sum(1 for c in brain.get("coverage_cells") or []
                       if isinstance(c, dict) and c.get("first_pass_outcome") == "tested_clean")
    candidates = [{
        "id": c.get("id"), "title": c.get("title"), "class": c.get("vulnerability_class"),
        "target": c.get("target"), "status": c.get("status"),
        "verifier": str(c.get("verifier_summary") or "")[:160],
    } for c in brain.get("candidates") or [] if isinstance(c, dict)]
    view = {
        "first_pass_signals": signals[:max_rows],
        "inputs_tested_clean": tested_clean,
        "candidates": candidates[:max_rows],
        "tasks": [i.brief() for i in intents][-max_rows:],
    }
    if budget:
        view["request_budget"] = budget
    return json.dumps(view, indent=1, default=str)


class HuntEngine:
    def __init__(
        self,
        *,
        plan: Callable[[str], Awaitable[str]],
        run_worker: Callable[[Intent], Awaitable[Dict[str, Any]]],
        overview: Callable[[List[Intent]], str],
        in_scope: Callable[[str], bool],
        specialists: List[str],
        scope_label: str,
        objective: str,
        workers: int = DEFAULT_WORKERS,
        max_rounds: int = DEFAULT_MAX_ROUNDS,
        max_intents: int = DEFAULT_MAX_INTENTS,
        max_seconds: float = 1200.0,
        debounce: float = DEBOUNCE_SECONDS,
        should_stop: Callable[[], bool] = lambda: False,
        worker_timeout: float = WORKER_TIMEOUT_SECONDS,
        planner_tick: float = 15.0,
    ):
        self._plan = plan
        self._run_worker = run_worker
        self._overview = overview
        self._in_scope = in_scope
        self.specialists = list(specialists)
        self.scope_label = scope_label
        self.objective = objective
        self.workers = max(1, int(workers))
        self.max_rounds = max(1, int(max_rounds))
        self.max_intents = max(1, int(max_intents))
        self.deadline = time.monotonic() + max(10.0, float(max_seconds))
        self.debounce = debounce
        self._should_stop = should_stop
        self.worker_timeout = worker_timeout
        # Re-plan at least this often while workers run, so the planner can
        # cancel or redirect long-running work instead of only reacting to
        # completions (AntiFox's kill/steer). Bounded by the deadline.
        self.planner_tick = max(0.5, float(planner_tick))

        self.intents: List[Intent] = []
        self.rounds = 0
        self.rejected: List[Dict[str, str]] = []
        self.stop_reason = ""
        self._queue: asyncio.Queue[Intent] = asyncio.Queue()
        self._wake = asyncio.Event()
        self._running: Dict[str, asyncio.Task] = {}
        self._planner_done = False
        self._finished = asyncio.Event()

    # -- planning -------------------------------------------------------------
    def _prompt(self) -> str:
        return PLANNER_PROMPT.format(
            max_intents=MAX_INTENTS_PER_ROUND, scope=self.scope_label,
            specialists=", ".join(self.specialists), objective=self.objective[:1500],
            overview=self._overview(self.intents),
        )

    def _accept(self, row: Dict[str, Any]) -> Optional[Intent]:
        title = str(row.get("title") or "").strip()[:200]
        specialist = str(row.get("specialist") or "").strip().lower()
        target = str(row.get("target") or "").strip()
        parameter = str(row.get("parameter") or "").strip()[:128]
        objective = str(row.get("objective") or "").strip()[:1500]
        reason = ""
        if not title or not objective:
            reason = "missing title or objective"
        elif specialist not in self.specialists:
            reason = f"unknown specialist {specialist!r}"
        elif not target or not self._in_scope(target):
            reason = "target outside the session scope"
        elif len(self.intents) >= self.max_intents:
            reason = "task limit reached"
        if reason:
            self.rejected.append({"title": title, "reason": reason})
            return None
        intent = Intent(id=f"T{len(self.intents) + 1}", title=title, specialist=specialist,
                        target=target, parameter=parameter, objective=objective,
                        round=self.rounds)
        active = {i.key() for i in self.intents if i.status in ("queued", "running", "done")}
        if intent.key() in active:
            self.rejected.append({"title": title, "reason": "duplicate of an existing task"})
            return None
        return intent

    async def _plan_round(self) -> int:
        self.rounds += 1
        try:
            text = await asyncio.wait_for(self._plan(self._prompt()), timeout=PLANNER_TIMEOUT_SECONDS)
        except Exception as exc:
            logger.warning("hunt planner round failed: %s", type(exc).__name__)
            return 0
        plan = parse_plan(text)
        for intent_id in plan["cancel"]:
            task = self._running.get(intent_id)
            if task is not None:
                task.cancel()
        added = 0
        for row in plan["intents"]:
            intent = self._accept(row)
            if intent is None:
                continue
            self.intents.append(intent)
            self._queue.put_nowait(intent)
            added += 1
        if plan["done"]:
            self._planner_done = True
        return added

    def _out_of_time(self) -> bool:
        return time.monotonic() >= self.deadline

    def _halt_reason(self) -> str:
        if self._should_stop():
            return "stopped"
        if self._out_of_time():
            return "deadline"
        return ""

    async def _planner_loop(self) -> None:
        added = await self._plan_round()
        idle_rounds = 0 if added else 1
        while True:
            busy = bool(self._running) or not self._queue.empty()
            halt = self._halt_reason()
            if halt:
                self.stop_reason = halt
                break
            if self._planner_done and not busy:
                self.stop_reason = "planner_done"
                break
            if not busy and (idle_rounds >= 1 or self.rounds >= self.max_rounds):
                self.stop_reason = "idle" if idle_rounds else "max_rounds"
                break
            # Wait for a worker to finish, a periodic tick, or the deadline,
            # then debounce. The tick lets the planner re-plan (and cancel
            # stuck work) even while every worker is still running.
            wait = min(self.planner_tick, max(0.1, self.deadline - time.monotonic()))
            woke = True
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=wait)
            except asyncio.TimeoutError:
                woke = False
            if woke:
                await asyncio.sleep(self.debounce)
            self._wake.clear()
            if self._planner_done or self.rounds >= self.max_rounds or self._halt_reason():
                continue
            # A bare tick with no finished work and a full queue is not a
            # planning round unless the planner might cancel something.
            if not woke and self._queue.empty() and not self._running:
                continue
            added = await self._plan_round()
            idle_rounds = 0 if added else idle_rounds + 1
        self._finished.set()

    # -- workers --------------------------------------------------------------
    async def _execute(self, intent: Intent) -> None:
        intent.status = "running"
        intent.started_at = time.time()
        try:
            report = await asyncio.wait_for(self._run_worker(intent), timeout=self.worker_timeout)
            intent.status = "done"
            intent.verdict = str(report.get("verdict") or "")
            intent.summary = str(report.get("summary") or "")
            intent.key_findings = [str(x) for x in report.get("key_findings") or []][:8]
        except asyncio.CancelledError:
            intent.status = "cancelled"
        except asyncio.TimeoutError:
            intent.status = "failed"
            intent.summary = "worker timed out"
        except Exception as exc:
            intent.status = "failed"
            intent.summary = f"worker error: {type(exc).__name__}"
        finally:
            intent.finished_at = time.time()

    async def _worker_loop(self) -> None:
        while not self._finished.is_set():
            try:
                intent = await asyncio.wait_for(self._queue.get(), timeout=0.2)
            except asyncio.TimeoutError:
                continue
            if intent.status == "cancelled" or self._halt_reason():
                intent.status = "cancelled"
                self._wake.set()
                continue
            task = asyncio.create_task(self._execute(intent))
            self._running[intent.id] = task
            try:
                await task
            except asyncio.CancelledError:
                if not task.cancelled():
                    raise
            finally:
                self._running.pop(intent.id, None)
                self._wake.set()

    async def run(self) -> Dict[str, Any]:
        started = time.monotonic()
        workers = [asyncio.create_task(self._worker_loop()) for _ in range(self.workers)]
        try:
            await self._planner_loop()
        finally:
            for task in list(self._running.values()):
                task.cancel()
            for intent in self.intents:
                if intent.status == "queued":
                    intent.status = "cancelled"
            for worker in workers:
                worker.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
        return self.summary(time.monotonic() - started)

    def summary(self, elapsed: float = 0.0) -> Dict[str, Any]:
        by_status: Dict[str, int] = {}
        for intent in self.intents:
            by_status[intent.status] = by_status.get(intent.status, 0) + 1
        return {
            "rounds": self.rounds,
            "tasks": [i.brief() for i in self.intents],
            "by_status": by_status,
            "rejected": self.rejected[:20],
            "stop_reason": self.stop_reason,
            "elapsed_seconds": round(elapsed, 1),
        }


def format_summary(summary: Dict[str, Any]) -> str:
    lines = [f"Hunt engine: {summary['rounds']} planning rounds, {len(summary['tasks'])} tasks "
             f"({', '.join(f'{k}={v}' for k, v in sorted(summary['by_status'].items())) or 'none'}); "
             f"stopped: {summary['stop_reason']}."]
    for task in summary["tasks"]:
        lines.append(f"- {task['id']} [{task['status']}{'/' + task['verdict'] if task.get('verdict') else ''}] "
                     f"{task['specialist']}: {task['title']}"
                     + (f" — {task['result'][:200]}" if task.get("result") else ""))
    if summary["rejected"]:
        lines.append(f"Rejected planner tasks: {len(summary['rejected'])} "
                     f"({'; '.join(r['reason'] for r in summary['rejected'][:5])}).")
    lines.append("Workers submit candidates only; the independent verifier decides true or "
                 "false positive before anything is published.")
    return "\n".join(lines)
