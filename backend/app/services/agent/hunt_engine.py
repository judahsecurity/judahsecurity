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
- Facts with lineage. What the first pass and the verifier found, and what
  each worker concluded (including negatives), is kept as facts. Once facts
  exist, every intent must name the facts it derives from, and each finished
  intent records the facts it yielded, so the planner can combine facts into
  new directions and run a dependent chain step by step.
- A finished task is not retried unless the planner names what is new (a
  fact recorded after the first attempt) or re-checks a negative that was
  only inferred. Each route gets at most one retry.
- The planner keeps a to-do list across wake-ups for multi-step chains.

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

MAX_FACTS_IN_PROMPT = 40
MAX_TODO_ITEMS = 12

PLANNER_PROMPT = """You plan follow-up testing for an authorized web assessment. You do not run
tools; you decide which focused tasks the specialist workers run next.

Rules:
- Ground every task in facts. Each task must list in "parent_ids" the ids of the facts
  (F1, F2, ...) it derives from. When several facts together suggest a direction, list
  all of them. Tasks citing no existing fact are rejected while facts exist.
- A finished task is a blocked route. Do not send it again unless "differs_by" names a
  genuinely new mechanism AND a parent fact recorded after the earlier attempt, or the
  earlier attempt only produced an inferred negative worth one re-check. Rewording or
  "try again" is not new. Queued or running tasks are never repeated.
- Negative facts with confidence "observed" are dead ends: do not plan against them.
  An "inferred" negative is weak evidence; one re-check task is allowed if the route matters.
- Keep two or three fundamentally different attack routes alive (for example an
  injection route and an authorization route); do not pile every task on one input.
  Concentrate only once a route has produced evidence toward impact.
- Dependent chains: when step 2 needs step 1's actual output, write the whole chain in
  "todo" and send only the step whose prerequisites exist as facts. Mark steps done
  once a fact satisfies them. Independent inputs may run in parallel.
- At most {max_intents} new tasks. Zero tasks is valid when every direction is covered or
  the next step waits on a running task. Set "done": true only when the remaining facts
  are exhausted.
- Targets must be URLs inside: {scope}.
- specialist must be one of: {specialists}.
- To stop a running task that is no longer worth it, list its id in "cancel".

Return ONLY JSON:
{{"done": false, "cancel": [], "todo": [{{"step": str, "done": false}}],
  "intents": [{{"title": str, "specialist": str, "target": "in-scope URL", "parameter": str,
  "objective": "what to establish and how", "parent_ids": ["F1"], "differs_by": ""}}]}}

Assessment objective: {objective}

Facts (id, summary, confidence, negative, source, from_task):
{facts}

Your to-do list from earlier rounds:
{todo}

Current state:
{overview}
"""

WORKER_RULES = """Worker rules:
- Do only this task. If you notice a new lead outside it (a path in an error, a hidden
  parameter, an admin link, a token format), do not chase it: report it as a fact so
  the planner can assign it.
- An initial setback is not a verdict. Before concluding the input is clean, work
  through the variants that fit what you saw: encodings, another content type or
  method, a second injection context, case/whitespace, blind or timing variants.
- Mark a negative "observed" only when you exhausted those variants; otherwise mark it
  "inferred" so the planner can re-check it rather than abandon the route.
- Check recorded traffic (search_evidence) before re-sending a request already made.
- Prove with evidence. Submit a finding candidate only for what you triggered in this
  run; the independent verifier decides.
- In your final done JSON add "facts": an array with one object per distinct
  conclusion: {"summary": "one sentence", "confidence": "observed"|"inferred",
  "negative": true|false, "evidence_ids": ["execution-owned evidence_id"], "detail": "short"}.
  Summarize several observations into one fact; do not restate the facts listed above.
  Negative conclusions ("category is not injectable with A, B, C") are facts too.
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
    parents: List[str] = field(default_factory=list)   # fact ids this task derives from
    yields: List[str] = field(default_factory=list)    # fact ids this task produced
    differs_by: str = ""
    retry_of: str = ""
    fact_seq: int = 0          # facts that existed when the task was accepted

    def key(self) -> tuple:
        return (self.specialist, self.target.split("#")[0], self.parameter.strip().lower())

    def brief(self) -> Dict[str, Any]:
        row = {"id": self.id, "title": self.title, "specialist": self.specialist,
               "target": self.target, "parameter": self.parameter, "status": self.status}
        if self.parents:
            row["parents"] = list(self.parents)
        if self.yields:
            row["yields"] = list(self.yields)
        if self.retry_of:
            row["retry_of"] = self.retry_of
        if self.verdict:
            row["verdict"] = self.verdict
        if self.summary:
            row["result"] = self.summary[:300]
        return row


@dataclass
class Fact:
    """One conclusion the planner can build on: positive or negative, with evidence."""
    id: str
    summary: str
    source: str                     # first_pass | candidate | task
    confidence: str = "observed"    # observed | inferred
    negative: bool = False
    detail: str = ""
    from_intent: str = ""
    target: str = ""
    parameter: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    seq: int = 0
    key: str = ""                   # dedup key for facts seeded from the brain

    def brief(self) -> Dict[str, Any]:
        row: Dict[str, Any] = {"id": self.id, "summary": self.summary[:240],
                               "confidence": self.confidence, "negative": self.negative,
                               "source": self.source}
        if self.from_intent:
            row["from_task"] = self.from_intent
        if self.target:
            row["target"] = self.target
        if self.parameter:
            row["parameter"] = self.parameter
        if self.evidence_ids:
            row["evidence_ids"] = self.evidence_ids[:4]
        return row


def _clean_ids(values: Any, limit: int = 8) -> List[str]:
    out: List[str] = []
    for value in values if isinstance(values, list) else []:
        text = str(value or "").strip()
        if text and text not in out and len(text) <= 128:
            out.append(text)
    return out[:limit]


def facts_from_brain(brain: Any) -> List[Dict[str, Any]]:
    """Origin facts from the deterministic passes and the verifier.

    First-pass signals become facts (a held proof signal is observed, an
    inconclusive one inferred), and each candidate becomes a fact carrying
    the verifier's verdict. Keys are stable so re-seeding adds only new facts.
    """
    brain = brain if isinstance(brain, dict) else {}
    rows: List[Dict[str, Any]] = []
    for cell in brain.get("coverage_cells") or []:
        if not isinstance(cell, dict):
            continue
        outcome = cell.get("first_pass_outcome")
        if outcome not in ("proof_signal", "inconclusive"):
            continue
        test = str(cell.get("test_type") or "test")
        method = str(cell.get("method") or "GET")
        path = str(cell.get("path") or "/")
        param = str(cell.get("parameter") or "")
        reason = str(cell.get("first_pass_reason") or cell.get("first_pass_signal") or "").strip()
        rows.append({
            "key": "cell:" + str(cell.get("id") or f"{method}|{path}|{param}|{test}") + ":" + str(outcome),
            "source": "first_pass",
            "summary": (f"First-pass {test} on {method} {path} {param}: "
                        + ("proof signal" if outcome == "proof_signal" else "inconclusive")
                        + (f" ({reason[:120]})" if reason else "")),
            "confidence": "observed" if outcome == "proof_signal" else "inferred",
            "negative": False,
            "target": str(cell.get("url") or path), "parameter": param,
            "evidence_ids": _clean_ids([cell.get("first_pass_evidence_id"),
                                        cell.get("first_pass_baseline_id"),
                                        cell.get("first_pass_probe_id")]),
        })
    for cand in brain.get("candidates") or []:
        if not isinstance(cand, dict):
            continue
        status = str(cand.get("status") or "pending")
        verdict = str(cand.get("verifier_summary") or "").strip()
        rows.append({
            "key": f"candidate:{cand.get('id')}:{status}",
            "source": "candidate",
            "summary": (f"Candidate {cand.get('id')} {cand.get('vulnerability_class') or ''} "
                        f"'{str(cand.get('title') or '')[:80]}' is {status}"
                        + (f"; verifier: {verdict[:120]}" if verdict else "")),
            "confidence": "observed" if status in ("confirmed", "rejected", "refuted") else "inferred",
            "negative": status in ("rejected", "refuted", "false_positive"),
            "target": str(cand.get("target") or ""),
            "parameter": str(cand.get("parameter") or ""),
            "evidence_ids": _clean_ids(cand.get("evidence_ids") or []),
        })
    return rows


_FACTS_MARK = re.compile(r"FACTS:\s*", re.IGNORECASE)


def parse_worker_facts(text: str, limit: int = 6) -> List[Dict[str, Any]]:
    """Read the worker's trailing ``FACTS: [...]`` line; malformed means none."""
    found: List[Dict[str, Any]] = []
    for match in _FACTS_MARK.finditer(text or ""):
        tail = (text or "")[match.end():]
        try:
            data, _ = json.JSONDecoder().raw_decode(tail)
        except ValueError:
            continue
        found.extend(_normalize_fact_rows(data))
    return found[:limit]


def _normalize_fact_rows(data: Any, limit: int = 8) -> List[Dict[str, Any]]:
    if isinstance(data, dict):
        data = [data]
    out: List[Dict[str, Any]] = []
    for row in data if isinstance(data, list) else []:
        if not isinstance(row, dict):
            continue
        summary = str(row.get("summary") or "").strip()
        if not summary:
            continue
        # A claim the worker did not label is treated as weak evidence.
        confidence = str(row.get("confidence") or "inferred").strip().lower()
        out.append({
            "summary": summary[:300],
            "detail": str(row.get("detail") or "")[:600],
            "confidence": confidence if confidence in ("observed", "inferred") else "inferred",
            "negative": bool(row.get("negative")),
            "evidence_ids": _clean_ids(row.get("evidence_ids") or []),
        })
    return out[:limit]


def worker_mission(intent: "Intent", facts: List["Fact"]) -> str:
    """The specialist's brief: the task, the facts behind it, and the worker rules."""
    by_id = {f.id: f for f in facts}
    basis = [by_id[pid] for pid in intent.parents if pid in by_id]
    lines = [
        f"Focused follow-up task {intent.id}: {intent.title}",
        f"Target: {intent.target}",
        f"Parameter: {intent.parameter or '(none)'}",
        f"Objective: {intent.objective}",
    ]
    if intent.differs_by:
        lines.append(f"This is a retry of {intent.retry_of}; what is new: {intent.differs_by}")
    if basis:
        lines.append("Facts this task builds on:")
        for fact in basis:
            ev = f" evidence={','.join(fact.evidence_ids[:3])}" if fact.evidence_ids else ""
            lines.append(f"- {fact.id} [{fact.confidence}{', negative' if fact.negative else ''}] "
                         f"{fact.summary[:240]}{ev}")
    lines.append("Do not widen scope.")
    lines.append(WORKER_RULES)
    return "\n".join(lines)


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
    plan: Dict[str, Any] = {"done": bool(data.get("done")), "cancel": cancel,
                            "intents": intents[:MAX_INTENTS_PER_ROUND]}
    todo = data.get("todo")
    if isinstance(todo, list):
        items = []
        for row in todo:
            if isinstance(row, dict) and str(row.get("step") or "").strip():
                items.append({"step": str(row["step"]).strip()[:200], "done": bool(row.get("done"))})
            elif isinstance(row, str) and row.strip():
                items.append({"step": row.strip()[:200], "done": False})
        plan["todo"] = items[:MAX_TODO_ITEMS]
    return plan


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
        seed_facts: Optional[Callable[[], List[Dict[str, Any]]]] = None,
        known_evidence: Optional[Callable[[str], bool]] = None,
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
        self._seed_facts = seed_facts
        self._known_evidence = known_evidence
        self.facts: List[Fact] = []
        self._fact_keys: set = set()
        self.todo: List[Dict[str, Any]] = []

    # -- facts ----------------------------------------------------------------
    def add_fact(self, *, summary: str, source: str, confidence: str = "observed",
                 negative: bool = False, detail: str = "", from_intent: str = "",
                 target: str = "", parameter: str = "",
                 evidence_ids: Optional[List[str]] = None, key: str = "",
                 verify_evidence: bool = True) -> Optional[Fact]:
        summary = str(summary or "").strip()
        if not summary:
            return None
        if key and key in self._fact_keys:
            return None
        ids = _clean_ids(list(evidence_ids or []))
        if verify_evidence and self._known_evidence is not None:
            # The model may only point at evidence that was actually recorded.
            ids = [i for i in ids if self._known_evidence(i)]
        fact = Fact(id=f"F{len(self.facts) + 1}", summary=summary[:300], source=source,
                    confidence=confidence if confidence in ("observed", "inferred") else "inferred",
                    negative=bool(negative), detail=str(detail or "")[:600],
                    from_intent=from_intent, target=target, parameter=parameter,
                    evidence_ids=ids, seq=len(self.facts) + 1, key=key)
        self.facts.append(fact)
        if key:
            self._fact_keys.add(key)
        return fact

    def _sync_facts(self) -> None:
        if self._seed_facts is None:
            return
        try:
            rows = self._seed_facts() or []
        except Exception:
            logger.debug("hunt fact seeding failed", exc_info=True)
            return
        for row in rows:
            if isinstance(row, dict):
                self.add_fact(**{k: row.get(k) for k in (
                    "summary", "source", "confidence", "negative", "detail",
                    "target", "parameter", "evidence_ids", "key") if row.get(k) is not None},
                    # Seeded from the brain by code, not claimed by a model.
                    verify_evidence=False)

    def _record_worker_facts(self, intent: Intent, report: Dict[str, Any]) -> None:
        rows = _normalize_fact_rows(report.get("facts") or [])
        if not rows:
            text = "\n".join([str(report.get("summary") or ""),
                              *[str(x) for x in report.get("key_findings") or []]])
            rows = parse_worker_facts(text)
        # Per-check verdicts the specialist already reports become facts too.
        for result in report.get("hypothesis_results") or []:
            if not isinstance(result, dict):
                continue
            verdict = str(result.get("verdict") or "").lower()
            evidence = str(result.get("evidence") or "").strip()
            if not evidence:
                continue
            rows.append({"summary": f"{result.get('hypothesis_id') or 'check'} {verdict}: {evidence[:220]}",
                         "confidence": "observed" if result.get("evidence_ids") else "inferred",
                         "negative": verdict == "killed",
                         "evidence_ids": _clean_ids(result.get("evidence_ids") or [])})
        # Out-of-lane leads are handed to the planner as facts, not chased.
        for lead in report.get("leads") or []:
            if isinstance(lead, dict) and lead.get("url") and lead.get("evidence_ids"):
                rows.append({"summary": f"Lead: {lead.get('method') or 'GET'} {lead['url']}"
                                        f" — {str(lead.get('why') or '')[:160]}",
                             "confidence": "observed", "negative": False,
                             "evidence_ids": _clean_ids(lead.get("evidence_ids") or [])})
        if not rows:
            # No structured facts: keep the result as one fact so the planner
            # still sees the outcome. Only a killed verdict is a negative, and
            # without the worker's own claim of exhaustion it stays inferred.
            verdict = intent.verdict.lower()
            summary = intent.summary.strip() or f"{intent.specialist} task finished ({verdict or 'no verdict'})"
            rows = [{"summary": f"{intent.title}: {summary[:240]}",
                     "confidence": "observed" if verdict == "proven" else "inferred",
                     "negative": verdict == "killed", "evidence_ids": []}]
        for row in rows:
            fact = self.add_fact(source="task", from_intent=intent.id, target=intent.target,
                                 parameter=intent.parameter, **row)
            if fact is not None:
                intent.yields.append(fact.id)

    def _facts_view(self) -> str:
        if not self.facts:
            return "(none yet)"
        rows = [f.brief() for f in self.facts][-MAX_FACTS_IN_PROMPT:]
        return json.dumps(rows, indent=1, default=str)

    def _todo_view(self) -> str:
        if not self.todo:
            return "(empty)"
        return "\n".join(f"{'[x]' if t.get('done') else '[ ]'} {t['step']}" for t in self.todo)

    # -- planning -------------------------------------------------------------
    def _prompt(self) -> str:
        return PLANNER_PROMPT.format(
            max_intents=MAX_INTENTS_PER_ROUND, scope=self.scope_label,
            specialists=", ".join(self.specialists), objective=self.objective[:1500],
            facts=self._facts_view(), todo=self._todo_view(),
            overview=self._overview(self.intents),
        )

    def _accept(self, row: Dict[str, Any]) -> Optional[Intent]:
        title = str(row.get("title") or "").strip()[:200]
        specialist = str(row.get("specialist") or "").strip().lower()
        target = str(row.get("target") or "").strip()
        parameter = str(row.get("parameter") or "").strip()[:128]
        objective = str(row.get("objective") or "").strip()[:1500]
        differs_by = str(row.get("differs_by") or "").strip()[:300]
        known = {f.id: f for f in self.facts}
        cited = [pid for pid in _clean_ids(row.get("parent_ids") or row.get("parents") or [])]
        parents = [pid for pid in cited if pid in known]
        reason = ""
        if not title or not objective:
            reason = "missing title or objective"
        elif specialist not in self.specialists:
            reason = f"unknown specialist {specialist!r}"
        elif not target or not self._in_scope(target):
            reason = "target outside the session scope"
        elif cited and len(parents) < len(cited):
            reason = "parent_ids name facts that do not exist"
        elif self.facts and not parents:
            reason = "task cites no existing fact"
        elif len(self.intents) >= self.max_intents:
            reason = "task limit reached"
        if reason:
            self.rejected.append({"title": title, "reason": reason})
            return None
        intent = Intent(id=f"T{len(self.intents) + 1}", title=title, specialist=specialist,
                        target=target, parameter=parameter, objective=objective,
                        round=self.rounds, parents=parents, differs_by=differs_by,
                        fact_seq=len(self.facts))
        same = [i for i in self.intents if i.key() == intent.key()]
        if any(i.status in ("queued", "running") for i in same):
            self.rejected.append({"title": title, "reason": "duplicate of an existing task"})
            return None
        finished = [i for i in same if i.status in ("done", "failed")]
        if finished:
            reason = self._retry_block(finished, intent, known)
            if reason:
                self.rejected.append({"title": title, "reason": reason})
                return None
            intent.retry_of = finished[-1].id
        return intent

    def _retry_block(self, finished: List[Intent], intent: Intent, known: Dict[str, Fact]) -> str:
        """Why a retry of a finished route is refused; empty when it is allowed."""
        if not intent.differs_by:
            return "duplicate of an existing task"
        if any(i.retry_of for i in finished) or len(finished) > 1:
            return "route already retried once"
        last = finished[-1]
        new_material = any(known[pid].seq > last.fact_seq for pid in intent.parents)
        weak_negative = any(
            known[fid].negative and known[fid].confidence == "inferred"
            for fid in last.yields if fid in known)
        if new_material or weak_negative:
            return ""
        return "retry names no fact recorded after the earlier attempt"

    async def _plan_round(self) -> int:
        self.rounds += 1
        self._sync_facts()
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
        if "todo" in plan:
            self.todo = plan["todo"]
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
            self._record_worker_facts(intent, report)
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
            "facts": [f.brief() for f in self.facts][-60:],
            "todo": list(self.todo),
            "stop_reason": self.stop_reason,
            "elapsed_seconds": round(elapsed, 1),
        }


def format_summary(summary: Dict[str, Any]) -> str:
    lines = [f"Hunt engine: {summary['rounds']} planning rounds, {len(summary['tasks'])} tasks "
             f"({', '.join(f'{k}={v}' for k, v in sorted(summary['by_status'].items())) or 'none'}); "
             f"{len(summary.get('facts') or [])} facts; stopped: {summary['stop_reason']}."]
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
