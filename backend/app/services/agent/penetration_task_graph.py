"""
Penetration Task Graph (PTG) — swarm schedule over methodology cards.

Methodology / chain hypotheses are nodes. Edges are dependencies
(coverage waits on high-pri logic; chain cards wait on a parent finding).
Joshua (orchestrator) only schedules ready nodes. Specialists are short-lived
executors: fresh context, summary contract back to the graph — never raw
nmap dumps into the commander window.

The engagement brain remains shared memory. This graph is the planner.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from typing import Any, Dict, Iterable, List, Optional, Sequence


# Graph node status. Hypothesis.status stays open|in_progress|proven|killed;
# these are scheduler states layered on top.
NODE_PENDING = "pending"
NODE_READY = "ready"
NODE_RUNNING = "running"
NODE_PROVEN = "proven"
NODE_KILLED = "killed"
NODE_BLOCKED = "blocked"
NODE_RETRY = "retry"

_TERMINAL = {NODE_PROVEN, NODE_KILLED}
_OPEN_HYP = {"open", "in_progress"}
_HIGH_PRI = {"critical", "high"}
_COVERAGE_SPECIALISTS = {"coverage"}
_COVERAGE_METHOD_IDS = {"coverage_known_vulns"}
_JUDGE_ROLES = {"finding_judge", "independent_verifier", "risk_assessor"}

# Verdicts executors may return in the summary contract.
VALID_VERDICTS = {"proven", "killed", "blocked", "retry", "inconclusive"}


@dataclass
class TaskNode:
    """One swarm work item — usually a methodology or chain hypothesis."""

    id: str
    title: str
    specialist: str
    methodology_id: str = ""
    status: str = NODE_PENDING
    priority: str = "high"
    depends_on: List[str] = field(default_factory=list)
    attempts: int = 0
    max_attempts: int = 2
    last_failure: str = ""
    rewritten_test: str = ""
    parent_finding: str = ""
    evidence: str = ""
    source: str = "methodology"  # methodology | map | chain | spawn

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExecutorSummary:
    """Compact contract a specialist must return. Planner never sees raw tool dumps."""

    specialist: str
    hypothesis_ids: List[str] = field(default_factory=list)
    verdict: str = "inconclusive"  # proven | killed | blocked | retry | inconclusive
    evidence: str = ""
    tools_run: List[str] = field(default_factory=list)
    spawn: List[str] = field(default_factory=list)
    rewrite_hint: str = ""
    key_findings: List[str] = field(default_factory=list)
    summary: str = ""
    soliloquy: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PenetrationTaskGraph:
    nodes: Dict[str, TaskNode] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"nodes": {k: n.to_dict() for k, n in self.nodes.items()}}

    def snapshot(self) -> Dict[str, List[Dict[str, Any]]]:
        buckets: Dict[str, List[Dict[str, Any]]] = {
            "ready": [],
            "running": [],
            "blocked": [],
            "retry": [],
            "proven": [],
            "killed": [],
            "pending": [],
        }
        for n in self.nodes.values():
            row = {
                "id": n.id,
                "title": n.title,
                "specialist": n.specialist,
                "status": n.status,
                "priority": n.priority,
                "depends_on": list(n.depends_on),
                "attempts": n.attempts,
            }
            buckets.setdefault(n.status, []).append(row)
        return buckets


def graph_from_dict(data: Optional[Dict[str, Any]]) -> PenetrationTaskGraph:
    if not data:
        return PenetrationTaskGraph()
    raw_nodes = data.get("nodes") if isinstance(data, dict) else None
    if not isinstance(raw_nodes, dict):
        return PenetrationTaskGraph()
    known = {f.name for f in fields(TaskNode)}
    nodes: Dict[str, TaskNode] = {}
    for nid, raw in raw_nodes.items():
        if not isinstance(raw, dict):
            continue
        filtered = {k: v for k, v in raw.items() if k in known}
        filtered.setdefault("id", str(nid))
        nodes[str(nid)] = TaskNode(**filtered)
    return PenetrationTaskGraph(nodes=nodes)


def _is_coverage(hyp: Any) -> bool:
    mid = str(getattr(hyp, "methodology_id", "") or "").lower()
    if mid in _COVERAGE_METHOD_IDS:
        return True
    specialist = str(getattr(hyp, "specialist", "") or "")
    title = str(getattr(hyp, "title", "") or "").lower()
    return specialist in _COVERAGE_SPECIALISTS or "coverage" in title


def _hyp_status_to_node(status: str) -> str:
    if status == "proven":
        return NODE_PROVEN
    if status == "killed":
        return NODE_KILLED
    if status == "in_progress":
        return NODE_RUNNING
    return NODE_PENDING


def sync_graph_from_brain(brain: Any) -> PenetrationTaskGraph:
    """Upsert nodes from hypotheses, apply default deps, recompute ready/blocked."""
    existing = graph_from_dict(getattr(brain, "task_graph", None) or {})
    hyps = list(getattr(brain, "hypotheses", None) or [])
    by_id = {h.id: h for h in hyps}

    for h in hyps:
        node = existing.nodes.get(h.id)
        if node is None:
            node = TaskNode(
                id=h.id,
                title=h.title,
                specialist=h.specialist or "injection",
                methodology_id=getattr(h, "methodology_id", "") or "",
                priority=h.priority or "high",
                parent_finding=getattr(h, "parent_finding", "") or "",
                evidence=(h.evidence or "")[:500],
                source=getattr(h, "source", "") or "methodology",
            )
            existing.nodes[h.id] = node
        else:
            node.title = h.title
            node.specialist = h.specialist or node.specialist
            node.methodology_id = getattr(h, "methodology_id", "") or node.methodology_id
            node.priority = h.priority or node.priority
            node.parent_finding = getattr(h, "parent_finding", "") or node.parent_finding
            if h.evidence:
                node.evidence = (h.evidence or "")[:500]
            node.source = getattr(h, "source", "") or node.source

        if h.status in ("proven", "killed"):
            node.status = _hyp_status_to_node(h.status)
        elif node.status in _TERMINAL:
            pass
        elif h.status == "in_progress" and node.status not in (NODE_RETRY, NODE_RUNNING):
            node.status = NODE_RUNNING

    # Drop nodes whose hypothesis disappeared (reset).
    live = set(by_id)
    for nid in list(existing.nodes):
        if nid not in live:
            del existing.nodes[nid]

    _apply_default_dependencies(existing, hyps)
    _recompute_readiness(existing)
    brain.task_graph = existing.to_dict()
    return existing


def _apply_default_dependencies(graph: PenetrationTaskGraph, hyps: Sequence[Any]) -> None:
    """Coverage waits on high-pri logic. Chain cards wait on a parent hyp if known."""
    high_logic_ids = [
        h.id
        for h in hyps
        if h.priority in _HIGH_PRI and not _is_coverage(h) and h.source in (
            "methodology",
            "map",
            "threat_model",
        )
    ]
    title_index = {h.title.lower(): h.id for h in hyps}

    for h in hyps:
        node = graph.nodes.get(h.id)
        if not node:
            continue
        deps: List[str] = list(node.depends_on)

        if _is_coverage(h):
            for hid in high_logic_ids:
                if hid != h.id and hid not in deps:
                    deps.append(hid)

        parent = (getattr(h, "parent_finding", None) or "").strip()
        if parent:
            parent_id = title_index.get(parent.lower())
            if parent_id and parent_id != h.id and parent_id not in deps:
                deps.append(parent_id)

        node.depends_on = deps


def _deps_satisfied(graph: PenetrationTaskGraph, node: TaskNode) -> bool:
    for dep_id in node.depends_on:
        dep = graph.nodes.get(dep_id)
        if dep is None:
            continue
        # Coverage may start once deps have been attempted (running/retry/terminal),
        # not only after every logic card is proven — otherwise one stuck card
        # blocks leftovers forever. Chain cards still want a terminal parent.
        if node.source == "chain":
            if dep.status not in _TERMINAL:
                return False
        else:
            if dep.status not in _TERMINAL | {NODE_RUNNING, NODE_RETRY}:
                # First wave: coverage stays blocked until logic cards leave pending.
                if dep.status in (NODE_PENDING, NODE_READY, NODE_BLOCKED):
                    return False
    return True


def _recompute_readiness(graph: PenetrationTaskGraph) -> None:
    for node in graph.nodes.values():
        if node.status in _TERMINAL | {NODE_RUNNING}:
            continue
        if node.status == NODE_RETRY and node.attempts < node.max_attempts:
            node.status = NODE_READY
            continue
        if not _deps_satisfied(graph, node):
            node.status = NODE_BLOCKED
        elif node.status in (NODE_PENDING, NODE_BLOCKED, NODE_READY):
            node.status = NODE_READY


def ready_wave(
    graph: PenetrationTaskGraph,
    *,
    max_specialists: int = 6,
    include_app_mapper: bool = False,
) -> List[str]:
    """Specialist names whose ready nodes can run in this swarm wave."""
    pri = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    ready_nodes = [
        n
        for n in graph.nodes.values()
        if n.status == NODE_READY and n.specialist not in _JUDGE_ROLES
    ]
    ready_nodes.sort(key=lambda n: (pri.get(n.priority, 9), n.attempts, n.title))

    selected: List[str] = []
    if include_app_mapper and "app_mapper" not in selected:
        selected.append("app_mapper")
    for n in ready_nodes:
        if n.specialist and n.specialist not in selected:
            selected.append(n.specialist)
        if len(selected) >= max_specialists:
            break
    return selected[:max_specialists]


def mark_running(graph: PenetrationTaskGraph, specialists: Iterable[str]) -> None:
    wanted = set(specialists)
    for node in graph.nodes.values():
        if node.specialist in wanted and node.status == NODE_READY:
            node.status = NODE_RUNNING
            node.attempts += 1


def parse_executor_summary(report: Any) -> ExecutorSummary:
    """Build the contract from a SpecialistReport (LLM done-payload + tool log)."""
    specialist = str(getattr(report, "specialist", "") or "")
    tool_calls = list(getattr(report, "tool_calls", None) or [])
    tools_run = []
    for t in tool_calls:
        name = getattr(t, "tool", None) or (t.get("tool") if isinstance(t, dict) else None)
        if name and name not in tools_run:
            tools_run.append(str(name))

    verdict = str(getattr(report, "verdict", "") or "").strip().lower()
    if verdict not in VALID_VERDICTS:
        verdict = "inconclusive"
    hyp_ids = [str(x) for x in (getattr(report, "hypothesis_ids", None) or []) if x]
    spawn = [str(x).strip() for x in (getattr(report, "spawn", None) or []) if str(x).strip()]
    evidence = str(getattr(report, "evidence", "") or "")[:2000]
    rewrite_hint = str(getattr(report, "rewrite_hint", "") or "")[:500]
    findings = [str(x) for x in (getattr(report, "key_findings", None) or [])][:20]
    summary = str(getattr(report, "summary", "") or "")[:2000]
    soliloquy = not tool_calls and bool(summary) and not getattr(report, "error", None)

    if soliloquy and verdict in ("proven", "killed"):
        # EnIGMA: imagined success without tools is not a verdict.
        verdict = "retry"
        rewrite_hint = rewrite_hint or "soliloquy: no tool calls — do not invent output"

    return ExecutorSummary(
        specialist=specialist,
        hypothesis_ids=hyp_ids,
        verdict=verdict,
        evidence=evidence or summary[:500],
        tools_run=tools_run,
        spawn=spawn,
        rewrite_hint=rewrite_hint,
        key_findings=findings,
        summary=summary,
        soliloquy=soliloquy,
    )


def apply_executor_summary(
    graph: PenetrationTaskGraph,
    brain: Any,
    summary: ExecutorSummary,
) -> List[str]:
    """Fold a specialist contract into the graph + hypothesis cards. Returns spawn names."""
    from app.services.agent.engagement_brain import update_hypothesis

    matched = []
    if summary.hypothesis_ids:
        id_set = set(summary.hypothesis_ids)
        matched = [graph.nodes[i] for i in id_set if i in graph.nodes]
    if not matched:
        matched = [
            n
            for n in graph.nodes.values()
            if n.specialist == summary.specialist
            and n.status in (NODE_RUNNING, NODE_READY, NODE_RETRY)
        ]
    if not matched:
        matched = [
            n for n in graph.nodes.values()
            if n.specialist == summary.specialist and n.status not in _TERMINAL
        ]

    node_verdict = summary.verdict
    if node_verdict == "proven":
        node_status = NODE_PROVEN
        hyp_status = "proven"
    elif node_verdict == "killed":
        node_status = NODE_KILLED
        hyp_status = "killed"
    elif node_verdict == "retry":
        node_status = NODE_RETRY
        hyp_status = "open"
    elif node_verdict == "blocked":
        node_status = NODE_BLOCKED
        hyp_status = "open"
    else:
        node_status = NODE_RETRY
        hyp_status = "open"

    for n in matched:
        n.status = node_status
        n.evidence = (summary.evidence or n.evidence)[:2000]
        if summary.rewrite_hint:
            n.last_failure = summary.rewrite_hint[:500]
        update_hypothesis(
            brain,
            n.id,
            status=hyp_status,
            evidence=summary.evidence or None,
        )

    _recompute_readiness(graph)
    brain.task_graph = graph.to_dict()
    return list(summary.spawn or [])


def format_graph_for_scheduler(graph: PenetrationTaskGraph, *, limit: int = 8) -> str:
    """Compact PTG view for Joshua — summaries only, no scan dumps."""
    snap = graph.snapshot()
    lines = [
        "PENETRATION TASK GRAPH (schedule this; do not hunt it yourself):",
        f"  ready={len(snap['ready'])} running={len(snap['running'])} "
        f"blocked={len(snap['blocked'])} retry={len(snap['retry'])} "
        f"proven={len(snap['proven'])} killed={len(snap['killed'])}",
    ]
    for label in ("ready", "retry", "blocked", "running"):
        rows = snap.get(label) or []
        if not rows:
            continue
        lines.append(f"  {label}:")
        for row in rows[:limit]:
            deps = ",".join(row.get("depends_on") or []) or "—"
            lines.append(
                f"    - [{row['priority']}] {row['specialist']} id={row['id']} "
                f"attempts={row.get('attempts', 0)} deps={deps} | {row['title']}"
            )
    proven = snap.get("proven") or []
    killed = snap.get("killed") or []
    if proven:
        lines.append("  proven: " + "; ".join(r["title"] for r in proven[:6]))
    if killed:
        lines.append("  killed: " + "; ".join(r["title"] for r in killed[:6]))
    lines.append(
        "Next: fireteam_dispatch(specialists='auto') for ready nodes; "
        "queue_finding_followups on proven; coverage only when unblocked."
    )
    return "\n".join(lines)


def compact_scheduler_mission(mission: str, *, ready_count: int, target: str = "") -> str:
    """Strip map/brain dumps so executors get a fresh, small context window."""
    head = (mission or "").split("CAPABILITY MAP")[0].split("ENGAGEMENT BRAIN")[0].strip()
    head = head[:900]
    tgt = f" Target: {target}." if target else ""
    return (
        f"{head}{tgt}\n\n"
        f"You are a short-lived executor ({ready_count} ready this wave). "
        "Obey your OPERATION DIRECTIVE only. Return the summary contract. "
        "Do not request the full scan dump or spawn fireteams."
    )


def format_executor_slice(brain: Any, specialist: str) -> str:
    """Specialist-scoped brain slice — matching cards, creds, failed approaches."""
    hyps = [
        h
        for h in (getattr(brain, "hypotheses", None) or [])
        if getattr(h, "specialist", None) == specialist and h.status in _OPEN_HYP
    ]
    lines = [f"EXECUTOR SLICE — {specialist} ({len(hyps)} open cards)"]
    for h in hyps[:4]:
        mid = f" method={h.methodology_id}" if getattr(h, "methodology_id", "") else ""
        lines.append(f"  - id={h.id}{mid} [{h.priority}] {h.title}")
        lines.append(f"      test: {h.test}")
        lines.append(f"      pass: {h.pass_criteria} | kill: {h.kill_criteria}")
        if h.evidence:
            lines.append(f"      evidence: {h.evidence[:240]}")
    creds = list(getattr(brain, "credentials", None) or [])
    if creds:
        lines.append("Credentials (redacted; reuse if your lane needs a session):")
        for c in creds[:4]:
            view = c.redacted() if hasattr(c, "redacted") else {}
            lines.append(
                f"  - {view.get('username', '?')}:{view.get('secret', '')} "
                f"({view.get('secret_type', '')})"
            )
    approaches = [
        a
        for a in (getattr(brain, "approaches", None) or [])
        if specialist.replace("_", " ") in f"{getattr(a, 'technique', '')} {getattr(a, 'target', '')}".lower()
        or getattr(a, "result", "") == "failed"
    ]
    if approaches:
        lines.append("Failed approaches (do not repeat):")
        for a in approaches[-5:]:
            lines.append(f"  - {a.technique} @ {a.target or '?'} → {a.result}")
    return "\n".join(lines)


def persist_graph(brain: Any, graph: PenetrationTaskGraph) -> None:
    _recompute_readiness(graph)
    brain.task_graph = graph.to_dict()
