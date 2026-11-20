"""CAI-style session compact, prior-hunt reload, and spend-cap helpers."""

from __future__ import annotations

import json
import hashlib
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import settings
from app.services.agent.observability import redact_string

_KEEP_RECENT = 8
_MAX_BRIEF = 6000


def session_cost_usd(token_usage: Optional[Dict[str, Any]]) -> float:
    if not isinstance(token_usage, dict):
        return 0.0
    try:
        return float(token_usage.get("cost_usd") or 0.0)
    except (TypeError, ValueError):
        return 0.0


def price_limit_usd(session_override: Optional[float] = None) -> float:
    if session_override is not None:
        try:
            return max(0.0, float(session_override))
        except (TypeError, ValueError):
            pass
    return max(0.0, float(getattr(settings, "AGENT_PRICE_LIMIT_USD", 0) or 0))


def over_budget(token_usage: Optional[Dict[str, Any]], limit_usd: float) -> bool:
    if limit_usd <= 0:
        return False
    return session_cost_usd(token_usage) >= limit_usd


def prior_identical_browser_action(
    trace: List[Dict[str, Any]], tool_args: Dict[str, Any], *, across_run: bool = False,
) -> Optional[Dict[str, Any]]:
    """Reuse only passive browser observations; proof and writes need fresh runs."""
    wanted = _passive_browser_signature(tool_args)
    if not wanted:
        return None
    steps = reversed(trace if across_run else trace[-24:])
    for step in steps:
        if across_run and wanted in (step.get("passive_browser_signatures") or []):
            return step
        if step.get("tool_name") != "execute_browser" or not step.get("success"):
            if across_run:
                continue
            break
        if _passive_browser_signature(step.get("tool_args") or {}) == wanted:
            return step
        if not across_run:
            break
    return None


def _passive_browser_signature(tool_args: Dict[str, Any]) -> str:
    try:
        spec = json.loads(tool_args.get("args") or "{}")
        actions = spec.get("actions")
        if not isinstance(actions, list) or not actions:
            return ""
        # A matching URL is not a duplicate proof: check_xss needs a fresh
        # execution nonce, while clicks, form submits and JS can change state.
        passive = {"navigate", "get_source", "check_response"}
        if any(not isinstance(action, dict) or action.get("action") not in passive
               for action in actions):
            return ""
        identity = spec.get("identity") or tool_args.get("identity") or "anonymous"
        signature = json.dumps(
            [identity, actions], sort_keys=True, separators=(",", ":"),
        )
        return hashlib.sha256(signature.encode()).hexdigest()
    except (TypeError, ValueError, AttributeError):
        return ""


_THREAD_KEYS = ("hypothesis_id", "coverage_cell_id", "candidate_id", "goal_id", "lease_id")
_MAX_KEPT_ACTIVE = 12
_MAX_ARCHIVED_PER_THREAD = 40


def step_thread(step: Dict[str, Any]) -> str:
    """The unit of work a step belongs to, from its arguments ("" if none)."""
    args = step.get("tool_args")
    if isinstance(args, dict):
        for key in _THREAD_KEYS:
            value = args.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()[:96]
    return ""


def _archived(step: Dict[str, Any]) -> Dict[str, Any]:
    args = step.get("tool_args") if isinstance(step.get("tool_args"), dict) else {}
    return {
        "iteration": step.get("iteration"),
        "tool_name": step.get("tool_name"),
        "args": {k: redact_string(str(v))[:200] for k, v in list(args.items())[:12]},
        "success": step.get("success"),
        "thought": redact_string(str(step.get("thought") or ""))[:300],
        "output": redact_string(str(step.get("tool_output") or ""))[:1200],
        "actionable_findings": [redact_string(str(f))[:240]
                                for f in (step.get("actionable_findings") or [])[:5]],
    }


def compact_execution_trace(
    trace: List[Dict[str, Any]],
    *,
    keep_recent: int = _KEEP_RECENT,
    active_threads: Optional[set] = None,
    archive: Optional[Dict[str, List[Dict[str, Any]]]] = None,
) -> Tuple[List[Dict[str, Any]], str]:
    """Collapse older steps into one summary step. Returns (new_trace, brief).

    With ``active_threads`` (ids of hypotheses, coverage cells, candidates or
    goals still being worked), older steps of those threads are kept verbatim
    and only finished threads are folded, one digest line each. Folded steps
    go to ``archive`` (thread id -> step summaries) so ``expand_compacted``
    can bring them back.
    """
    steps = [s for s in (trace or []) if isinstance(s, dict)]
    if len(steps) <= keep_recent + 4:
        return steps, ""

    older, recent = steps[:-keep_recent], steps[-keep_recent:]
    active = {str(t) for t in (active_threads or set()) if t}
    kept_active = [step for step in older
                   if step.get("tool_name") != "compact_context"
                   and step_thread(step) in active][-_MAX_KEPT_ACTIVE:]
    kept_ids = {id(step) for step in kept_active}
    folded = [step for step in older if id(step) not in kept_ids]

    tools = Counter()
    findings: List[str] = []
    passive_signatures: set[str] = set()
    threads: Dict[str, Dict[str, Any]] = {}
    for step in folded:
        passive_signatures.update(step.get("passive_browser_signatures") or [])
        if step.get("tool_name") == "execute_browser" and step.get("success"):
            signature = _passive_browser_signature(step.get("tool_args") or {})
            if signature:
                passive_signatures.add(signature)
        name = step.get("tool_name")
        if name:
            tools[str(name)] += 1
        for finding in step.get("actionable_findings") or []:
            text = redact_string(str(finding))[:240]
            if text and text not in findings:
                findings.append(text)
        thread = step_thread(step)
        if thread and step.get("tool_name") != "compact_context":
            row = threads.setdefault(thread, {"steps": 0, "tools": Counter(), "last": ""})
            row["steps"] += 1
            row["tools"][str(name or "?")] += 1
            row["last"] = redact_string(str(step.get("thought") or step.get("tool_output") or ""))[:120]
        if archive is not None and step.get("tool_name") != "compact_context":
            bucket = archive.setdefault(thread or "unthreaded", [])
            bucket.append(_archived(step))
            del bucket[:-_MAX_ARCHIVED_PER_THREAD]

    tool_line = ", ".join(f"{n}×{c}" for n, c in tools.most_common(16)) or "none"
    finding_line = "; ".join(findings[:12]) or "none recorded"
    thread_lines = [
        f"{thread}: {row['steps']} step(s) ("
        + ", ".join(f"{n}×{c}" for n, c in row["tools"].most_common(4))
        + f"); last: {row['last']}"
        for thread, row in list(threads.items())[-20:]
    ]
    brief = (
        f"Compacted {len(folded)} earlier steps. Tools: {tool_line}. "
        f"Actionable notes: {finding_line}."
        + (" Finished threads (expand_compacted(thread_id) restores them): "
           + " | ".join(thread_lines) if thread_lines else "")
        + (f" Kept {len(kept_active)} older step(s) of active work verbatim." if kept_active else "")
    )[:_MAX_BRIEF]

    compact_step = {
        "iteration": older[-1].get("iteration") or 0,
        "phase": older[-1].get("phase") or "informational",
        "thought": "Context compacted to keep the hunt in-window",
        "reasoning": "CAI-style /compact — finished threads folded, active work kept",
        "tool_name": "compact_context",
        "tool_output": brief,
        "success": True,
        "actionable_findings": findings[:8],
        "passive_browser_signatures": sorted(passive_signatures)[:100],
        "folded_threads": sorted(threads)[:50],
    }
    return [compact_step, *kept_active, *recent], brief


def active_threads_from_brain(brain: Any) -> set:
    """Ids of work still in progress: compaction keeps their steps verbatim."""
    from app.services.agent.engagement_brain import engagement_brain_from_dict

    if isinstance(brain, dict) or brain is None:
        brain = engagement_brain_from_dict(brain)
    active: set = set()
    active.update(h.id for h in brain.hypotheses if h.status in ("open", "in_progress"))
    for cell in brain.coverage_cells or []:
        if isinstance(cell, dict) and cell.get("status") == "leased":
            active.update(filter(None, (cell.get("id"), cell.get("lease_id"))))
    for row in brain.candidates or []:
        if isinstance(row, dict) and row.get("status") in ("pending", "inconclusive"):
            active.add(row.get("id"))
    for goal in brain.engagement_goals or []:
        if isinstance(goal, dict) and goal.get("status") == "open":
            active.add(goal.get("id"))
    return {str(value) for value in active if value}


def should_auto_compact(trace: List[Any], threshold: Optional[int] = None) -> bool:
    limit = threshold if threshold is not None else int(
        getattr(settings, "AGENT_COMPACT_TRACE_STEPS", 24) or 24
    )
    if limit <= 0:
        return False
    return len([s for s in (trace or []) if isinstance(s, dict)]) >= limit


def format_prior_hunt_brief(
    *,
    source_session_id: str,
    title: Optional[str] = None,
    execution_summary: Optional[str] = None,
    engagement_replay: Optional[List[Any]] = None,
    messages: Optional[List[Any]] = None,
) -> str:
    """Build an in-context brief from a saved conversation (CAI /load analog)."""
    lines = [f"## Prior hunt loaded from session {source_session_id[:12]}"]
    if title:
        lines.append(f"Title: {redact_string(str(title))[:200]}")
    if execution_summary:
        lines.append(redact_string(str(execution_summary))[:1500])

    replay_lines: List[str] = []
    for step in (engagement_replay or [])[-12:]:
        if not isinstance(step, dict):
            continue
        tool = step.get("tool_name") or "thought"
        thought = redact_string(str(step.get("thought") or ""))[:160]
        evidence = step.get("evidence") or []
        ev = "; ".join(redact_string(str(e))[:120] for e in evidence[:3] if e)
        bit = f"- {tool}: {thought}"
        if ev:
            bit += f" | {ev}"
        replay_lines.append(bit)
    if replay_lines:
        lines.append("Recent steps:")
        lines.extend(replay_lines)

    last_user = ""
    for msg in reversed(messages or []):
        if isinstance(msg, dict) and msg.get("role") == "user":
            last_user = redact_string(str(msg.get("content") or ""))[:400]
            break
    if last_user:
        lines.append(f"Last operator prompt: {last_user}")

    lines.append(
        "Use this as starting context. Do not re-run the same scanners unless "
        "the operator asked you to. Pivot from open hypotheses and leftovers."
    )
    return "\n".join(lines)[:_MAX_BRIEF]


def load_prior_conversation_brief(
    db,
    organization_id: int,
    source_session_id: str,
) -> str:
    """Load a prior AgentConversation for this org into a compact brief."""
    from app.models.agent_conversation import AgentConversation

    conv = (
        db.query(AgentConversation)
        .filter(
            AgentConversation.session_id == source_session_id,
            AgentConversation.organization_id == organization_id,
        )
        .first()
    )
    if not conv:
        return ""
    return format_prior_hunt_brief(
        source_session_id=source_session_id,
        title=conv.title,
        execution_summary=conv.execution_summary,
        engagement_replay=conv.engagement_replay,
        messages=conv.messages,
    )
