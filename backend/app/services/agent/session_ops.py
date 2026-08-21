"""CAI-style session compact, prior-hunt reload, and spend-cap helpers."""

from __future__ import annotations

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


def compact_execution_trace(
    trace: List[Dict[str, Any]],
    *,
    keep_recent: int = _KEEP_RECENT,
) -> Tuple[List[Dict[str, Any]], str]:
    """Collapse older steps into one summary step. Returns (new_trace, brief)."""
    steps = [s for s in (trace or []) if isinstance(s, dict)]
    if len(steps) <= keep_recent + 4:
        return steps, ""

    older, recent = steps[:-keep_recent], steps[-keep_recent:]
    tools = Counter()
    findings: List[str] = []
    for step in older:
        name = step.get("tool_name")
        if name:
            tools[str(name)] += 1
        for finding in step.get("actionable_findings") or []:
            text = redact_string(str(finding))[:240]
            if text and text not in findings:
                findings.append(text)

    tool_line = ", ".join(f"{n}×{c}" for n, c in tools.most_common(16)) or "none"
    finding_line = "; ".join(findings[:12]) or "none recorded"
    brief = (
        f"Compacted {len(older)} earlier steps. Tools: {tool_line}. "
        f"Actionable notes: {finding_line}."
    )[:_MAX_BRIEF]

    compact_step = {
        "iteration": older[-1].get("iteration") or 0,
        "phase": older[-1].get("phase") or "informational",
        "thought": "Context compacted to keep the hunt in-window",
        "reasoning": "CAI-style /compact — older tool output dropped, summary retained",
        "tool_name": "compact_context",
        "tool_output": brief,
        "success": True,
        "actionable_findings": findings[:8],
    }
    return [compact_step, *recent], brief


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
