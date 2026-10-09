"""CAI-style session compact, prior-hunt reload, and spend-cap helpers."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import settings
from app.services.agent.observability import redact_string

_KEEP_RECENT = 8
_MAX_BRIEF = 6000
_MAX_ANCHORS = 48
_MAX_EVIDENCE_CARDS = 12
_CONTROL_TOOLS = frozenset({
    "assessment_kickoff", "execute_interceptor", "execute_deep_crawl", "execute_katana",
    "scoped_browser_assessment", "spawn_recon_workers", "wait_recon_workers",
    "execute_feroxbuster", "execute_ffuf", "recon_worker:ferox_dirs",
    "recon_worker:katana_urls", "discover_parameters", "execute_arjun",
    "fingerprint_api", "fetch_lazy_chunks", "extract_js_endpoints",
    "sync_engagement_brain", "build_threat_model", "fireteam_dispatch",
    "check_cve_applicability", "validate_finding", "create_finding",
})
_CONTROL_ARGS = frozenset({
    "root_status", "needs_dir_brute", "operation", "pack", "kinds", "mode",
    "surface_signature", "pending_input_count", "specialists",
})
_ARTIFACT_ID = re.compile(r"[0-9a-f]{32}\Z")


def _control_anchor(step: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    name = str(step.get("tool_name") or "")
    if name not in _CONTROL_TOOLS:
        return None
    args = step.get("tool_args") if isinstance(step.get("tool_args"), dict) else {}
    safe_args = {}
    for key, value in args.items():
        if key not in _CONTROL_ARGS:
            continue
        if isinstance(value, str):
            safe_args[key] = value[:120]
        elif isinstance(value, (int, bool)):
            safe_args[key] = value
        elif key in {"kinds", "specialists"} and isinstance(value, list):
            safe_args[key] = [str(item)[:80] for item in value[:12]]
    anchor = {
        "iteration": step.get("iteration") or 0,
        "tool_name": name,
        "tool_args": safe_args,
        "success": step.get("success"),
        "compaction_anchor": True,
    }
    if name == "create_finding":
        anchor["claim_key"] = step.get("claim_key") or finding_attempt_key(args, exact=False)
        anchor["submission_key"] = step.get("submission_key") or finding_attempt_key(args, exact=True)
    if name in {"check_cve_applicability", "validate_finding", "create_finding"}:
        anchor["tool_output"] = redact_string(str(step.get("tool_output") or ""))[:2000]
    if name == "assessment_kickoff":
        anchor["tool_output"] = redact_string(str(step.get("tool_output") or ""))[:1500]
    return anchor


def finding_attempt_key(args: Dict[str, Any], *, exact: bool) -> str:
    """Retain publication attempts without copying claim text into compact state."""
    fields = ("title", "target", "description", "severity") if exact else ("title", "target")
    payload = {key: str(args.get(key) or "") for key in fields}
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def _anchor_key(anchor: Dict[str, Any]) -> tuple:
    args = anchor.get("tool_args") or {}
    return (anchor.get("tool_name"), args.get("operation"), args.get("mode"),
            args.get("surface_signature"), args.get("pack"),
            anchor.get("submission_key"), anchor.get("success"))


def _compact_anchors(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    candidates = [anchor for step in steps if (anchor := _control_anchor(step))]
    kept: List[Dict[str, Any]] = []
    seen: set[tuple] = set()
    waits = 0
    for anchor in reversed(candidates):
        if anchor["tool_name"] == "wait_recon_workers":
            if waits >= 2:
                continue
            waits += 1
        else:
            key = _anchor_key(anchor)
            if key in seen:
                continue
            seen.add(key)
        kept.append(anchor)
        if len(kept) >= _MAX_ANCHORS:
            break
    return list(reversed(kept))


def _evidence_cards(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    cards: List[Dict[str, Any]] = []
    for step in steps:
        if step.get("tool_name") == "compact_context":
            cards.extend(card for card in step.get("evidence_cards", []) if isinstance(card, dict))
        artifact_id = step.get("artifact_id")
        if isinstance(artifact_id, str) and _ARTIFACT_ID.fullmatch(artifact_id):
            args = step.get("tool_args") if isinstance(step.get("tool_args"), dict) else {}
            cards.append({
                "tool": str(step.get("tool_name") or "")[:64],
                "artifact_id": artifact_id,
                "success": step.get("success") is True,
                "hypothesis_id": str(args.get("hypothesis_id") or "")[:80],
                "coverage_cell_id": str(args.get("coverage_cell_id") or "")[:80],
            })
    unique: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for card in reversed(cards):
        artifact_id = card.get("artifact_id")
        if not isinstance(artifact_id, str) or not _ARTIFACT_ID.fullmatch(artifact_id) or artifact_id in seen:
            continue
        seen.add(artifact_id)
        unique.append(card)
        if len(unique) >= _MAX_EVIDENCE_CARDS:
            break
    return list(reversed(unique))


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
    trace: List[Dict[str, Any]], tool_args: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """Find a successful identical browser action before it can run again."""
    try:
        spec = json.loads(tool_args.get("args") or "{}")
        actions = spec.get("actions")
        if not isinstance(actions, list) or not actions:
            return None
        identity = spec.get("identity") or tool_args.get("identity") or "anonymous"
        signature = json.dumps(actions, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError, AttributeError):
        return None

    for step in reversed(trace[-24:]):
        if step.get("tool_name") != "execute_browser" or not step.get("success"):
            continue
        try:
            prior_args = step.get("tool_args") or {}
            prior_spec = json.loads(prior_args.get("args") or "{}")
            prior_actions = prior_spec.get("actions")
            prior_identity = prior_spec.get("identity") or prior_args.get("identity") or "anonymous"
            if prior_identity == identity and json.dumps(
                prior_actions, sort_keys=True, separators=(",", ":")
            ) == signature:
                return step
        except (TypeError, ValueError, AttributeError):
            continue
    return None


def compact_execution_trace(
    trace: List[Dict[str, Any]],
    *,
    keep_recent: int = _KEEP_RECENT,
) -> Tuple[List[Dict[str, Any]], str]:
    """Collapse older steps into one summary step. Returns (new_trace, brief)."""
    steps = [s for s in (trace or []) if isinstance(s, dict)]
    active = [s for s in steps if not s.get("compaction_anchor")]
    if len(active) <= keep_recent + 4:
        return steps, ""

    older, recent = active[:-keep_recent], active[-keep_recent:]
    anchors = _compact_anchors([s for s in steps if s.get("compaction_anchor")] + older)
    cards = _evidence_cards(older)
    tools = Counter()
    findings: List[str] = []
    for step in older:
        if step.get("tool_name") == "compact_context" and isinstance(step.get("tool_counts"), dict):
            tools.update({str(name): int(count) for name, count in step["tool_counts"].items()
                          if isinstance(count, int) and count > 0})
            for finding in step.get("actionable_findings") or []:
                text = redact_string(str(finding))[:240]
                if text and text not in findings:
                    findings.append(text)
            continue
        name = step.get("tool_name")
        if name:
            tools[str(name)] += 1
        for finding in step.get("actionable_findings") or []:
            text = redact_string(str(finding))[:240]
            if text and text not in findings:
                findings.append(text)

    tool_line = ", ".join(f"{n}×{c}" for n, c in tools.most_common(16)) or "none"
    finding_line = "; ".join(findings[:12]) or "none recorded"
    receipts = "; ".join(
        f"{card['tool']} {'ok' if card['success'] else 'failed'} "
        f"artifact_id={card['artifact_id']}"
        for card in cards
    )
    brief = (
        f"Compacted {len(older)} earlier steps. Tools: {tool_line}. "
        f"Actionable notes: {finding_line}."
        + (f" Evidence receipts (read_evidence for stored redacted payload): {receipts}." if receipts else "")
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
        "tool_counts": dict(tools),
        "evidence_cards": cards,
    }
    return [compact_step, *anchors, *recent], brief


def should_auto_compact(trace: List[Any], threshold: Optional[int] = None) -> bool:
    limit = threshold if threshold is not None else int(
        getattr(settings, "AGENT_COMPACT_TRACE_STEPS", 24) or 24
    )
    if limit <= 0:
        return False
    active = [s for s in (trace or []) if isinstance(s, dict) and not s.get("compaction_anchor")]
    if len(active) >= limit:
        return True
    if threshold is not None or len(active) < 12:
        return False
    last = active[-1]
    return bool(
        last.get("tool_name") == "fireteam_dispatch"
        and last.get("success") is True
        and sum(len(str(s.get("tool_output") or "")) for s in active[:-_KEEP_RECENT]) >= 6000
    )


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
