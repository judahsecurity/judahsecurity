"""
Auto-prompter — rewrite a failed hunter instead of looping the same prompt.

D-CIPHER-style: when an executor returns retry/inconclusive, soliloquizes
(no tools), or exhausts iterations, rewrite the operation directive / skill
suffix once and re-dispatch. Never retry proven/killed. Max one rewrite per
node per wave (graph.attempts vs max_attempts).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from app.services.agent.penetration_task_graph import (
    ExecutorSummary,
    NODE_RETRY,
    PenetrationTaskGraph,
)


SOLILOQUY = "soliloquy"
TOOLS_FAILED = "tools_failed"
EMPTY_VERDICT = "empty_verdict"
EXHAUSTED = "exhausted"
INCONCLUSIVE = "inconclusive"
LLM_ERROR = "llm_error"


@dataclass
class Rewrite:
    specialist: str
    failure: str
    note: str
    rewritten_test: str


def classify_failure(summary: ExecutorSummary, report: Any) -> Optional[str]:
    """Return a failure class to rewrite, or None if the run should stand."""
    if summary.verdict in ("proven", "killed"):
        return None
    if getattr(report, "error", None):
        return LLM_ERROR
    if summary.soliloquy or not summary.tools_run:
        return SOLILOQUY
    text = (summary.summary or "").lower()
    if "exhausted" in text or "without concluding" in text:
        return EXHAUSTED
    successful = [
        t
        for t in (getattr(report, "tool_calls", None) or [])
        if getattr(t, "success", False)
    ]
    if summary.tools_run and not successful:
        return TOOLS_FAILED
    if summary.verdict in ("retry", "inconclusive", "blocked") and not (summary.evidence or "").strip():
        return EMPTY_VERDICT
    if summary.verdict in ("retry", "inconclusive"):
        return INCONCLUSIVE
    return None


def rewrite_note(failure: str, summary: ExecutorSummary, directive: Any = None) -> str:
    """Concrete instruction appended to the specialist's next prompt."""
    hint = (summary.rewrite_hint or "").strip()
    goal = getattr(directive, "test", "") or getattr(directive, "goal", "") or ""
    base = {
        SOLILOQUY: (
            "AUTO-PROMPTER: previous turn invented output (no tool calls). "
            "You MUST call an allowlisted tool before any claim. "
            "status 200 is not a finding. If the first tool fails, finish with "
            "verdict=killed and evidence=the tool error — do not narrate success."
        ),
        TOOLS_FAILED: (
            "AUTO-PROMPTER: every tool call failed. Change approach: smaller args, "
            "different path from the executor slice, or kill the card with the error. "
            "Do not repeat the identical tool+args. If the target blocked you (WAF, 403, "
            "timeout), read the defense body and call compare_requests or run_custom_probe "
            "with one mutation that avoids the blocked pattern — then prove or kill."
        ),
        EMPTY_VERDICT: (
            "AUTO-PROMPTER: you returned no evidence. Execute ONE differential or "
            "procedure step from the directive, then verdict=proven|killed with "
            "tool-backed evidence. Inconclusive without a tool result is a failure. "
            "Silence is not a kill."
        ),
        INCONCLUSIVE: (
            "AUTO-PROMPTER: last verdict was inconclusive. Pick the next procedure "
            "step you have not tried. Do not re-run the same technique. If a scanner "
            "was blocked, rewrite the probe (compare_requests / run_custom_probe) "
            "instead of stopping."
        ),
        EXHAUSTED: (
            "AUTO-PROMPTER: you burned the iteration budget. Run at most two tools, "
            "then done=true with a binary verdict. Narrow to a single hypothesis id."
        ),
        LLM_ERROR: (
            "AUTO-PROMPTER: prior LLM error. Shorter JSON only: one tool_calls array "
            "or done=true. No prose outside JSON."
        ),
    }.get(failure, "AUTO-PROMPTER: try a different test than last turn.")
    extra = []
    if hint:
        extra.append(f"Hunter hint: {hint}")
    if goal:
        extra.append(f"Stay on this test: {goal[:400]}")
    if extra:
        return base + " " + " ".join(extra)
    return base


def should_rewrite(
    graph: PenetrationTaskGraph,
    summary: ExecutorSummary,
    report: Any,
) -> Optional[Rewrite]:
    failure = classify_failure(summary, report)
    if not failure:
        return None
    nodes = [
        n
        for n in graph.nodes.values()
        if n.specialist == summary.specialist and n.status in (NODE_RETRY, "running", "ready")
    ]
    if not nodes:
        nodes = [n for n in graph.nodes.values() if n.specialist == summary.specialist]
    if nodes and all(n.attempts >= n.max_attempts for n in nodes):
        return None
    note = rewrite_note(failure, summary)
    test = (nodes[0].rewritten_test if nodes else "") or note
    return Rewrite(
        specialist=summary.specialist,
        failure=failure,
        note=note,
        rewritten_test=test,
    )


def apply_rewrite_to_directive(directive: Any, rewrite: Rewrite) -> Any:
    """Mutate an OperationDirective with the rewrite note + narrowed test."""
    if directive is None:
        return None
    if rewrite.rewritten_test:
        current = getattr(directive, "test", "") or ""
        if rewrite.note not in current:
            directive.test = f"{current}\n{rewrite.note}".strip() if current else rewrite.note
    if hasattr(directive, "rewrite_note"):
        directive.rewrite_note = rewrite.note
    # Shorter retry loop
    if hasattr(directive, "max_iterations"):
        try:
            directive.max_iterations = min(int(directive.max_iterations or 6), 4)
        except (TypeError, ValueError):
            directive.max_iterations = 4
    return directive


def apply_rewrite_to_profile(profile: Any, rewrite: Rewrite) -> Any:
    """Clone-ish: append rewrite to system_prompt_suffix (caller may pass a copy)."""
    suffix = getattr(profile, "system_prompt_suffix", "") or ""
    if rewrite.note not in suffix:
        profile.system_prompt_suffix = (suffix + "\n\n" + rewrite.note).strip()
    if hasattr(profile, "max_iterations"):
        try:
            profile.max_iterations = min(int(profile.max_iterations or 6), 4)
        except (TypeError, ValueError):
            profile.max_iterations = 4
    return profile


def record_failure_approach(brain: Any, summary: ExecutorSummary, failure: str) -> None:
    try:
        from app.services.agent.engagement_brain import log_approach
    except Exception:
        return
    log_approach(
        brain,
        technique=f"auto_prompter:{failure}:{summary.specialist}",
        target=summary.hypothesis_ids[0] if summary.hypothesis_ids else summary.specialist,
        result="failed",
        detail=(summary.rewrite_hint or summary.summary or failure)[:500],
    )
