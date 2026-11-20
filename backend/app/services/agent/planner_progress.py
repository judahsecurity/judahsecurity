"""Keep the planner from paying for the same decision twice.

A ``think -> think`` hop (a gated ``complete``, a blocked phase transition, an
unparseable reply) runs no tool, so nothing in the rendered state changes. Two
helpers address that:

* Rejection feedback. A gate's reason is kept on the state, tagged with the
  execution-trace length at the time, and shown in the next planner prompt.
  It drops out on its own once a tool runs and the trace grows.
* An identical-prompt guard. The planner prompt is fingerprinted without its
  iteration counter. When the same prompt would be sent ``MAX_IDENTICAL_PLANS``
  times in a row, the turn stops instead of calling the model again.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Mapping

MAX_IDENTICAL_PLANS = 3
_MAX_FEEDBACK = 3
_MAX_FEEDBACK_CHARS = 1500

# "- **Iteration**: 4/40" (ReAct) and "- Iteration: 4/40" (pilot).
_ITERATION_LINE = re.compile(r"^- (?:\*\*)?Iteration(?:\*\*)?:.*$", re.MULTILINE)

PARSE_FAILURE_NOTE = (
    "Your previous reply was not one valid JSON decision object, so it was "
    "treated as a completion request. Reply with exactly one JSON object."
)


def _trace_len(state: Mapping[str, Any]) -> int:
    return len(state.get("execution_trace") or [])


def record_feedback(
    state: Mapping[str, Any], text: str, *, trace_len: int | None = None,
) -> list[dict]:
    """Return the state's feedback list with ``text`` appended (bounded)."""
    length = _trace_len(state) if trace_len is None else trace_len
    kept = [f for f in state.get("planner_feedback") or []
            if isinstance(f, dict) and f.get("trace_len") == length]
    entry = {"trace_len": length, "text": str(text)[:_MAX_FEEDBACK_CHARS]}
    # The same rejection again must leave the prompt unchanged, or the
    # identical-prompt guard would never see a repeat.
    kept = [f for f in kept if f.get("text") != entry["text"]]
    kept.append(entry)
    return kept[-_MAX_FEEDBACK:]


def active_feedback(state: Mapping[str, Any]) -> list[str]:
    """Rejections recorded since the last tool ran."""
    length = _trace_len(state)
    return [str(f.get("text") or "") for f in state.get("planner_feedback") or []
            if isinstance(f, dict) and f.get("trace_len") == length and f.get("text")]


def format_feedback(state: Mapping[str, Any]) -> str:
    notes = active_feedback(state)
    if not notes:
        return ""
    lines = ["## Previous decision rejected (no tool ran; change the decision)"]
    lines += [f"- {note}" for note in notes]
    return "\n".join(lines)


def prompt_fingerprint(prompt: str) -> str:
    """Hash of the planner prompt with the iteration counter removed."""
    stable = _ITERATION_LINE.sub("", prompt)
    return hashlib.sha256(stable.encode("utf-8", "replace")).hexdigest()


def repeat_count(state: Mapping[str, Any], fingerprint: str) -> int:
    """How many times in a row this prompt would now have been sent."""
    if fingerprint and fingerprint == state.get("planner_fingerprint"):
        return int(state.get("planner_repeats") or 0) + 1
    return 1


def stall_reason(state: Mapping[str, Any]) -> str:
    notes = active_feedback(state)
    detail = f" Last rejection: {notes[-1][:400]}" if notes else ""
    return (
        f"Planner made no progress: the same decision context was rejected "
        f"{MAX_IDENTICAL_PLANS - 1} times without a tool run, so the turn stopped "
        f"instead of repeating the model call. Coverage is incomplete.{detail}"
    )
