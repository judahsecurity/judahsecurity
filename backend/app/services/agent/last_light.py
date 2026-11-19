"""Last light: the final report always says what this run did not cover.

When a run ends on a budget, a time limit, an iteration cap or an operator
stop, the model-written report tends to describe what was found and stay
silent on what was never looked at. A reader then takes an untested class for
a clean one.

:func:`coverage_gaps` reads the engagement brain and the tester-loop checklist
and lists, deterministically:

* coverage cells still open (untested, in focus, inconclusive, leased, blocked),
  grouped by test class;
* hypotheses still open or in progress;
* finding candidates still waiting on, or inconclusive at, independent verify;
* tester-loop steps that never ran.

:func:`append_gaps` adds that list to the final answer. It is not generated
by the model, so it cannot be dropped or softened.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Optional

_OPEN_CELL = frozenset({"untested", "in_focus", "inconclusive", "leased", "blocked"})
_MAX_ITEMS = 8


def _get(row: Any, key: str, default: Any = "") -> Any:
    if isinstance(row, dict):
        return row.get(key, default)
    return getattr(row, key, default)


def coverage_gaps(state: Optional[dict]) -> dict:
    state = state or {}
    brain = state.get("engagement_brain") or {}
    cells = [c for c in brain.get("coverage_cells") or [] if isinstance(c, dict)]
    open_cells = [c for c in cells if str(c.get("status") or "untested") in _OPEN_CELL]
    by_class = Counter(str(c.get("test_type") or "unclassified") for c in open_cells)
    by_status = Counter(str(c.get("status") or "untested") for c in open_cells)
    hypotheses = [
        h for h in brain.get("hypotheses") or []
        if str(_get(h, "status", "open")) in ("open", "in_progress")
    ]
    candidates = [
        c for c in brain.get("candidates") or []
        if str(_get(c, "status", "pending")) in ("pending", "inconclusive")
    ]
    missing_steps: list[dict] = []
    try:
        from app.services.agent.tester_loop import tester_loop_progress

        progress = tester_loop_progress(state) if state.get("mode") == "agent" else {}
        if progress.get("is_web"):
            missing_steps = list(progress.get("missing") or [])
    except Exception:
        missing_steps = []
    return {
        "open_cells": len(open_cells),
        "open_cells_by_class": dict(by_class.most_common()),
        "open_cells_by_status": dict(by_status),
        "total_cells": len(cells),
        "open_hypotheses": [str(_get(h, "title")) for h in hypotheses],
        "unverified_candidates": [
            f"{_get(c, 'title')} ({_get(c, 'status', 'pending')})" for c in candidates
        ],
        "missing_steps": [str(m.get("title") or m.get("id")) for m in missing_steps],
    }


def has_gaps(gaps: dict) -> bool:
    return bool(gaps.get("open_cells") or gaps.get("open_hypotheses")
                or gaps.get("unverified_candidates") or gaps.get("missing_steps"))


def _bullets(items: list[str]) -> list[str]:
    shown = [f"  - {item}" for item in items[:_MAX_ITEMS]]
    if len(items) > _MAX_ITEMS:
        shown.append(f"  - … and {len(items) - _MAX_ITEMS} more")
    return shown


def format_gaps(gaps: dict, completion_reason: str = "") -> str:
    if not has_gaps(gaps):
        return ""
    lines = ["## Not covered in this run"]
    if completion_reason:
        lines.append(f"Run ended: {completion_reason}.")
    lines.append("Nothing below was shown to be clean; treat it as untested.")
    if gaps["open_cells"]:
        classes = ", ".join(f"{k} ({v})" for k, v in gaps["open_cells_by_class"].items())
        lines.append(f"- Coverage cells still open: {gaps['open_cells']} of {gaps['total_cells']} — {classes}")
    if gaps["open_hypotheses"]:
        lines.append(f"- Hypotheses not proven or killed: {len(gaps['open_hypotheses'])}")
        lines.extend(_bullets(gaps["open_hypotheses"]))
    if gaps["unverified_candidates"]:
        lines.append(f"- Candidates not independently confirmed: {len(gaps['unverified_candidates'])}")
        lines.extend(_bullets(gaps["unverified_candidates"]))
    if gaps["missing_steps"]:
        lines.append("- Assessment steps that never ran:")
        lines.extend(_bullets(gaps["missing_steps"]))
    return "\n".join(lines)


def append_gaps(answer: str, state: Optional[dict], completion_reason: str = "") -> str:
    """Append the gap list for autonomous and pilot runs; chat answers are left alone."""
    if (state or {}).get("mode") not in ("agent", "pilot"):
        return answer
    try:
        block = format_gaps(coverage_gaps(state), completion_reason)
    except Exception:
        block = ("## Not covered in this run\nCoverage gaps could not be computed; "
                 "treat any class not reported as tested as untested.")
    if not block:
        return answer
    return f"{answer.rstrip()}\n\n{block}"


__all__ = ["append_gaps", "coverage_gaps", "format_gaps", "has_gaps"]
