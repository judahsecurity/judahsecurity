"""Repeat-probe guard for specialist ReAct loops.

A specialist that re-issues a structurally identical (tool, args) call learns
nothing new, yet each one spends an action from the shared wall-clock budget.
Left unchecked a single lane can re-probe one parameter dozens of times and
starve every other hypothesis of time (observed: 104 repeated actions in a
36-minute run that then timed out with 101 hypotheses never attempted).

Kept dependency-free (stdlib only) so it is unit-testable without the heavy
LLM/agent imports that ``fireteam_service`` carries.
"""

from __future__ import annotations

import json
from typing import Optional


def probe_signature(tool: str, args: Optional[dict]) -> str:
    """Stable signature for a tool call, independent of key order."""
    try:
        normalized = json.dumps(args or {}, sort_keys=True, default=str)
    except (TypeError, ValueError):
        normalized = repr(args)
    return f"{tool}:{normalized}"


class RepeatGuard:
    """Track probe signatures within a single specialist run.

    ``allow`` returns False once a given (tool, args) signature has already been
    seen ``max_repeats`` times, so the caller can drop the duplicate and nudge
    the model to vary its approach instead of re-sending the same probe.
    """

    def __init__(self, max_repeats: int = 2) -> None:
        self._counts: dict[str, int] = {}
        self._max = max(1, int(max_repeats))

    def allow(self, tool: str, args: Optional[dict]) -> bool:
        sig = probe_signature(tool, args)
        self._counts[sig] = self._counts.get(sig, 0) + 1
        return self._counts[sig] <= self._max

    @property
    def duplicate_count(self) -> int:
        return sum(count - self._max for count in self._counts.values() if count > self._max)
