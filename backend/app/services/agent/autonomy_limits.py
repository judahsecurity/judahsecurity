"""Execution limits carried through an opted-in scheduled agent turn."""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass


@dataclass(frozen=True)
class AutonomyLimits:
    max_specialist_tool_calls: int = 12
    max_specialist_seconds: int = 300
    max_parallel_specialists: int = 3


current_autonomy_limits: ContextVar[AutonomyLimits | None] = ContextVar(
    "current_autonomy_limits", default=None,
)


def limits_from_config(config: dict | None) -> AutonomyLimits:
    cfg = config or {}

    def bounded(key: str, default: int, upper: int) -> int:
        try:
            return max(1, min(int(cfg.get(key) or default), upper))
        except (ValueError, TypeError):
            return default

    return AutonomyLimits(
        max_specialist_tool_calls=bounded("max_specialist_tool_calls", 12, 40),
        max_specialist_seconds=bounded("max_specialist_seconds", 300, 600),
        max_parallel_specialists=bounded("max_parallel_specialists", 3, 6),
    )
