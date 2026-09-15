"""AI Agent module for autonomous security assessment."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from app.services.agent.orchestrator import AgentOrchestrator
    from app.services.agent.state import AgentState, ExecutionStep, TargetInfo

__all__ = [
    "AgentOrchestrator",
    "AgentState", 
    "ExecutionStep",
    "TargetInfo",
]


def __getattr__(name: str) -> Any:
    """Keep public imports compatible without initializing the full LLM stack."""
    if name == "AgentOrchestrator":
        from app.services.agent.orchestrator import AgentOrchestrator

        return AgentOrchestrator
    if name in {"AgentState", "ExecutionStep", "TargetInfo"}:
        from app.services.agent import state

        return getattr(state, name)
    raise AttributeError(name)
