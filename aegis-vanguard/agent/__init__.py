"""
Aegis Vanguard Agent Framework

CAI-inspired ReACT agent architecture for autonomous pentesting.
Provides tool-calling, multi-agent handoffs, guardrails, and tracing.
"""

from agent.tools import security_tool, ToolRegistry
from agent.core import Agent, AgentRunner, RunResult
from agent.guardrails import GuardrailEngine
from agent.tracing import Tracer

__all__ = [
    "security_tool", "ToolRegistry",
    "Agent", "AgentRunner", "RunResult",
    "GuardrailEngine", "Tracer",
]
