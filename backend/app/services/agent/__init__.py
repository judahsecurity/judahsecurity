"""AI agent exports, loaded lazily for lightweight worker processes."""

from importlib import import_module

_LAZY_IMPORTS = {
    "AgentOrchestrator": ("app.services.agent.orchestrator", "AgentOrchestrator"),
    "AgentState": ("app.services.agent.state", "AgentState"),
    "ExecutionStep": ("app.services.agent.state", "ExecutionStep"),
    "TargetInfo": ("app.services.agent.state", "TargetInfo"),
}

__all__ = list(_LAZY_IMPORTS)


def __getattr__(name: str):
    target = _LAZY_IMPORTS.get(name)
    if target is None:
        raise AttributeError(name)
    module_name, attribute = target
    value = getattr(import_module(module_name), attribute)
    globals()[name] = value
    return value
