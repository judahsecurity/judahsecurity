"""Planning turns that start no check end the run instead of burning the budget."""

import asyncio

import pytest

from app.services.agent import orchestrator as orchestrator_module
from app.services.agent.orchestrator import AgentOrchestrator

IDLE = {"_decision": {"action": "complete"}, "current_iteration": 1}
TOOL = {"_decision": {"action": "use_tool", "tool_name": "send_http_request"},
        "current_iteration": 1}


def _orch(monkeypatch, step, *, background=False, limit=4):
    monkeypatch.setattr(orchestrator_module.settings, "AGENT_MAX_IDLE_PLANNING_TURNS", limit)
    orch = AgentOrchestrator()

    async def think(state, config=None):
        return dict(step)

    orch._think_node = think
    monkeypatch.setattr(AgentOrchestrator, "_background_work_pending",
                        staticmethod(lambda: background))
    return orch


def _run(orch, turns):
    state = {"session_id": "stall-test", "max_iterations": 100}
    for _ in range(turns):
        state = {**state, **asyncio.run(orch._guarded_think_node(state))}
    return state


def test_idle_turns_end_the_run_with_an_honest_reason(monkeypatch):
    orch = _orch(monkeypatch, IDLE)
    state = _run(orch, 3)
    assert not state.get("task_complete") and state["idle_planning_turns"] == 3
    state = _run_from(orch, state)
    assert state["task_complete"] is True
    assert state["completion_reason"].startswith("Planning stalled: 4")
    assert "not clean" in state["completion_reason"]
    assert orch._route_after_think(state) == "generate_response"


def _run_from(orch, state):
    return {**state, **asyncio.run(orch._guarded_think_node(state))}


def test_a_tool_call_resets_the_count(monkeypatch):
    orch = _orch(monkeypatch, TOOL)
    state = _run_from(orch, {"idle_planning_turns": 3, "max_iterations": 100})
    assert state["idle_planning_turns"] == 0
    assert not state.get("task_complete")


def test_waiting_on_background_scan_is_not_a_stall(monkeypatch):
    orch = _orch(monkeypatch, IDLE, background=True)
    state = _run(orch, 10)
    assert not state.get("task_complete")
    assert not state.get("idle_planning_turns")


def test_limit_zero_disables_the_stop(monkeypatch):
    orch = _orch(monkeypatch, IDLE, limit=0)
    assert not _run(orch, 10).get("task_complete")


@pytest.mark.parametrize("reason", ["Planning stalled: 4 planning steps in a row started no new check."])
def test_stall_triggers_budget_settlement(reason):
    from app.services.agent.settlement import settlement_applies

    assert settlement_applies(reason)
