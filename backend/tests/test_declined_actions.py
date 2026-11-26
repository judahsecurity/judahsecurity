"""A declined approval refuses that action, but the run continues to verification."""

import asyncio

from app.services.agent.declined_actions import (
    DECLINED, action_signature, continue_note, is_declined,
)
from app.services.agent.orchestrator import AgentOrchestrator

ARGS = {"url": "https://shop.test/catalog", "method": "GET", "marker": "probe"}
BRAIN = {"candidates": [{"id": "cand-sqli", "status": "pending",
                         "vulnerability_class": "sql_injection"}]}


def _state(**extra):
    state = {
        "mode": "pilot", "session_id": "decline-test", "execution_trace": [],
        "engagement_brain": BRAIN,
        "_current_step": {"tool_name": "compare_requests", "tool_args": dict(ARGS),
                          "error_message": DECLINED, "success": False,
                          "tool_output": "declined"},
    }
    state.update(extra)
    return state


def _analyze(orch, state):
    return asyncio.run(orch._analyze_output_node(state))


def test_signature_is_stable_and_arg_sensitive():
    assert action_signature("compare_requests", ARGS) == action_signature(
        "compare_requests", dict(reversed(list(ARGS.items()))))
    assert action_signature("compare_requests", ARGS) != action_signature(
        "compare_requests", {**ARGS, "marker": "other"})
    assert is_declined([action_signature("compare_requests", ARGS)], "compare_requests", ARGS)


def test_continue_note_points_at_pending_verification():
    note = continue_note("compare_requests", 1, BRAIN)
    assert "declined" in note and "cand-sqli" in note and "independent_verify" in note


def test_one_decline_records_the_signature_and_continues():
    orch = AgentOrchestrator()
    out = _analyze(orch, _state())
    assert not out.get("task_complete")
    assert out["operator_declines"] == 1
    assert action_signature("compare_requests", ARGS) in out["declined_action_signatures"]
    # The step is kept in the trace with guidance toward verification.
    assert out["execution_trace"][-1]["output_analysis"].count("independent_verify") == 1
    assert orch._route_after_analyze({**out}) == "think"


def test_third_decline_stops_the_run():
    orch = AgentOrchestrator()
    # Two distinct inputs already declined; a third decline hits the limit.
    prior = [action_signature("compare_requests", {**ARGS, "marker": f"m{i}"}) for i in range(2)]
    out = _analyze(orch, _state(operator_declines=2, declined_action_signatures=prior))
    assert out["task_complete"] is True
    assert out["operator_declines"] == 3
    assert "declined 3 actions" in out["completion_reason"]


def test_previously_declined_action_is_refused_at_execution():
    orch = AgentOrchestrator()
    sig = action_signature("compare_requests", ARGS)
    state = {
        "mode": "pilot", "session_id": "s", "user_id": "1", "organization_id": 1,
        "current_phase": "informational", "current_iteration": 2,
        "declined_action_signatures": [sig],
        "_current_step": {"tool_name": "compare_requests", "tool_args": dict(ARGS)},
    }
    out = asyncio.run(orch._execute_tool_node(state))
    step = out["_current_step"]
    assert step["success"] is False
    assert step["error_message"] == "operator_declined_previously"
    assert "already declined" in step["tool_output"]


def test_re_decline_does_not_double_count():
    """A refused repeat (operator_declined_previously) is not a new decline."""
    orch = AgentOrchestrator()
    sig = action_signature("compare_requests", ARGS)
    state = _state(operator_declines=1, declined_action_signatures=[sig])
    state["_current_step"]["error_message"] = "operator_declined_previously"
    out = _analyze(orch, state)
    assert out["operator_declines"] == 1  # unchanged
    assert not out.get("task_complete")
