"""Structured tool results must survive the agent's text trace boundary."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.services.agent import evograph
from app.services.agent.orchestrator import AgentOrchestrator


@pytest.mark.asyncio
async def test_port_probe_result_reaches_trace_and_status_as_text(monkeypatch):
    observation = {
        "host": "ginandjuice.shop",
        "protocol": "tcp",
        "observations": [{"port": 443, "state": "open", "budget_count": 1}],
    }
    orchestrator = AgentOrchestrator()
    orchestrator.tool_manager = SimpleNamespace(
        execute=AsyncMock(return_value={"success": True, "output": observation}),
        _fallback_target="",
    )
    orchestrator._emit_status = AsyncMock()
    monkeypatch.setattr(evograph, "record_step", lambda **_kwargs: None)
    monkeypatch.setattr(evograph, "get_session_chain", lambda _session_id: {})

    result = await orchestrator._execute_tool_node({
        "user_id": "1",
        "organization_id": 1,
        "session_id": "structured-tool-output-test",
        "mode": "pilot",
        "current_phase": "informational",
        "current_iteration": 2,
        "target_info": {"primary_target": "https://ginandjuice.shop"},
        "_current_step": {
            "iteration": 2,
            "phase": "informational",
            "thought": "Check priority ports",
            "tool_name": "probe_pilot_ports",
            "tool_args": {"protocol": "tcp", "ports": [443]},
        },
    })

    output = result["_current_step"]["tool_output"]
    assert isinstance(output, str)
    assert json.loads(output) == observation
    completion = [call.args[0] for call in orchestrator._emit_status.await_args_list
                  if call.args[0].get("type") == "tool_complete"]
    assert completion and completion[-1]["success"] is True
    assert completion[-1]["output_summary"].startswith('{"host":')


@pytest.mark.asyncio
async def test_duplicate_passive_browser_action_is_skipped_before_tool_execution(monkeypatch):
    from app.services.agent import action_ledger

    monkeypatch.setattr(action_ledger, "append_action", lambda *_args, **_kwargs: None)
    args = {"args": json.dumps({"actions": [
        {"action": "navigate", "url": "https://ginandjuice.shop/catalog"},
        {"action": "get_source"},
    ]})}
    orchestrator = AgentOrchestrator()
    orchestrator.tool_manager = SimpleNamespace(execute=AsyncMock(), _fallback_target="")
    orchestrator._emit_status = AsyncMock()

    result = await orchestrator._execute_tool_node({
        "user_id": "1", "organization_id": 1, "session_id": "duplicate-browser-test",
        "mode": "agent", "current_phase": "exploitation", "current_iteration": 2,
        "target_info": {"primary_target": "https://ginandjuice.shop"},
        "execution_trace": [{"tool_name": "execute_browser", "tool_args": args,
                             "success": True, "tool_output": "HTTP 200"}],
        "_current_step": {"tool_name": "execute_browser", "tool_args": args},
    })

    assert result["_current_step"]["error_message"] == "duplicate_browser_action"
    orchestrator.tool_manager.execute.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("error", ["confirmation_denied", "pilot_policy_denied"])
async def test_denied_pilot_action_stops_without_more_model_calls(error):
    orchestrator = AgentOrchestrator()
    step = {
        "tool_name": "execute_browser", "tool_output": "Approval timed out",
        "error_message": error, "success": False,
    }
    result = await orchestrator._analyze_output_node({
        "mode": "pilot", "execution_trace": [], "_current_step": step,
        "session_id": "pilot-denial-test",
    })
    assert result["task_complete"] is True
    assert result["execution_trace"] == [step]
    assert error in result["completion_reason"]
