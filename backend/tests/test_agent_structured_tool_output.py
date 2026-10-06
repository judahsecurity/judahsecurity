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
