"""Structured tool results must survive the agent's text trace boundary."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.services.agent import evograph
from app.services.agent import orchestrator as orchestrator_module
from app.services.agent.orchestrator import (
    AgentOrchestrator, _initial_operator_note, _operator_recon_limits,
)


@pytest.mark.asyncio
async def test_manual_operator_note_blocks_automatic_directory_enrichment(monkeypatch):
    note = "Focus on manual SQLi/XSS. Avoid automated scanners and directory brute forcing."
    assert _initial_operator_note("Web App Assessment — https://example.test\nOperator note: " + note) == note
    assert _operator_recon_limits([note]) == (True, True)

    from app.services.agent import recon_workers
    spawn = AsyncMock()
    monkeypatch.setattr(recon_workers, "spawn_workers", spawn)
    orchestrator = AgentOrchestrator()
    state = {
        "mode": "agent", "session_id": "manual-only", "needs_dir_brute": True,
        "original_objective": "Web App Assessment — https://example.test",
        "operator_steers": [note],
        "target_info": {"primary_target": "https://example.test"},
        "execution_trace": [],
    }
    assert await orchestrator._maybe_spawn_dir_brute(state, {"ready_for_attack": False}) is None
    spawn.assert_not_awaited()


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
@pytest.mark.parametrize("error", ["confirmation_denied", "confirmation_expired", "pilot_policy_denied"])
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


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [
    ValueError({"message": "We were unable to start processing within the 900-second timeout limit."}),
    TimeoutError(),
])
async def test_model_analysis_failure_keeps_tool_observation_and_continues(monkeypatch, failure):
    timeouts = []

    async def unavailable(*_args, **_kwargs):
        timeouts.append(_kwargs.get("timeout"))
        raise failure

    recorded_findings = []
    monkeypatch.setattr(orchestrator_module, "_ledger_llm_call", unavailable)
    monkeypatch.setattr(evograph, "record_finding", lambda **kwargs: recorded_findings.append(kwargs))
    orchestrator = AgentOrchestrator()
    orchestrator._resolve_llm = lambda *_args: object()
    orchestrator._emit_status = AsyncMock()
    step = {
        "tool_name": "execute_interceptor",
        "tool_output": "13 named inputs observed",
        "success": True,
        "iteration": 2,
    }

    result = await orchestrator._analyze_output_node({
        "mode": "agent", "execution_trace": [], "_current_step": step,
        "current_phase": "informational", "session_id": "analysis-provider-timeout",
        "target_info": {"primary_target": "https://ginandjuice.shop"},
    })

    assert result["execution_trace"] == [step]
    assert result["_current_step"]["analysis_error"] == type(failure).__name__
    assert result["_current_step"]["actionable_findings"] == []
    assert result["target_info"]["primary_target"] == "https://ginandjuice.shop"
    assert "task_complete" not in result
    assert recorded_findings == []
    assert timeouts == [orchestrator_module.settings.AGENT_ANALYZE_TIMEOUT_SECONDS]


@pytest.mark.asyncio
async def test_structured_browser_map_skips_advisory_model_call(monkeypatch):
    async def unexpected_call(*_args, **_kwargs):
        pytest.fail("structured browser results must not call the analysis model")

    monkeypatch.setattr(orchestrator_module, "_ledger_llm_call", unexpected_call)
    monkeypatch.setattr(evograph, "record_finding", lambda **_kwargs: None)
    orchestrator = AgentOrchestrator()
    orchestrator._emit_status = AsyncMock()
    orchestrator._maybe_spawn_dir_brute = AsyncMock(return_value=False)
    cmap = {"target": "https://ginandjuice.shop", "capabilities": [], "quality_score": 0}

    result = await orchestrator._analyze_output_node({
        "mode": "agent", "execution_trace": [],
        "_current_step": {"tool_name": "execute_interceptor", "tool_output": "browser traffic",
                          "success": True, "iteration": 2, "capability_map": cmap},
        "current_phase": "informational", "session_id": "structured-browser-map",
        "target_info": {"primary_target": "https://ginandjuice.shop"},
    })

    assert result["_current_step"]["analysis_skipped"] == "structured_capability_map"
    assert result["execution_trace"][0]["tool_name"] == "execute_interceptor"
    assert result["capability_map"]["target"] == "https://ginandjuice.shop"
    assert "task_complete" not in result


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [
    TimeoutError(),
    ValueError({"message": "We were unable to start processing your request within the 900-second timeout limit."}),
])
async def test_planner_provider_timeout_reports_partial_coverage(monkeypatch, failure):
    from app.services.agent import action_ledger, recon_workers, tester_loop

    seen = []

    async def unavailable(*_args, **kwargs):
        seen.append(kwargs)
        raise failure

    async def no_recon(*_args, **_kwargs):
        return []

    monkeypatch.setattr(orchestrator_module, "_ledger_llm_call", unavailable)
    monkeypatch.setattr(recon_workers, "drain_completed", no_recon)
    monkeypatch.setattr(tester_loop, "forced_next_step", lambda _state: None)
    monkeypatch.setattr(action_ledger, "partial_report", lambda _run_id, reason: f"Partial: {reason}")
    orchestrator = AgentOrchestrator()
    orchestrator._resolve_llm = lambda *_args: object()
    orchestrator._emit_status = AsyncMock()
    state = {
        "user_id": "1", "session_id": "planner-provider-timeout",
        "mode": "agent", "current_iteration": 4,
        "current_phase": "informational", "execution_trace": [],
        "target_info": {"primary_target": "https://ginandjuice.shop"},
    }

    result = await orchestrator._think_node(state)

    assert result["task_complete"] is True
    assert "Planning model unavailable" in result["completion_reason"]
    assert result["execution_trace"] == []
    assert seen[0]["timeout"] == orchestrator_module.settings.AGENT_PLAN_TIMEOUT_SECONDS
    assert orchestrator._route_after_think(result) == "generate_response"
    report = await orchestrator._generate_response_node(result)
    assert report["messages"][0].content.startswith("Partial: Planning model unavailable")
    assert len(seen) == 1


def test_planner_timeout_classifier_does_not_hide_code_errors():
    assert not orchestrator_module._is_plan_provider_timeout(ValueError("invalid tool args"))


@pytest.mark.asyncio
async def test_planner_tries_configured_alternate_after_queue_timeout(monkeypatch):
    from app.services.agent.model_router import consume_llm_degrade_notice

    alternate = object()
    preferred = SimpleNamespace(fallbacks=[alternate], fallback_labels=["alternate:model"])
    attempted = []

    async def planning_call(model, _messages, **kwargs):
        attempted.append((model, kwargs["timeout"]))
        if model is preferred:
            raise TimeoutError()
        return "planned"

    monkeypatch.setattr(orchestrator_module, "_ledger_llm_call", planning_call)
    consume_llm_degrade_notice()

    response, chosen = await orchestrator_module._bounded_planning_call(
        preferred, [], target="https://ginandjuice.shop", phase="informational",
    )

    assert response == "planned"
    assert chosen is alternate
    assert attempted == [
        (preferred, orchestrator_module.settings.AGENT_PLAN_TIMEOUT_SECONDS),
        (alternate, orchestrator_module.settings.AGENT_PLAN_TIMEOUT_SECONDS),
    ]
    assert "alternate:model" in (consume_llm_degrade_notice() or "")
