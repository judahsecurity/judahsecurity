import json
from types import SimpleNamespace

import pytest

from app.services.agent.autonomy_limits import (
    AutonomyLimits, current_autonomy_limits, limits_from_config,
)
from app.services.agent.fireteam_service import (
    SpecialistProfile, _out_of_scope_url, _run_specialist, _safe_invoke,
)
from app.services.agent.operation_directive import OperationDirective


def test_scheduled_limits_are_bounded():
    limits = limits_from_config({
        "max_specialist_tool_calls": 999,
        "max_specialist_seconds": 9999,
        "max_parallel_specialists": 99,
    })
    assert limits == AutonomyLimits(40, 600, 6)


@pytest.mark.asyncio
async def test_specialist_explicit_cross_host_url_is_rejected_before_tool_execution():
    class Manager:
        called = False

        async def execute(self, *_args):
            self.called = True
            return {"success": True}

    manager = Manager()
    assert _out_of_scope_url({"url": "https://outside.test/api"}, "https://app.example.test") == "outside.test"
    receipt = await _safe_invoke(
        manager, "replay_http_request", {"url": "https://outside.test/api"},
        scope_target="https://app.example.test",
    )
    assert receipt.error == "specialist_scope_denied"
    assert manager.called is False


@pytest.mark.asyncio
async def test_specialist_stops_at_tool_call_budget(monkeypatch):
    from app.services.agent import fireteam_service, orchestrator

    calls = []

    async def fake_llm(*_args, **_kwargs):
        return SimpleNamespace(content=json.dumps({
            "tool_calls": [{"tool": "safe_tool", "args": {}} for _ in range(3)],
        }))

    async def fake_invoke(_manager, name, args, **_kwargs):
        calls.append(name)
        return fireteam_service.ToolInvocation(
            tool=name, args=args, success=True, summary="ok",
        )

    class Manager:
        _credential_testing_allowed = False
        _oob_callbacks_allowed = False

        def get_tool(self, name):
            def tool():
                pass
            return tool

    monkeypatch.setattr(orchestrator, "_ledger_llm_call", fake_llm)
    monkeypatch.setattr(fireteam_service, "_safe_invoke", fake_invoke)
    token = current_autonomy_limits.set(AutonomyLimits(2, 10, 1))
    try:
        report = await _run_specialist(
            SpecialistProfile(name="bounded", role="Safe test", allowed_tools=["safe_tool"],
                              max_iterations=5, max_tools_per_iteration=4),
            "Assess one target", ["https://app.example.test"], llm=None,
            tools_manager=Manager(),
            directive=OperationDirective(
                specialist="bounded", epithet="Bounded", target="https://app.example.test",
                goal="Check", max_tool_calls=2, max_seconds=10,
            ),
        )
    finally:
        current_autonomy_limits.reset(token)
    assert calls == ["safe_tool", "safe_tool"]
    assert report.verdict == "inconclusive"
    assert "tool calls" in report.summary
