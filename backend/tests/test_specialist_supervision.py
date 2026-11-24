"""Running specialists can be corrected or stopped without losing progress."""

import asyncio
import json
from types import SimpleNamespace

import pytest

from app.services.agent import fireteam_service, orchestrator
from app.services.agent import specialist_supervision as supervision
from app.services.agent.auto_prompter import classify_failure
from app.services.agent.fireteam_service import SpecialistProfile, _run_specialist
from app.services.agent.penetration_task_graph import parse_executor_summary
from app.services.agent.tools import current_organization_id, current_session_id

TARGET = "https://app.example.test"


class _Manager:
    _credential_testing_allowed = False
    _oob_callbacks_allowed = False

    def get_tool(self, name):
        return lambda: None


def _profile():
    return SpecialistProfile(name="bounded", role="test", allowed_tools=["probe", "save_note"],
                             max_iterations=8, max_tools_per_iteration=2)


@pytest.fixture
def session():
    org = current_organization_id.set(7)
    sid = current_session_id.set("supervision-test")
    yield "supervision-test"
    current_session_id.reset(sid)
    current_organization_id.reset(org)


def _patch(monkeypatch, reply, *, succeed=True):
    prompts, kinds, calls = [], [], []

    async def fake_llm(llm, messages, *, kind="", **_):
        kinds.append(kind)
        prompts.append([getattr(m, "content", "") for m in messages])
        return SimpleNamespace(content=json.dumps(reply(kind, len(kinds))))

    async def fake_invoke(_manager, name, args, **_):
        calls.append((name, dict(args)))
        return fireteam_service.ToolInvocation(
            tool=name, args=args, success=succeed, summary="ok" if succeed else "",
            error="" if succeed else "HTTP 404")

    monkeypatch.setattr(orchestrator, "_ledger_llm_call", fake_llm)
    monkeypatch.setattr(fireteam_service, "_safe_invoke", fake_invoke)
    return prompts, kinds, calls


def _same_probe(kind, n):
    if kind == "agent_specialist_wrapup":
        return {"done": True, "summary": "wrapped", "verdict": "inconclusive",
                "progress": "probe repeated; try another input"}
    return {"tool_calls": [{"tool": "probe", "args": {"url": f"{TARGET}/x"}}]}


@pytest.mark.asyncio
async def test_repeat_is_corrected_then_stopped_through_wrap_up(monkeypatch, session):
    prompts, kinds, calls = _patch(monkeypatch, _same_probe)
    report = await _run_specialist(_profile(), "m", [TARGET], llm=None, tools_manager=_Manager())
    # Turn 2 repeats -> correction before turn 3; turn 3 repeats again -> stop.
    assert len(calls) == 3
    assert any("CORRECTION" in text and "identical arguments" in text
               for text in prompts[2])
    assert "agent_specialist_wrapup" in kinds  # leads are still written back
    assert report.stop_reason == "exhausted"
    assert report.rewrite_hint.startswith("supervisor stopped the run")
    assert supervision.running_members(session) == []  # unregistered afterwards


@pytest.mark.asyncio
async def test_failure_streak_gets_a_correction(monkeypatch, session):
    def varied(kind, n):
        if kind == "agent_specialist_wrapup":
            return {"done": True, "summary": "x", "verdict": "inconclusive"}
        if n >= 5:
            return {"done": True, "summary": "nothing", "verdict": "inconclusive"}
        return {"tool_calls": [{"tool": "probe", "args": {"url": f"{TARGET}/{n}"}}]}

    prompts, kinds, calls = _patch(monkeypatch, varied, succeed=False)
    await _run_specialist(_profile(), "m", [TARGET], llm=None, tools_manager=_Manager())
    assert any("last 3 tool calls failed (HTTP 404)" in text for text in prompts[3])


@pytest.mark.asyncio
async def test_operator_can_steer_and_stop_a_named_specialist(monkeypatch, session):
    seen = {}

    def reply(kind, n):
        if kind == "agent_specialist_wrapup":
            return {"done": True, "summary": "stopped", "verdict": "inconclusive"}
        if n == 1:
            routed = supervision.route_operator_message(
                session, "@bounded test the id parameter instead", organization_id=7)
            seen["steer"] = routed
            seen["other_org"] = supervision.route_operator_message(
                session, "@bounded x", organization_id=8)
        if n == 2:
            seen["stop"] = supervision.route_operator_message(
                session, "@stop bounded wrong host", organization_id=7)
        return {"tool_calls": [{"tool": "probe", "args": {"url": f"{TARGET}/{n}"}}]}

    prompts, kinds, calls = _patch(monkeypatch, reply)
    report = await _run_specialist(_profile(), "m", [TARGET], llm=None, tools_manager=_Manager())
    assert seen["steer"] == {"action": "steer", "target": "bounded", "matched": 1}
    assert seen["other_org"] is None  # another organization cannot reach it
    assert seen["stop"]["matched"] == 1
    assert any("[operator] test the id parameter instead" in text for text in prompts[1])
    assert report.rewrite_hint == "operator_stopped: wrong host"
    # An operator stop is final: the auto-prompter does not retry it.
    assert classify_failure(parse_executor_summary(report), report) is None


def test_messages_not_addressed_to_a_running_specialist_fall_through():
    assert supervision.route_operator_message("s", "focus on auth") is None
    assert supervision.route_operator_message("s", "@nobody hello") is None
