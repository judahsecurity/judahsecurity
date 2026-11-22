"""Advisory steering for the assessment pipeline and hunt-discipline prompts."""

from app.core.config import settings
from app.services.agent import fireteam_service
from app.services.agent.model_led import (
    always_forced,
    format_pipeline_suggestion,
    model_turns_since_forced,
    pipeline_step_due,
    steering_free_turns,
    steering_mode,
)
from app.services.agent.prompts import HUNT_DISCIPLINE_GUIDANCE, render_system_prompt

from tests.test_agent_prompt_rendering import CONTEXT

FINGERPRINT = {"tool_name": "fingerprint_api", "tool_args": {}, "thought": "fingerprint"}


def _trace(*sources):
    return [{"tool_name": f"t{i}", "decision_source": s} for i, s in enumerate(sources)]


def test_strict_mode_is_the_default_and_always_forces(monkeypatch):
    assert settings.AGENT_STEERING_MODE == "strict"
    assert steering_mode() == "strict"
    state = {"mode": "agent", "execution_trace": _trace("forced")}
    assert pipeline_step_due(state, FINGERPRINT)


def test_unknown_mode_falls_back_to_strict(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_STEERING_MODE", "loose")
    assert steering_mode() == "strict"


def test_advisory_defers_until_model_has_free_turns(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_STEERING_MODE", "advisory")
    monkeypatch.setattr(settings, "AGENT_STEERING_FREE_TURNS", 2)
    assert not pipeline_step_due({"execution_trace": _trace("forced")}, FINGERPRINT)
    assert not pipeline_step_due({"execution_trace": _trace("forced", "model")}, FINGERPRINT)
    assert pipeline_step_due({"execution_trace": _trace("forced", "model", "model")}, FINGERPRINT)


def test_model_turns_reset_at_last_forced_step():
    assert model_turns_since_forced(_trace("model", "model", "forced", "model")) == 1
    assert model_turns_since_forced(_trace("model", None, "model")) == 2
    assert model_turns_since_forced([]) == 0


def test_advisory_never_defers_mapping_proof_or_pilot(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_STEERING_MODE", "advisory")
    state = {"execution_trace": _trace("forced")}
    for name in ("execute_deep_crawl", "independent_verify", "submit_finding_candidate",
                 "create_finding", "check_cve_applicability"):
        assert pipeline_step_due(state, {"tool_name": name}), name
    crawl = {"tool_name": "scoped_browser_assessment", "tool_args": {"operation": "crawl"}}
    assert always_forced(crawl) and pipeline_step_due(state, crawl)
    xss = {"tool_name": "scoped_browser_assessment", "tool_args": {"operation": "check_xss"}}
    assert not always_forced(xss)
    assert pipeline_step_due({**state, "mode": "pilot"}, FINGERPRINT)


def test_free_turns_are_bounded(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_STEERING_FREE_TURNS", 99)
    assert steering_free_turns() == 10
    monkeypatch.setattr(settings, "AGENT_STEERING_FREE_TURNS", -3)
    assert steering_free_turns() == 0


def test_suggestion_names_the_step_and_the_deadline():
    text = format_pipeline_suggestion(FINGERPRINT, 1)
    assert "fingerprint_api" in text and "after 1 more" in text
    assert "completion stays blocked" in text


def test_hunt_discipline_prompt_is_flagged(monkeypatch):
    from app.services.agent.prompts import render_system_prompt_parts

    assert HUNT_DISCIPLINE_GUIDANCE not in render_system_prompt(mode="agent", **CONTEXT)
    assert HUNT_DISCIPLINE_GUIDANCE not in render_system_prompt_parts(mode="agent", **CONTEXT)[0]
    monkeypatch.setattr(settings, "AGENT_HUNT_DISCIPLINE_PROMPT", True)
    assert HUNT_DISCIPLINE_GUIDANCE in render_system_prompt(mode="agent", **CONTEXT)
    # The orchestrator renders with the parts API; guidance sits in the cached static block.
    assert HUNT_DISCIPLINE_GUIDANCE in render_system_prompt_parts(mode="agent", **CONTEXT)[0]
    assert HUNT_DISCIPLINE_GUIDANCE not in render_system_prompt(mode="pilot", **CONTEXT)


def test_specialist_finish_rule_follows_flag(monkeypatch):
    assert fireteam_service._specialist_finish_rule() == fireteam_service._STRICT_FINISH_RULE
    monkeypatch.setattr(settings, "AGENT_HUNT_DISCIPLINE_PROMPT", True)
    rule = fireteam_service._specialist_finish_rule()
    assert "inconclusive, not killed" in rule
    rendered = fireteam_service._SPECIALIST_SYSTEM_PROMPT.format(
        epithet="e", role="r", directive="d", mission="m", targets="t",
        tool_list="x", memory="", max_iter=5, finish_rule=rule, suffix="",
    )
    assert "Do not exceed 5 iterations. Before finishing" in rendered


def _think(monkeypatch, *, trace):
    import asyncio
    from unittest.mock import AsyncMock

    from app.services.agent import recon_workers, tester_loop
    from app.services.agent.orchestrator import AgentOrchestrator

    async def no_recon(*_args, **_kwargs):
        return []

    class ModelCalled(Exception):
        pass

    def resolve_llm(*_args, **_kwargs):
        raise ModelCalled

    monkeypatch.setattr(recon_workers, "drain_completed", no_recon)
    monkeypatch.setattr(tester_loop, "forced_next_step", lambda _state: dict(FINGERPRINT))
    orch = AgentOrchestrator()
    orch._emit_status = AsyncMock()
    orch._resolve_llm = resolve_llm
    state = {
        "user_id": "7", "session_id": "steer", "mode": "agent",
        "current_iteration": 3, "current_phase": "exploitation", "execution_trace": trace,
        "target_info": {"primary_target": "https://app.example.com"},
        "capability_map": {"target": "https://app.example.com"},
        "original_objective": "Assess https://app.example.com",
    }
    try:
        return asyncio.run(orch._think_node(state)), False
    except ModelCalled:
        return None, True


def test_think_node_strict_forces_pipeline_step(monkeypatch):
    result, model_called = _think(monkeypatch, trace=_trace("forced"))
    assert not model_called
    assert result["_decision"]["tool_name"] == "fingerprint_api"
    assert result["_current_step"]["decision_source"] == "forced"


def test_think_node_advisory_hands_turn_to_model(monkeypatch):
    from app.services.agent import orchestrator

    monkeypatch.setattr(settings, "AGENT_STEERING_MODE", "advisory")
    prompts = []
    real_render = orchestrator.render_system_prompt_parts

    def capture(**kwargs):
        prompts.append(kwargs.get("tool_recommendations", ""))
        assert "Suggested pipeline step" not in str(kwargs.get("available_tools", ""))
        return real_render(**kwargs)

    monkeypatch.setattr(orchestrator, "render_system_prompt_parts", capture)
    _, model_called = _think(monkeypatch, trace=_trace("forced"))
    assert model_called
    assert "Suggested pipeline step (advisory)" in prompts[-1]
    assert "fingerprint_api" in prompts[-1] and "after 2 more" in prompts[-1]


def test_think_node_advisory_forces_after_free_turns(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_STEERING_MODE", "advisory")
    result, model_called = _think(monkeypatch, trace=_trace("forced", "model", "model"))
    assert not model_called
    assert result["_decision"]["tool_name"] == "fingerprint_api"
