"""Deep assessment mode: larger budgets and model-led steps, same gates."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from langchain_core.messages import AIMessage

from app.services.agent import assessment_depth as depth_module
from app.services.agent import orchestrator as orchestrator_module
from app.services.agent.assessment_depth import (
    DEEP,
    STANDARD,
    assessment_depth,
    current_assessment_depth,
    fireteam_dispatch_cap,
    hunter_budget,
    pipeline_step_is_advisory,
    resolve_assessment_depth,
    set_assessment_depth,
)
from app.services.agent.orchestrator import AgentOrchestrator


@pytest.fixture
def deep():
    token = set_assessment_depth("deep")
    try:
        yield
    finally:
        current_assessment_depth.reset(token)


def test_resolve_uses_request_then_configured_default(monkeypatch):
    assert resolve_assessment_depth("deep") is DEEP
    assert resolve_assessment_depth("DEEP") is DEEP
    assert resolve_assessment_depth("bogus") is STANDARD
    monkeypatch.setattr(orchestrator_module.settings, "AGENT_ASSESSMENT_MODE", "deep")
    assert resolve_assessment_depth(None) is DEEP
    monkeypatch.setattr(orchestrator_module.settings, "AGENT_ASSESSMENT_MODE", "standard")
    assert resolve_assessment_depth(None) is STANDARD


def test_standard_mode_keeps_existing_budgets():
    assert assessment_depth() is STANDARD
    assert hunter_budget(64) == 64
    assert fireteam_dispatch_cap(600) == 600
    assert not pipeline_step_is_advisory("fireteam_dispatch", 0)


def test_deep_mode_scales_hunter_budgets_and_dispatch_cap(deep):
    assert hunter_budget(64) == 64 * DEEP.hunter_budget_factor
    assert fireteam_dispatch_cap(600) == DEEP.fireteam_timeout_seconds
    assert fireteam_dispatch_cap(5000) == 5000


def test_pilot_and_scheduled_autonomy_stay_standard(deep):
    from app.services.agent.autonomy_limits import AutonomyLimits, current_autonomy_limits
    from app.services.agent import pilot_policy

    assert assessment_depth() is DEEP
    token = current_autonomy_limits.set(AutonomyLimits())
    try:
        assert assessment_depth() is STANDARD
        assert hunter_budget(64) == 64
    finally:
        current_autonomy_limits.reset(token)

    original = pilot_policy.current_pilot
    pilot_policy.current_pilot = lambda: object()
    try:
        assert assessment_depth() is STANDARD
    finally:
        pilot_policy.current_pilot = original


def test_recon_and_publication_steps_are_always_forced(deep):
    for tool in ("execute_deep_crawl", "sync_engagement_brain", "independent_verify",
                 "submit_finding_candidate", "create_finding"):
        assert not pipeline_step_is_advisory(tool, 0), tool
    assert pipeline_step_is_advisory("fireteam_dispatch", 0)
    assert pipeline_step_is_advisory("probe_observed_input_batch", DEEP.advisory_decline_limit - 1)
    # A model that keeps declining gets the pipeline step forced.
    assert not pipeline_step_is_advisory("fireteam_dispatch", DEEP.advisory_decline_limit)


def test_specialist_turns_scale_with_depth(monkeypatch, deep):
    from app.services.agent.fireteam_service import _scaled_turns

    monkeypatch.setattr(orchestrator_module.settings, "AGENT_SPECIALIST_TURN_MULTIPLIER", 1.0)
    assert _scaled_turns(8) == 8 * int(DEEP.specialist_turn_factor)
    monkeypatch.setattr(orchestrator_module.settings, "AGENT_SPECIALIST_TURN_MULTIPLIER", 4.0)
    assert _scaled_turns(8) == 8 * int(DEEP.specialist_turn_cap)


def test_standard_specialist_turns_unchanged(monkeypatch):
    from app.services.agent.fireteam_service import _scaled_turns

    monkeypatch.setattr(orchestrator_module.settings, "AGENT_SPECIALIST_TURN_MULTIPLIER", 1.0)
    assert _scaled_turns(8) == 8
    monkeypatch.setattr(orchestrator_module.settings, "AGENT_SPECIALIST_TURN_MULTIPLIER", 9.0)
    assert _scaled_turns(8) == 32


def test_hunter_post_budget_scales_but_verifier_budget_does_not(deep):
    from app.services.agent.evidence_store import verification_run
    from app.services.agent.scoped_assessment_tools import (
        HUNTER_POST_BUDGET, VERIFIER_POST_BUDGET, ScopedAssessmentTools,
    )

    manager = SimpleNamespace()
    claim = ScopedAssessmentTools._scoped_claim_posts
    claim(manager, HUNTER_POST_BUDGET + 1)  # over the standard hunter budget
    with pytest.raises(ValueError):
        claim(manager, HUNTER_POST_BUDGET * DEEP.hunter_budget_factor)

    token = verification_run.set("verify-1")
    try:
        claim(manager, VERIFIER_POST_BUDGET)
        with pytest.raises(ValueError):
            claim(manager, 1)
    finally:
        verification_run.reset(token)


def test_specialist_opening_is_bare_in_standard_and_seeded_in_deep():
    from app.services.agent.fireteam_service import (
        PeerTraceBoard, ToolInvocation, _specialist_opening,
    )

    board = PeerTraceBoard()
    board.record("run-a", "web_recon", [ToolInvocation(
        tool="execute_curl", args={}, success=True,
        summary="GET /api/v2/users returns 200 with an internal_id field",
    )])
    manager = SimpleNamespace(_peer_trace_board=board, _engagement_brain={})
    assert _specialist_opening(manager, "api_authz") == "Begin."

    token = set_assessment_depth("deep")
    try:
        opening = _specialist_opening(manager, "api_authz")
        assert "internal_id" in opening
        assert opening.endswith("Begin.")
        # A specialist is not shown its own results.
        assert "internal_id" not in _specialist_opening(manager, "web_recon")
    finally:
        current_assessment_depth.reset(token)


async def _think_with(monkeypatch, *, state_extra, model_tool):
    from app.services.agent import recon_workers, tester_loop

    async def no_recon(*_args, **_kwargs):
        return []

    prompts = []

    async def planning_call(llm, messages, **_kwargs):
        prompts.append(messages[0].content)
        return AIMessage(content=json.dumps({
            "thought": "Chase the reflected internal_id first",
            "reasoning": "A stronger lead than the queued wave",
            "action": "use_tool",
            "tool_name": model_tool,
            "tool_args": {"url": "https://example.test/api/v2/users"},
        })), llm

    monkeypatch.setattr(recon_workers, "drain_completed", no_recon)
    monkeypatch.setattr(tester_loop, "forced_next_step", lambda _state: {
        "tool_name": "fireteam_dispatch",
        "tool_args": {"mode": "attack"},
        "thought": "Dispatch the ready hypothesis wave",
    })
    monkeypatch.setattr(orchestrator_module, "_bounded_planning_call", planning_call)
    orchestrator = AgentOrchestrator()
    orchestrator._emit_status = AsyncMock()
    orchestrator._resolve_llm = lambda *_args: object()
    state = {
        "user_id": "1", "session_id": "deep-advisory",
        "mode": "agent", "current_iteration": 5,
        "current_phase": "exploitation", "execution_trace": [],
        "target_info": {"primary_target": "https://example.test"},
        **state_extra,
    }
    return await orchestrator._think_node(state), prompts


@pytest.mark.asyncio
async def test_standard_mode_forces_the_pipeline_step(monkeypatch):
    result, prompts = await _think_with(monkeypatch, state_extra={}, model_tool="execute_curl")
    assert result["_current_step"]["tool_name"] == "fireteam_dispatch"
    assert result["_current_step"]["decision_source"] == "forced"
    assert prompts == []


@pytest.mark.asyncio
async def test_deep_mode_lets_the_model_decline_then_forces(monkeypatch, deep):
    result, prompts = await _think_with(
        monkeypatch, state_extra={"pipeline_advisory_declines": 0}, model_tool="execute_curl",
    )
    assert result["_current_step"]["tool_name"] == "execute_curl"
    assert result["_current_step"]["decision_source"] == "model"
    assert result["pipeline_advisory_declines"] == 1
    assert "you choose the next step" in prompts[0]
    assert "fireteam_dispatch" in prompts[0]

    result, prompts = await _think_with(
        monkeypatch,
        state_extra={"pipeline_advisory_declines": DEEP.advisory_decline_limit},
        model_tool="execute_curl",
    )
    assert result["_current_step"]["tool_name"] == "fireteam_dispatch"
    assert result["pipeline_advisory_declines"] == 0
    assert prompts == []


@pytest.mark.asyncio
async def test_deep_mode_following_the_suggestion_resets_declines(monkeypatch, deep):
    result, _ = await _think_with(
        monkeypatch, state_extra={"pipeline_advisory_declines": 2}, model_tool="fireteam_dispatch",
    )
    assert result["_current_step"]["tool_name"] == "fireteam_dispatch"
    assert result["pipeline_advisory_declines"] == 0


def test_org_default_mode_reads_project_settings(monkeypatch):
    from app.services.agent import assessment_depth as mod

    class FakeSettings:
        @staticmethod
        def get_config(db, org_id, module):
            return {"assessment_mode": "deep"} if org_id == 7 else {}

    class FakeSession:
        def __enter__(self): return object()
        def __exit__(self, *a): return False

    monkeypatch.setitem(__import__("sys").modules, "app.models.project_settings",
                        type("M", (), {"MODULE_AGENT": "agent", "ProjectSettings": FakeSettings}))
    monkeypatch.setitem(__import__("sys").modules, "app.db.database",
                        type("M", (), {"SessionLocal": FakeSession}))
    assert mod.resolve_org_default_mode(7) == "deep"
    assert mod.resolve_org_default_mode(1) is None       # no setting
    assert mod.resolve_org_default_mode(None) is None     # no org


def test_org_default_mode_ignores_invalid_values(monkeypatch):
    from app.services.agent import assessment_depth as mod

    class FakeSettings:
        @staticmethod
        def get_config(db, org_id, module):
            return {"assessment_mode": "turbo"}

    class FakeSession:
        def __enter__(self): return object()
        def __exit__(self, *a): return False

    monkeypatch.setitem(__import__("sys").modules, "app.models.project_settings",
                        type("M", (), {"MODULE_AGENT": "agent", "ProjectSettings": FakeSettings}))
    monkeypatch.setitem(__import__("sys").modules, "app.db.database",
                        type("M", (), {"SessionLocal": FakeSession}))
    assert mod.resolve_org_default_mode(7) is None


def test_depth_module_documents_unchanged_gates():
    doc = depth_module.__doc__ or ""
    for phrase in ("scope enforcement", "proof policy", "pilot mode"):
        assert phrase in doc
