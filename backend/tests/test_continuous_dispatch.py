"""Continuous fireteam refill and signal-earned specialist budgets."""

import asyncio
import json
from types import SimpleNamespace

import pytest

from app.services.agent import fireteam_service
from app.services.agent.autonomy_limits import (
    AutonomyLimits, SignalBonusPool, current_autonomy_limits,
    current_signal_bonus_pool, limits_from_config,
)
from app.services.agent.fireteam_service import (
    SpecialistProfile, SpecialistReport, ToolInvocation, _run_specialist,
    invocation_has_signal, run_fireteam,
)
from app.services.agent.operation_directive import OperationDirective

TARGET = "https://app.example.test"


def _fake_members(monkeypatch, delays):
    started = []

    async def specialist(profile, mission, targets, llm, tools_manager,
                         directive=None, execution_progress=None):
        started.append(profile.name)
        await asyncio.sleep(delays.get(profile.name, 0))
        return SpecialistReport(
            specialist=profile.name, role=profile.role, mission=mission,
            summary="completed", lease_id=getattr(directive, "lease_id", ""),
        )

    monkeypatch.setattr(fireteam_service, "_run_specialist", specialist)
    return started


def _profile(name):
    return SpecialistProfile(name=name, role=name, allowed_tools=[])


@pytest.mark.asyncio
async def test_finished_member_frees_a_slot_for_newly_ready_work(monkeypatch):
    started = _fake_members(monkeypatch, {"slow": 0.3})
    refill_calls = []

    async def refill(report):
        refill_calls.append(report.specialist)
        if report.specialist == "quick":
            return [(_profile("follow_up"), SimpleNamespace(lease_id="lease-2", max_seconds=0))]
        return []

    result = await run_fireteam(
        mission="m", targets=[TARGET],
        specialists=[_profile("quick"), _profile("slow")],
        llm=None, tools_manager=None, max_parallel=2,
        refill=refill, min_refill_seconds=0.1,
        member_timeout_sec=5, wave_timeout_sec=5,
    )
    # follow_up started while slow was still running, not after the wave.
    assert started[:3] == ["quick", "slow", "follow_up"]
    assert started.index("follow_up") < len(started)
    assert [r.specialist for r in result.reports] == ["quick", "slow", "follow_up"]
    assert all(r.summary == "completed" for r in result.reports)
    assert result.reports[2].lease_id == "lease-2"
    assert "quick" in refill_calls and "follow_up" in refill_calls


@pytest.mark.asyncio
async def test_no_refill_when_too_little_wave_time_remains(monkeypatch):
    _fake_members(monkeypatch, {})
    called = []

    async def refill(report):
        called.append(report.specialist)
        return [(_profile("late"), None)]

    result = await run_fireteam(
        mission="m", targets=[TARGET], specialists=[_profile("quick")],
        llm=None, tools_manager=None, refill=refill,
        min_refill_seconds=90, member_timeout_sec=5, wave_timeout_sec=5,
    )
    assert called == []
    assert [r.specialist for r in result.reports] == ["quick"]


@pytest.mark.asyncio
async def test_refill_failure_does_not_lose_running_members(monkeypatch):
    _fake_members(monkeypatch, {"slow": 0.1})

    async def refill(report):
        raise RuntimeError("graph unavailable")

    result = await run_fireteam(
        mission="m", targets=[TARGET], specialists=[_profile("quick"), _profile("slow")],
        llm=None, tools_manager=None, refill=refill, min_refill_seconds=0.01,
        member_timeout_sec=5, wave_timeout_sec=5,
    )
    assert [r.summary for r in result.reports] == ["completed", "completed"]


def test_only_candidates_and_proof_leads_count_as_signals():
    def inv(tool="probe", success=True, summary="ok"):
        return ToolInvocation(tool=tool, args={}, success=success, summary=summary)

    assert invocation_has_signal(inv("submit_finding_candidate"))
    assert invocation_has_signal(inv(summary=json.dumps({"verdict": "LIKELY_IMPACT"})))
    assert invocation_has_signal(inv(summary=json.dumps({"proof_escalation": {"id": "e1"}})))
    assert not invocation_has_signal(inv(summary=json.dumps({"proof_escalation": None})))
    assert not invocation_has_signal(inv(summary=json.dumps({"verdict": "NO_SIGNAL"})))
    assert not invocation_has_signal(inv("submit_finding_candidate", success=False))
    assert not invocation_has_signal(inv(summary="200 OK, evidence_id=abc"))


def test_bonus_pool_is_shared_and_capped_per_specialist():
    pool = SignalBonusPool(total=10, step=4)
    assert pool.grant("xss", base=2) == 4       # cap: 2 * (3 - 1) = 4 extra
    assert pool.grant("xss", base=2) == 0
    assert pool.grant("sqli", base=12) == 4
    assert pool.grant("sqli", base=12) == 2     # pool exhausted
    assert pool.grant("api_authz", base=12) == 0
    assert SignalBonusPool(total=10, step=0).grant("xss", base=12) == 0


def test_bonus_limits_round_trip_and_allow_zero():
    stored = limits_from_config({"signal_bonus_pool": 0, "signal_bonus_step": 6}, target=TARGET).__dict__
    limits = limits_from_config(stored, target=TARGET)
    assert (limits.signal_bonus_pool, limits.signal_bonus_step) == (0, 6)
    capped = limits_from_config({"signal_bonus_pool": 10 ** 6, "signal_bonus_step": 99})
    assert (capped.signal_bonus_pool, capped.signal_bonus_step) == (200, 20)
    assert limits_from_config({}).signal_bonus_pool == 24


class _Manager:
    _credential_testing_allowed = False
    _oob_callbacks_allowed = False

    def get_tool(self, name):
        def tool():
            pass
        return tool


async def _run_bounded(monkeypatch, *, signal_on_call, pool):
    from app.services.agent import orchestrator

    calls = []
    prompts = []

    async def fake_llm(_llm, messages, **_kwargs):
        prompts.append(messages[-1].content)
        return SimpleNamespace(content=json.dumps({
            "tool_calls": [{"tool": "safe_tool", "args": {}}],
        }))

    async def fake_invoke(_manager, name, args, **_kwargs):
        calls.append(name)
        summary = json.dumps({"verdict": "LIKELY_IMPACT"}) if len(calls) == signal_on_call else "ok"
        return ToolInvocation(tool=name, args=args, success=True, summary=summary)

    monkeypatch.setattr(orchestrator, "_ledger_llm_call", fake_llm)
    monkeypatch.setattr(fireteam_service, "_safe_invoke", fake_invoke)
    token = current_autonomy_limits.set(AutonomyLimits(2, 10, 1))
    pool_token = current_signal_bonus_pool.set(pool)
    try:
        report = await _run_specialist(
            SpecialistProfile(name="bounded", role="Safe test", allowed_tools=["safe_tool"],
                              max_iterations=10, max_tools_per_iteration=1),
            "Assess one target", [TARGET], llm=None, tools_manager=_Manager(),
            directive=OperationDirective(
                specialist="bounded", epithet="Bounded", target=TARGET,
                goal="Check", max_tool_calls=2, max_seconds=10, max_iterations=10,
            ),
        )
    finally:
        current_signal_bonus_pool.reset(pool_token)
        current_autonomy_limits.reset(token)
    return report, calls, prompts


@pytest.mark.asyncio
async def test_signal_extends_specialist_budget(monkeypatch):
    pool = SignalBonusPool(total=24, step=2)
    report, calls, prompts = await _run_bounded(monkeypatch, signal_on_call=1, pool=pool)
    assert len(calls) == 4                      # base 2 + 2 earned
    assert report.bonus_tool_calls == 2
    assert pool.remaining == 22
    assert any("budget_extended" in str(p) for p in prompts)
    assert "tool calls" in report.summary


@pytest.mark.asyncio
async def test_no_signal_keeps_base_budget(monkeypatch):
    pool = SignalBonusPool(total=24, step=2)
    report, calls, _ = await _run_bounded(monkeypatch, signal_on_call=0, pool=pool)
    assert len(calls) == 2
    assert report.bonus_tool_calls == 0
    assert pool.remaining == 24


@pytest.mark.asyncio
async def test_bonus_requests_raise_the_request_gate():
    from app.services.agent.fireteam_service import _SpecialistBudget

    budget = _SpecialistBudget(OperationDirective(
        specialist="x", epithet="X", target=TARGET, goal="g",
        max_requests=1, interval_ms=0,
    ))
    assert await budget.acquire("get_coverage", {}) == ""
    assert await budget.acquire("get_coverage", {}) == "specialist_request_budget_exhausted"
    budget.bonus_requests = 1
    assert await budget.acquire("get_coverage", {}) == ""


# --- fireteam_dispatch leases unblocked work as soon as its prerequisite ends --

from app.services.agent.engagement_brain import EngagementBrain, Hypothesis  # noqa: E402
from app.services.agent.fireteam_service import FireteamResult  # noqa: E402
from app.services.agent.tools import (  # noqa: E402
    ASMToolsManager, current_organization_id, current_session_id,
)


@pytest.fixture
def manager():
    org = current_organization_id.set(98765)
    session = current_session_id.set("continuous-dispatch-test")
    instance = ASMToolsManager()
    instance._assessment_scope.update({"app.test"})
    yield instance
    current_session_id.reset(session)
    current_organization_id.reset(org)


def _hyp(hid, specialist):
    return Hypothesis(
        id=hid, title=f"Test {hid}", assumption="A", test="T",
        pass_criteria="P", kill_criteria="K", specialist=specialist,
    )


def _killed(specialist, directive, mission):
    hid = directive.hypothesis_ids[0]
    return SpecialistReport(
        specialist=specialist, role=specialist, mission=mission,
        summary="denied", verdict="killed", hypothesis_ids=[hid],
        assigned_hypothesis_id=hid, lease_id=directive.lease_id,
        hypothesis_results=[{
            "hypothesis_id": hid, "verdict": "killed",
            "evidence_ids": [f"ev-{hid}"], "evidence": "Control held",
        }],
        tool_calls=[ToolInvocation(
            tool="compare_requests", args={"hypothesis_id": hid}, success=True,
            summary="denied", evidence_ids=[f"ev-{hid}"],
        )],
    )


@pytest.mark.asyncio
async def test_dispatch_starts_unblocked_hypothesis_without_a_new_wave(manager, monkeypatch):
    brain = EngagementBrain(
        target="https://app.test",
        hypotheses=[_hyp("a", "api_authz"), _hyp("b", "sqli")],
        task_graph={"nodes": {"b": {
            "id": "b", "title": "Test b", "specialist": "sqli",
            "depends_on": ["a"], "source": "chain",
        }}},
    )
    manager._engagement_brain = brain.to_dict()
    monkeypatch.setattr(manager, "_cheap_llm", lambda: object())
    monkeypatch.setattr("app.services.agent.run_snapshot.save_run_snapshot", lambda *a: None)
    seen = {}

    async def fake_fireteam(*, mission, directives, refill=None, **_kwargs):
        if refill is None:  # the existing auto-prompter retry wave
            return FireteamResult(mission=mission, specialists_run=[], reports=[])
        assert list(directives) == ["api_authz"]  # b is blocked on a
        first = _killed("api_authz", directives["api_authz"], mission)
        additions = await refill(first)
        seen["additions"] = [(profile.name, d.hypothesis_ids) for profile, d in additions]
        live_graph = manager._engagement_brain["task_graph"]["nodes"]
        seen["b_leased_before_run"] = bool(live_graph["b"]["lease_id"])
        second = _killed("sqli", additions[0][1], mission)
        assert await refill(second) == []  # nothing else is ready
        return FireteamResult(
            mission=mission, specialists_run=["api_authz", "sqli"], reports=[first, second],
        )

    monkeypatch.setattr("app.services.agent.fireteam_service.run_fireteam", fake_fireteam)
    result = json.loads(await manager.fireteam_dispatch(
        mission="Chain", targets=["https://app.test"], specialists="auto",
    ))
    assert seen["additions"] == [("sqli", ["b"])]
    assert seen["b_leased_before_run"] is True
    assert result["refilled_specialists"] == ["sqli"]
    assert result["task_leases"]["sqli"]["hypothesis_id"] == "b"
    nodes = manager._engagement_brain["task_graph"]["nodes"]
    assert nodes["a"]["status"] == "killed" and nodes["b"]["status"] == "killed"
    assert nodes["a"]["lease_id"] == "" and nodes["b"]["lease_id"] == ""
    # Each report is folded into the graph once.
    assert nodes["a"]["attempts"] == 1 and nodes["b"]["attempts"] == 1


@pytest.mark.asyncio
async def test_explicit_dispatch_does_not_refill(manager, monkeypatch):
    manager._engagement_brain = EngagementBrain(
        target="https://app.test", hypotheses=[_hyp("a", "api_authz")],
    ).to_dict()
    monkeypatch.setattr(manager, "_cheap_llm", lambda: object())
    monkeypatch.setattr("app.services.agent.run_snapshot.save_run_snapshot", lambda *a: None)

    calls = []

    async def fake_fireteam(*, mission, directives, refill=None, **_kwargs):
        calls.append(refill)
        if len(calls) > 1:
            return FireteamResult(mission=mission, specialists_run=[], reports=[])
        return FireteamResult(mission=mission, specialists_run=["api_authz"], reports=[
            _killed("api_authz", directives["api_authz"], mission),
        ])

    monkeypatch.setattr("app.services.agent.fireteam_service.run_fireteam", fake_fireteam)
    result = json.loads(await manager.fireteam_dispatch(
        mission="One", targets=["https://app.test"], specialists=["api_authz"],
    ))
    assert result["refilled_specialists"] == []
    assert calls[0] is None
