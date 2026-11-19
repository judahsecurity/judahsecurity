"""Run purse: one spend account for every model call, with specialist reservations."""

from types import SimpleNamespace

import pytest
from langchain_core.messages import AIMessage

from app.services.agent import action_ledger
from app.services.agent.fireteam_service import SpecialistProfile, SpecialistReport, run_fireteam
from app.services.agent.orchestrator import _ledger_llm_call
from app.services.agent.run_purse import (
    RunBudgetExhausted, RunPurse, WRAPUP_FRACTION, drop_purse, get_purse, purse_for,
)


def test_reservations_and_wrapup_reserve():
    purse = RunPurse(limit_usd=10.0)
    working = 10.0 * (1 - WRAPUP_FRACTION)
    assert purse.reserve("a", 5.0) and purse.reserve("b", 4.0)
    assert not purse.reserve("c", 1.0)  # 9.0 held of 9.5 working budget
    purse.release("a")
    assert purse.reserve("c", 1.0)
    purse.record(working)
    assert not purse.allows_call("agent_plan")
    assert purse.allows_call("agent_report")  # final report still fits
    purse.record(10.0)
    assert not purse.allows_call("agent_report")
    assert RunPurse(limit_usd=0).reserve("x", 1e9)  # 0 = unlimited


def test_resume_never_lowers_recorded_spend():
    try:
        purse = purse_for("run-resume", limit_usd=8.0, spent_usd=3.0)
        purse.record(1.0)
        assert purse_for("run-resume", spent_usd=3.0).spent_usd == 4.0
        assert purse_for("run-resume", limit_usd=12.0).limit_usd == 12.0
        assert get_purse(None) is None and purse_for(None) is None
    finally:
        drop_purse("run-resume")


class _LLM:
    model = "claude-sonnet-4-6"

    def __init__(self):
        self.calls = 0

    async def ainvoke(self, messages):
        self.calls += 1
        return AIMessage(content="ok", usage_metadata={
            "input_tokens": 1_000_000, "output_tokens": 0, "total_tokens": 1_000_000})


@pytest.fixture()
def run(monkeypatch):
    events = []
    monkeypatch.setattr(action_ledger, "append_action",
                        lambda run_id, action_id, event, kind, **kw: events.append((event, kind, kw.get("detail"))))
    token = action_ledger.active_run_id.set("run-purse-test")
    yield events
    action_ledger.active_run_id.reset(token)
    drop_purse("run-purse-test")


@pytest.mark.asyncio
async def test_every_model_call_is_charged_and_refused_when_spent(run):
    purse = purse_for("run-purse-test", limit_usd=1.0)
    llm = _LLM()
    await _ledger_llm_call(llm, [], kind="agent_specialist_model")
    assert purse.spent_usd > 0  # nested specialist calls are counted
    purse.record(1.0)
    with pytest.raises(RunBudgetExhausted):
        await _ledger_llm_call(llm, [], kind="agent_specialist_model")
    assert llm.calls == 1
    assert ("skipped", "agent_specialist_model", "run budget exhausted") in run


@pytest.mark.asyncio
async def test_specialist_not_started_when_its_cap_cannot_be_reserved(run, monkeypatch):
    started = []

    async def specialist(profile, mission, targets, llm, tools_manager,
                         directive=None, execution_progress=None):
        started.append(profile.name)
        return SpecialistReport(specialist=profile.name, role="r", mission=mission, summary="done")

    monkeypatch.setattr("app.services.agent.fireteam_service._run_specialist", specialist)
    purse = purse_for("run-purse-test", limit_usd=3.0)
    profiles = [SpecialistProfile(name=n, role=n, allowed_tools=[]) for n in ("a", "b")]
    directives = {n: SimpleNamespace(max_spend_usd=2.0, hypothesis_ids=["h-" + n], lease_id="")
                  for n in ("a", "b")}
    result = await run_fireteam(mission="m", targets=["https://app.test"], specialists=profiles,
                                llm=None, tools_manager=None, directives=directives, max_parallel=2)
    by_name = {r.specialist: r for r in result.reports}
    assert len(started) == 1
    skipped = [r for r in by_name.values() if r.rewrite_hint == "run_budget_exhausted"]
    assert len(skipped) == 1 and skipped[0].verdict == "blocked"
    assert skipped[0].hypothesis_ids  # lease bookkeeping can requeue the hypothesis
    assert purse.reserved == {}  # released after the wave
