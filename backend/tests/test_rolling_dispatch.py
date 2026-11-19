"""Rolling fireteam dispatch: new work starts as soon as a member finishes."""

import asyncio
import json
from types import SimpleNamespace

import pytest

from app.services.agent import fireteam_service
from app.services.agent.engagement_brain import EngagementBrain, Hypothesis
from app.services.agent.fireteam_service import (
    FireteamResult,
    SpecialistProfile,
    SpecialistReport,
    run_fireteam,
)
from app.services.agent.tools import (
    ASMToolsManager,
    current_organization_id,
    current_session_id,
)


def _profile(name):
    return SpecialistProfile(name=name, role=name, allowed_tools=[])


@pytest.fixture
def fast_window(monkeypatch):
    monkeypatch.setattr(fireteam_service, "_MIN_DYNAMIC_MEMBER_SECONDS", 0.0)


def _fake_specialists(monkeypatch, durations, log):
    async def specialist(profile, mission, targets, llm, tools_manager,
                         directive=None, execution_progress=None):
        log.append(("start", profile.name, getattr(directive, "lease_id", None)))
        await asyncio.sleep(durations.get(profile.name, 0))
        log.append(("end", profile.name))
        return SpecialistReport(
            specialist=profile.name, role=profile.role, mission=mission,
            summary="done", lease_id=getattr(directive, "lease_id", "") or "",
        )

    monkeypatch.setattr(fireteam_service, "_run_specialist", specialist)


@pytest.mark.asyncio
async def test_new_work_starts_before_the_slowest_member_finishes(monkeypatch, fast_window):
    log = []
    _fake_specialists(monkeypatch, {"quick": 0.0, "slow": 0.3, "chain": 0.0}, log)
    calls = []

    async def next_work(report, slots, window):
        calls.append((report.specialist, slots))
        if report.specialist == "quick":
            return [(_profile("chain"), SimpleNamespace(lease_id="lease-chain"))]
        return []

    result = await run_fireteam(
        mission="m", targets=["https://app.test"],
        specialists=[_profile("quick"), _profile("slow")],
        llm=None, tools_manager=None, max_parallel=2,
        next_work=next_work, max_dynamic_members=4,
        member_timeout_sec=30, wave_timeout_sec=30,
    )

    assert [r.specialist for r in result.reports] == ["quick", "slow", "chain"]
    assert result.reports[2].lease_id == "lease-chain"
    assert log.index(("start", "chain", "lease-chain")) < log.index(("end", "slow"))
    # Every finished member is reported, including the one started mid-wave.
    assert {name for name, _ in calls} == {"quick", "slow", "chain"}


@pytest.mark.asyncio
async def test_mid_wave_starts_are_capped(monkeypatch, fast_window):
    log = []
    _fake_specialists(monkeypatch, {}, log)
    slots_seen = []

    async def next_work(report, slots, window):
        slots_seen.append(slots)
        return [(_profile(f"{report.specialist}+{i}"), SimpleNamespace(lease_id=""))
                for i in range(3)]

    result = await run_fireteam(
        mission="m", targets=[], specialists=[_profile("a")],
        llm=None, tools_manager=None, max_parallel=4,
        next_work=next_work, max_dynamic_members=2,
        member_timeout_sec=30, wave_timeout_sec=30,
    )

    assert len(result.reports) == 3  # the original member plus two mid-wave starts
    assert slots_seen[0] == 2
    assert slots_seen[1:] == [0, 0]


@pytest.mark.asyncio
async def test_no_starts_when_the_wave_is_nearly_over(monkeypatch):
    monkeypatch.setattr(fireteam_service, "_MIN_DYNAMIC_MEMBER_SECONDS", 60.0)
    log = []
    _fake_specialists(monkeypatch, {}, log)
    seen = []

    async def next_work(report, slots, window):
        seen.append(slots)
        return [(_profile("late"), None)]

    result = await run_fireteam(
        mission="m", targets=[], specialists=[_profile("a")],
        llm=None, tools_manager=None,
        next_work=next_work, max_dynamic_members=4,
        member_timeout_sec=30, wave_timeout_sec=30,
    )

    assert seen == [0]
    assert [r.specialist for r in result.reports] == ["a"]


@pytest.mark.asyncio
async def test_failing_next_work_does_not_stop_the_wave(monkeypatch, fast_window):
    log = []
    _fake_specialists(monkeypatch, {"slow": 0.05}, log)

    async def next_work(report, slots, window):
        raise RuntimeError("planner bug")

    result = await run_fireteam(
        mission="m", targets=[], specialists=[_profile("quick"), _profile("slow")],
        llm=None, tools_manager=None, max_parallel=2,
        next_work=next_work, max_dynamic_members=4,
        member_timeout_sec=30, wave_timeout_sec=30,
    )

    assert [r.summary for r in result.reports] == ["done", "done"]


@pytest.mark.asyncio
async def test_mid_wave_member_cut_off_by_the_wave_keeps_its_lease(monkeypatch, fast_window):
    log = []
    _fake_specialists(monkeypatch, {"chain": 5.0}, log)

    async def next_work(report, slots, window):
        if report.specialist == "quick":
            return [(_profile("chain"), SimpleNamespace(
                lease_id="lease-chain", hypothesis_ids=["h-chain"],
            ))]
        return []

    result = await run_fireteam(
        mission="m", targets=[], specialists=[_profile("quick")],
        llm=None, tools_manager=None,
        next_work=next_work, max_dynamic_members=4,
        member_timeout_sec=10, wave_timeout_sec=0.3,
    )

    chain = result.reports[1]
    assert chain.specialist == "chain"
    assert "timed out" in chain.error
    assert chain.lease_id == "lease-chain"
    assert chain.hypothesis_ids == ["h-chain"]


# ---------------------------------------------------------------------------
# fireteam_dispatch integration
# ---------------------------------------------------------------------------


@pytest.fixture
def manager():
    org = current_organization_id.set(98765)
    session = current_session_id.set("rolling-dispatch-test")
    instance = ASMToolsManager()
    instance._assessment_scope.update({"app.test"})
    yield instance
    current_session_id.reset(session)
    current_organization_id.reset(org)


def _hypothesis():
    return Hypothesis(
        id="h-xss", title="Reflected input", assumption="Input reflects",
        test="Bounded canary", pass_criteria="Browser execution",
        kill_criteria="No execution", specialist="xss",
    )


async def _dispatch_with(manager, monkeypatch, *, rolling, on_report):
    from app.core.config import settings

    monkeypatch.setattr(settings, "FIRETEAM_ROLLING_DISPATCH", rolling, raising=False)
    monkeypatch.setattr(manager, "_cheap_llm", lambda: object())
    monkeypatch.setattr("app.services.agent.run_snapshot.save_run_snapshot",
                        lambda *_a, **_k: None)
    manager._engagement_brain = EngagementBrain(
        target="https://app.test", hypotheses=[_hypothesis()],
    ).to_dict()
    seen = {}

    async def fake_fireteam(*, mission, directives, next_work=None, **kwargs):
        if "xss" not in directives:  # the post-wave retry wave
            seen.setdefault("retry_waves", []).append(
                [getattr(p, "name", p) for p in kwargs.get("specialists", [])]
            )
            return FireteamResult(mission=mission, specialists_run=[], reports=[])
        seen["next_work"] = next_work
        report = SpecialistReport(
            specialist="xss", role="XSS", mission=mission, summary="Found a GraphQL route",
            verdict="killed", hypothesis_ids=["h-xss"], assigned_hypothesis_id="h-xss",
            lease_id=directives["xss"].lease_id, spawn=["graphql_api"],
        )
        reports = [report]
        if next_work is not None:
            additions = await on_report(next_work, report)
            seen["additions"] = additions
            for profile, directive in additions:
                mid = SpecialistReport(
                    specialist=profile.name, role=profile.role, mission=mission,
                    summary="mid-wave run", verdict="killed",
                    hypothesis_ids=list(directive.hypothesis_ids),
                    assigned_hypothesis_id=directive.hypothesis_ids[0],
                    lease_id=directive.lease_id,
                )
                reports.append(mid)
                # run_fireteam reports every finished member, mid-wave ones too.
                assert await next_work(mid, 0, 300.0) == []
        return FireteamResult(mission=mission, specialists_run=[r.specialist for r in reports],
                              reports=reports)

    monkeypatch.setattr("app.services.agent.fireteam_service.run_fireteam", fake_fireteam)
    result = json.loads(await manager.fireteam_dispatch(
        mission="Test", targets=["https://app.test"], specialists=["xss"],
    ))
    return result, seen


@pytest.mark.asyncio
async def test_dispatch_is_unchanged_with_rolling_off(manager, monkeypatch):
    async def never(*_a):
        raise AssertionError("next_work must not run in wave mode")

    result, seen = await _dispatch_with(manager, monkeypatch, rolling=False, on_report=never)
    assert seen["next_work"] is None
    assert result["started_mid_wave"] == []


@pytest.mark.asyncio
async def test_spawned_hypothesis_starts_mid_wave(manager, monkeypatch):
    async def on_report(next_work, report):
        return await next_work(report, 2, 300.0)

    result, seen = await _dispatch_with(manager, monkeypatch, rolling=True, on_report=on_report)

    additions = seen["additions"]
    # "killed" with no evidence is downgraded, so xss retries at once; the
    # GraphQL card it spawned starts in the other free slot.
    assert [profile.name for profile, _ in additions] == ["xss", "graphql_api"]
    assert [row["reason"] for row in result["started_mid_wave"]] == ["retry", "spawned"]
    directive = additions[1][1]
    assert directive.lease_id and directive.hypothesis_ids
    # xss already retried mid-wave; only the GraphQL run, which finished
    # with no slot left, is retried in the post-wave retry wave.
    assert seen["retry_waves"] == [["graphql_api"]]
    nodes = manager._engagement_brain["task_graph"]["nodes"]
    assert nodes[directive.hypothesis_ids[0]]["specialist"] == "graphql_api"


@pytest.mark.asyncio
async def test_no_slots_still_records_the_result_once(manager, monkeypatch):
    async def on_report(next_work, report):
        return await next_work(report, 0, 300.0)

    result, seen = await _dispatch_with(manager, monkeypatch, rolling=True, on_report=on_report)

    assert seen["additions"] == []
    assert result["started_mid_wave"] == []
    # The spawned card exists once and is left for the next dispatch.
    titles = [h["specialist"] for h in manager._engagement_brain["hypotheses"]]
    assert titles.count("graphql_api") == 1
