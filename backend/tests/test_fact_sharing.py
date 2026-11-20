"""Facts shared mid-run, code-only endpoint checks, and mid-wave follow-ups."""

import asyncio
import json
from types import SimpleNamespace

import pytest

from app.services.agent import fireteam_service
from app.services.agent.engagement_brain import EngagementBrain, engagement_brain_from_dict
from app.services.agent.evidence_store import evidence_store
from app.services.agent.fireteam_service import SpecialistProfile, SpecialistReport, run_fireteam
from app.services.agent.tools import (
    ASMToolsManager,
    current_organization_id,
    current_session_id,
)


def _profile(name):
    return SpecialistProfile(name=name, role=name, allowed_tools=[])


@pytest.fixture
def manager():
    org = current_organization_id.set(98765)
    session = current_session_id.set("fact-sharing-test")
    instance = ASMToolsManager()
    instance._assessment_scope.update({"app.test"})
    instance._engagement_brain = EngagementBrain(target="https://app.test").to_dict()
    yield instance
    current_session_id.reset(session)
    current_organization_id.reset(org)


def _evidence(manager, success=True):
    return evidence_store(manager).record("scoped_http_get", {"status": 200},
                                          target="https://app.test/", success=success)


# ---------------------------------------------------------------------------
# run_fireteam: a fact wakes the dispatcher before any member finishes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_fact_starts_work_while_every_member_is_still_running(monkeypatch):
    monkeypatch.setattr(fireteam_service, "_MIN_DYNAMIC_MEMBER_SECONDS", 0.0)
    monkeypatch.setattr(fireteam_service, "_FACT_BATCH_SECONDS", 0.0)
    wake = asyncio.Event()
    log = []

    async def specialist(profile, mission, targets, llm, tools_manager,
                         directive=None, execution_progress=None):
        log.append(("start", profile.name))
        if profile.name == "hunter":
            await asyncio.sleep(0.05)
            wake.set()  # record_fact during the run
            await asyncio.sleep(0.4)
        log.append(("end", profile.name))
        return SpecialistReport(specialist=profile.name, role=profile.role,
                                mission=mission, summary="done")

    monkeypatch.setattr(fireteam_service, "_run_specialist", specialist)
    calls = []

    async def next_work(report, slots, window):
        calls.append(None if report is None else report.specialist)
        if report is None:
            return [(_profile("followup"), SimpleNamespace(lease_id="", coverage_lease_id="c1"))]
        return []

    result = await run_fireteam(
        mission="m", targets=[], specialists=[_profile("hunter")], llm=None,
        tools_manager=None, max_parallel=2, next_work=next_work,
        max_dynamic_members=2, member_timeout_sec=30, wave_timeout_sec=30, wake_event=wake,
    )
    assert calls[0] is None
    assert log.index(("start", "followup")) < log.index(("end", "hunter"))
    assert [r.specialist for r in result.reports] == ["hunter", "followup"]


# ---------------------------------------------------------------------------
# record_fact
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_record_fact_rejects_unsupported_input(manager):
    evidence = _evidence(manager)
    bad_kind = json.loads(await manager.record_fact("secret", "x", evidence))
    assert bad_kind["success"] is False
    no_evidence = json.loads(await manager.record_fact("note", "x", "f" * 32))
    assert "evidence_id" in no_evidence["error"]
    failed = json.loads(await manager.record_fact("note", "x", _evidence(manager, success=False)))
    assert failed["success"] is False
    outside = json.loads(await manager.record_fact("endpoint", "GET https://evil.test/x", evidence))
    assert outside["success"] is False and "evil.test" in outside["error"]


@pytest.mark.asyncio
async def test_endpoint_fact_queues_a_followup_wakes_dispatch_and_is_checked_in_code(manager, monkeypatch):
    gets = []

    async def fake_get(url, identity="anonymous"):
        gets.append(url)
        return json.dumps({"status": 401, "content_type": "application/json",
                           "bytes_captured": 30, "evidence_id": "e" * 32})

    monkeypatch.setattr(manager, "scoped_http_get", fake_get)
    manager._fact_wake = asyncio.Event()
    evidence = _evidence(manager)
    out = json.loads(await manager.record_fact(
        "endpoint", "GET https://app.test/api/admin/users?page=2", evidence,
        note="linked from the error page"))
    assert out == {"success": True, "duplicate": False, "followup_queued": True}
    assert manager._fact_wake.is_set()
    await manager.wait_for_enrichment()
    # Query values are dropped from the code-only check.
    assert gets == ["https://app.test/api/admin/users"]
    brain = engagement_brain_from_dict(manager._engagement_brain)
    surface = next(row for row in brain.surfaces if row["path"] == "/api/admin/users")
    assert surface["probe"]["status"] == 401 and surface["auth_gated"] is True
    assert any(e.get("kind") == "capture" for e in brain.observation_events)
    assert [r["fact_kind"] for r in brain.recon_observations if r.get("kind") == "fact"] == ["endpoint"]

    again = json.loads(await manager.record_fact(
        "endpoint", "GET https://app.test/api/admin/users?page=2", evidence))
    assert again["duplicate"] is True and again["followup_queued"] is False
    await manager.wait_for_enrichment()
    assert len(gets) == 1


@pytest.mark.asyncio
async def test_unsafe_paths_are_never_fetched(manager, monkeypatch):
    gets = []

    async def fake_get(url, identity="anonymous"):
        gets.append(url)
        return json.dumps({"status": 200})

    monkeypatch.setattr(manager, "scoped_http_get", fake_get)
    await manager.record_fact("endpoint", "GET https://app.test/account/logout", _evidence(manager))
    await manager.wait_for_enrichment()
    assert gets == []


# ---------------------------------------------------------------------------
# fireteam_dispatch: leads land on the live brain mid-wave and survive the wave
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mid_wave_leads_are_recorded_once_and_kept(manager, monkeypatch):
    from app.core.config import settings
    from app.services.agent.engagement_brain import Hypothesis
    from app.services.agent.fireteam_service import FireteamResult, ToolInvocation

    monkeypatch.setattr(settings, "FIRETEAM_ROLLING_DISPATCH", True, raising=False)
    monkeypatch.setattr(manager, "_cheap_llm", lambda: object())
    monkeypatch.setattr("app.services.agent.run_snapshot.save_run_snapshot", lambda *a, **k: None)
    monkeypatch.setattr(manager, "scoped_http_get",
                        lambda url, identity="anonymous": asyncio.sleep(0, json.dumps({"status": 200})))
    manager._engagement_brain = EngagementBrain(target="https://app.test", hypotheses=[Hypothesis(
        id="h-xss", title="Reflected input", assumption="a", test="t", pass_criteria="p",
        kill_criteria="k", specialist="xss")]).to_dict()
    seen = {}

    async def fake_fireteam(*, mission, directives, next_work=None, **kwargs):
        if "xss" not in directives:
            return FireteamResult(mission=mission, specialists_run=[], reports=[])
        report = SpecialistReport(
            specialist="xss", role="XSS", mission=mission, summary="done", verdict="killed",
            hypothesis_ids=["h-xss"], assigned_hypothesis_id="h-xss",
            lease_id=directives["xss"].lease_id,
            tool_calls=[ToolInvocation(tool="scoped_http_get", args={}, summary="ok", success=True,
                                       evidence_ids=["a" * 32])],
            leads=[{"method": "GET", "url": "https://app.test/internal/debug",
                    "why": "linked in an error", "evidence_ids": ["a" * 32]}],
        )
        await next_work(report, 0, 300.0)
        live = engagement_brain_from_dict(manager._engagement_brain)
        seen["mid_wave_events"] = [e for e in live.observation_events if e.get("kind") == "capture"]
        return FireteamResult(mission=mission, specialists_run=["xss"], reports=[report])

    monkeypatch.setattr("app.services.agent.fireteam_service.run_fireteam", fake_fireteam)
    result = json.loads(await manager.fireteam_dispatch(
        mission="Test", targets=["https://app.test"], specialists=["xss"],
    ))
    assert len(seen["mid_wave_events"]) == 1
    assert result["wave_changes"]["leads_recorded"] == 1
    final = engagement_brain_from_dict(manager._engagement_brain)
    captures = [e for e in final.observation_events if e.get("kind") == "capture"]
    assert len(captures) == 1  # kept after the wave, not recorded twice


@pytest.mark.asyncio
async def test_followups_are_claimed_mid_wave_and_closed_when_their_member_reports(manager, monkeypatch):
    from app.core.config import settings
    from app.services.agent import followup_runtime
    from app.services.agent.coverage_cells import CoverageCellLease
    from app.services.agent.fireteam_service import FireteamResult

    monkeypatch.setattr(settings, "FIRETEAM_ROLLING_DISPATCH", True, raising=False)
    monkeypatch.setattr(manager, "_cheap_llm", lambda: object())
    monkeypatch.setattr("app.services.agent.run_snapshot.save_run_snapshot", lambda *a, **k: None)
    lease = CoverageCellLease(id="lease-f1", coverage_cell_id="cell-f1", specialist="injection",
                              hypothesis_id="", task_lease_id="", attempt=1,
                              started_at=0.0, deadline=9e9)
    monkeypatch.setattr(followup_runtime, "specialists_with_followups",
                        lambda brain, policy: ["injection"])
    claims = []

    def fake_claim(brain, names, policy, **k):
        # The round-start claim finds nothing; the planner's result arrives mid-wave.
        claims.append(list(names))
        return {"injection": lease} if names and len(claims) > 1 else {}

    monkeypatch.setattr(followup_runtime, "claim_for_specialists", fake_claim)
    monkeypatch.setattr(followup_runtime, "required_identities", lambda brain, lease: [])
    finished = []
    monkeypatch.setattr(followup_runtime, "finish_followup",
                        lambda brain, lease, reports, **k: finished.append((lease.id, len(reports))))
    seen = {}

    async def fake_fireteam(*, mission, directives, next_work=None, **kwargs):
        if next_work is None:
            return FireteamResult(mission=mission, specialists_run=[], reports=[])
        additions = await next_work(None, 2, 300.0)  # woken by a fact
        seen["additions"] = additions
        profile, directive = additions[0]
        report = SpecialistReport(specialist=profile.name, role=profile.role, mission=mission,
                                  summary="checked", verdict="killed",
                                  coverage_cell_id=directive.coverage_cell_id,
                                  coverage_lease_id=directive.coverage_lease_id)
        await next_work(report, 0, 300.0)
        seen["finished_mid_wave"] = list(finished)
        return FireteamResult(mission=mission, specialists_run=[profile.name], reports=[report])

    monkeypatch.setattr("app.services.agent.fireteam_service.run_fireteam", fake_fireteam)
    result = json.loads(await manager.fireteam_dispatch(
        mission="Test", targets=["https://app.test"], specialists=["injection"],
    ))
    profile, directive = seen["additions"][0]
    assert profile.name == "injection" and directive.coverage_lease_id == "lease-f1"
    assert seen["finished_mid_wave"] == [("lease-f1", 1)]
    # Not closed a second time after the wave.
    assert finished == [("lease-f1", 1)]
    assert {"specialist": "injection", "reason": "followup",
            "coverage_cell_id": "cell-f1"} in result["started_mid_wave"]
