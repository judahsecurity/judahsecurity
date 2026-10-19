"""Bounded Fireteam execution keeps completed work available on a stall."""

import asyncio
import time
from types import SimpleNamespace

import pytest

from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.fireteam_service import (
    SpecialistProfile,
    SpecialistReport,
    ToolInvocation,
    _safe_invoke,
    run_fireteam,
)
from app.services.agent.penetration_task_graph import (
    NODE_BLOCKED,
    NODE_READY,
    NODE_RUNNING,
    PenetrationTaskGraph,
    TaskNode,
    apply_executor_summary,
    parse_executor_summary,
)


@pytest.mark.asyncio
async def test_fireteam_returns_completed_report_when_another_member_times_out(monkeypatch):
    async def specialist(profile, mission, targets, llm, tools_manager,
                         directive=None, execution_progress=None):
        if profile.name == "slow":
            execution_progress["tool_inflight"] = True
            await asyncio.sleep(1)
        return SpecialistReport(
            specialist=profile.name,
            role=profile.role,
            mission=mission,
            summary="completed",
        )

    monkeypatch.setattr(
        "app.services.agent.fireteam_service._run_specialist", specialist
    )
    profiles = [
        SpecialistProfile(name=name, role=name, allowed_tools=[])
        for name in ("quick", "slow")
    ]
    result = await run_fireteam(
        mission="test",
        targets=["https://example.test"],
        specialists=profiles,
        llm=None,
        tools_manager=None,
        directives={
            "slow": SimpleNamespace(hypothesis_ids=["h1"], lease_id="lease1")
        },
        member_timeout_sec=0.05,
        wave_timeout_sec=0.2,
    )
    assert [report.specialist for report in result.reports] == ["quick", "slow"]
    assert result.reports[0].summary == "completed"
    assert "timed out" in result.reports[1].error
    assert result.reports[1].lease_id == "lease1"

    graph = PenetrationTaskGraph(nodes={
        "h1": TaskNode(
            id="h1", title="test", specialist="slow", status=NODE_RUNNING,
            lease_id="lease1",
        )
    })
    apply_executor_summary(graph, EngagementBrain(), parse_executor_summary(result.reports[1]))
    assert graph.nodes["h1"].status == NODE_BLOCKED
    assert graph.nodes["h1"].recovery_required is True


@pytest.mark.asyncio
async def test_member_deadline_returns_even_if_cancellation_is_slow(monkeypatch):
    async def slow_cancel(profile, mission, targets, llm, tools_manager,
                          directive=None, execution_progress=None):
        try:
            await asyncio.sleep(1)
        except asyncio.CancelledError:
            await asyncio.sleep(0.2)
        return SpecialistReport(
            specialist=profile.name, role=profile.role, mission=mission,
            summary="late result",
        )

    monkeypatch.setattr(
        "app.services.agent.fireteam_service._run_specialist", slow_cancel
    )
    started = time.monotonic()
    result = await run_fireteam(
        mission="test",
        targets=[],
        specialists=[SpecialistProfile(name="slow", role="slow", allowed_tools=[])],
        llm=None,
        tools_manager=None,
        member_timeout_sec=0.02,
        wave_timeout_sec=0.1,
    )
    assert time.monotonic() - started < 0.15
    assert result.reports[0].verdict == "retry"
    assert result.reports[0].rewrite_hint == "execution_timeout_no_inflight_tool"
    await asyncio.sleep(0.25)  # Allow the deliberately slow cancellation to settle.


@pytest.mark.asyncio
async def test_model_only_timeout_releases_lease_without_recovery_block(monkeypatch):
    async def waiting_on_model(profile, mission, targets, llm, tools_manager,
                               directive=None, execution_progress=None):
        await asyncio.sleep(1)

    monkeypatch.setattr("app.services.agent.fireteam_service._run_specialist", waiting_on_model)
    result = await run_fireteam(
        mission="test", targets=["https://example.test"],
        specialists=[SpecialistProfile(name="slow", role="slow", allowed_tools=[])],
        llm=None, tools_manager=None,
        directives={"slow": SimpleNamespace(hypothesis_ids=["h1"], lease_id="lease1")},
        member_timeout_sec=0.02, wave_timeout_sec=0.1,
    )
    graph = PenetrationTaskGraph(nodes={
        "h1": TaskNode(id="h1", title="test", specialist="slow", status=NODE_RUNNING,
                       lease_id="lease1", max_attempts=2),
    })
    apply_executor_summary(graph, EngagementBrain(), parse_executor_summary(result.reports[0]))
    assert graph.nodes["h1"].status == NODE_READY
    assert graph.nodes["h1"].recovery_required is False
    assert graph.nodes["h1"].lease_id == ""


@pytest.mark.asyncio
async def test_timeout_after_completed_tool_keeps_receipt_and_retries(monkeypatch):
    async def completed_then_waiting(profile, mission, targets, llm, tools_manager,
                                     directive=None, execution_progress=None):
        execution_progress["completed_calls"].append(ToolInvocation(
            tool="query_assets", args={"hypothesis_id": "h1"}, success=True,
            summary="Completed inventory query",
        ))
        await asyncio.sleep(1)

    monkeypatch.setattr(
        "app.services.agent.fireteam_service._run_specialist", completed_then_waiting
    )
    result = await run_fireteam(
        mission="test", targets=["https://example.test"],
        specialists=[SpecialistProfile(name="slow", role="slow", allowed_tools=[])],
        llm=None, tools_manager=None,
        directives={"slow": SimpleNamespace(hypothesis_ids=["h1"], lease_id="lease1")},
        member_timeout_sec=0.02, wave_timeout_sec=0.1,
    )
    report = result.reports[0]
    assert report.verdict == "retry"
    assert [call.tool for call in report.tool_calls] == ["query_assets"]
    graph = PenetrationTaskGraph(nodes={
        "h1": TaskNode(id="h1", title="test", specialist="slow", status=NODE_RUNNING,
                       lease_id="lease1", max_attempts=2),
    })
    apply_executor_summary(graph, EngagementBrain(), parse_executor_summary(report))
    assert graph.nodes["h1"].status == NODE_READY
    assert graph.nodes["h1"].recovery_required is False


@pytest.mark.asyncio
async def test_wave_deadline_keeps_completed_member(monkeypatch):
    async def specialist(profile, mission, targets, llm, tools_manager,
                         directive=None, execution_progress=None):
        if profile.name == "slow":
            await asyncio.sleep(1)
        return SpecialistReport(
            specialist=profile.name, role=profile.role, mission=mission,
            summary="completed",
        )

    monkeypatch.setattr(
        "app.services.agent.fireteam_service._run_specialist", specialist
    )
    profiles = [
        SpecialistProfile(name=name, role=name, allowed_tools=[])
        for name in ("quick", "slow")
    ]
    result = await run_fireteam(
        mission="test", targets=[], specialists=profiles,
        llm=None, tools_manager=None,
        member_timeout_sec=1,
        wave_timeout_sec=0.05,
    )
    assert result.reports[0].summary == "completed"
    assert "wave timed out" in result.reports[1].error


@pytest.mark.asyncio
async def test_scoped_probe_receipt_handoffs_to_its_leased_hypothesis(monkeypatch):
    receipt_id = "a" * 32
    cell_id = "cell-1"
    lease_id = "lease-1"
    record = {"kind": "scoped_string_sqli", "payload": {"proof_confirmed": False}}
    monkeypatch.setattr(
        "app.services.agent.evidence_store.evidence_store",
        lambda manager: SimpleNamespace(records={receipt_id: record}),
    )

    class Manager:
        _engagement_brain = {"coverage_cells": [{
            "id": cell_id, "lease_id": lease_id,
            "probe_artifact_ids": [receipt_id],
        }]}

        async def execute(self, name, args):
            return {"success": True, "output": {
                "success": True, "coverage_cell_id": cell_id,
                "coverage_lease_id": lease_id, "evidence_id": receipt_id,
            }}

    call = await _safe_invoke(Manager(), "scoped_input_probe_assigned", {
        "coverage_cell_id": cell_id, "coverage_lease_id": lease_id,
    })
    assert call.evidence_ids == [receipt_id]
    report = SpecialistReport(
        specialist="sqli", role="sqli", mission="test", summary="bounded probe",
        assigned_hypothesis_id="hyp-1", coverage_cell_id=cell_id,
        coverage_lease_id=lease_id, tool_calls=[call],
        hypothesis_results=[{"hypothesis_id": "hyp-1", "verdict": "killed",
                             "evidence_ids": [receipt_id], "evidence": "negative control"}],
    )
    summary = parse_executor_summary(report)
    assert summary.hypothesis_results[0]["evidence_ids"] == [receipt_id]
    assert summary.hypothesis_results[0]["verdict"] == "inconclusive"

    report.coverage_cell_id = "other-cell"
    assert parse_executor_summary(report).hypothesis_results == []
    report.coverage_cell_id = cell_id
    report.assigned_hypothesis_id = "other-hypothesis"
    assert parse_executor_summary(report).hypothesis_results == []


@pytest.mark.asyncio
async def test_scoped_probe_receipt_rejects_unlinked_artifact(monkeypatch):
    receipt_id = "b" * 32
    monkeypatch.setattr(
        "app.services.agent.evidence_store.evidence_store",
        lambda manager: SimpleNamespace(records={receipt_id: {
            "kind": "scoped_string_sqli", "payload": {},
        }}),
    )

    class Manager:
        _engagement_brain = {"coverage_cells": [{
            "id": "cell-1", "lease_id": "lease-1", "probe_artifact_ids": [],
        }]}

        async def execute(self, name, args):
            return {"success": True, "output": {
                "success": True, "coverage_cell_id": "cell-1",
                "coverage_lease_id": "lease-1", "evidence_id": receipt_id,
            }}

    call = await _safe_invoke(Manager(), "scoped_input_probe_assigned", {
        "coverage_cell_id": "cell-1", "coverage_lease_id": "lease-1",
    })
    assert call.evidence_ids == []


@pytest.mark.asyncio
async def test_completed_hunter_can_start_verification_before_sibling_finishes(monkeypatch):
    release_slow = asyncio.Event()
    verified_early = asyncio.Event()

    async def specialist(profile, mission, targets, llm, tools_manager,
                         directive=None, execution_progress=None):
        if profile.name == "slow":
            await release_slow.wait()
        return SpecialistReport(
            specialist=profile.name, role=profile.role, mission=mission,
            summary="completed", key_findings=["candidate"] if profile.name == "quick" else [],
        )

    async def verify(report):
        if report.specialist == "quick":
            verified_early.set()

    monkeypatch.setattr("app.services.agent.fireteam_service._run_specialist", specialist)
    profiles = [SpecialistProfile(name=name, role=name, allowed_tools=[])
                for name in ("quick", "slow")]
    wave = asyncio.create_task(run_fireteam(
        mission="test", targets=[], specialists=profiles, llm=None,
        tools_manager=None, report_callback=verify,
    ))
    await asyncio.wait_for(verified_early.wait(), timeout=1)
    assert not wave.done()
    release_slow.set()
    result = await asyncio.wait_for(wave, timeout=1)
    assert [report.specialist for report in result.reports] == ["quick", "slow"]


def test_cms_followup_profile_can_submit_candidates():
    from app.services.agent.fireteam_service import get_specialist

    profile = get_specialist("cms_followup")
    assert profile is not None
    assert "submit_finding_candidate" in profile.allowed_tools
    assert "execute_wpscan" in profile.allowed_tools
