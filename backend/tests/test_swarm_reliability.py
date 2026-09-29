"""Bounded Fireteam execution keeps completed work available on a stall."""

import asyncio
import time
from types import SimpleNamespace

import pytest

from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.fireteam_service import (
    SpecialistProfile,
    SpecialistReport,
    run_fireteam,
)
from app.services.agent.penetration_task_graph import (
    NODE_BLOCKED,
    NODE_RUNNING,
    PenetrationTaskGraph,
    TaskNode,
    apply_executor_summary,
    parse_executor_summary,
)


@pytest.mark.asyncio
async def test_fireteam_returns_completed_report_when_another_member_times_out(monkeypatch):
    async def specialist(profile, mission, targets, llm, tools_manager, directive=None):
        if profile.name == "slow":
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
    async def slow_cancel(profile, mission, targets, llm, tools_manager, directive=None):
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
    assert result.reports[0].verdict == "blocked"
    await asyncio.sleep(0.25)  # Allow the deliberately slow cancellation to settle.


@pytest.mark.asyncio
async def test_wave_deadline_keeps_completed_member(monkeypatch):
    async def specialist(profile, mission, targets, llm, tools_manager, directive=None):
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
