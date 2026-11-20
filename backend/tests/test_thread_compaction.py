"""Compaction folds finished threads and keeps active work verbatim."""

import json

import pytest

from app.services.agent.engagement_brain import EngagementBrain, Hypothesis
from app.services.agent.session_ops import (
    active_threads_from_brain,
    compact_execution_trace,
    step_thread,
)
from app.services.agent.tools import ASMToolsManager, current_organization_id, current_session_id


def _step(i, tool="scoped_http_get", **args):
    return {"iteration": i, "tool_name": tool, "tool_args": args, "success": True,
            "thought": f"step {i}", "tool_output": f"output {i}"}


def _trace():
    steps = []
    for i in range(10):
        steps.append(_step(i, hypothesis_id="h-done"))
    for i in range(10, 14):
        steps.append(_step(i, hypothesis_id="h-active"))
    for i in range(14, 30):
        steps.append(_step(i))
    return steps


def test_thread_of_a_step():
    assert step_thread(_step(1, hypothesis_id="h1")) == "h1"
    assert step_thread(_step(1, coverage_cell_id="c1")) == "c1"
    assert step_thread(_step(1)) == ""


def test_active_threads_stay_verbatim_and_finished_ones_fold():
    archive = {}
    trace, brief = compact_execution_trace(_trace(), active_threads={"h-active"}, archive=archive)
    kept = [step["iteration"] for step in trace[1:]]
    assert kept[:4] == [10, 11, 12, 13]  # older active work, verbatim
    assert kept[4:] == list(range(22, 30))  # the recent window
    assert "h-done: 10 step(s)" in brief and "expand_compacted" in brief
    assert trace[0]["folded_threads"] == ["h-done"]
    assert len(archive["h-done"]) == 10 and archive["h-done"][0]["output"] == "output 0"
    assert len(archive["unthreaded"]) == 8


def test_without_active_threads_behaves_as_before():
    trace, brief = compact_execution_trace(_trace())
    assert [step["iteration"] for step in trace[1:]] == list(range(22, 30))
    assert brief.startswith("Compacted 22 earlier steps")


def test_active_threads_from_brain():
    brain = EngagementBrain(hypotheses=[
        Hypothesis(id="h-open", title="t", assumption="a", test="t", pass_criteria="p",
                   kill_criteria="k", specialist="xss", status="open"),
        Hypothesis(id="h-killed", title="t", assumption="a", test="t", pass_criteria="p",
                   kill_criteria="k", specialist="xss", status="killed"),
    ])
    brain.coverage_cells = [{"id": "c-leased", "status": "leased", "lease_id": "l1"},
                            {"id": "c-clean", "status": "tested_clean"}]
    brain.candidates = [{"id": "cand-pending", "status": "pending"},
                        {"id": "cand-ok", "status": "confirmed"}]
    brain.engagement_goals = [{"id": "goal-1", "status": "open"}]
    assert active_threads_from_brain(brain) == {"h-open", "c-leased", "l1", "cand-pending", "goal-1"}


@pytest.mark.asyncio
async def test_expand_compacted_restores_a_folded_thread():
    org = current_organization_id.set(1)
    session = current_session_id.set("compaction-test")
    try:
        manager = ASMToolsManager()
        compact_execution_trace(_trace(), active_threads={"h-active"},
                                archive=manager._compacted_archive)
        out = json.loads(await manager.expand_compacted("h-done", limit=3))
        assert out["total"] == 10
        assert [s["iteration"] for s in out["steps"]] == [7, 8, 9]
        missing = json.loads(await manager.expand_compacted("nope"))
        assert "h-done" in missing["available"]
    finally:
        current_session_id.reset(session)
        current_organization_id.reset(org)
