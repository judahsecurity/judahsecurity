"""Interrupted reads retry, uncertain writes block, and retries get valid leases."""

import asyncio
import time

import pytest

from app.services.agent.coverage_cells import (
    MAX_RETRY_ATTEMPTS,
    claim_coverage_cell_leases,
    record_coverage_cell,
    release_coverage_cell_lease,
    renew_coverage_cell_leases,
)
from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.fireteam_service import (
    SpecialistProfile,
    SpecialistReport,
    is_safe_read_call,
    run_fireteam,
)
from app.services.agent.penetration_task_graph import (
    NODE_READY,
    NODE_RETRY,
    NODE_RUNNING,
    PenetrationTaskGraph,
    TaskNode,
    apply_executor_summary,
    parse_executor_summary,
)


@pytest.mark.parametrize("tool,args,safe", [
    ("get_engagement_brain", {}, True),
    ("replay_http_request", {"method": "GET", "url": "https://a.test/x"}, True),
    ("replay_http_request", {"url": "https://a.test/x"}, True),
    ("replay_http_request", {"method": "POST", "url": "https://a.test/x"}, False),
    ("replay_http_request", {"method": "GET", "body": "a=1"}, False),
    ("compare_requests", {"baseline": {"method": "GET"}, "mutant": {"method": "HEAD"}}, True),
    ("compare_requests", {"baseline": {"method": "GET"}, "mutant": {"method": "PUT"}}, False),
    ("compare_requests", {"baseline": {"method": "GET"}, "mutant": {"json": {"a": 1}}}, False),
    ("scoped_browser_assessment", {"operation": "crawl"}, True),
    ("scoped_browser_assessment", {"operation": "check_stored_xss"}, False),
    ("execute_sqlmap", {}, False),
    ("", {}, False),
])
def test_safe_read_classification(tool, args, safe):
    assert is_safe_read_call(tool, args) is safe


async def _timed_out_report(monkeypatch, call):
    async def hang(profile, mission, targets, llm, tools_manager,
                   directive=None, execution_progress=None):
        execution_progress["tool_inflight"] = True
        execution_progress["inflight_calls"] = [call]
        await asyncio.sleep(1)

    monkeypatch.setattr("app.services.agent.fireteam_service._run_specialist", hang)
    result = await run_fireteam(
        mission="t", targets=[],
        specialists=[SpecialistProfile(name="sqli", role="sqli", allowed_tools=[])],
        llm=None, tools_manager=None, member_timeout_sec=0.02, wave_timeout_sec=0.2,
    )
    return result.reports[0]


@pytest.mark.asyncio
async def test_interrupted_read_is_retryable(monkeypatch):
    report = await _timed_out_report(
        monkeypatch, {"tool": "replay_http_request", "args": {"method": "GET"}})
    assert report.verdict == "retry"
    assert report.rewrite_hint == "execution_timeout_read_inflight"
    assert report.stop_reason == "exhausted"

    graph = PenetrationTaskGraph(nodes={"h1": TaskNode(
        id="h1", title="t", specialist="sqli", status=NODE_RUNNING)})
    apply_executor_summary(graph, EngagementBrain(), parse_executor_summary(report))
    # Released for rescheduling, not held for analyst reconciliation.
    assert graph.nodes["h1"].status in {NODE_RETRY, NODE_READY}
    assert not graph.nodes["h1"].recovery_required


@pytest.mark.asyncio
async def test_interrupted_write_stays_blocked(monkeypatch):
    report = await _timed_out_report(
        monkeypatch, {"tool": "replay_http_request", "args": {"method": "POST"}})
    assert report.verdict == "blocked"
    assert report.rewrite_hint == "execution_timeout"


def _brain_with_cell():
    brain = EngagementBrain(target="https://a.test")
    cell = record_coverage_cell(
        brain, method="GET", path="/item", host="a.test", status="untested",
        parameter="query:id", test_type="sqli",
    )
    cell["specialist"] = "sqli"
    return brain, cell["id"]


def _cell(brain, cell_id):
    return next(c for c in brain.coverage_cells if c["id"] == cell_id)


def test_blocked_release_holds_cell_for_review():
    brain, cell_id = _brain_with_cell()
    lease = claim_coverage_cell_leases(brain, ["sqli"])["sqli"]
    release_coverage_cell_lease(brain, lease, verdict="blocked", reason="POST cancelled")
    cell = _cell(brain, cell_id)
    assert cell["status"] == "blocked" and cell["review_required"]
    assert claim_coverage_cell_leases(brain, ["sqli"]) == {}


def test_retry_release_reopens_until_attempts_exhausted():
    brain, cell_id = _brain_with_cell()
    for attempt in range(1, MAX_RETRY_ATTEMPTS + 1):
        lease = claim_coverage_cell_leases(brain, ["sqli"])["sqli"]
        release_coverage_cell_lease(brain, lease, verdict="retry", reason="timed out")
        status = _cell(brain, cell_id)["status"]
        assert status == ("blocked" if attempt == MAX_RETRY_ATTEMPTS else "inconclusive")
    assert "interrupted attempts" in _cell(brain, cell_id)["reason"]
    assert claim_coverage_cell_leases(brain, ["sqli"]) == {}


def test_renewal_keeps_live_lease_and_releases_consumed_one():
    brain, cell_id = _brain_with_cell()
    lease = claim_coverage_cell_leases(brain, ["sqli"])["sqli"]
    assert renew_coverage_cell_leases(brain, {"sqli": lease}, ["sqli"])["sqli"] is lease

    # A first-wave inconclusive receipt consumes the lease but leaves the cell open.
    record_coverage_cell(brain, method="GET", path="/item", status="inconclusive",
                         reason="first technique negative", coverage_cell_id_value=cell_id,
                         coverage_lease_id=lease.id)
    renewed = renew_coverage_cell_leases(brain, {"sqli": lease}, ["sqli"])["sqli"]
    assert renewed.id != lease.id and renewed.coverage_cell_id == cell_id
    assert _cell(brain, cell_id)["lease_id"] == renewed.id


def test_renewal_drops_lease_for_finished_or_expired_cells():
    brain, cell_id = _brain_with_cell()
    lease = claim_coverage_cell_leases(brain, ["sqli"])["sqli"]
    record_coverage_cell(brain, method="GET", path="/item", status="tested_clean",
                         coverage_cell_id_value=cell_id, coverage_lease_id=lease.id)
    assert renew_coverage_cell_leases(brain, {"sqli": lease}, ["sqli"]) == {}

    brain, cell_id = _brain_with_cell()
    lease = claim_coverage_cell_leases(brain, ["sqli"], now=time.time() - 7200)["sqli"]
    renewed = renew_coverage_cell_leases(brain, {"sqli": lease}, ["sqli"])
    # An expired lease is recovered to inconclusive and leased again.
    assert renewed["sqli"].id != lease.id
