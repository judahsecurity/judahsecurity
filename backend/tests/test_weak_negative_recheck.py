"""Weak negatives go back once for a different technique before closing."""

from types import SimpleNamespace

from app.core.config import settings
from app.services.agent.penetration_task_graph import (
    NODE_BLOCKED,
    NODE_KILLED,
    NODE_READY,
    NODE_RETRY,
    ExecutorSummary,
    apply_executor_summary,
    claim_task_leases,
    parse_executor_summary,
    ready_wave,
    sync_graph_from_brain,
    weak_negative_reason,
)

from tests.test_penetration_task_graph import _seeded_brain


def _leased():
    brain = _seeded_brain()
    graph = sync_graph_from_brain(brain)
    specialist = ready_wave(graph)[0]
    lease = claim_task_leases(graph, [specialist])[specialist]
    return brain, graph, specialist, graph.nodes[lease.hypothesis_id], lease


def _killed(specialist, node, lease, *, evidence_ids, tools):
    return ExecutorSummary(
        specialist=specialist,
        hypothesis_ids=[node.id],
        verdict="killed",
        evidence="no reflection",
        tools_run=tools,
        assigned_hypothesis_id=node.id,
        lease_id=lease.id,
        hypothesis_results=[{"hypothesis_id": node.id, "verdict": "killed",
                             "evidence_ids": evidence_ids, "evidence": "payload not reflected"}],
    )


def test_weak_negative_reason():
    summary = ExecutorSummary(specialist="xss", tools_run=["replay_http_request", "save_note"])
    assert "evidence receipt" in weak_negative_reason({"evidence_ids": ["e1"]}, summary)
    assert "one testing tool" in weak_negative_reason({"evidence_ids": ["e1", "e2"]}, summary)
    strong = ExecutorSummary(specialist="xss", tools_run=["replay_http_request", "execute_browser"])
    assert weak_negative_reason({"evidence_ids": ["e1", "e2"]}, strong) == ""
    assert "one testing tool" in weak_negative_reason(
        {"evidence_ids": ["e1", "e2"], "evidence_tool_names": ["replay_http_request"]}, strong)
    strong.stop_reason = "exhausted"
    assert "exhausted" in weak_negative_reason({"evidence_ids": ["e1", "e2"]}, strong)


def test_unrelated_tool_does_not_strengthen_negative_receipts():
    report = SimpleNamespace(
        specialist="xss", assigned_hypothesis_id="h1", tool_calls=[
            SimpleNamespace(tool="replay_http_request", args={"hypothesis_id": "h1"},
                            success=True, evidence_ids=["e1", "e2"]),
            SimpleNamespace(tool="execute_browser", args={"hypothesis_id": "other"},
                            success=True, evidence_ids=["e3"]),
        ], hypothesis_results=[{"hypothesis_id": "h1", "verdict": "killed",
                                "evidence_ids": ["e1", "e2"], "evidence": "no reflection"}],
    )
    parsed = parse_executor_summary(report)
    result = parsed.hypothesis_results[0]
    assert result["evidence_tool_names"] == ["replay_http_request"]
    assert "one testing tool" in weak_negative_reason(result, parsed)


def test_weak_kill_closes_immediately_when_flag_off(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_RECHECK_WEAK_NEGATIVES", False)
    brain, graph, specialist, node, lease = _leased()
    apply_executor_summary(graph, brain, _killed(specialist, node, lease,
                                                 evidence_ids=["e1"], tools=["replay_http_request"]))
    assert graph.nodes[node.id].status == NODE_KILLED


def test_weak_kill_is_rechecked_once(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_RECHECK_WEAK_NEGATIVES", True)
    brain, graph, specialist, node, lease = _leased()
    apply_executor_summary(graph, brain, _killed(specialist, node, lease,
                                                 evidence_ids=["e1"], tools=["replay_http_request"]))
    rechecked = graph.nodes[node.id]
    assert rechecked.status in (NODE_RETRY, NODE_READY) and rechecked.rechecked
    hypothesis = next(h for h in brain.hypotheses if h.id == node.id)
    assert hypothesis.status == "in_progress"
    assert "RE-CHECK (single attempt)" in hypothesis.test
    assert "replay_http_request" in hypothesis.test

    lease2 = claim_task_leases(graph, [specialist])[specialist]
    assert lease2.hypothesis_id == node.id
    apply_executor_summary(graph, brain, _killed(specialist, rechecked, lease2,
                                                 evidence_ids=["e2"], tools=["execute_browser"]))
    assert graph.nodes[node.id].status == NODE_KILLED
    assert graph.nodes[node.id].evidence_ids == ["e1", "e2"]
    assert graph.nodes[node.id].negative_tool_names == ["replay_http_request", "execute_browser"]
    assert hypothesis.status == "killed"
    assert hypothesis.test.count("RE-CHECK") == 1


def test_second_thin_negative_stays_open_after_one_recheck(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_RECHECK_WEAK_NEGATIVES", True)
    brain, graph, specialist, node, lease = _leased()
    apply_executor_summary(graph, brain, _killed(specialist, node, lease,
                                                 evidence_ids=["e1"], tools=["replay_http_request"]))
    lease2 = claim_task_leases(graph, [specialist])[specialist]
    apply_executor_summary(graph, brain, _killed(specialist, node, lease2,
                                                 evidence_ids=["e2"], tools=["replay_http_request"]))
    assert graph.nodes[node.id].status == NODE_BLOCKED
    assert graph.nodes[node.id].evidence_ids == ["e1", "e2"]
    assert graph.nodes[node.id].blocked_reason.startswith("Negative coverage incomplete")
    assert next(h for h in brain.hypotheses if h.id == node.id).status == "open"


def test_strong_kill_closes_with_flag_on(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_RECHECK_WEAK_NEGATIVES", True)
    brain, graph, specialist, node, lease = _leased()
    apply_executor_summary(graph, brain, _killed(
        specialist, node, lease, evidence_ids=["e1", "e2", "e3"],
        tools=["replay_http_request", "execute_browser"]))
    assert graph.nodes[node.id].status == NODE_KILLED
