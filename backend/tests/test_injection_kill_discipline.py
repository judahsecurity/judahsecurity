"""Regression tests for the two injection-coverage fixes.

Both target the observed Gin & Juice failure where the SQLi lane saw a real
9399->8690 byte differential on `category`, never escalated to sqlmap, and the
coverage cell was closed `negative with evidence` on a single pass — while the
lane's repeated identical probes burned the wall-clock so 101 other hypotheses
were never attempted.

1. kill_is_disciplined / apply_executor_summary — a high-value injection/XSS
   kill that never escalated is sent back for one confirmation pass instead of
   closing clean (bounded by the node's retry budget, so it can never loop).
2. _RepeatGuard — structurally identical re-probes are refused so one lane
   cannot spin on a single parameter.
"""

from types import SimpleNamespace

from app.services.agent.probe_guard import RepeatGuard as _RepeatGuard
from app.services.agent.probe_guard import probe_signature as _probe_signature
from app.services.agent.penetration_task_graph import (
    NODE_KILLED,
    NODE_READY,
    NODE_RETRY,
    ExecutorSummary,
    apply_executor_summary,
    kill_is_disciplined,
)


# --- kill_is_disciplined -----------------------------------------------------

def test_undisciplined_injection_kill_is_rejected():
    # Differential probing only, no escalation, first attempt -> not disciplined.
    assert kill_is_disciplined("sqli", ["compare_requests", "run_custom_probe"], 1) is False
    assert kill_is_disciplined("injection", ["compare_requests"], 1) is False
    assert kill_is_disciplined("xss", ["compare_requests"], 1) is False


def test_escalated_kill_is_disciplined():
    assert kill_is_disciplined("sqli", ["compare_requests", "execute_sqlmap"], 1) is True
    assert kill_is_disciplined("injection", ["execute_commix"], 1) is True
    assert kill_is_disciplined("xss", ["execute_browser"], 1) is True
    assert kill_is_disciplined("xss", ["execute_dalfox"], 1) is True


def test_retry_budget_bounds_the_gate():
    # Once the retry budget is spent the kill is accepted so a lane never loops.
    assert kill_is_disciplined("sqli", ["compare_requests"], 2, 2) is True
    assert kill_is_disciplined("sqli", ["compare_requests"], 3, 2) is True


def test_non_high_value_lanes_are_unchanged():
    assert kill_is_disciplined("ssrf", ["compare_requests"], 1) is True
    assert kill_is_disciplined("business_logic", [], 1) is True
    assert kill_is_disciplined("", [], 1) is True


# --- apply_executor_summary (node-level wiring) ------------------------------

def _graph_with_running_node(specialist: str, attempts: int = 1):
    from app.services.agent.penetration_task_graph import NODE_RUNNING, PenetrationTaskGraph, TaskNode

    node = TaskNode(
        id="h-inj",
        title="Injection on mapped parameters",
        specialist=specialist,
        status=NODE_RUNNING,
        attempts=attempts,
        max_attempts=2,
        lease_id="lease-1",
    )
    graph = PenetrationTaskGraph(nodes={node.id: node})
    brain = SimpleNamespace(hypotheses=[], coverage_cells=[], candidates=[])
    return graph, brain, node


def _killed_summary(specialist: str, tools_run):
    return ExecutorSummary(
        specialist=specialist,
        assigned_hypothesis_id="h-inj",
        lease_id="lease-1",
        tools_run=list(tools_run),
        hypothesis_results=[{
            "hypothesis_id": "h-inj",
            "verdict": "killed",
            "evidence_ids": ["ev-1", "ev-2"],
            "evidence": "baseline 9399 vs 8690 byte differential, no escalation",
        }],
    )


def test_node_kill_without_escalation_becomes_retry():
    graph, brain, node = _graph_with_running_node("sqli", attempts=1)
    apply_executor_summary(graph, brain, _killed_summary("sqli", ["compare_requests"]))
    result = graph.nodes["h-inj"]
    # Not closed clean; sent back for a second escalated pass (retry is re-readied
    # by _recompute_readiness while attempts < max_attempts).
    assert result.status != NODE_KILLED
    assert result.status in (NODE_RETRY, NODE_READY)
    assert "escalat" in result.last_failure.lower()


def test_node_kill_with_escalation_closes():
    graph, brain, node = _graph_with_running_node("sqli", attempts=1)
    apply_executor_summary(graph, brain, _killed_summary("sqli", ["compare_requests", "execute_sqlmap"]))
    assert graph.nodes["h-inj"].status == NODE_KILLED


def test_node_kill_accepted_once_budget_spent():
    graph, brain, node = _graph_with_running_node("sqli", attempts=2)
    apply_executor_summary(graph, brain, _killed_summary("sqli", ["compare_requests"]))
    assert graph.nodes["h-inj"].status == NODE_KILLED


# --- repeat guard ------------------------------------------------------------

def test_probe_signature_is_key_order_independent():
    assert _probe_signature("compare_requests", {"a": 1, "b": 2}) == \
        _probe_signature("compare_requests", {"b": 2, "a": 1})


def test_repeat_guard_refuses_third_identical_probe():
    guard = _RepeatGuard()
    args = {"url": "/catalog?category=x"}
    assert [guard.allow("compare_requests", args) for _ in range(4)] == [True, True, False, False]
    # distinct arg / distinct tool are independent
    assert guard.allow("compare_requests", {"url": "/catalog?category=y"}) is True
    assert guard.allow("http_exchange", args) is True
    assert guard.duplicate_count == 2
