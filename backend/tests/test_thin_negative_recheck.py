"""A 'clean' verdict from one receipt and one tool is re-checked once."""

from app.services.agent.engagement_brain import EngagementBrain, Hypothesis
from app.services.agent.operation_directive import directives_from_hypotheses
from app.services.agent.penetration_task_graph import (
    ExecutorSummary,
    PenetrationTaskGraph,
    TaskNode,
    apply_executor_summary,
    claim_task_leases,
    graph_from_dict,
)
from app.services.agent.fireteam_service import get_specialist


def _setup():
    brain = EngagementBrain(target="https://app.test", hypotheses=[Hypothesis(
        id="h1", title="SQLi in id", assumption="a", test="t", pass_criteria="p",
        kill_criteria="k", specialist="injection")])
    graph = PenetrationTaskGraph(nodes={
        "h1": TaskNode(id="h1", title="SQLi in id", specialist="injection",
                       status="running", attempts=1)})
    return brain, graph


def _kill(receipts, tools):
    return ExecutorSummary(
        specialist="injection", verdict="killed", evidence="no change",
        tools_run=tools,
        hypothesis_results=[{"hypothesis_id": "h1", "verdict": "killed",
                             "evidence_ids": receipts, "evidence": "responses identical"}],
    )


def test_thin_kill_is_rechecked_once_with_guidance():
    brain, graph = _setup()
    apply_executor_summary(graph, brain, _kill(["e1"], ["scoped_numeric_sqli"]))
    node = graph.nodes["h1"]
    assert node.status == "ready" and node.negative_rechecked is True
    assert "different techniques" in node.rewritten_test
    assert brain.hypotheses[0].status == "in_progress"

    # The re-check lease carries the guidance to the specialist.
    leases = claim_task_leases(graph, ["injection"])
    brain.task_graph = graph.to_dict()
    directive = directives_from_hypotheses(
        brain=brain, profiles_by_name={"injection": get_specialist("injection")},
        specialists=["injection"], default_target="https://app.test", task_leases=leases,
    )["injection"]
    assert "Re-check a thin negative" in directive.rewrite_note
    assert "Re-check a thin negative" in directive.to_prompt_block()

    # A second thin kill stands: the re-check happens once.
    node.status = "running"
    apply_executor_summary(graph, brain, _kill(["e2"], ["scoped_numeric_sqli"]))
    assert graph.nodes["h1"].status == "killed"


def test_kill_from_several_receipts_or_tools_stands():
    for receipts, tools in ((["e1", "e2"], ["scoped_numeric_sqli"]),
                            (["e1"], ["scoped_numeric_sqli", "scoped_string_sqli"])):
        brain, graph = _setup()
        apply_executor_summary(graph, brain, _kill(receipts, tools))
        assert graph.nodes["h1"].status == "killed"


def test_flag_round_trips_and_is_omitted_when_unused():
    brain, graph = _setup()
    assert "negative_rechecked" not in graph.nodes["h1"].to_dict()
    apply_executor_summary(graph, brain, _kill(["e1"], ["x"]))
    again = graph_from_dict(graph.to_dict())
    assert again.nodes["h1"].negative_rechecked is True
