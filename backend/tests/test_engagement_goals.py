"""Operator goals and constraints: derived once, proven or closed before completion."""

import json

import pytest
from langchain_core.messages import AIMessage

from app.services.agent import engagement_goals as goals
from app.services.agent.engagement_brain import (
    EngagementBrain,
    engagement_brain_from_dict,
    format_methodology_progress_for_prompt,
    methodology_progress,
)
from app.services.agent.tester_loop import forced_next_step
from app.services.agent.tools import (
    ASMToolsManager,
    current_organization_id,
    current_session_id,
)

OBJECTIVE = ("Assess https://shop.example.test. Show whether one customer can read another "
             "customer's invoices. Do not touch the payments API on this site.")
MODEL_JSON = json.dumps({
    "constraints": [
        {"kind": "deny", "text": "Do not test the payments API on shop.example.test"},
        {"kind": "deny", "text": "Do not test the payments API on shop.example.test"},
        {"kind": "maybe", "text": "Only use the staging tenant"},
    ],
    "goals": [
        {"text": "Read another customer's invoice", "vuln_class": "IDOR!"},
        {"text": "x"},
        {"text": "read another customer's invoice"},
    ],
})


@pytest.mark.parametrize("objective,expected", [
    ("Assess https://shop.example.test", False),
    ("please run a full security assessment of app.example.test", False),
    ("pentest api.example.com/v1", False),
    (OBJECTIVE, True),
    ("Get admin on https://a.test without credentials", True),
])
def test_only_objectives_with_more_than_a_target_are_read(objective, expected):
    assert goals.objective_states_more_than_a_target(objective) is expected


def test_model_output_is_validated_not_trusted():
    parsed_goals, constraints = goals.parse_goals_response("Here you go:\n" + MODEL_JSON)
    assert [g["text"] for g in parsed_goals] == ["Read another customer's invoice"]
    assert parsed_goals[0]["vuln_class"] == "idor" and parsed_goals[0]["status"] == "open"
    assert constraints == [
        {"kind": "deny", "text": "Do not test the payments API on shop.example.test"},
        # An unknown kind is treated as the conservative one.
        {"kind": "deny", "text": "Only use the staging tenant"},
    ]
    assert goals.parse_goals_response("not json") == ([], [])


def _brain_with_goal(candidate_status="confirmed", verified=True):
    brain = EngagementBrain(target="https://shop.example.test")
    parsed_goals, constraints = goals.parse_goals_response(MODEL_JSON)
    goals.record_goals(brain, parsed_goals, constraints)
    brain.candidates = [{
        "id": "cand-1", "title": "IDOR on /api/invoices/{id}", "status": candidate_status,
        "verified_at": "2026-11-20T00:00:00Z" if verified else "",
        "evidence_ids": ["a" * 32], "finding_id": "",
    }]
    return brain, parsed_goals[0]["id"]


def test_only_a_verified_candidate_proves_a_goal():
    brain, goal_id = _brain_with_goal(candidate_status="pending", verified=False)
    with pytest.raises(ValueError, match="verified"):
        goals.prove_goal(brain, goal_id, "cand-1", "Customer B's invoice returned to customer A")
    brain, goal_id = _brain_with_goal()
    with pytest.raises(ValueError, match="Explain"):
        goals.prove_goal(brain, goal_id, "cand-1", "yes")
    goal = goals.prove_goal(brain, goal_id, "cand-1", "Customer B's invoice returned to customer A")
    assert goal["status"] == "met"
    assert goal["proof"]["candidate_id"] == "cand-1"
    assert goal["proof"]["evidence_ids"] == ["a" * 32]


def test_closing_a_goal_needs_the_routes_tried():
    brain, goal_id = _brain_with_goal()
    with pytest.raises(ValueError, match="routes"):
        goals.close_goal(brain, goal_id, "not found")
    goal = goals.close_goal(brain, goal_id, "Tried sequential invoice ids, other tenants' ids "
                                            "from the export, and the GraphQL invoice query; all 403.")
    assert goal["status"] == "not_achieved"


def test_open_goals_block_completion_and_show_in_the_planner_prompt():
    brain, goal_id = _brain_with_goal()
    progress = methodology_progress(brain)
    assert progress["ready_to_complete"] is False
    assert progress["open_goals"] == 1
    assert any(row["methodology_id"] == "engagement_goal" for row in progress["blockers"])
    text = format_methodology_progress_for_prompt(progress)
    assert "DENY: Do not test the payments API on shop.example.test" in text
    assert f"{goal_id} (open)" in text

    goals.prove_goal(brain, goal_id, "cand-1", "Customer B's invoice returned to customer A")
    progress = methodology_progress(brain)
    assert progress["open_goals"] == 0
    assert not any(row["methodology_id"] == "engagement_goal" for row in progress["blockers"])


def test_goals_survive_a_round_trip():
    brain, _ = _brain_with_goal()
    again = engagement_brain_from_dict(json.loads(json.dumps(brain.to_dict())))
    assert again.engagement_goals == brain.engagement_goals
    assert again.operator_constraints == brain.operator_constraints
    assert again.goals_derived is True


def test_specialists_see_constraints_and_open_goals_only():
    brain, goal_id = _brain_with_goal()
    block = goals.specialist_block(brain)
    assert "DENY: Do not test the payments API" in block
    assert "Read another customer's invoice" in block
    goals.prove_goal(brain, goal_id, "cand-1", "Customer B's invoice returned to customer A")
    assert "Read another customer's invoice" not in goals.specialist_block(brain)


def test_pipeline_derives_goals_once_for_a_specific_objective():
    state = {"mode": "agent", "original_objective": OBJECTIVE,
             "target_info": {"primary_target": "https://shop.example.test"},
             "execution_trace": []}
    step = forced_next_step(state)
    assert step["tool_name"] == "derive_engagement_goals"
    assert step["tool_args"]["objective"] == OBJECTIVE
    state["execution_trace"] = [{"tool_name": "derive_engagement_goals", "success": True}]
    assert forced_next_step(state)["tool_name"] != "derive_engagement_goals"
    plain = {**state, "original_objective": "Assess https://shop.example.test",
             "execution_trace": []}
    assert forced_next_step(plain)["tool_name"] != "derive_engagement_goals"


@pytest.fixture
def manager():
    org = current_organization_id.set(98765)
    session = current_session_id.set("engagement-goals-test")
    instance = ASMToolsManager()
    yield instance
    current_session_id.reset(session)
    current_organization_id.reset(org)


@pytest.mark.asyncio
async def test_tools_derive_prove_and_close(manager, monkeypatch):
    calls = []

    class FakeLLM:
        async def ainvoke(self, messages):
            calls.append(messages[0].content)
            return AIMessage(content=MODEL_JSON)

    monkeypatch.setattr(manager, "_hypothesis_llm", lambda: FakeLLM())
    manager._engagement_brain = EngagementBrain(target="https://shop.example.test").to_dict()
    derived = json.loads(await manager.derive_engagement_goals(OBJECTIVE))
    assert derived["success"] and len(derived["goals"]) == 1
    assert OBJECTIVE in calls[0]
    # A second call does not ask the model again.
    again = json.loads(await manager.derive_engagement_goals(OBJECTIVE))
    assert again["already_derived"] and len(calls) == 1

    goal_id = derived["goals"][0]["id"]
    failed = json.loads(await manager.prove_goal(goal_id, "missing", "Customer B's invoice shown"))
    assert failed["success"] is False
    closed = json.loads(await manager.close_goal(
        goal_id, "Tried sequential ids, exported ids and the GraphQL query; every request 403."))
    assert closed["success"] and closed["open_goals"] == 0
    listed = json.loads(await manager.list_engagement_goals())
    assert listed["goals"][0]["status"] == "not_achieved"
