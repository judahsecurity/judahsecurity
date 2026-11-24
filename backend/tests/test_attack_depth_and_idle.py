"""Confirmed footholds are pressed first; open goals never leave the run idle."""

import json

import pytest

from app.services.agent import attack_focus
from app.services.agent.engagement_brain import (
    EngagementBrain,
    format_methodology_progress_for_prompt,
    methodology_progress,
)
from app.services.agent.engagement_goals import (
    MAX_GOAL_ATTEMPTS,
    goal_specialist,
    seed_goal_hypotheses,
)
from app.services.agent.independent_verify import FindingCandidate
from app.services.agent.penetration_task_graph import ready_wave, sync_graph_from_brain


def _candidate(**kw):
    base = dict(id="cand-1", title="Default admin login on /admin", severity="high",
                target="https://app.test", vulnerability_class="default_login",
                evidence="admin/admin accepted", status="confirmed")
    base.update(kw)
    return FindingCandidate(**base)


def test_confirmed_foothold_queues_critical_followups_once():
    brain = EngagementBrain(target="https://app.test")
    created = attack_focus.deepen_after_confirmation(brain, _candidate())
    assert created
    followups = [h for h in brain.hypotheses if h.id in created]
    assert all(h.priority == "critical" and h.parent_finding for h in followups)
    assert brain.attack_routes[0]["candidate_id"] == "cand-1"
    # The same candidate does not queue its chain twice.
    assert attack_focus.deepen_after_confirmation(brain, _candidate()) == []
    # Critical follow-ups lead the next wave.
    graph = sync_graph_from_brain(brain)
    wave = ready_wave(graph, max_specialists=6)
    assert wave and wave[0] == followups[0].specialist
    text = format_methodology_progress_for_prompt(methodology_progress(brain))
    assert "ACTIVE ATTACK ROUTES" in text and "Default admin login" in text


def test_low_impact_confirmation_is_not_a_route():
    brain = EngagementBrain()
    low = _candidate(severity="low", vulnerability_class="info_disclosure", title="Server banner")
    assert attack_focus.deepen_after_confirmation(brain, low) == []
    assert brain.attack_routes == []


def test_routes_survive_serialization_and_are_omitted_when_unused():
    brain = EngagementBrain()
    assert "attack_routes" not in brain.to_dict()
    attack_focus.deepen_after_confirmation(brain, _candidate())
    from app.services.agent.engagement_brain import engagement_brain_from_dict

    assert engagement_brain_from_dict(brain.to_dict()).attack_routes == brain.attack_routes


def _brain_with_goal(vuln_class="idor"):
    brain = EngagementBrain(target="https://app.test")
    brain.engagement_goals = [{"id": "goal-a", "text": "Read another tenant's invoice",
                               "vuln_class": vuln_class, "status": "open"}]
    return brain


def test_open_goal_gets_work_when_nothing_is_queued():
    brain = _brain_with_goal()
    assert seed_goal_hypotheses(brain) == ["goal-a-try-1"]
    hypothesis = brain.hypotheses[0]
    assert hypothesis.specialist == "api_authz" and hypothesis.priority == "critical"
    # While that attempt is open, no second one is added.
    assert seed_goal_hypotheses(brain) == []
    hypothesis.status = "killed"
    hypothesis.evidence = "sequential ids all 403"
    assert seed_goal_hypotheses(brain) == ["goal-a-try-2"]
    assert "sequential ids all 403" in brain.hypotheses[-1].test


def test_attempts_are_capped_and_met_goals_get_nothing():
    brain = _brain_with_goal(vuln_class="")
    assert goal_specialist(brain.engagement_goals[0]) == "business_logic"
    for _ in range(MAX_GOAL_ATTEMPTS + 2):
        for h in brain.hypotheses:
            h.status = "killed"
        seed_goal_hypotheses(brain)
    assert len(brain.hypotheses) == MAX_GOAL_ATTEMPTS
    brain.engagement_goals[0]["status"] = "met"
    for h in brain.hypotheses:
        h.status = "killed"
    assert seed_goal_hypotheses(brain) == []


@pytest.mark.asyncio
async def test_dispatch_seeds_goal_work_instead_of_idling(monkeypatch):
    from app.services.agent.fireteam_service import FireteamResult
    from app.services.agent.tools import ASMToolsManager, current_organization_id, current_session_id

    org = current_organization_id.set(5)
    session = current_session_id.set("idle-test")
    try:
        manager = ASMToolsManager()
        manager._assessment_scope.update({"app.test"})
        monkeypatch.setattr(manager, "_cheap_llm", lambda: object())
        monkeypatch.setattr("app.services.agent.run_snapshot.save_run_snapshot", lambda *a, **k: None)
        manager._engagement_brain = _brain_with_goal().to_dict()
        seen = {}

        async def fake_fireteam(*, mission, directives, **kwargs):
            seen.setdefault("directives", []).append(sorted(directives))
            return FireteamResult(mission=mission, specialists_run=[], reports=[])

        monkeypatch.setattr("app.services.agent.fireteam_service.run_fireteam", fake_fireteam)
        result = json.loads(await manager.fireteam_dispatch(
            mission="Test", targets=["https://app.test"], specialists="auto"))
        assert result["goal_work_seeded"] == ["goal-a-try-1"]
        assert seen["directives"][0] == ["api_authz"]
    finally:
        current_session_id.reset(session)
        current_organization_id.reset(org)
