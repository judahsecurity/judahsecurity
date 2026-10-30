"""Cross-session learning: prior kills demote a methodology card's seed priority."""

from app.services.agent import evograph
from app.services.agent.engagement_brain import (
    EngagementBrain,
    seed_hypotheses_from_capability_map,
)
from app.services.agent.evograph import (
    demote_for_priors,
    methodology_signature,
)
from app.services.agent.tools import current_organization_id


def test_methodology_signature_normalizes_to_host():
    assert methodology_signature("https://App.Example.TEST/path?x=1") == "app.example.test"
    assert methodology_signature("app.example.test") == "app.example.test"
    assert methodology_signature("") == ""


def test_demote_keeps_priority_without_priors():
    assert demote_for_priors("high", None) == ("high", "")
    assert demote_for_priors("high", {"killed": 1}) == ("high", "")


def test_demote_on_repeated_same_target_kills():
    prior = {"killed": 2, "confirmed": 0, "same_target_killed": 2, "same_target_confirmed": 0}
    priority, reason = demote_for_priors("high", prior)
    assert priority == "medium"
    assert "this target" in reason


def test_demote_on_org_wide_kills():
    prior = {"killed": 3, "confirmed": 0, "same_target_killed": 0, "same_target_confirmed": 0}
    priority, reason = demote_for_priors("critical", prior)
    assert priority == "high"
    assert "org-wide" in reason


def test_confirmed_finding_blocks_demotion():
    prior = {"killed": 9, "confirmed": 1, "same_target_killed": 9, "same_target_confirmed": 0}
    assert demote_for_priors("high", prior) == ("high", "")
    same = {"killed": 9, "confirmed": 0, "same_target_killed": 9, "same_target_confirmed": 1}
    assert demote_for_priors("high", same) == ("high", "")


def test_demote_never_below_low():
    prior = {"same_target_killed": 2, "confirmed": 0}
    assert demote_for_priors("low", prior)[0] == "low"


def test_no_driver_queries_are_safe():
    # No Neo4j in the test env: reads return {}, writes are no-ops (no raise).
    assert evograph.get_methodology_priors(1, "https://app.example.test") == {}
    evograph.record_methodology_outcome(
        session_id="s1", organization_id=1, methodology_id="idor_x",
        outcome="killed", target="https://app.example.test", cwe_ids=["CWE-639"],
    )


def test_prior_kills_demote_seeded_hypothesis(monkeypatch):
    monkeypatch.setattr(
        evograph,
        "get_methodology_priors",
        lambda org, target, **kw: {
            "idor_x": {
                "killed": 2, "confirmed": 0, "inconclusive": 0,
                "same_target_killed": 2, "same_target_confirmed": 0,
            }
        },
    )
    token = current_organization_id.set(1)
    try:
        brain = EngagementBrain(target="https://app.example.test")
        cmap = {
            "target": "https://app.example.test",
            "methodologies": [
                {"id": "idor_x", "title": "IDOR", "priority": "high",
                 "specialist": "api_authz", "cwe_ids": ["CWE-639"]},
                {"id": "fresh_y", "title": "SSRF", "priority": "high",
                 "specialist": "ssrf", "cwe_ids": ["CWE-918"]},
            ],
        }
        seed_hypotheses_from_capability_map(brain, cmap)
    finally:
        current_organization_id.reset(token)

    demoted = next(h for h in brain.hypotheses if h.methodology_id == "idor_x")
    untouched = next(h for h in brain.hypotheses if h.methodology_id == "fresh_y")
    assert demoted.priority == "medium"
    assert "demoted" in demoted.evidence
    assert untouched.priority == "high"


def test_no_org_context_leaves_priority_unchanged(monkeypatch):
    called = {"n": 0}

    def _spy(*a, **k):
        called["n"] += 1
        return {}

    monkeypatch.setattr(evograph, "get_methodology_priors", _spy)
    # Ensure no org in context.
    token = current_organization_id.set(None)
    try:
        brain = EngagementBrain(target="https://app.example.test")
        cmap = {
            "target": "https://app.example.test",
            "methodologies": [
                {"id": "idor_x", "title": "IDOR", "priority": "high", "specialist": "api_authz"},
            ],
        }
        seed_hypotheses_from_capability_map(brain, cmap)
    finally:
        current_organization_id.reset(token)

    assert called["n"] == 0  # no org → no EvoGraph query
    assert next(h for h in brain.hypotheses if h.methodology_id == "idor_x").priority == "high"
