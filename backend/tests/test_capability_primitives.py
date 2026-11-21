"""Capability primitives combine proven results into chain hypotheses."""

import json

import pytest

from app.services.agent.capability_primitives import (
    ADMIN_SURFACE, CREDENTIAL, READ_FILE, SECRET, VICTIM_BROWSER,
    brain_primitives, evaluate_patterns, primitives_from_text, queue_chain_hypotheses,
)
from app.services.agent.engagement_brain import (
    CredentialRecord, EngagementBrain, Hypothesis, engagement_brain_from_dict,
)


def _hyp(hid, title, status="proven", evidence=""):
    return Hypothesis(id=hid, title=title, assumption="", test="", pass_criteria="",
                      kill_criteria="", specialist="xss", status=status, evidence=evidence)


@pytest.mark.parametrize("text, primitive", [
    ("Path traversal reads /etc/passwd", READ_FILE),
    ("Reflected XSS in search", VICTIM_BROWSER),
    ("Hardcoded API key in main.js", SECRET),
    ("Grafana admin panel reachable", ADMIN_SURFACE),
    ("Default login admin/admin accepted", CREDENTIAL),
])
def test_text_maps_to_primitives(text, primitive):
    assert primitive in primitives_from_text(text)


def test_only_proven_hypotheses_and_valid_credentials_count():
    brain = EngagementBrain()
    brain.hypotheses = [_hyp("h1", "Reflected XSS in search"),
                        _hyp("h2", "Path traversal", status="open")]
    brain.credentials = [CredentialRecord(username="a", secret="b", valid_on=["https://app.test"]),
                         CredentialRecord(username="c", secret="d")]
    held = brain_primitives(brain)
    assert held[VICTIM_BROWSER] == ["h1"]
    assert READ_FILE not in held
    assert held[CREDENTIAL] == ["credential:0"]


def test_patterns_complete_and_one_step_away():
    complete, near = evaluate_patterns({VICTIM_BROWSER})
    assert not any(p.id == "xss_to_admin_action" for p in complete)
    assert ("xss_to_admin_action", ADMIN_SURFACE) in [(p.id, m) for p, m in near]
    complete, _ = evaluate_patterns({VICTIM_BROWSER, ADMIN_SURFACE})
    assert "xss_to_admin_action" in [p.id for p in complete]


def test_queue_is_idempotent_and_cards_are_open_chain_hypotheses():
    brain = EngagementBrain()
    brain.hypotheses = [_hyp("h1", "Stored XSS on comments"),
                        _hyp("h2", "Jenkins admin panel exposed")]
    first = queue_chain_hypotheses(brain, target="https://app.test")
    ids = [h.methodology_id for h in first["queued"]]
    assert "primitive_chain:xss_to_admin_action" in ids
    card = next(h for h in first["queued"] if h.methodology_id.endswith("xss_to_admin_action"))
    assert card.status == "open" and card.source == "chain"
    assert set(card.parent_finding.split(",")) == {"h1", "h2"}
    assert queue_chain_hypotheses(brain)["queued"] == []


@pytest.mark.asyncio
async def test_tool_updates_brain_and_skill_pack_attached():
    from app.services.agent.specialist_skills import skill_pack_for
    from app.services.agent.tools import ASMToolsManager

    manager = ASMToolsManager()
    brain = EngagementBrain()
    brain.hypotheses = [_hyp("h1", "Hardcoded API key in bundle.js")]
    manager._engagement_brain = brain.to_dict()
    out = json.loads(await manager.suggest_capability_chains(target="https://app.test"))
    assert [h["methodology_id"] for h in out["queued"]] == ["primitive_chain:leak_to_api"]
    stored = engagement_brain_from_dict(manager._engagement_brain)
    assert any(h.methodology_id == "primitive_chain:leak_to_api" for h in stored.hypotheses)
    assert "Capability chains" in skill_pack_for("api_authz")
