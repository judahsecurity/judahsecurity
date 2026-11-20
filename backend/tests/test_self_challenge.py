"""Hunter self-challenge, verifier checklist, and the analyst-review bucket."""

import asyncio
import json

from app.core.config import settings
from app.services.agent.engagement_brain import EngagementBrain, engagement_brain_from_dict
from app.services.agent.evidence_store import VerificationRun, verification_run
from app.services.agent.independent_verify import (
    SELF_CHALLENGE_FIELDS,
    apply_verdict,
    candidate_from_dict,
    normalize_challenge,
    submit_candidate,
    verifier_mission,
)
from app.services.agent.prompts import SELF_CHALLENGE_GUIDANCE, render_system_prompt
from app.services.agent.tools import ASMToolsManager

from tests.test_agent_prompt_rendering import CONTEXT

CHALLENGE = {
    "reachability": "Anonymous internet user reaches /api/orders/{id} directly.",
    "preconditions": "Only a valid order id, which is sequential and guessable.",
    "downstream_controls": "No ownership check observed; response returned full order.",
    "scope": "app.example.com is the engagement's primary in-scope host.",
    "benign_explanation": "Could be a public demo order, but it holds another user's email.",
    "strongest_objection": "Order 1002 might belong to the same test tenant as order 1001.",
    "disproof_test": "Request order 1002 with identity B and expect 403 if owner-checked.",
}


def _manager():
    manager = ASMToolsManager.__new__(ASMToolsManager)
    manager._engagement_brain = EngagementBrain().to_dict()
    manager._require_independent_verify = False
    return manager


def _submit(manager, **kwargs):
    args = dict(title="IDOR on order detail", target="https://app.example.com/api/orders/1002",
                description="Cross-user order read", severity="high",
                vulnerability_class="authorization")
    args.update(kwargs)
    return json.loads(asyncio.run(manager.submit_finding_candidate(**args)))


def test_normalize_challenge_reports_missing_fields():
    clean, missing = normalize_challenge(json.dumps({"scope": "in scope host app.example.com",
                                                     "reachability": "short"}))
    assert clean == {"scope": "in scope host app.example.com"}
    assert set(missing) == set(SELF_CHALLENGE_FIELDS) - {"scope"}
    assert normalize_challenge("not json")[1] == list(SELF_CHALLENGE_FIELDS)
    assert normalize_challenge(CHALLENGE) == (CHALLENGE, [])


def test_challenge_not_required_by_default():
    assert settings.AGENT_SELF_CHALLENGE is False
    out = _submit(_manager())
    assert "error" not in out


def test_challenge_required_when_enabled(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_SELF_CHALLENGE", True)
    manager = _manager()
    out = _submit(manager)
    assert out["error"] == "self_challenge_required"
    assert set(out["missing"]) == set(SELF_CHALLENGE_FIELDS)
    assert not engagement_brain_from_dict(manager._engagement_brain).candidates

    out = _submit(manager, challenge=CHALLENGE)
    assert "error" not in out
    stored = candidate_from_dict(engagement_brain_from_dict(manager._engagement_brain).candidates[0])
    assert stored.challenge == CHALLENGE


def test_verifier_mission_carries_challenge_as_untrusted_checklist():
    brain = EngagementBrain()
    cand = submit_candidate(brain, title="IDOR on order detail",
                            target="https://app.example.com/api/orders/1002",
                            challenge=CHALLENGE)
    mission = verifier_mission(cand)
    assert "self-challenge (untrusted" in mission
    assert CHALLENGE["disproof_test"] in mission
    plain = submit_candidate(brain, title="Other", target="https://app.example.com/x")
    assert "self-challenge" not in verifier_mission(plain)


def _verdict(manager, cand, verdict, **kwargs):
    run = VerificationRun("verifier-1", cand.id, cand.revision, cand.nonce)
    token = verification_run.set(run)
    try:
        return apply_verdict(manager, candidate_id=cand.id, verdict=verdict, **kwargs)
    finally:
        verification_run.reset(token)


def test_inconclusive_with_evidence_and_challenge_needs_review():
    manager = _manager()
    brain = engagement_brain_from_dict(manager._engagement_brain)
    cand = submit_candidate(brain, title="IDOR on order detail",
                            target="https://app.example.com/api/orders/1002",
                            evidence_ids=["hunter-evidence-1"], challenge=CHALLENGE)
    bare = submit_candidate(brain, title="Weak lead", target="https://app.example.com/y")
    manager._engagement_brain = brain.to_dict()

    flagged = _verdict(manager, cand, "inconclusive", summary="Second identity unavailable",
                       proof={"next_step": "Register identity B and replay"})
    assert flagged.status == "inconclusive"
    assert flagged.review_status == "needs_analyst_review"

    unflagged = _verdict(manager, bare, "inconclusive", summary="No evidence")
    assert unflagged.review_status == ""


def test_resubmission_clears_review_flag():
    manager = _manager()
    brain = engagement_brain_from_dict(manager._engagement_brain)
    cand = submit_candidate(brain, title="IDOR on order detail",
                            target="https://app.example.com/api/orders/1002",
                            evidence_ids=["hunter-evidence-1"], challenge=CHALLENGE)
    manager._engagement_brain = brain.to_dict()
    _verdict(manager, cand, "inconclusive", summary="gap")
    brain = engagement_brain_from_dict(manager._engagement_brain)
    again = submit_candidate(brain, title="IDOR on order detail",
                             target="https://app.example.com/api/orders/1002",
                             evidence_ids=["hunter-evidence-2"])
    assert again.status == "pending" and again.review_status == ""
    assert again.challenge == CHALLENGE


def test_candidate_summary_exposes_review_fields():
    from app.services.agent.external_candidates import candidate_summary

    row = candidate_summary({"id": "c1", "review_status": "needs_analyst_review",
                             "challenge": CHALLENGE, "proof_gap": {"reason": "gap"}})
    assert row["review_status"] == "needs_analyst_review"
    assert row["challenge"]["disproof_test"] == CHALLENGE["disproof_test"]


def test_self_challenge_prompt_follows_flag(monkeypatch):
    assert SELF_CHALLENGE_GUIDANCE not in render_system_prompt(mode="agent", **CONTEXT)
    monkeypatch.setattr(settings, "AGENT_SELF_CHALLENGE", True)
    assert SELF_CHALLENGE_GUIDANCE in render_system_prompt(mode="agent", **CONTEXT)
