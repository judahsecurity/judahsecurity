"""Generic reproduction proof, strictness profile and POST path suggestions."""

from types import SimpleNamespace

import pytest

from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.evidence_store import EvidenceStore, VerificationRun, verification_run
from app.services.agent.finding_gate import cap_reproduced_severity, classify_verification_level
from app.services.agent.generic_reproduction import validate_replay_reproduction
from app.services.agent.independent_verify import apply_verdict, submit_candidate
from app.services.agent.proof_policy import proof_kind_allowed
from app.services.agent.verification_profile import (
    auto_approve_body_paths,
    looks_destructive,
    normalize_strictness,
    suggest_body_replay_paths,
)

TARGET = "https://app.example.com/api/report"
SIGNAL = "PG::SyntaxError: unterminated quoted string"


def _exchange(store, url, body, *, query="", identity="anonymous"):
    return store.record(
        "http_exchange",
        {"request": {"method": "GET", "url": url + query, "headers": {}},
         "response": {"status": 500, "url": url + query, "body": body}},
        target=url + query, identity=identity, success=True,
    )


def _setup(*, candidate_class="", probe_body=None, control_body="ok", probe_query="?id=1'",
           hunter_query="?id=1'", control_query="?id=1", hunter_body=None, strictness="standard"):
    brain = EngagementBrain(target="https://app.example.com")
    store = EvidenceStore()
    hunter_id = _exchange(store, TARGET, hunter_body or f"error: {SIGNAL}", query=hunter_query)
    candidate = submit_candidate(brain, title="Database error leaks query internals",
                                 target=TARGET, severity="critical",
                                 vulnerability_class=candidate_class, evidence_ids=[hunter_id])
    manager = SimpleNamespace(_engagement_brain=brain.to_dict(), _verify_receipts={},
                              _evidence_store=store, _verification_strictness=strictness)
    token = verification_run.set(VerificationRun("verifier-1", candidate.id, candidate.revision, candidate.nonce))
    try:
        probe_id = _exchange(store, TARGET, probe_body or f"error: {SIGNAL}", query=probe_query)
        control_id = _exchange(store, TARGET, control_body, query=control_query)
    finally:
        verification_run.reset(token)
    proof = {"kind": "replay_reproduction", "hunter_artifact_id": hunter_id,
             "artifact_id": probe_id, "control_id": control_id, "signal": SIGNAL}
    return manager, store, candidate, proof, [probe_id, control_id]


def _verdict(manager, candidate, proof, evidence_ids):
    token = verification_run.set(VerificationRun("verifier-1", candidate.id, candidate.revision, candidate.nonce))
    try:
        return apply_verdict(manager, candidate_id=candidate.id, verdict="confirmed",
                             evidence="Replayed; database error reproduced, control clean",
                             evidence_ids=evidence_ids, proof=proof)
    finally:
        verification_run.reset(token)


def test_generic_kind_allowed_for_any_class_but_not_conflicting_claims():
    for cls in ("", "known_cve", "account_enumeration", "sql_injection"):
        cand = SimpleNamespace(title="Odd behavior", description="", vulnerability_class=cls)
        assert proof_kind_allowed(cand, "replay_reproduction") == (True, "")
    conflict = SimpleNamespace(title="Reflected XSS on search", description="",
                               vulnerability_class="sql_injection")
    assert proof_kind_allowed(conflict, "replay_reproduction")[0] is False


def test_valid_reproduction_confirms_as_reproduced():
    manager, _store, candidate, proof, ids = _setup()
    result = _verdict(manager, candidate, proof, ids)
    assert result.status == "confirmed", result.proof_gap
    assert result.confirmed_proof_kind == "replay_reproduction"
    level = classify_verification_level(runtime_confirmed=True, proof_kind=result.confirmed_proof_kind)
    assert level == "reproduced"
    assert cap_reproduced_severity("critical", level) == ("high", True)
    assert cap_reproduced_severity("critical", "exploit_verified") == ("critical", False)


@pytest.mark.parametrize("change,reason", [
    ({"control_body": f"also {SIGNAL}"}, "control"),
    ({"probe_body": "fine"}, "probe"),
    ({"control_query": "?id=1'"}, "control must change"),
])
def test_reproduction_rejections(change, reason):
    manager, store, candidate, proof, ids = _setup(**change)
    ok, why = validate_replay_reproduction(store, candidate, proof, ids)
    assert not ok and reason in why.lower()


def test_echoed_input_and_status_phrases_are_not_signals():
    manager, store, candidate, proof, ids = _setup(
        probe_query="?q=" + SIGNAL.replace(" ", "+"), hunter_query="?q=" + SIGNAL.replace(" ", "+"),
        control_query="?q=hello")
    ok, why = validate_replay_reproduction(store, candidate, proof, ids)
    assert not ok and "echoed" in why
    manager, store, candidate, proof, ids = _setup(hunter_body="Internal Server Error",
                                                   probe_body="Internal Server Error")
    ok, why = validate_replay_reproduction(store, candidate, {**proof, "signal": "Internal Server Error"}, ids)
    assert not ok and "status" in why


def test_hunter_evidence_cannot_double_as_verifier_evidence():
    manager, store, candidate, proof, ids = _setup()
    ok, why = validate_replay_reproduction(
        store, candidate, {**proof, "artifact_id": proof["hunter_artifact_id"]},
        [proof["hunter_artifact_id"], ids[1]])
    assert not ok


def test_conservative_profile_rejects_generic_reproduction():
    manager, _store, candidate, proof, ids = _setup(strictness="conservative")
    result = _verdict(manager, candidate, proof, ids)
    assert result.status == "inconclusive"
    assert "conservative" in result.proof_gap["reason"]


def test_ssrf_readback_requires_internal_destination():
    meta = "ami-id\ninstance-type\nsecurity-credentials"
    manager, store, candidate, proof, ids = _setup(
        candidate_class="ssrf", hunter_body=meta, probe_body=meta,
        hunter_query="?url=http://169.254.169.254/latest/meta-data/",
        probe_query="?url=http://169.254.169.254/latest/meta-data/",
        control_query="?url=https://example.org/")
    proof = {**proof, "kind": "scoped_ssrf_readback", "signal": "security-credentials"}
    assert validate_replay_reproduction(store, candidate, proof, ids) == (True, "")
    manager, store, candidate, proof2, ids = _setup(
        candidate_class="ssrf", hunter_body=meta, probe_body=meta,
        hunter_query="?url=https://cdn.example.org/a", probe_query="?url=https://cdn.example.org/a",
        control_query="?url=https://example.org/")
    ok, why = validate_replay_reproduction(
        store, candidate, {**proof2, "kind": "scoped_ssrf_readback", "signal": "security-credentials"}, ids)
    assert not ok and "internal destination" in why


def test_strictness_normalization():
    assert normalize_strictness("AGGRESSIVE") == "aggressive"
    assert normalize_strictness(None) == "standard"
    assert normalize_strictness("yolo") == "standard"


def _brain_with_post_cells():
    brain = EngagementBrain(target="https://app.example.com")
    brain.coverage_cells = [
        {"id": "a", "method": "POST", "path": "/api/search", "status": "blocked",
         "first_pass_blocked_reason": "post_path_not_approved", "test_type": "sql_injection"},
        {"id": "b", "method": "POST", "path": "/api/search", "status": "untested", "test_type": "xss"},
        {"id": "c", "method": "POST", "path": "/api/account/delete", "status": "untested"},
        {"id": "d", "method": "POST", "path": "/api/comments", "status": "tested_clean"},
        {"id": "e", "method": "GET", "path": "/api/items", "status": "untested"},
        {"id": "f", "method": "POST", "path": "/api/feedback", "status": "untested"},
    ]
    return brain


def test_body_path_suggestions_split_destructive_paths():
    out = suggest_body_replay_paths(_brain_with_post_cells(), approved=["/api/feedback"])
    assert [r["path"] for r in out["suggested"]] == ["/api/search"]
    assert out["suggested"][0]["inputs"] == 2
    assert out["suggested"][0]["classes"] == ["sql_injection", "xss"]
    assert [r["path"] for r in out["needs_review"]] == ["/api/account/delete"]
    assert looks_destructive("/checkout/pay") and not looks_destructive("/api/search")


def test_auto_approval_only_under_aggressive_profile():
    brain = _brain_with_post_cells()
    standard = SimpleNamespace(_verification_strictness="standard", _scoped_body_replay_paths=set())
    assert auto_approve_body_paths(standard, brain) == []
    aggressive = SimpleNamespace(_verification_strictness="aggressive",
                                 _scoped_body_replay_paths={"/api/existing"})
    picked = auto_approve_body_paths(aggressive, brain)
    assert set(picked) == {"/api/search", "/api/feedback"}
    assert "/api/account/delete" not in aggressive._scoped_body_replay_paths
    assert aggressive._scoped_body_replay_paths >= {"/api/existing", "/api/search"}
