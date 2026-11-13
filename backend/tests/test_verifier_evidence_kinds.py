"""Class-specific verifier evidence must be accepted only when it proves impact."""

import pytest

from app.services.agent.evidence_store import EvidenceStore, VerificationRun, verification_run

TARGET = "https://app.test/api/redeem"


def _record(store, kind, payload, *, run, target=TARGET, success=True):
    token = verification_run.set(run)
    try:
        return store.record(kind, payload, target=target, success=success)
    finally:
        verification_run.reset(token)


def _validate(store, ids, run):
    return store.validate(ids, candidate_id=run.candidate_id, revision=run.revision,
                          run_id=run.id, target=TARGET)


@pytest.fixture
def store():
    return EvidenceStore()


@pytest.fixture
def run():
    return VerificationRun("run-1", "cand-1", 1, "nonce-1")


def test_fresh_race_burst_that_overran_the_limit_is_accepted(store, run):
    artifact = _record(store, "scoped_race_probe", {"proof_confirmed": True}, run=run)
    assert _validate(store, [artifact], run) == (True, "")


def test_race_burst_without_overrun_does_not_confirm(store, run):
    artifact = _record(store, "scoped_race_probe", {"proof_confirmed": False}, run=run, success=False)
    ok, why = _validate(store, [artifact], run)
    assert ok is False and "demonstrates" in why


def test_xxe_with_observed_callback_is_accepted(store, run):
    artifact = _record(store, "scoped_xml_xxe", {"callback_observed": True}, run=run)
    assert _validate(store, [artifact], run) == (True, "")


def test_xxe_without_callback_does_not_confirm(store, run):
    artifact = _record(store, "scoped_xml_xxe", {"callback_observed": False}, run=run, success=False)
    assert _validate(store, [artifact], run)[0] is False


def test_race_evidence_from_another_origin_is_rejected(store, run):
    artifact = _record(store, "scoped_race_probe", {"proof_confirmed": True}, run=run,
                       target="https://other.test/api/redeem")
    ok, why = _validate(store, [artifact], run)
    assert ok is False and "origin" in why


def test_hunter_race_artifact_cannot_confirm(store, run):
    hunter = store.record("scoped_race_probe", {"proof_confirmed": True}, target=TARGET)
    ok, why = _validate(store, [hunter], run)
    assert ok is False and "different" in why
