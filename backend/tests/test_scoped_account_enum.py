"""Account-enumeration proof recipe and its independent publication gate."""

from types import SimpleNamespace

import pytest

from app.services.agent.proof_policy import proof_kind_allowed, validate_proof
from app.services.agent.scoped_assessment.account_enum import (
    _with_value,
    absent_value,
    account_enum_proof_valid,
    decide_differential,
)

# --- pure decision -------------------------------------------------------

def test_stable_difference_confirms():
    decision = decide_differential([[200, 40], [200, 40]], [[404, 2], [404, 2]])
    assert decision["proof_confirmed"] is True
    assert decision["existing_discriminator"] == [200, 40]
    assert decision["absent_discriminator"] == [404, 2]


def test_identical_sides_are_inconclusive():
    decision = decide_differential([[200, 40], [200, 40]], [[200, 40], [200, 40]])
    assert decision["proof_confirmed"] is False


def test_unstable_existing_side_is_inconclusive():
    # A response that jitters between requests is not an oracle.
    decision = decide_differential([[200, 40], [200, 99]], [[404, 2], [404, 2]])
    assert decision["proof_confirmed"] is False
    assert decision["existing_discriminator"] is None


# --- validity helper -----------------------------------------------------

def _row(**over):
    base = {
        "operation": "scoped_account_enum",
        "proof_recipe": "account_enum_differential_v1",
        "parameter": "email",
        "requests_sent": 4,
        "existing_discriminator": [200, 40],
        "absent_discriminator": [404, 2],
        "existing_stable": True,
        "absent_stable": True,
        "proof_confirmed": True,
    }
    base.update(over)
    return base


def test_proof_valid_requires_four_bounded_requests():
    assert account_enum_proof_valid(_row()) is True
    assert account_enum_proof_valid(_row(requests_sent=2)) is False


def test_proof_valid_rejects_equal_discriminators():
    assert account_enum_proof_valid(_row(absent_discriminator=[200, 40])) is False


def test_absent_value_is_nonce_bound_and_bounded():
    assert absent_value("abcd1234").startswith("aegis-enum-absent-")
    with pytest.raises(ValueError):
        absent_value("not alnum!")


def test_with_value_requires_observed_parameter():
    url = "https://app.example.test/api/auth/account?email=real@corp.test"
    rewritten = _with_value(url, "email", "aegis-enum-absent-x")
    assert "aegis-enum-absent-x" in rewritten and "real@corp.test" not in rewritten
    with pytest.raises(ValueError):
        _with_value(url, "username", "x")


# --- publication gate ----------------------------------------------------

def record(artifact_id, payload, created_at):
    return {
        "id": artifact_id, "kind": "scoped_account_enum", "payload": payload,
        "target": "https://app.example.test/api/auth/account",
        "identity": "anonymous", "created_at": created_at,
    }


class Store:
    def __init__(self, hunter, verifier):
        self.records = {"hunter": hunter, "verifier": verifier}


def _candidate():
    return SimpleNamespace(
        target="https://app.example.test/api/auth/account", evidence_ids=["hunter"],
        title="Account enumeration on password reset", description="",
        vulnerability_class="account_enumeration",
    )


def test_kind_matches_only_enumeration_claims():
    assert proof_kind_allowed(
        SimpleNamespace(title="User enumeration on reset", description="",
                        vulnerability_class=""),
        "differential_account_enum",
    )[0]
    assert not proof_kind_allowed(
        SimpleNamespace(title="Reflected XSS", description="", vulnerability_class=""),
        "differential_account_enum",
    )[0]


def test_two_actor_enum_gate():
    payload = lambda nonce: _row(nonce=nonce)
    hunter = record("hunter", payload("aaaa"), 1)
    verifier = record("verifier", payload("bbbb"), 2)
    store = Store(hunter, verifier)
    proof = {"kind": "differential_account_enum", "hunter_artifact_id": "hunter",
             "artifact_id": "verifier"}
    assert validate_proof(store, _candidate(), proof, ["verifier"])[0]

    # A reused nonce is not an independent run.
    verifier["payload"]["nonce"] = "aaaa"
    assert not validate_proof(store, _candidate(), proof, ["verifier"])[0]
    verifier["payload"]["nonce"] = "bbbb"

    # The verifier must reproduce the same oracle, not a different split.
    verifier["payload"]["absent_discriminator"] = [500, 9]
    assert not validate_proof(store, _candidate(), proof, ["verifier"])[0]
    verifier["payload"]["absent_discriminator"] = [404, 2]

    # An unconfirmed run cannot be published.
    verifier["payload"]["proof_confirmed"] = False
    assert not validate_proof(store, _candidate(), proof, ["verifier"])[0]
