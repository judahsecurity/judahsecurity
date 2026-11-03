"""Deterministic validators for formerly-unprovable classes.

command_injection (time-based) and path_traversal (out-of-root sentinel read)
previously had empty proof sets, so every candidate stayed inconclusive. These
tests pin the new deterministic recipes and their independent-verification gate.
"""

from types import SimpleNamespace

from app.services.agent.proof_policy import proof_kind_allowed, validate_proof
from app.services.agent.scoped_assessment.command_injection import (
    SEPARATION_RATIO,
    command_timing_proof_valid,
)
from app.services.agent.scoped_assessment.path_traversal import path_canary_proof_valid

_MARKER_SHA = "a" * 64


class Store:
    def __init__(self, hunter, verifier):
        self.records = {"hunter": hunter, "verifier": verifier}


def record(artifact_id, kind, payload, created_at):
    return {
        "id": artifact_id, "kind": kind, "payload": payload,
        "target": "https://app.example.test/api/items",
        "identity": "anonymous", "created_at": created_at,
    }


# --------------------------------------------------------------------------
# Claim/kind gating
# --------------------------------------------------------------------------

def test_new_classes_now_have_proof_kinds():
    cases = (
        ("OS command injection in export field", "command_timing", True),
        ("Blind RCE via ping", "oob_callback", True),
        ("Path traversal in download handler", "path_canary", True),
        ("Directory traversal / LFI in template", "path_canary", True),
        # A proof kind cannot confirm an unrelated class.
        ("Reflected XSS", "command_timing", False),
        ("Path traversal in download", "command_timing", False),
        ("OS command injection", "path_canary", False),
    )
    for title, kind, expected in cases:
        candidate = SimpleNamespace(title=title, description="", vulnerability_class="")
        assert proof_kind_allowed(candidate, kind)[0] is expected, (title, kind)


# --------------------------------------------------------------------------
# command_injection — bounded time-based proof
# --------------------------------------------------------------------------

def _timing_payload(nonce, *, control=(0.10, 0.12, 0.11), probe=(4.3, 4.2, 4.5),
                    delay=4, parameter="path"):
    control = list(control)
    probe = list(probe)
    separation = min(probe) - max(control)
    return {
        "operation": "scoped_command_timing", "test_type": "command_injection",
        "parameter": parameter, "nonce": nonce, "delay_seconds": delay,
        "trials": len(control), "requests_sent": len(control) + len(probe),
        "control": {"samples": control, "max": max(control)},
        "probe": {"samples": probe, "min": min(probe)},
        "separation": round(separation, 4),
        "proof_confirmed": separation >= SEPARATION_RATIO * delay,
    }


def test_command_timing_proof_valid_requires_repeatable_separation():
    assert command_timing_proof_valid(_timing_payload("n1"))
    # Overlapping distributions are jitter, not an injected sleep.
    assert not command_timing_proof_valid(
        _timing_payload("n1", control=(3.9, 0.1, 0.1), probe=(4.1, 0.2, 0.2))
    )
    # The delay must stay inside the bounded window.
    assert not command_timing_proof_valid(
        _timing_payload("n1", probe=(40.0, 41.0, 42.0), delay=40)
    )


def test_command_timing_needs_two_independent_bounded_delays():
    hunter = record("hunter", "scoped_command_timing", _timing_payload("aaaa"), 1)
    verifier = record("verifier", "scoped_command_timing", _timing_payload("bbbb"), 2)
    store = Store(hunter, verifier)
    candidate = SimpleNamespace(
        target=hunter["target"], evidence_ids=["hunter"], nonce="z",
        title="OS command injection in export", description="",
        vulnerability_class="command_injection",
    )
    proof = {"kind": "command_timing", "hunter_artifact_id": "hunter",
             "artifact_id": "verifier"}
    assert validate_proof(store, candidate, proof, ["verifier"])[0]

    # Reused nonce across the two actors is not independent.
    verifier["payload"]["nonce"] = "aaaa"
    assert not validate_proof(store, candidate, proof, ["verifier"])[0]
    verifier["payload"]["nonce"] = "bbbb"

    # A verifier whose separation collapsed must not confirm.
    verifier["payload"] = _timing_payload("bbbb", control=(0.1, 0.1, 0.1),
                                          probe=(0.2, 0.2, 0.2))
    assert not validate_proof(store, candidate, proof, ["verifier"])[0]
    verifier["payload"] = _timing_payload("bbbb")

    # Both actors must probe the same parameter.
    verifier["payload"]["parameter"] = "other"
    assert not validate_proof(store, candidate, proof, ["verifier"])[0]


def test_command_timing_requires_ordered_distinct_evidence():
    payload = _timing_payload("aaaa")
    # Same timestamp / same record cannot be both hunter and verifier.
    hunter = record("hunter", "scoped_command_timing", payload, 2)
    verifier = record("verifier", "scoped_command_timing", _timing_payload("bbbb"), 1)
    store = Store(hunter, verifier)
    candidate = SimpleNamespace(
        target=hunter["target"], evidence_ids=["hunter"], nonce="z",
        title="OS command injection", description="",
        vulnerability_class="command_injection",
    )
    proof = {"kind": "command_timing", "hunter_artifact_id": "hunter",
             "artifact_id": "verifier"}
    # verifier.created_at (1) is before hunter.created_at (2): rejected.
    assert not validate_proof(store, candidate, proof, ["verifier"])[0]


# --------------------------------------------------------------------------
# path_traversal — out-of-root sentinel read
# --------------------------------------------------------------------------

def _canary_payload(nonce, *, marker_sha=_MARKER_SHA, control_present=False,
                    probe_present=True):
    return {
        "operation": "scoped_path_canary", "test_type": "path_traversal",
        "nonce": nonce, "requests_sent": 2, "marker_sha256": marker_sha,
        "traversal_template": "https://app.example.test/dl?f=../../../../etc/motd",
        "control_template": "https://app.example.test/dl?f=readme.txt",
        "control": {"status": 200, "truncated": False,
                    "marker_present": control_present},
        "probe": {"status": 200, "truncated": False,
                  "marker_present": probe_present},
        "proof_confirmed": bool(probe_present and not control_present),
    }


def test_path_canary_proof_valid_requires_marker_only_through_traversal():
    assert path_canary_proof_valid(_canary_payload("n1"))
    # Marker already visible without traversal is not traversal.
    assert not path_canary_proof_valid(_canary_payload("n1", control_present=True))
    # No marker in the traversal response is just a lead.
    assert not path_canary_proof_valid(_canary_payload("n1", probe_present=False))


def test_path_canary_needs_two_reads_of_the_same_sentinel():
    hunter = record("hunter", "scoped_path_canary", _canary_payload("aaaa"), 1)
    verifier = record("verifier", "scoped_path_canary", _canary_payload("bbbb"), 2)
    store = Store(hunter, verifier)
    candidate = SimpleNamespace(
        target=hunter["target"], evidence_ids=["hunter"], nonce="z",
        title="Path traversal in download handler", description="",
        vulnerability_class="path_traversal",
    )
    proof = {"kind": "path_canary", "hunter_artifact_id": "hunter",
             "artifact_id": "verifier"}
    assert validate_proof(store, candidate, proof, ["verifier"])[0]

    # Different sentinel between actors is not the same proof.
    verifier["payload"]["marker_sha256"] = "b" * 64
    assert not validate_proof(store, candidate, proof, ["verifier"])[0]
    verifier["payload"]["marker_sha256"] = _MARKER_SHA

    # A traversal that resolved to a different path is a different claim.
    verifier["payload"]["traversal_template"] = (
        "https://app.example.test/dl?f=../../../../etc/hostname"
    )
    assert not validate_proof(store, candidate, proof, ["verifier"])[0]
    verifier["payload"]["traversal_template"] = hunter["payload"]["traversal_template"]

    # Reused nonce is not an independent read.
    verifier["payload"]["nonce"] = "aaaa"
    assert not validate_proof(store, candidate, proof, ["verifier"])[0]
