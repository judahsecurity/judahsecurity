"""Cross-identity write-authorization proof confirms only a real cross-account write."""

import hashlib

from app.services.agent.scoped_assessment.authz_write_proof import (
    owner_only_write_proof_valid,
    probe_owner_only_write,
)

TARGET = "https://app.example.test/api/orders/42"
READBACK = "https://app.example.test/api/orders/42"


class FakeApp:
    """A minimal object whose one field reflects the last accepted write."""

    def __init__(self, *, other_may_write=True, other_reflected=True, owner_write_ok=True):
        self.value = "original"
        self.other_may_write = other_may_write
        self.other_reflected = other_reflected
        self.owner_write_ok = owner_write_ok
        self.writes = []

    def write(self, identity, canary):
        self.writes.append((identity, canary))
        if identity == "owner":
            if not self.owner_write_ok:
                return {"status": 500}
            self.value = canary
            return {"status": 200}
        # other identity
        if not self.other_may_write:
            return {"status": 403}
        if self.other_reflected:
            self.value = canary
        return {"status": 200}

    def readback(self, markers):
        return {
            "status": 200,
            "content_type": "application/json",
            "body_sha256": hashlib.sha256(self.value.encode()).hexdigest(),
            "truncated": False,
            "redirected": False,
            "markers": {m: (m == self.value) for m in markers},
        }


def _run(app, **over):
    kwargs = dict(
        method="PUT", field="/note",
        owner_identity="owner", other_identity="attacker",
        owner_canary="ownerAAA", other_canary="otherBBB", restore_canary="restoreCCC",
        write_fn=app.write, readback_fn=app.readback, before_request=lambda: None,
    )
    kwargs.update(over)
    return probe_owner_only_write(TARGET, READBACK, **kwargs)


def test_vulnerable_app_confirms_cross_account_write():
    app = FakeApp(other_may_write=True, other_reflected=True)
    result = _run(app)
    assert result["proof_confirmed"] is True
    assert owner_only_write_proof_valid(result) is True
    assert result["cleanup_confirmed"] is True
    assert result["checks"]["owner_readback_after_other_write"]["markers"]["otherBBB"] is True


def test_secure_app_rejects_other_write_not_confirmed():
    app = FakeApp(other_may_write=False)
    result = _run(app)
    assert result["proof_confirmed"] is False
    assert result["checks"]["other_write_canary"]["status"] == 403


def test_other_write_accepted_but_not_reflected_not_confirmed():
    # 200 but the write did not land on the owner's object.
    app = FakeApp(other_may_write=True, other_reflected=False)
    result = _run(app)
    assert result["proof_confirmed"] is False
    assert result["checks"]["owner_readback_after_other_write"]["markers"]["otherBBB"] is False


def test_owner_write_not_reflected_not_confirmed():
    app = FakeApp(owner_write_ok=False)
    result = _run(app)
    # If the owner's own write never reflects, the recipe cannot establish the
    # field is writable; proof must not confirm.
    assert result["proof_confirmed"] is False


def test_cleanup_restores_and_is_reported_separately():
    app = FakeApp()
    result = _run(app)
    assert result["cleanup_confirmed"] is True
    assert app.value == "restoreCCC"  # neither test canary left behind
    assert result["checks"]["cleanup"]["restored"] is True


def test_distinct_identities_required():
    app = FakeApp()
    try:
        _run(app, other_identity="owner")
    except ValueError:
        pass
    else:
        raise AssertionError("expected distinct-identity guard")


def test_distinct_canaries_required():
    app = FakeApp()
    try:
        _run(app, other_canary="ownerAAA")
    except ValueError:
        pass
    else:
        raise AssertionError("expected distinct-canary guard")


def test_write_method_guard():
    app = FakeApp()
    try:
        _run(app, method="GET")
    except ValueError:
        pass
    else:
        raise AssertionError("expected write-method guard")


def test_validator_rejects_redirected_readback():
    app = FakeApp()
    result = _run(app)
    result["checks"]["owner_readback_after_other_write"]["redirected"] = True
    assert owner_only_write_proof_valid(result) is False


def test_validator_rejects_stale_baseline_marker():
    app = FakeApp()
    result = _run(app)
    # If a canary was somehow present at baseline, the proof is not fresh.
    result["checks"]["owner_readback_baseline"]["markers"]["otherBBB"] = True
    assert owner_only_write_proof_valid(result) is False


def test_validator_rejects_same_identities():
    app = FakeApp()
    result = _run(app)
    result["other_identity"] = result["owner_identity"]
    assert owner_only_write_proof_valid(result) is False


def test_no_cross_account_write_when_app_secure_but_cleanup_still_runs():
    app = FakeApp(other_may_write=False)
    result = _run(app)
    assert result["proof_confirmed"] is False
    # Owner's own canary and the restore still execute, leaving a clean field.
    assert result["cleanup_confirmed"] is True


# --- publication gate (proof_policy) -----------------------------------------

from types import SimpleNamespace  # noqa: E402

from app.services.agent.proof_policy import validate_proof  # noqa: E402


class _Store:
    def __init__(self, hunter, verifier):
        self.records = {"hunter": hunter, "verifier": verifier}


def _confirmed_payload(owner_c, other_c, source_id):
    app = FakeApp(other_may_write=True, other_reflected=True)
    result = _run(app, owner_canary=owner_c, other_canary=other_c,
                  restore_canary="restore" + source_id)
    assert result["proof_confirmed"] is True
    result["source_artifact_id"] = source_id
    return result


def _record(rid, created_at, payload):
    return {"id": rid, "kind": "scoped_owner_only_write", "created_at": created_at,
            "target": payload["target"], "identity": payload["owner_identity"],
            "payload": payload}


def _candidate():
    return SimpleNamespace(title="Cross-user write IDOR", description="",
                           vulnerability_class="authorization", target=TARGET,
                           evidence_ids=["hunter"])


def test_gate_accepts_two_independent_confirmed_write_proofs():
    hunter = _record("hunter", 1, _confirmed_payload("ownerAAA111", "otherBBB111", "capA"))
    verifier = _record("verifier", 2, _confirmed_payload("ownerAAA222", "otherBBB222", "capB"))
    store = _Store(hunter, verifier)
    ok, _ = validate_proof(store, _candidate(), {"kind": "owner_only_write",
             "hunter_artifact_id": "hunter", "artifact_id": "verifier"}, ["verifier"])
    assert ok is True


def test_gate_rejects_reused_source_capture():
    hunter = _record("hunter", 1, _confirmed_payload("ownerAAA111", "otherBBB111", "capSame"))
    verifier = _record("verifier", 2, _confirmed_payload("ownerAAA222", "otherBBB222", "capSame"))
    store = _Store(hunter, verifier)
    ok, reason = validate_proof(store, _candidate(), {"kind": "owner_only_write",
             "hunter_artifact_id": "hunter", "artifact_id": "verifier"}, ["verifier"])
    assert ok is False and "separate captures" in reason


def test_gate_rejects_reused_canary():
    hunter = _record("hunter", 1, _confirmed_payload("ownerSAME", "otherBBB111", "capA"))
    verifier = _record("verifier", 2, _confirmed_payload("ownerSAME", "otherBBB222", "capB"))
    store = _Store(hunter, verifier)
    ok, _ = validate_proof(store, _candidate(), {"kind": "owner_only_write",
             "hunter_artifact_id": "hunter", "artifact_id": "verifier"}, ["verifier"])
    assert ok is False


def test_gate_rejects_unconfirmed_write_proof():
    secure = _run(FakeApp(other_may_write=False), owner_canary="ownerAAA111",
                  other_canary="otherBBB111", restore_canary="restoreX")
    secure["source_artifact_id"] = "capA"
    assert secure["proof_confirmed"] is False
    hunter = _record("hunter", 1, _confirmed_payload("ownerAAA222", "otherBBB222", "capB"))
    verifier = _record("verifier", 2, secure)
    store = _Store(hunter, verifier)
    ok, _ = validate_proof(store, _candidate(), {"kind": "owner_only_write",
             "hunter_artifact_id": "hunter", "artifact_id": "verifier"}, ["verifier"])
    assert ok is False


def test_gate_rejects_wrong_class_claim():
    # A write-authz proof cannot back a non-authorization claim.
    hunter = _record("hunter", 1, _confirmed_payload("ownerAAA111", "otherBBB111", "capA"))
    verifier = _record("verifier", 2, _confirmed_payload("ownerAAA222", "otherBBB222", "capB"))
    store = _Store(hunter, verifier)
    candidate = SimpleNamespace(title="SQL injection", description="",
                                vulnerability_class="sql_injection", target=TARGET,
                                evidence_ids=["hunter"])
    ok, _ = validate_proof(store, candidate, {"kind": "owner_only_write",
             "hunter_artifact_id": "hunter", "artifact_id": "verifier"}, ["verifier"])
    assert ok is False
