"""Independent Aegis publication gate for migrated PROWL recipes."""

from types import SimpleNamespace

from app.services.agent.proof_policy import validate_proof
from app.services.agent.evidence_store import EvidenceStore, VerificationRun, verification_run
from app.services.agent.scoped_assessment.sqli_boolean import (
    plan_text_boolean, probe_text_boolean, text_sql_proof_valid,
)
from app.services.agent.scoped_assessment.browser_traffic import package_exchange


class Store:
    def __init__(self, hunter, verifier):
        self.records = {"hunter": hunter, "verifier": verifier}


def record(artifact_id, kind, payload, created_at):
    return {
        "id": artifact_id, "kind": kind, "payload": payload,
        "target": "https://app.example.test/api/items",
        "identity": "anonymous", "created_at": created_at,
    }


def numeric(nonce):
    names = ("baseline_first", "true_first", "false_first",
             "true_second", "false_second", "baseline_last")
    hashes = ("a" * 64, "a" * 64, "b" * 64,
              "a" * 64, "b" * 64, "a" * 64)
    return {
        "operation": "sqli_boolean_numeric", "proof_recipe": "numeric_and_boolean_v1",
        "proof_confirmed": True, "method": "GET", "location": "query",
        "target": "https://app.example.test/api/items", "parameter": "id",
        "nonce": nonce,
        "checks": {name: {"status": 200, "content_type": "application/json",
                          "truncated": False, "redirected": False,
                          "body_sha256": digest}
                   for name, digest in zip(names, hashes)},
    }


def text_boolean(nonce):
    return {**numeric(nonce), "operation": "sqli_boolean_text",
            "proof_recipe": "quoted_text_boolean_v1", "parameter": "category"}


def test_text_boolean_plan_and_independent_proof_require_stable_controls():
    _, private = package_exchange(
        url="https://app.example.test/api/items?category=shoes&sort=recent",
        expected_origin="https://app.example.test", action_ref="navigate",
        method="GET", resource_type="fetch", status=200,
        content_type="text/html", request_body=b"", response_body=b"items",
    )
    baseline, true_url, false_url, nonce = plan_text_boolean(
        private, parameter="category", allowed_origins=["https://app.example.test"],
    )
    assert baseline.endswith("category=shoes&sort=recent")
    assert "%27%20AND%20%27" in true_url and true_url != false_url
    assert "sort=recent" in true_url and "sort=recent" in false_url
    assert nonce in true_url and nonce in false_url

    hunter = record("hunter", "scoped_text_sqli", text_boolean("12345"), 1)
    verifier = record("verifier", "scoped_text_sqli", text_boolean("67890"), 2)
    store = Store(hunter, verifier)
    candidate = SimpleNamespace(
        target="https://app.example.test/api/items", evidence_ids=["hunter"],
    )
    proof = {"kind": "text_boolean_sqli", "hunter_artifact_id": "hunter",
             "artifact_id": "verifier"}
    assert validate_proof(store, candidate, proof, ["verifier"])[0]
    verifier["payload"]["checks"]["baseline_last"]["body_sha256"] = "b" * 64
    assert not text_sql_proof_valid(verifier["payload"])
    assert not validate_proof(store, candidate, proof, ["verifier"])[0]


def test_text_probe_requires_repeatable_true_false_responses(monkeypatch):
    from app.services.agent.scoped_assessment import sqli_boolean

    baseline = "https://app.example.test/catalog?category=shoes"
    true_url = baseline + "%27%20AND%20%2712345%27%3D%2712345"
    false_url = baseline + "%27%20AND%20%2712345%27%3D%2712346"
    sent = []

    def observe(url, allowed_origins, storage_state):
        sent.append(url)
        return {"status": 200, "content_type": "text/html", "bytes_captured": 12,
                "truncated": False, "redirected": False,
                "body_sha256": ("b" if url == false_url else "a") * 64}

    monkeypatch.setattr(sqli_boolean, "observe_get", observe)
    result = probe_text_boolean(
        baseline, true_url, false_url, "12345", parameter="category",
        allowed_origins=["https://app.example.test"], storage_state=None,
        before_request=lambda: None,
    )
    assert result["proof_confirmed"] is True
    assert sent == [baseline, true_url, false_url, true_url, false_url, baseline]
    result["checks"]["baseline_last"]["body_sha256"] = "c" * 64
    assert text_sql_proof_valid(result) is False


def test_numeric_proof_requires_two_matching_independent_observations():
    hunter = record("hunter", "scoped_numeric_sqli", numeric("12345"), 1)
    verifier = record("verifier", "scoped_numeric_sqli", numeric("67890"), 2)
    store = Store(hunter, verifier)
    candidate = SimpleNamespace(
        target="https://app.example.test/api/items", evidence_ids=["hunter"],
    )
    proof = {"kind": "numeric_boolean_sqli", "hunter_artifact_id": "hunter",
             "artifact_id": "verifier"}
    assert validate_proof(store, candidate, proof, ["verifier"])[0]
    verifier["payload"]["nonce"] = "12345"
    assert not validate_proof(store, candidate, proof, ["verifier"])[0]
    verifier["payload"]["nonce"] = "67890"
    verifier["payload"]["checks"]["false_second"]["body_sha256"] = "a" * 64
    assert not validate_proof(store, candidate, proof, ["verifier"])[0]
    verifier["payload"] = numeric("67890")
    assert not validate_proof(store, candidate, proof, ["hunter"])[0]


def test_directory_listing_needs_complete_anonymous_repeat():
    observation = {
        "operation": "http_get", "status": 200, "content_type": "text/html",
        "target_template": "https://app.example.test/api/items",
        "directory_index": True, "truncated": False, "redirected": False,
    }
    hunter = record("hunter", "scoped_http_get", dict(observation), 1)
    verifier = record("verifier", "scoped_http_get", dict(observation), 2)
    store = Store(hunter, verifier)
    candidate = SimpleNamespace(
        target="https://app.example.test/api/items", evidence_ids=["hunter"],
    )
    proof = {"kind": "public_directory_index", "hunter_artifact_id": "hunter",
             "artifact_id": "verifier"}
    assert validate_proof(store, candidate, proof, ["verifier"])[0]
    verifier["payload"]["truncated"] = True
    assert not validate_proof(store, candidate, proof, ["verifier"])[0]


def test_real_evidence_receipts_preserve_the_numeric_proof_boundary():
    store = EvidenceStore()
    target = "https://app.example.test/api/items"
    hunter_id = store.record(
        "scoped_numeric_sqli", numeric("12345"), target=target, identity="anonymous",
    )
    run = VerificationRun("verifier-run", "candidate", 1, "fresh-nonce")
    token = verification_run.set(run)
    try:
        verifier_id = store.record(
            "scoped_numeric_sqli", numeric("67890"), target=target, identity="anonymous",
        )
    finally:
        verification_run.reset(token)
    candidate = SimpleNamespace(target=target, evidence_ids=[hunter_id])
    assert validate_proof(store, candidate, {
        "kind": "numeric_boolean_sqli", "hunter_artifact_id": hunter_id,
        "artifact_id": verifier_id,
    }, [verifier_id])[0]
