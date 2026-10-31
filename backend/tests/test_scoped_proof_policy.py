"""Independent Aegis publication gate for migrated PROWL recipes."""

from types import SimpleNamespace

from app.services.agent.proof_policy import proof_kind_allowed, validate_proof
from app.services.agent.evidence_store import EvidenceStore, VerificationRun, verification_run


class Store:
    def __init__(self, hunter, verifier):
        self.records = {"hunter": hunter, "verifier": verifier}


def test_proof_kind_must_match_the_claimed_vulnerability():
    cases = (
        ("SQL injection in search", "response_match", False),
        ("Reflected XSS", "response_match", False),
        ("CVE-2025-12345 affects server", "response_match", False),
        ("CVE-2025-12345 stored XSS", "browser_xss", True),
        ("Command injection in export", "oob_callback", False),
        ("XXE in XML upload", "oob_callback", True),
        ("Sensitive configuration exposure", "response_match", True),
        ("Sensitive configuration exposure", "workflow", False),
        ("Blind SSRF in image fetch", "oob_callback", True),
        ("SQL injection in search", "numeric_boolean_sqli", True),
    )
    for title, kind, expected in cases:
        candidate = SimpleNamespace(title=title, description="", vulnerability_class="")
        assert proof_kind_allowed(candidate, kind)[0] is expected, (title, kind)

    mislabeled = SimpleNamespace(
        title="SQL injection in search", description="", vulnerability_class="exposure",
    )
    assert not proof_kind_allowed(mislabeled, "response_match")[0]


def test_response_header_proof_needs_two_fresh_controlled_canaries():
    payload = lambda nonce: {
        "operation": "scoped_response_probe", "test_type": "crlf",
        "parameter": "searchTerm", "request_context": "browser_link",
        "nonce": nonce, "requests_sent": 2, "proof_confirmed": True,
        "control": {"header_marker": False}, "probe": {"header_marker": True},
    }
    hunter = record("hunter", "scoped_response_probe", payload("first"), 1)
    verifier = record("verifier", "scoped_response_probe", payload("second"), 2)
    store = Store(hunter, verifier)
    candidate = SimpleNamespace(
        target=hunter["target"], evidence_ids=["hunter"],
        title="CRLF response header injection", description="", vulnerability_class="crlf",
    )
    proof = {"kind": "scoped_response_crlf", "hunter_artifact_id": "hunter",
             "artifact_id": "verifier"}
    assert validate_proof(store, candidate, proof, ["verifier"])[0]
    verifier["payload"]["nonce"] = "first"
    assert not validate_proof(store, candidate, proof, ["verifier"])[0]


def test_cors_proof_needs_two_fresh_credentialed_canaries():
    payload = lambda nonce: {
        "operation": "scoped_response_probe", "test_type": "cors",
        "parameter": "origin", "request_context": "origin_header",
        "nonce": nonce, "requests_sent": 2, "proof_confirmed": True,
        "control": {"cors_canary": False}, "probe": {"cors_canary": True},
    }
    hunter = record("hunter", "scoped_response_probe", payload("aaaa"), 1)
    verifier = record("verifier", "scoped_response_probe", payload("bbbb"), 2)
    store = Store(hunter, verifier)
    candidate = SimpleNamespace(
        target=hunter["target"], evidence_ids=["hunter"],
        title="Credentialed CORS origin reflection", description="",
        vulnerability_class="cors",
    )
    proof = {"kind": "scoped_cors_credentialed", "hunter_artifact_id": "hunter",
             "artifact_id": "verifier"}
    assert validate_proof(store, candidate, proof, ["verifier"])[0]
    # A wildcard / non-credentialed reflection never satisfies the signal.
    verifier["payload"]["probe"]["cors_canary"] = False
    assert not validate_proof(store, candidate, proof, ["verifier"])[0]
    verifier["payload"]["probe"]["cors_canary"] = True
    # The two runs must carry distinct canary nonces.
    verifier["payload"]["nonce"] = "aaaa"
    assert not validate_proof(store, candidate, proof, ["verifier"])[0]


def test_cors_proof_kind_matches_only_cors_claims():
    assert proof_kind_allowed(
        SimpleNamespace(title="CORS misconfiguration", description="",
                        vulnerability_class=""),
        "scoped_cors_credentialed",
    )[0]
    # A CORS proof cannot confirm an unrelated class.
    assert not proof_kind_allowed(
        SimpleNamespace(title="Open redirect in return_to", description="",
                        vulnerability_class=""),
        "scoped_cors_credentialed",
    )[0]


def test_client_template_proof_requires_fresh_rendered_execution():
    payload = lambda nonce: {
        "operation": "check_client", "client_test_type": "client_template_injection",
        "target_template": "https://app.example.test/api/items#{{7*7}}__PROWL_NONCE__",
        "nonce": nonce, "behavior_observed": True,
        "observations": {"initial_document_ok": True, "template_evaluated": True,
                         "server_body_checked": True, "server_template_evaluated": False},
    }
    hunter = record("hunter", "scoped_browser_check_client", payload("first"), 1)
    verifier = record("verifier", "scoped_browser_check_client", payload("second"), 2)
    store = Store(hunter, verifier)
    candidate = SimpleNamespace(
        target=hunter["target"], evidence_ids=["hunter"],
        title="Client-side template injection", description="",
        vulnerability_class="client_template_injection",
    )
    proof = {"kind": "scoped_browser_client", "hunter_artifact_id": "hunter",
             "artifact_id": "verifier"}
    assert validate_proof(store, candidate, proof, ["verifier"])[0]
    verifier["payload"]["observations"]["template_evaluated"] = False
    assert not validate_proof(store, candidate, proof, ["verifier"])[0]


def test_response_match_requires_direct_anonymous_get():
    target = "https://app.example.test/config"
    row = {
        "id": "verifier", "kind": "http_exchange", "identity": "anonymous",
        "payload": {
            "request": {"method": "GET", "url": target},
            "response": {"status": 200, "url": target, "body": "private diagnostic configuration"},
        },
    }
    store = SimpleNamespace(records={"verifier": row})
    candidate = SimpleNamespace(title="Sensitive configuration exposure", description="")
    proof = {"kind": "response_match", "artifact_id": "verifier",
             "contains": "private diagnostic configuration"}
    assert validate_proof(store, candidate, proof, ["verifier"])[0]
    row["identity"] = "legacy"
    assert not validate_proof(store, candidate, proof, ["verifier"])[0]
    row["identity"] = "anonymous"
    row["payload"]["response"]["url"] = "https://app.example.test/login"
    assert not validate_proof(store, candidate, proof, ["verifier"])[0]
    row["payload"]["response"]["url"] = target
    row["payload"]["request"]["headers"] = {"Authorization": "Bearer redacted"}
    assert not validate_proof(store, candidate, proof, ["verifier"])[0]
    row["payload"]["request"]["headers"] = {}
    candidate.description = "This might also enable SQL injection"
    assert not validate_proof(store, candidate, proof, ["verifier"])[0]


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


def test_numeric_proof_requires_two_matching_independent_observations():
    hunter = record("hunter", "scoped_numeric_sqli", numeric("12345"), 1)
    verifier = record("verifier", "scoped_numeric_sqli", numeric("67890"), 2)
    store = Store(hunter, verifier)
    candidate = SimpleNamespace(
        target="https://app.example.test/api/items", evidence_ids=["hunter"],
        title="SQL injection in item ID",
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
        title="Public directory index exposure",
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
    candidate = SimpleNamespace(target=target, evidence_ids=[hunter_id],
                                title="SQL injection in item ID")
    assert validate_proof(store, candidate, {
        "kind": "numeric_boolean_sqli", "hunter_artifact_id": hunter_id,
        "artifact_id": verifier_id,
    }, [verifier_id])[0]


def test_post_form_xss_requires_completed_post_before_nonce_dialog():
    target = "https://app.example.test/newsletter"
    payload = {"operation": "check_form_xss", "target_template": "https://app.example.test/",
               "form_action": target, "form_field": "email",
               "form_payload_template": '<img src=x onerror=alert("__PROWL_NONCE__")>',
               "post_submitted": True, "post_response_seen": True, "executed": True}
    hunter = {"id": "hunter", "kind": "scoped_browser_check_form_xss",
              "target": target, "identity": "anonymous", "created_at": 1,
              "payload": dict(payload, nonce="first")}
    verifier = {"id": "verifier", "kind": "scoped_browser_check_form_xss",
                "target": target, "identity": "anonymous", "created_at": 2,
                "payload": dict(payload, nonce="second")}
    candidate = SimpleNamespace(target=target, evidence_ids=["hunter"],
                                title="Reflected XSS in form", description="",
                                vulnerability_class="xss")
    store = Store(hunter, verifier)
    proof = {"kind": "scoped_browser_form_xss", "hunter_artifact_id": "hunter",
             "artifact_id": "verifier"}
    assert validate_proof(store, candidate, proof, ["verifier"])[0]
    verifier["payload"]["post_response_seen"] = False
    assert not validate_proof(store, candidate, proof, ["verifier"])[0]
    verifier["payload"]["post_response_seen"] = True
    verifier["payload"]["nonce"] = "first"
    assert not validate_proof(store, candidate, proof, ["verifier"])[0]
