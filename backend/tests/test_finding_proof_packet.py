"""Verified finding packets reference recorded proof without copying secrets."""

from types import SimpleNamespace

from app.services.agent.finding_proof_packet import (
    build_verified_proof_packet,
    proof_packet_steps,
)


def test_packet_links_hunter_and_verifier_with_value_free_request_shapes():
    store = SimpleNamespace(
        records={
            "hunter-id": {
                "kind": "http_exchange",
                "identity": "owner",
                "sha256": "h1",
                "payload": {
                    "request": {
                        "method": "GET",
                        "url": "https://app.test/orders?order_id=private-123&token=secret",
                    },
                    "response": {"status": 200, "body": "private data"},
                },
            },
            "verifier-id": {
                "kind": "http_exchange",
                "identity": "other",
                "sha256": "h2",
                "verifier_run_id": "verify-1",
                "payload": {
                    "request": {
                        "method": "GET",
                        "url": "https://app.test/orders?order_id=private-123",
                    },
                    "response": {"status": 200},
                },
            },
        }
    )
    candidate = SimpleNamespace(
        id="candidate-1",
        target="https://app.test/orders?order_id=private-123",
        identity="owner",
        test_type="authz",
        parameter="query:order_id",
        evidence_ids=["hunter-id"],
    )
    packet = build_verified_proof_packet(
        store, candidate, {"run_id": "verify-1", "evidence_ids": ["verifier-id"]}
    )

    assert [step["phase"] for step in packet["steps"]] == ["hunter", "verifier"]
    assert packet["steps"][0]["response_status"] == 200
    assert packet["steps"][1]["verifier_run_id"] == "verify-1"
    assert packet["prerequisites"]["identity"] == "owner"
    assert "private-123" not in str(packet) and "secret" not in str(packet)
    assert "private-123" not in proof_packet_steps(packet)
    assert "hunter-id" in proof_packet_steps(packet)


def test_missing_artifact_is_explicit_in_packet():
    store = SimpleNamespace(records={})
    candidate = SimpleNamespace(
        id="candidate-1",
        target="https://app.test/",
        identity="anonymous",
        test_type="xss",
        parameter="query:q",
        evidence_ids=["missing"],
    )
    packet = build_verified_proof_packet(
        store, candidate, {"run_id": "v", "evidence_ids": []}
    )
    assert packet["steps"] == [
        {"phase": "hunter", "evidence_id": "missing", "available": False}
    ]
