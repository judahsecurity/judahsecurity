"""Captured authorization leads are work items, never vulnerability verdicts."""

import json
from types import SimpleNamespace

from app.services.agent.authorization_leads import handoff_report
from app.services.agent.request_capture import RequestCaptureStore
from app.services.agent.runtime_mapper import normalize_request
from app.services.agent.tools import ASMToolsManager
from app.services.agent.vulnerability_catalog import parameter_test_classes


def test_capture_queues_path_and_query_references_without_query_values():
    assert "authz" in parameter_test_classes(
        {"name": "record", "location": "query", "method": "GET"}
    )
    store = RequestCaptureStore()
    request = {
        "method": "GET",
        "url": "https://app.test/api/records/42?record=42&view=full",
    }
    first = store.record(request, identity="owner", source="browser")
    assert first["url"] == "https://app.test/api/records/42"
    refs = {row["reference"]: row for row in first["authorization_references"]}
    assert refs["query:record"]["priority_score"] > refs["query:view"]["priority_score"]
    assert refs["path:3"]["replayable"] is True
    assert "record=42" not in json.dumps(first)
    leads = store.authorization_leads()
    assert {row["reference"] for row in leads} >= {
        "query:record",
        "query:view",
        "path:3",
    }
    assert all(row["capture_id"] == first["id"] for row in leads)
    second = store.record(request, identity="owner", source="browser")
    assert len(store.authorization_leads()) == len(leads)
    assert all(row["capture_id"] == second["id"] for row in store.authorization_leads())


def test_resource_path_slug_is_a_reference_lead():
    store = RequestCaptureStore()
    capture = store.record(
        {"method": "GET", "url": "https://app.test/objects/customer-123"},
        identity="owner",
        source="browser",
    )
    lead = store.authorization_leads()[0]
    assert lead["reference"] == "path:2"
    assert lead["priority_score"] >= 3
    assert lead["capture_id"] == capture["id"]


def test_ambiguous_reference_stays_blocked_and_never_mints_policy():
    store = RequestCaptureStore()
    capture = store.record(
        {"method": "GET", "url": "https://app.test/lookup?record=1&record=2"},
        identity="owner",
        source="browser",
    )
    lead = store.authorization_leads()[0]
    assert lead["replayable"] is False
    report = handoff_report([lead], SimpleNamespace(authorization_matrix=[]), {})
    assert report["summary"]["blocked"] == 1
    assert report["summary"]["needs_policy"] == 0
    assert capture["id"] == lead["capture_id"]


def test_eviction_removes_expired_leads_from_the_queue():
    store = RequestCaptureStore(limit=1)
    first = store.record(
        {"method": "GET", "url": "https://app.test/lookup?record=1"},
        identity="owner",
        source="browser",
    )
    second = store.record(
        {"method": "GET", "url": "https://app.test/lookup?record=2"},
        identity="owner",
        source="browser",
    )
    assert store.evicted == 1
    assert [lead["capture_id"] for lead in store.authorization_leads()] == [
        second["id"]
    ]
    assert first["id"] != second["id"]


def test_rejected_capture_shapes_are_counted_for_handoff_coverage():
    store = RequestCaptureStore()
    assert store.record(
        {"method": "POST", "url": "https://app.test/lookup?record=1"},
        identity="owner", source="browser",
    ) is None
    assert store.record(
        {"method": "GET", "url": "https://app.test/lookup?token=secret"},
        identity="owner", source="browser",
    ) is None
    assert store.rejected["unsupported_method"] == 1
    assert store.rejected["sensitive_query"] == 1


def test_expired_capture_remains_visible_as_inconclusive_coverage():
    manager = ASMToolsManager()
    store = manager._capture_requests()
    store.limit = 1
    captures = []
    for path in ("/records/1", "/records/2"):
        request = {"method": "GET", "url": "https://app.test" + path}
        manager._ingest_observed_operations(
            normalize_request(request, identity="owner", source="browser")
        )
        captures.append(store.record(request, identity="owner", source="browser"))
        manager._queue_captured_authorization_leads()
    rows = manager._engagement_brain["coverage_cells"]
    old = next(
        row
        for row in rows
        if row["path"] == "/records/1" and row["test_type"] == "authz"
    )
    new = next(
        row
        for row in rows
        if row["path"] == "/records/2" and row["test_type"] == "authz"
    )
    assert old["status"] == "inconclusive"
    assert old["capture_id"] == ""
    assert "expired" in old["reason"]
    assert new["capture_id"] == captures[1]["id"]


def test_handoff_counts_follow_explicit_policy_and_proof_receipts():
    store = RequestCaptureStore()
    capture = store.record(
        {"method": "GET", "url": "https://app.test/lookup?record=7"},
        identity="owner",
        source="browser",
    )
    lead = store.authorization_leads()[0]
    brain = SimpleNamespace(authorization_matrix=[])
    report = handoff_report([lead], brain, {})
    assert report["leads"][0]["status"] == "needs_policy"
    assert report["summary"]["candidates"] == 1
    assert report["summary"]["replayable"] == 1
    cell = {
        "operation_id": capture["operation_id"],
        "parameter": "query:record",
        "identity": "attacker",
        "expected": "deny",
        "status": "untested",
        "hypothesis_id": "authz-1",
    }
    brain.authorization_matrix = [cell]
    assert handoff_report([lead], brain, {})["leads"][0]["status"] == "policy_set"
    assert (
        handoff_report([lead], brain, {"authz-1": {}})["leads"][0]["status"]
        == "proof_prepared"
    )
    cell["proof_run_id"] = "run-1"
    assert handoff_report([lead], brain, {})["leads"][0]["status"] == "proof_attempted"
    cell["verifier_verdict"] = "confirmed"
    result = handoff_report([lead], brain, {})
    assert result["leads"][0]["status"] == "independently_confirmed"
    assert result["summary"]["independently_confirmed"] == 1
