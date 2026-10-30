from types import SimpleNamespace

import pytest

from app.services.agent.coverage_cells import (
    claim_coverage_cell_leases,
    coverage_cell_id,
    lead_packet_for_cell,
    migrate_coverage_cells,
    record_sqli_trace,
    recover_expired_coverage_leases,
    release_coverage_cell_lease,
)
from app.services.agent.engagement_brain import (
    EngagementBrain,
    Hypothesis,
    coverage_progress,
    denominator_surfaces,
    record_surface_coverage,
    seed_coverage_from_surfaces,
)
from app.services.agent.evidence_store import EvidenceStore
from app.services.agent.independent_verify import candidate_id, submit_candidate
from app.services.agent.operation_directive import directives_from_hypotheses
from app.services.agent.request_capture import RequestCaptureStore


def _operation_brain():
    operation = {
        "id": "op-orders",
        "url": "https://app.test/orders",
        "host": "app.test",
        "path": "/orders",
        "method": "GET",
        "protocol": "rest",
        "operation": "GET /orders",
        "parameters": ["query:id"],
        "identities": ["user_a", "user_b"],
    }
    return EngagementBrain(
        target="https://app.test",
        surfaces=[
            {
                "method": "GET",
                "path": "/orders",
                "host": "app.test",
                "takes_input": True,
            }
        ],
        application_operations=[operation],
        hypotheses=[
            Hypothesis(
                id="operation-op-orders",
                title="Assess orders",
                assumption="Observed operation needs testing",
                test="Exercise the operation",
                pass_criteria="Impact",
                kill_criteria="Evidence-backed negative",
                specialist="auth_logic",
                operation_id="op-orders",
            )
        ],
    )


def test_static_assets_do_not_consume_http_assessment_cells():
    brain = EngagementBrain(surfaces=[
        {"method": "GET", "path": "/catalog", "host": "app.test", "takes_input": True},
        {"method": "GET", "path": "/image/products/1.png", "host": "app.test",
         "assessment_check": True},
        {"method": "GET", "path": "/resources/js/app.js", "host": "app.test",
         "assessment_check": True},
        {"method": "GET", "path": "/image/resize.png", "host": "app.test",
         "takes_input": True},
    ])
    assert [row["path"] for row in denominator_surfaces(brain)] == [
        "/catalog", "/image/resize.png",
    ]


def test_legacy_surface_status_does_not_hide_new_identity_parameter_cells():
    brain = _operation_brain()
    brain.coverage = [
        {
            "method": "GET",
            "path": "/orders",
            "host": "app.test",
            "status": "tested_clean",
            "reason": "legacy endpoint check",
        }
    ]
    cells = migrate_coverage_cells(brain, denominator=denominator_surfaces(brain))
    assert len({cell["id"] for cell in cells}) == len(cells)
    assert {
        (cell["identity"], cell["parameter"], cell["test_type"])
        for cell in cells
        if cell["operation_id"] == "op-orders"
    } == {
        ("user_a", "endpoint", "operation_review"),
        ("user_a", "query:id", "input_boundary"),
        ("user_b", "endpoint", "operation_review"),
        ("user_b", "query:id", "input_boundary"),
    }
    progress = coverage_progress(brain)
    assert progress["ready_to_complete_coverage"] is False
    assert progress["open_cell_count"] >= 4
    first_ids = [cell["id"] for cell in brain.coverage_cells]
    migrate_coverage_cells(brain, denominator=denominator_surfaces(brain))
    assert [cell["id"] for cell in brain.coverage_cells] == first_ids


def test_inventory_migration_preserves_legacy_skip_behavior():
    brain = EngagementBrain(
        surfaces=[
            {
                "method": "POST",
                "path": "/login",
                "host": "app.test",
                "takes_input": True,
            }
        ]
    )
    seed_coverage_from_surfaces(brain)
    record_surface_coverage(
        brain,
        method="POST",
        path="/login",
        host="app.test",
        status="skipped",
        reason="SSO owned by another team",
    )
    progress = coverage_progress(brain)
    assert progress["ready_to_complete_coverage"] is True
    assert progress["cell_counts"] == {"skipped": 1}


def test_inconclusive_coverage_keeps_the_gap_open_and_rejects_unknown_status():
    brain = EngagementBrain(surfaces=[{
        "method": "GET", "path": "/search", "host": "app.test", "takes_input": True,
    }])
    seed_coverage_from_surfaces(brain)
    with pytest.raises(ValueError, match="Unknown coverage status"):
        record_surface_coverage(
            brain, method="GET", path="/search", host="app.test",
            status="tested_clena", reason="typo",
        )
    with pytest.raises(ValueError, match="inconclusive coverage requires a reason"):
        record_surface_coverage(
            brain, method="GET", path="/search", host="app.test",
            status="inconclusive",
        )
    record_surface_coverage(
        brain, method="GET", path="/search", host="app.test",
        status="inconclusive", reason="baseline changed; repeat controlled probes",
        test_type="sqli", parameter="query:q", identity="anonymous",
    )
    progress = coverage_progress(brain)
    assert progress["inconclusive"] == 1
    assert progress["tested_clean"] == 0
    assert progress["untested"][0]["status"] == "inconclusive"
    assert progress["ready_to_complete_coverage"] is False


def test_old_snapshot_endpoint_update_closes_migrated_legacy_cell():
    brain = EngagementBrain(
        surfaces=[
            {
                "method": "GET",
                "path": "/legacy",
                "host": "app.test",
                "takes_input": True,
            }
        ],
        coverage=[
            {
                "method": "GET",
                "path": "/legacy",
                "host": "app.test",
                "status": "untested",
            }
        ],
    )
    seed_coverage_from_surfaces(brain)
    record_surface_coverage(
        brain,
        method="GET",
        path="/legacy",
        host="app.test",
        status="skipped",
        reason="legacy adapter",
    )
    progress = coverage_progress(brain)
    assert progress["ready_to_complete_coverage"] is True
    assert len(brain.coverage_cells) == 1


def test_cell_leases_are_exclusive_and_evidence_closes_exact_cell():
    brain = EngagementBrain(
        surfaces=[
            {
                "method": "GET",
                "path": "/health",
                "host": "app.test",
                "takes_input": True,
            }
        ]
    )
    seed_coverage_from_surfaces(brain)
    first = claim_coverage_cell_leases(
        brain,
        ["app_mapper"],
        denominator=denominator_surfaces(brain),
        now=100,
    )
    assert first["app_mapper"].coverage_cell_id
    assert (
        claim_coverage_cell_leases(
            brain,
            ["app_mapper"],
            denominator=denominator_surfaces(brain),
            now=101,
        )
        == {}
    )
    row = release_coverage_cell_lease(
        brain,
        first["app_mapper"],
        verdict="killed",
        evidence_ids=["a" * 32],
    )
    assert row["status"] == "inconclusive"
    assert row["lease_id"] == ""


def test_expired_cell_lease_is_requeued_as_inconclusive():
    brain = EngagementBrain(
        surfaces=[
            {
                "method": "GET",
                "path": "/health",
                "host": "app.test",
                "takes_input": True,
            }
        ]
    )
    seed_coverage_from_surfaces(brain)
    lease = claim_coverage_cell_leases(
        brain,
        ["app_mapper"],
        denominator=denominator_surfaces(brain),
        lease_seconds=60,
        now=100,
    )["app_mapper"]
    assert recover_expired_coverage_leases(brain, now=161) == [lease.coverage_cell_id]
    cell = next(
        row for row in brain.coverage_cells if row["id"] == lease.coverage_cell_id
    )
    assert cell["status"] == "inconclusive"
    assert cell["lease_id"] == ""


def test_directive_carries_task_and_coverage_leases():
    brain = _operation_brain()
    leases = claim_coverage_cell_leases(
        brain,
        ["auth_logic"],
        task_leases={
            "auth_logic": SimpleNamespace(
                id="task-lease", hypothesis_id="operation-op-orders"
            )
        },
        denominator=denominator_surfaces(brain),
        now=100,
    )
    profile = SimpleNamespace(
        role="Authorization specialist.",
        allowed_tools=["compare_requests"],
        max_iterations=4,
        epithet="Daniel",
    )
    directives = directives_from_hypotheses(
        brain=brain,
        profiles_by_name={"auth_logic": profile},
        specialists=["auth_logic"],
        task_leases={
            "auth_logic": SimpleNamespace(
                id="task-lease", hypothesis_id="operation-op-orders"
            )
        },
        coverage_leases=leases,
    )
    directive = directives["auth_logic"]
    assert directive.coverage_cell_id == leases["auth_logic"].coverage_cell_id
    assert directive.coverage_lease_id == leases["auth_logic"].id
    assert "coverage_cell_id=" in directive.to_prompt_block()


def test_lead_packet_preserves_prior_receipt_and_control_result_across_waves():
    brain = _operation_brain()
    leases = claim_coverage_cell_leases(brain, ["auth_logic"],
                                        denominator=denominator_surfaces(brain), now=100)
    cell = next(row for row in brain.coverage_cells
                if row["id"] == leases["auth_logic"].coverage_cell_id)
    cell["capture_id"] = "browser-capture-1"
    cell["first_pass_outcome"] = "inconclusive"
    cell["first_pass_evidence_id"] = "evidence-1"
    record_sqli_trace(cell, {"proof_recipe": "string_or_json_rows_v1",
                             "input_encoding": "base64", "proof_confirmed": False,
                             "checks": {"baseline_first": {"status": 200},
                                        "quote_error": {"status": 400}}})
    packet = lead_packet_for_cell(cell)
    assert packet["capture_id"] == "browser-capture-1"
    assert packet["evidence_ids"] == ["evidence-1"]
    assert packet["sqli_trace"]["input_encoding"] == "base64"
    profile = SimpleNamespace(role="Specialist", allowed_tools=["compare_requests"],
                              max_iterations=4, epithet="Daniel")
    directive = directives_from_hypotheses(
        brain=brain, profiles_by_name={"auth_logic": profile},
        specialists=["auth_logic"], coverage_leases=leases,
    )["auth_logic"]
    assert directive.lead_packet == packet
    assert "evidence-1" in directive.to_prompt_block()


def test_trace_fields_survive_request_evidence_and_candidate_ledgers():
    cell_id = coverage_cell_id(
        method="GET",
        path="/orders",
        host="app.test",
        operation_id="op-orders",
        identity="user_b",
        tenant="tenant-b",
        parameter="query:id",
        test_type="authorization",
    )
    captures = RequestCaptureStore()
    capture = captures.record(
        {"url": "https://app.test/orders", "method": "GET"},
        identity="user_b",
        source="http_exchange",
        evidence_id="e" * 32,
        hypothesis_id="h1",
        coverage_cell_id=cell_id,
        tenant="tenant-b",
        parameter="query:id",
        test_type="authorization",
    )
    assert capture["coverage_cell_id"] == cell_id
    assert capture["operation_id"]

    evidence = EvidenceStore()
    evidence_id = evidence.record(
        "http_exchange",
        {"request": {}, "response": {"status": 200}},
        target="https://app.test/orders",
        identity="user_b",
        hypothesis_id="h1",
        operation_id="op-orders",
        coverage_cell_id=cell_id,
        tenant="tenant-b",
        parameter="query:id",
        test_type="authorization",
        capture_id=capture["id"],
    )
    row = evidence.records[evidence_id]
    assert row["coverage_cell_id"] == cell_id
    assert row["operation_id"] == "op-orders"

    brain = EngagementBrain()
    candidate = submit_candidate(
        brain,
        title="Cross-tenant order read",
        target="https://app.test/orders",
        hypothesis_id="h1",
        operation_id="op-orders",
        identity="user_b",
        tenant="tenant-b",
        parameter="query:id",
        test_type="authorization",
        coverage_cell_id=cell_id,
        capture_id=capture["id"],
        evidence_ids=[evidence_id],
    )
    assert candidate.coverage_cell_id == cell_id
    assert candidate.evidence_ids == [evidence_id]
    assert candidate.id == candidate_id(candidate.title, candidate.target, cell_id)
