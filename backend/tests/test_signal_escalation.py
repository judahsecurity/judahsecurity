import json

import httpx
import pytest

from app.services.agent.coverage_cells import (
    claim_coverage_cell_leases,
    migrate_coverage_cells,
)
from app.services.agent.engagement_brain import (
    EngagementBrain,
    Hypothesis,
    coverage_progress,
    denominator_surfaces,
)
from app.services.agent.operation_directive import directives_from_hypotheses
from app.services.agent.independent_verify import submit_candidate
from app.services.agent.signal_escalation import (
    apply_verifier_result,
    queue_signal_escalation,
)
from app.services.agent.tools import (
    ASMToolsManager,
    current_organization_id,
    current_session_id,
)


def _brain():
    operation = {
        "id": "op-orders",
        "url": "https://app.test/orders",
        "host": "app.test",
        "path": "/orders",
        "method": "GET",
        "protocol": "rest",
        "operation": "GET /orders",
        "parameters": ["query:id"],
        "identities": ["anonymous"],
    }
    brain = EngagementBrain(
        target="https://app.test",
        application_operations=[operation],
        surfaces=[
            {
                "method": "GET",
                "path": "/orders",
                "host": "app.test",
                "takes_input": True,
            }
        ],
        hypotheses=[
            Hypothesis(
                id="operation-op-orders",
                title="Assess orders",
                assumption="Order access may cross boundaries",
                test="Compare controlled identities",
                pass_criteria="Controlled object crosses the boundary",
                kill_criteria="Matched attacker control holds",
                specialist="auth_logic",
                target="https://app.test/orders",
                operation_id="op-orders",
            )
        ],
    )
    migrate_coverage_cells(brain, denominator=denominator_surfaces(brain))
    return brain


def _parameter_cell(brain):
    return next(
        cell
        for cell in brain.coverage_cells
        if cell["operation_id"] == "op-orders" and cell["parameter"] == "query:id"
    )


def test_strong_signal_queues_deduplicated_proof_and_prioritizes_hunter():
    brain = _brain()
    cell = _parameter_cell(brain)
    escalation = queue_signal_escalation(
        brain,
        verdict="LIKELY_IMPACT",
        signals=["body_changed", "interest_field_deltas=['owner_id']"],
        evidence_ids=["a" * 32, "b" * 32],
        target="https://app.test/orders",
        source_tool="compare_requests",
        coverage_cell_id=cell["id"],
        hypothesis_id=cell["hypothesis_id"],
        operation_id=cell["operation_id"],
        identity=cell["identity"],
        parameter=cell["parameter"],
        test_type=cell["test_type"],
    )
    assert escalation["strategy"] == "authorization_differential"
    assert escalation["specialist"] == "api_authz"
    assert cell["proof_escalation_id"] == escalation["id"]
    assert cell["specialist"] == "api_authz"
    assert cell["status"] == "in_focus"

    duplicate = queue_signal_escalation(
        brain,
        verdict="LIKELY_IMPACT",
        signals=["body_changed", "interest_field_deltas=['owner_id']"],
        evidence_ids=["a" * 32, "b" * 32],
        target="https://app.test/orders",
        source_tool="compare_requests",
        coverage_cell_id=cell["id"],
        hypothesis_id=cell["hypothesis_id"],
    )
    assert duplicate["id"] == escalation["id"]
    assert len(brain.proof_escalations) == 1
    assert coverage_progress(brain)["pending_proof_escalation_count"] == 1


def test_proof_escalation_is_injected_into_next_specialist_directive():
    brain = _brain()
    cell = _parameter_cell(brain)
    escalation = queue_signal_escalation(
        brain,
        verdict="MUTANT_BYPASS_CANDIDATE",
        signals=["auth_header_skip"],
        evidence_ids=["a" * 32, "b" * 32],
        target="https://app.test/orders",
        source_tool="compare_requests",
        coverage_cell_id=cell["id"],
        hypothesis_id=cell["hypothesis_id"],
        proof={"lane": "auth_header_bypass", "demonstrated": True},
    )
    leases = claim_coverage_cell_leases(
        brain,
        ["api_authz"],
        denominator=denominator_surfaces(brain),
        now=100,
    )
    profile = type(
        "Profile",
        (),
        {
            "role": "Authorization specialist.",
            "allowed_tools": ["compare_requests"],
            "max_iterations": 4,
            "epithet": "Daniel",
        },
    )()
    directive = directives_from_hypotheses(
        brain=brain,
        profiles_by_name={"api_authz": profile},
        specialists=["api_authz"],
        coverage_leases=leases,
    )["api_authz"]
    assert directive.proof_escalation_id == escalation["id"]
    assert directive.proof_strategy == "independent_lane_replay"
    assert "This signal is not a finding" in directive.to_prompt_block()


def test_candidate_and_verifier_advance_proof_escalation_state():
    brain = _brain()
    cell = _parameter_cell(brain)
    escalation = queue_signal_escalation(
        brain,
        verdict="TIME_BASED_INJECTION_CANDIDATE",
        signals=["elapsed_delta_s=2.0"],
        evidence_ids=["a" * 32, "b" * 32],
        target="https://app.test/orders",
        source_tool="compare_requests",
        coverage_cell_id=cell["id"],
    )
    candidate = submit_candidate(
        brain,
        title="Time-based injection",
        target="https://app.test/orders",
        coverage_cell_id=cell["id"],
        evidence_ids=["a" * 32, "b" * 32],
    )
    assert candidate.proof_escalation_id == escalation["id"]
    assert brain.proof_escalations[0]["status"] == "verifying"
    apply_verifier_result(
        brain,
        escalation["id"],
        verdict="confirmed",
        verifier_run_id="verify-1",
    )
    assert brain.proof_escalations[0]["status"] == "confirmed"


@pytest.mark.asyncio
async def test_compare_requests_automatically_queues_proof(monkeypatch):
    original = httpx.AsyncClient

    def handler(request):
        owner = "A" if request.url.path == "/owner" else "B"
        return httpx.Response(200, json={"owner_id": owner, "record": "private"})

    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs),
    )
    org_token = current_organization_id.set(98765)
    session_token = current_session_id.set("signal-escalation-test")
    try:
        manager = ASMToolsManager()
        manager._assessment_scope.add("app.test")
        brain = _brain()
        cell = _parameter_cell(brain)
        manager._engagement_brain = brain.to_dict()
        result = json.loads(
            await manager.compare_requests(
                {"method": "GET", "url": "https://app.test/owner"},
                {"method": "GET", "url": "https://app.test/orders"},
                interest_fields=["owner_id"],
                hypothesis_id=cell["hypothesis_id"],
                coverage_cell_id=cell["id"],
            )
        )
        assert result["verdict"] == "LIKELY_IMPACT"
        assert result["proof_escalation"]["strategy"] == "authorization_differential"
        assert len(result["proof_escalation"]["evidence_ids"]) == 2
        assert result["next_action"].startswith("Complete the structured proof")
        assert manager._engagement_brain["proof_escalations"][0]["status"] == "pending"
    finally:
        current_session_id.reset(session_token)
        current_organization_id.reset(org_token)
