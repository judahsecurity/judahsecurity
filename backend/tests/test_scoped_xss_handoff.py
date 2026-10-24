"""An observed XSS input is confirmed only after fresh browser execution."""

import json
from urllib.parse import quote

import pytest

from app.services.agent.coverage_cells import seed_parameter_coverage_cells
from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.evidence_store import evidence_store
from app.services.agent.independent_verify import (
    check_verify_receipt, run_independent_verifiers, submit_candidate,
)
from app.services.agent.tools import ASMToolsManager


TARGET = "https://app.example.test/catalog"
TEMPLATE = TARGET + "?searchTerm=" + quote('<img src=x onerror=alert("__PROWL_NONCE__")>')


@pytest.mark.asyncio
@pytest.mark.parametrize("linked_at_submission", [False, True])
@pytest.mark.parametrize("replayed_execution,replayed_identity", [
    (False, "anonymous"), (True, "anonymous"), (True, "other-user"),
])
async def test_xss_verifier_replays_exact_observed_browser_proof(
    replayed_execution, replayed_identity, linked_at_submission,
):
    manager = ASMToolsManager()
    store = evidence_store(manager)
    hunter = store.record(
        "scoped_browser_check_xss",
        {"operation": "check_xss", "target_template": TEMPLATE,
         "executed": True, "nonce": "hunter_nonce"},
        target=TARGET, identity="anonymous",
    )
    brain = EngagementBrain(target="https://app.example.test")
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "host": "app.example.test", "path": "/catalog",
        "name": "searchTerm", "location": "query", "identity": "anonymous",
        "source": "browser_link", "testable": True,
    }])
    cell = next(row for row in brain.coverage_cells if row.get("test_type") == "xss")
    candidate = submit_candidate(
        brain, title="Reflected XSS in catalog search", target=TARGET,
        vulnerability_class="xss",
        coverage_cell_id=cell["id"] if linked_at_submission else "",
        identity="anonymous", parameter="query:searchTerm", evidence_ids=[hunter],
    )
    manager._engagement_brain = brain.to_dict()
    calls = []

    async def execute(name, args):
        calls.append((name, args))
        assert name == "scoped_browser_assessment"
        assert args == {"operation": "check_xss", "url": TEMPLATE,
                        "identity": "anonymous"}
        proof = {"operation": "check_xss", "target_template": TEMPLATE,
                 "executed": replayed_execution, "nonce": "verifier_nonce"}
        artifact_id = store.record(
            "scoped_browser_check_xss", proof, target=TARGET,
            identity=replayed_identity, success=replayed_execution,
        )
        return {"success": replayed_execution,
                "output": json.dumps({**proof, "evidence_id": artifact_id})}

    manager.execute = execute
    reports = await run_independent_verifiers(
        [candidate], llm=None, tools_manager=manager, targets=[TARGET],
    )
    assert len(calls) == 1
    assert manager._engagement_brain["candidates"][0]["coverage_cell_id"] == cell["id"]
    confirmed = replayed_execution and replayed_identity == "anonymous"
    assert reports[0]["status"] == ("confirmed" if confirmed else "inconclusive")
    assert check_verify_receipt(
        manager._verify_receipts, title=candidate.title, target=TARGET,
        tools_manager=manager,
    )[0] is confirmed


@pytest.mark.asyncio
async def test_xss_candidate_handoff_links_real_browser_receipt():
    manager = ASMToolsManager()
    brain = EngagementBrain(target="https://app.example.test")
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "host": "app.example.test", "path": "/catalog",
        "name": "searchTerm", "location": "query", "identity": "anonymous",
        "source": "browser_link", "testable": True,
    }])
    manager._engagement_brain = brain.to_dict()
    proof_id = evidence_store(manager).record(
        "scoped_browser_check_xss",
        {"operation": "check_xss", "target_template": TEMPLATE,
         "executed": True, "nonce": "hunter_nonce"},
        target=TARGET, identity="anonymous",
    )
    await manager.submit_finding_candidate(
        title="Reflected XSS in catalog search", target=TARGET,
        evidence_ids=[proof_id], vulnerability_class="xss",
    )
    cell = next(row for row in brain.coverage_cells if row.get("test_type") == "xss")
    assert manager._engagement_brain["candidates"][0]["coverage_cell_id"] == cell["id"]
    assert manager._engagement_brain["candidates"][0]["parameter"] == "query:searchTerm"


@pytest.mark.asyncio
async def test_post_form_xss_verifier_replays_approved_form_with_fresh_nonce():
    manager = ASMToolsManager()
    store = evidence_store(manager)
    action = "https://app.example.test/catalog/subscribe"
    source = "https://app.example.test/catalog"
    payload = '<img src=x onerror=alert("__PROWL_NONCE__")>'
    hunter_proof = {"operation": "check_form_xss", "target_template": source,
                    "form_action": action, "form_field": "email",
                    "form_payload_template": payload, "post_submitted": True,
                    "post_response_seen": True,
                    "executed": True, "nonce": "hunter-nonce"}
    hunter = store.record("scoped_browser_check_form_xss", hunter_proof,
                          target=action, identity="anonymous")
    brain = EngagementBrain(target="https://app.example.test")
    seed_parameter_coverage_cells(brain, [{"method": "POST", "host": "app.example.test",
        "path": "/catalog/subscribe", "name": "email", "location": "body_form",
        "identity": "anonymous", "source": "observed_form", "testable": True}])
    cell = next(row for row in brain.coverage_cells if row.get("test_type") == "xss")
    candidate = submit_candidate(brain, title="Reflected XSS in subscription form",
                                 target=action, vulnerability_class="xss",
                                 coverage_cell_id=cell["id"], identity="anonymous",
                                 parameter="body_form:email", evidence_ids=[hunter])
    manager._engagement_brain = brain.to_dict()
    calls = []

    async def execute(name, args):
        calls.append((name, args))
        assert name == "scoped_browser_assessment"
        assert args == {"operation": "check_form_xss", "url": source,
                        "identity": "anonymous", "form_action": action,
                        "form_field": "email", "form_payload_template": payload}
        verifier_proof = dict(hunter_proof, nonce="verifier-nonce")
        artifact_id = store.record("scoped_browser_check_form_xss", verifier_proof,
                                   target=action, identity="anonymous", success=True)
        return {"success": True, "output": json.dumps({**verifier_proof,
                                                         "evidence_id": artifact_id})}

    manager.execute = execute
    reports = await run_independent_verifiers([candidate], llm=None,
                                               tools_manager=manager, targets=[action])
    assert len(calls) == 1
    assert reports[0]["status"] == "confirmed", reports
