"""An observed XSS input is confirmed only after fresh browser execution."""

import json
from urllib.parse import quote

import pytest

from app.services.agent.coverage_cells import (
    claim_coverage_cell_leases, seed_js_coverage_cells, seed_parameter_coverage_cells,
)
from app.services.agent.assessment_scope import register_scope
from app.services.agent.engagement_brain import EngagementBrain, engagement_brain_from_dict
from app.services.agent.evidence_store import evidence_store
from app.services.agent.independent_verify import (
    check_verify_receipt, run_independent_verifiers, submit_candidate,
)
from app.services.agent.tools import ASMToolsManager
from app.services.agent.scoped_assessment.browser_traffic import package_exchange


TARGET = "https://app.example.test/catalog"
TEMPLATE = TARGET + "?searchTerm=" + quote('<img src=x onerror=alert("__PROWL_NONCE__")>')


@pytest.mark.asyncio
async def test_captured_ui_action_is_private_and_replayed_for_xhr_proof(monkeypatch):
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    register_scope(manager, "app.example.test")
    public, private = package_exchange(
        url="https://app.example.test/api/search?term=seed",
        page_url=TARGET, action_ref="ui-1",
        expected_origin="https://app.example.test", method="GET", resource_type="fetch",
        status=200, content_type="text/html", request_body=b"", response_body=b"seed",
    )
    action = {"ref": "ui-1", "kind": "tab", "label": "Results",
              "aria_controls": "results", "before_path": "/catalog",
              "after_path": "/catalog", "status": "completed"}

    async def fake_browser(**kwargs):
        kwargs["traffic_exchanges"].append({"public": public, "private": private})
        return ({"operation": "inspect_js", "final_origin": "https://app.example.test",
                 "final_path": "/catalog", "status": 200, "requests": [],
                 "actions": [action]}, None)

    monkeypatch.setattr("app.services.agent.scoped_assessment_tools.browser.check_browser", fake_browser)
    observed = json.loads(await manager.scoped_browser_assessment("inspect_js", TARGET))
    captured = observed["traffic"][0]
    assert captured["replay_action_count"] == 1
    assert "Results" not in json.dumps(captured)
    private_record = json.loads(manager._scoped_browser_exchanges[captured["artifact_id"]]["private"])
    expected_actions = [{"kind": "tab", "label": "Results", "aria_controls": "results",
                         "before_path": "/catalog"}]
    assert private_record["replay_actions"] == expected_actions

    brain = EngagementBrain(target="https://app.example.test")
    seed_parameter_coverage_cells(brain, [{"method": "GET", "host": "app.example.test",
        "path": "/api/search", "name": "term", "location": "query",
        "identity": "anonymous", "source": "browser_traffic", "testable": True,
        "artifact_id": captured["artifact_id"]}])
    lease = claim_coverage_cell_leases(brain, ["xss"], first_pass_only=True)["xss"]
    manager._engagement_brain = brain.to_dict()
    calls = []

    async def fake_assessment(operation, url, **kwargs):
        calls.append((operation, url, kwargs))
        return json.dumps({"evidence_id": "proof-1", "executed": True})

    monkeypatch.setattr(manager, "scoped_browser_assessment", fake_assessment)
    result = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert result["proof_confirmed"] is True
    assert calls[0][2]["xhr_actions"] == expected_actions


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


@pytest.mark.asyncio
@pytest.mark.parametrize("replayed_execution", [False, True])
@pytest.mark.parametrize("with_action", [False, True])
async def test_rendered_xhr_xss_needs_fresh_browser_execution(replayed_execution, with_action):
    manager = ASMToolsManager()
    store = evidence_store(manager)
    endpoint = "https://app.example.test/api/search"
    source = "https://app.example.test/catalog"
    payload = '<img src=x onerror=alert("__PROWL_NONCE__")>'
    hunter_proof = {"operation": "check_xhr_xss", "target_template": source,
                    "xhr_path": "/api/search", "xhr_parameter": "term",
                    "xhr_query_keys": ["term"],
                    "xhr_payload_template": payload, "xhr_mutated": True,
                    "xhr_response_seen": True, "executed": True,
                    "nonce": "hunter-nonce"}
    actions = [{"kind": "tab", "label": "Results", "aria_controls": "results",
                "before_path": "/catalog"}] if with_action else []
    if actions:
        hunter_proof.update(xhr_actions=actions, xhr_actions_replayed=1)
    hunter = store.record("scoped_browser_check_xhr_xss", hunter_proof,
                          target=endpoint, identity="anonymous")
    brain = EngagementBrain(target="https://app.example.test")
    seed_parameter_coverage_cells(brain, [{"method": "GET", "host": "app.example.test",
        "path": "/api/search", "name": "term", "location": "query",
        "identity": "anonymous", "source": "browser_traffic", "testable": True}])
    cell = next(row for row in brain.coverage_cells if row.get("test_type") == "xss")
    candidate = submit_candidate(brain, title="XSS in rendered search result",
                                 target=endpoint, vulnerability_class="xss",
                                 identity="anonymous", parameter="query:term",
                                 evidence_ids=[hunter])
    manager._engagement_brain = brain.to_dict()
    calls = []

    async def execute(name, args):
        calls.append((name, args))
        assert name == "scoped_browser_assessment"
        assert args == {"operation": "check_xhr_xss", "url": source,
                        "identity": "anonymous", "xhr_path": "/api/search",
                        "xhr_parameter": "term", "xhr_payload_template": payload,
                        "xhr_query_keys": ["term"],
                        **({"xhr_actions": actions} if actions else {})}
        fresh_proof = dict(hunter_proof, nonce="verifier-nonce",
                           executed=replayed_execution)
        artifact_id = store.record("scoped_browser_check_xhr_xss", fresh_proof,
                                   target=endpoint, identity="anonymous",
                                   success=replayed_execution)
        return {"success": replayed_execution,
                "output": json.dumps({**fresh_proof, "evidence_id": artifact_id})}

    manager.execute = execute
    reports = await run_independent_verifiers([candidate], llm=None,
                                               tools_manager=manager, targets=[endpoint])
    assert len(calls) == 1
    assert manager._engagement_brain["candidates"][0]["coverage_cell_id"] == cell["id"]
    assert reports[0]["status"] == ("confirmed" if replayed_execution else "inconclusive")


@pytest.mark.asyncio
async def test_assigned_dom_fragment_replays_observed_page_and_fresh_nonce(monkeypatch):
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    manager._capability_map = {"target": "https://app.example.test",
        "scope": "https://app.example.test"}
    brain = EngagementBrain(target="https://app.example.test")
    seed_js_coverage_cells(brain, {"target": "https://app.example.test",
        "js_sources": [{"url": "https://app.example.test/static/app.js",
            "kind": "external", "page_path": "/catalog", "artifact_id": "script-1",
            "source_leads": [{"kind": "fragment", "line": 1}],
            "sink_leads": [{"kind": "html_assignment", "line": 2}]}]})
    lease = claim_coverage_cell_leases(brain, ["xss"],
                                       allowed_test_types=frozenset({"dom_xss"}))["xss"]
    manager._engagement_brain = brain.to_dict()
    store = evidence_store(manager)
    calls = []

    async def fake_assessment(operation, url, **kwargs):
        calls.append((operation, url))
        assert operation == "check_xss" and kwargs["identity"] == "anonymous"
        proof = {"operation": "check_xss", "target_template": url,
                 "executed": True, "nonce": "hunter-nonce"}
        artifact_id = store.record("scoped_browser_check_xss", proof,
                                   target="https://app.example.test/catalog",
                                   identity="anonymous")
        return json.dumps({**proof, "evidence_id": artifact_id})

    monkeypatch.setattr(manager, "scoped_browser_assessment", fake_assessment)
    probed = await manager.scoped_dom_xss_assigned(lease.coverage_cell_id, lease.id)
    assert probed["proof_confirmed"] is True
    assert calls[0][1].startswith("https://app.example.test/catalog#")
    assert "__PROWL_NONCE__" in calls[0][1]
    brain = engagement_brain_from_dict(manager._engagement_brain)
    candidate = submit_candidate(brain, title="DOM XSS in catalog fragment",
                                 target="https://app.example.test/catalog",
                                 vulnerability_class="xss", evidence_ids=[probed["evidence_id"]])
    manager._engagement_brain = brain.to_dict()

    async def execute(name, args):
        assert name == "scoped_browser_assessment"
        assert args == {"operation": "check_xss", "url": calls[0][1],
                        "identity": "anonymous"}
        fresh = {"operation": "check_xss", "target_template": calls[0][1],
                 "executed": True, "nonce": "verifier-nonce"}
        artifact_id = store.record("scoped_browser_check_xss", fresh,
                                   target="https://app.example.test/catalog",
                                   identity="anonymous", success=True)
        return {"success": True, "output": json.dumps({**fresh, "evidence_id": artifact_id})}

    manager.execute = execute
    reports = await run_independent_verifiers([candidate], llm=None,
        tools_manager=manager, targets=["https://app.example.test/catalog"])
    assert reports[0]["status"] == "confirmed", reports


@pytest.mark.asyncio
@pytest.mark.parametrize("cleanup_success", [False, True])
async def test_stored_xss_requires_readback_and_cleanup_on_both_runs(cleanup_success):
    manager = ASMToolsManager()
    store = evidence_store(manager)
    action = "https://app.example.test/comments"
    source = "https://app.example.test/new-comment"
    readback = "https://app.example.test/comments/view"
    cleanup = "https://app.example.test/comments/purge?marker=__PROWL_NONCE__"
    payload = '<img src=x onerror=alert("__PROWL_NONCE__")>'
    hunter_proof = {"operation": "check_stored_xss", "target_template": source,
                    "form_action": action, "form_field": "message",
                    "form_payload_template": payload, "post_submitted": True,
                    "post_response_seen": True, "readback_url": readback,
                    "readback_response_seen": True, "readback_status": 200,
                    "readback_final_exact": True, "readback_executed": True,
                    "cleanup_url_template": cleanup, "cleanup_success": True,
                    "executed": True, "nonce": "hunter-nonce"}
    hunter = store.record("scoped_browser_check_stored_xss", hunter_proof,
                          target=action, identity="anonymous")
    brain = EngagementBrain(target="https://app.example.test")
    seed_parameter_coverage_cells(brain, [{"method": "POST", "host": "app.example.test",
        "path": "/comments", "name": "message", "location": "body_form",
        "identity": "anonymous", "source": "observed_form", "testable": True}])
    cell = next(row for row in brain.coverage_cells if row.get("test_type") == "stored_xss")
    candidate = submit_candidate(brain, title="Stored XSS in comments",
                                 target=action, vulnerability_class="xss",
                                 coverage_cell_id=cell["id"], identity="anonymous",
                                 parameter="body_form:message", evidence_ids=[hunter])
    manager._engagement_brain = brain.to_dict()
    calls = []

    async def execute(name, args):
        calls.append((name, args))
        assert name == "scoped_browser_assessment"
        assert args == {"operation": "check_stored_xss", "url": source,
                        "identity": "anonymous", "form_action": action,
                        "form_field": "message", "form_payload_template": payload,
                        "readback_url": readback, "cleanup_url_template": cleanup}
        fresh = dict(hunter_proof, nonce="verifier-nonce",
                     cleanup_success=cleanup_success, executed=cleanup_success)
        artifact_id = store.record("scoped_browser_check_stored_xss", fresh,
                                   target=action, identity="anonymous",
                                   success=cleanup_success)
        return {"success": cleanup_success,
                "output": json.dumps({**fresh, "evidence_id": artifact_id})}

    manager.execute = execute
    reports = await run_independent_verifiers([candidate], llm=None,
                                               tools_manager=manager, targets=[action])
    assert len(calls) == 1
    assert reports[0]["status"] == ("confirmed" if cleanup_success else "inconclusive")
