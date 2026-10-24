"""PROWL execution primitives are available through the existing Aegis agent."""

import json

import pytest

from app.services.agent.assessment_scope import register_scope
from app.services.agent.assessment_sessions import identity_registry
from app.services.agent.evidence_store import VerificationRun, evidence_store, verification_run
from app.services.agent.scoped_assessment.browser_traffic import package_exchange
from app.services.agent.tools import ASMToolsManager
from app.services.agent.prompts import is_tool_allowed_in_phase


def test_legacy_scoped_identity_requires_proven_auth_on_exact_origin():
    manager = ASMToolsManager()
    manager._auth_session = {
        "target": "https://app.example.test",
        "authenticated": False,
        "cookies": [{"name": "session", "value": "private", "domain": "app.example.test"}],
    }
    with pytest.raises(ValueError, match="requires an authenticated session"):
        manager._scoped_state("legacy", "https://app.example.test/catalog")

    manager._auth_session["authenticated"] = True
    with pytest.raises(ValueError, match="requires an authenticated session"):
        manager._scoped_state("legacy", "https://elsewhere.test/catalog")
    state = manager._scoped_state("legacy", "https://app.example.test/catalog")
    assert state["cookies"][0]["name"] == "session"


@pytest.mark.asyncio
async def test_agent_browser_inventory_keeps_private_exchange_values_out_of_tool_output(monkeypatch):
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    register_scope(manager, "app.example.test")
    public, private = package_exchange(
        url="https://app.example.test/api/items?id=7",
        expected_origin="https://app.example.test", action_ref="ui-1",
        method="GET", resource_type="fetch", status=200,
        content_type="application/json", request_body=b"",
        response_body=b'{"secret":"private-response"}',
    )

    async def fake_browser(**kwargs):
        assert kwargs["allowed_origins"] == ["https://app.example.test"]
        kwargs["traffic_exchanges"].append({"public": public, "private": private})
        kwargs["link_baselines"].append("https://app.example.test/catalog?category=gin")
        return ({"operation": "inspect_js", "final_origin": "https://app.example.test",
                 "final_path": "/", "requests": [], "actions": [], "status": 200}, b"png")

    monkeypatch.setattr(
        "app.services.agent.scoped_assessment_tools.browser.check_browser", fake_browser,
    )
    result = json.loads(await manager.scoped_browser_assessment(
        "inspect_js", "https://app.example.test/",
    ))
    assert result["surface_inventory"]["finding"] is False
    assert result["surface_inventory"]["test_suggestions"][0]["operation"] == "http_sqli_boolean"
    assert "private-response" not in json.dumps(result)
    assert "category=gin" not in json.dumps(result)
    assert manager._scoped_link_baselines["anonymous"] == [
        "https://app.example.test/catalog?category=gin",
    ]
    exchange = result["traffic"][0]
    assert exchange["path"] == "/api/items"
    assert "id=7" not in json.dumps(result)
    assert exchange["artifact_id"] in manager._scoped_browser_exchanges
    summary = json.loads(await manager.scoped_assessment_summary())
    assert summary["complete"] is False
    assert summary["coverage"]["denominator"] >= 1
    assert manager._capability_map["scope"] == "https://app.example.test"
    assert any(row["name"] == "id" for row in manager._capability_map["parameter_inventory"])
    tool_result = await manager.execute("scoped_browser_assessment", {
        "operation": "inspect_js", "url": "https://app.example.test/",
    })
    assert tool_result["success"] is True
    assert tool_result["capability_map"]["scope"] == "https://app.example.test"
    assert result["technology_detection"]["engine"] == "wappalyzer-offline"
    with pytest.raises(ValueError, match="unfinished coverage"):
        await manager.complete_scoped_assessment()
    partial = json.loads(await manager.complete_scoped_assessment(
        reason="Operator limited this run to anonymous manual checks",
    ))
    assert partial["status"] == "partial"
    assert partial["complete"] is False
    assert partial["coverage"]["open_cell_count"] > 0
    assert manager._scoped_assessment_partial_reason == partial["reason"]
    assert is_tool_allowed_in_phase("scoped_numeric_sqli", "exploitation")
    assert not is_tool_allowed_in_phase("scoped_numeric_sqli", "informational")


@pytest.mark.asyncio
async def test_browser_capture_store_preserves_open_cell_references(monkeypatch):
    from app.services.agent.engagement_brain import EngagementBrain

    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    register_scope(manager, "app.example.test")
    brain = EngagementBrain(target="https://app.example.test")
    brain.coverage_cells = [{"id": "open-cell", "status": "untested",
                             "capture_id": "pinned-capture"}]
    manager._engagement_brain = brain.to_dict()
    manager._scoped_browser_exchanges = {
        **{"pinned-capture": {"identity": "anonymous", "private": b"{}", "public": {}}},
        **{f"old-{index}": {"identity": "anonymous", "private": b"{}", "public": {}}
           for index in range(119)},
    }
    public, private = package_exchange(
        url="https://app.example.test/api/search?term=seed",
        page_url="https://app.example.test/catalog", action_ref="navigate",
        expected_origin="https://app.example.test", method="GET", resource_type="fetch",
        status=200, content_type="text/html", request_body=b"", response_body=b"seed",
    )

    async def fake_browser(**kwargs):
        kwargs["traffic_exchanges"].append({"public": public, "private": private})
        return ({"operation": "map", "final_origin": "https://app.example.test",
                 "final_path": "/catalog", "status": 200, "requests": []}, None)

    monkeypatch.setattr("app.services.agent.scoped_assessment_tools.browser.check_browser", fake_browser)
    result = json.loads(await manager.scoped_browser_assessment(
        "map", "https://app.example.test/catalog"))
    assert result["traffic_store_dropped"] == 0
    assert "pinned-capture" in manager._scoped_browser_exchanges
    assert result["traffic"][0]["artifact_id"] in manager._scoped_browser_exchanges
    assert len(manager._scoped_browser_exchanges) == 120


@pytest.mark.asyncio
async def test_post_form_xss_requires_operator_path_and_keeps_fresh_proof(monkeypatch):
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    register_scope(manager, "app.example.test")
    calls = []

    async def fake_browser(**kwargs):
        calls.append(kwargs)
        return ({"operation": "check_form_xss", "target_template": kwargs["url"],
                 "final_origin": "https://app.example.test", "final_path": "/catalog",
                 "form_action": kwargs["form_action"], "form_field": kwargs["form_field"],
                 "form_payload_template": kwargs["form_payload_template"],
                 "post_submitted": True, "post_response_seen": True,
                 "executed": True, "nonce": "fresh-nonce",
                 "dialog_count": 1, "requests": []}, None)

    monkeypatch.setattr("app.services.agent.scoped_assessment_tools.browser.check_browser", fake_browser)
    kwargs = {"operation": "check_form_xss", "url": "https://app.example.test/catalog",
              "form_action": "https://app.example.test/catalog/subscribe",
              "form_field": "email",
              "form_payload_template": '<img src=x onerror=alert("__PROWL_NONCE__")>'}
    with pytest.raises(ValueError, match="approved"):
        await manager.scoped_browser_assessment(**kwargs)
    assert not calls
    manager.set_scoped_assessment_policy({"body_replay_paths": ["/catalog/subscribe"]})
    result = json.loads(await manager.scoped_browser_assessment(**kwargs))
    assert result["executed"] is True
    assert calls[0]["form_action"] == kwargs["form_action"]
    receipt = evidence_store(manager).records[result["evidence_id"]]
    assert receipt["target"] == kwargs["form_action"]
    assert receipt["kind"] == "scoped_browser_check_form_xss"


@pytest.mark.asyncio
async def test_stored_xss_requires_separate_cleanup_approval(monkeypatch):
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    register_scope(manager, "app.example.test")
    calls = []

    async def fake_browser(**kwargs):
        calls.append(kwargs)
        return ({"operation": "check_stored_xss", "target_template": kwargs["url"],
                 "form_action": kwargs["form_action"], "form_field": kwargs["form_field"],
                 "form_payload_template": kwargs["form_payload_template"],
                 "readback_url": kwargs["readback_url"],
                 "cleanup_url_template": kwargs["cleanup_url_template"],
                 "post_submitted": True, "post_response_seen": True,
                 "readback_response_seen": True, "readback_status": 200,
                 "readback_final_exact": True, "readback_executed": True,
                 "cleanup_success": True, "executed": True, "nonce": "fresh-nonce",
                 "final_origin": "https://app.example.test", "requests": []}, None)

    monkeypatch.setattr("app.services.agent.scoped_assessment_tools.browser.check_browser", fake_browser)
    kwargs = {"operation": "check_stored_xss", "url": "https://app.example.test/new",
              "form_action": "https://app.example.test/comments", "form_field": "message",
              "form_payload_template": '<img src=x onerror=alert("__PROWL_NONCE__")>',
              "readback_url": "https://app.example.test/comments/view",
              "cleanup_url_template": "https://app.example.test/comments/purge?marker=__PROWL_NONCE__"}
    manager.set_scoped_assessment_policy({"body_replay_paths": ["/comments"]})
    with pytest.raises(ValueError, match="cleanup path was not approved"):
        await manager.scoped_browser_assessment(**kwargs)
    assert not calls
    manager.set_scoped_assessment_policy({"body_replay_paths": ["/comments"],
                                          "stored_xss_cleanup_paths": ["/comments/purge"]})
    result = json.loads(await manager.scoped_browser_assessment(**kwargs))
    assert result["executed"] is True
    receipt = evidence_store(manager).records[result["evidence_id"]]
    assert receipt["target"] == kwargs["form_action"]
    assert receipt["kind"] == "scoped_browser_check_stored_xss"


@pytest.mark.asyncio
async def test_assigned_post_form_xss_binds_browser_receipt_to_exact_cell(monkeypatch):
    from app.services.agent.coverage_cells import (
        claim_coverage_cell_leases, seed_parameter_coverage_cells,
    )
    from app.services.agent.engagement_brain import EngagementBrain

    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    register_scope(manager, "app.example.test")
    action = "https://app.example.test/newsletter"
    page = "https://app.example.test/catalog"
    manager._capability_map = {"target": "https://app.example.test",
        "scope": "https://app.example.test", "forms": [{
            "method": "POST", "action": action, "page": page,
            "inputs": ["email"], "fields": [{"name": "email", "control_type": "email"}],
        }]}
    brain = EngagementBrain(target="https://app.example.test")
    seed_parameter_coverage_cells(brain, [{"method": "POST", "host": "app.example.test",
        "path": "/newsletter", "name": "email", "location": "body_form",
        "identity": "anonymous", "source": "observed_form", "testable": True}])
    lease = claim_coverage_cell_leases(brain, ["xss"], first_pass_only=True)["xss"]
    manager._engagement_brain = brain.to_dict()
    store = evidence_store(manager)

    async def fake_assessment(operation, url, **kwargs):
        assert operation == "check_form_xss" and url == page
        assert kwargs["form_action"] == action and kwargs["form_field"] == "email"
        artifact_id = store.record("scoped_browser_check_form_xss", {
            "operation": operation, "executed": True, "nonce": "first",
            "target_template": page, "form_action": action, "form_field": "email",
            "form_payload_template": kwargs["form_payload_template"],
            "post_submitted": True, "post_response_seen": True,
        }, target=action, identity="anonymous")
        return json.dumps({"evidence_id": artifact_id, "executed": True})

    monkeypatch.setattr(manager, "scoped_browser_assessment", fake_assessment)
    result = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert result["success"] and result["proof_confirmed"] is True
    cell = next(row for row in manager._engagement_brain["coverage_cells"]
                if row["id"] == lease.coverage_cell_id)
    assert result["evidence_id"] in cell["probe_artifact_ids"]


@pytest.mark.asyncio
async def test_captured_get_xss_replays_the_rendering_page(monkeypatch):
    from app.services.agent.coverage_cells import (
        claim_coverage_cell_leases, seed_parameter_coverage_cells,
    )
    from app.services.agent.engagement_brain import EngagementBrain

    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    register_scope(manager, "app.example.test")
    manager._capability_map = {"target": "https://app.example.test",
                               "scope": "https://app.example.test"}
    public, private = package_exchange(
        url="https://app.example.test/api/search?term=seed&category=all",
        page_url="https://app.example.test/catalog", action_ref="navigate",
        expected_origin="https://app.example.test", method="GET",
        resource_type="fetch", status=200, content_type="text/html",
        request_body=b"", response_body=b"seed",
    )
    manager._scoped_browser_exchanges = {
        "capture-1": {"identity": "anonymous", "private": private, "public": public},
    }
    brain = EngagementBrain(target="https://app.example.test")
    seed_parameter_coverage_cells(brain, [{"method": "GET", "host": "app.example.test",
        "path": "/api/search", "name": "term", "location": "query",
        "identity": "anonymous", "source": "browser_traffic", "testable": True,
        "artifact_id": "capture-1"}])
    lease = claim_coverage_cell_leases(brain, ["xss"], first_pass_only=True)["xss"]
    manager._engagement_brain = brain.to_dict()
    calls = []

    async def fake_assessment(operation, url, **kwargs):
        calls.append((operation, url, kwargs))
        return json.dumps({"evidence_id": "proof-1", "executed": True})

    monkeypatch.setattr(manager, "scoped_browser_assessment", fake_assessment)
    result = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert calls == [("check_xhr_xss", "https://app.example.test/catalog", {
        "identity": "anonymous", "xhr_path": "/api/search", "xhr_parameter": "term",
        "xhr_query_keys": ["category", "term"],
        "xhr_payload_template": '<img src=x onerror=alert("__PROWL_NONCE__")>',
    })]
    assert result["operation"] == "scoped_browser_check_xhr_xss"
    assert result["probe_result"]["request_context"] == "observed_xhr_render_page"


@pytest.mark.asyncio
async def test_assigned_stored_xss_uses_observed_form_and_readback(monkeypatch):
    from app.services.agent.coverage_cells import (
        claim_coverage_cell_leases, seed_parameter_coverage_cells,
    )
    from app.services.agent.engagement_brain import EngagementBrain

    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    register_scope(manager, "app.example.test")
    page = "https://app.example.test/new"
    action = "https://app.example.test/comments"
    readback = "https://app.example.test/comments/view"
    cleanup = "https://app.example.test/comments/purge?marker=__PROWL_NONCE__"
    manager._capability_map = {"target": "https://app.example.test",
        "scope": "https://app.example.test", "pages_visited": [readback],
        "forms": [{"method": "POST", "action": action, "page": page,
                   "inputs": ["message"]}]}
    brain = EngagementBrain(target="https://app.example.test")
    seed_parameter_coverage_cells(brain, [{"method": "POST", "host": "app.example.test",
        "path": "/comments", "name": "message", "location": "body_form",
        "identity": "anonymous", "source": "observed_form", "testable": True}])
    lease = claim_coverage_cell_leases(brain, ["xss"],
        allowed_test_types=frozenset({"stored_xss"}))["xss"]
    manager._engagement_brain = brain.to_dict()
    calls = []

    async def fake_assessment(operation, url, **kwargs):
        calls.append((operation, url, kwargs))
        return json.dumps({"evidence_id": "stored-proof", "executed": True,
                           "readback_executed": True, "cleanup_success": True})

    monkeypatch.setattr(manager, "scoped_browser_assessment", fake_assessment)
    result = await manager.scoped_stored_xss_assigned(
        lease.coverage_cell_id, lease.id, readback, cleanup)
    assert result["proof_confirmed"] is True
    assert calls[0][0:2] == ("check_stored_xss", page)
    assert calls[0][2]["form_action"] == action
    assert calls[0][2]["readback_url"] == readback
    assert calls[0][2]["cleanup_url_template"] == cleanup


@pytest.mark.asyncio
async def test_scoped_assessment_cannot_complete_with_confirmed_unpublished_candidate():
    from app.services.agent.engagement_brain import (
        EngagementBrain, record_surface_coverage, seed_coverage_from_surfaces,
    )

    manager = ASMToolsManager()
    brain = EngagementBrain(target="https://app.example.test")
    brain.threat_model = {"actors": ["anonymous"]}
    brain.surfaces = [{"method": "GET", "path": "/search",
                       "host": "app.example.test", "takes_input": True}]
    seed_coverage_from_surfaces(brain)
    record_surface_coverage(
        brain, method="GET", path="/search", host="app.example.test",
        status="tested_clean", reason="Negative control",
    )
    brain.candidates = [{"id": "candidate-1", "status": "confirmed", "finding_id": ""}]
    manager._engagement_brain = brain.to_dict()

    blocked = json.loads(await manager.scoped_assessment_summary())
    assert blocked["complete"] is False
    assert blocked["unpublished_candidates"] == ["candidate-1"]

    brain.candidates[0]["finding_id"] = "finding-1"
    manager._engagement_brain = brain.to_dict()
    complete = json.loads(await manager.scoped_assessment_summary())
    assert complete["complete"] is True
    closed = json.loads(await manager.complete_scoped_assessment())
    assert closed["status"] == "completed"
    assert closed["complete"] is True


@pytest.mark.asyncio
async def test_coverage_tool_cannot_turn_empty_or_unknown_status_into_clean():
    manager = ASMToolsManager()
    for status in ("", "tested_clena"):
        result = json.loads(await manager.record_surface_coverage(
            path="/search", status=status, host="app.example.test",
        ))
        assert "error" in result
    brain = manager._engagement_brain
    assert not brain.get("coverage")


@pytest.mark.asyncio
async def test_numeric_probe_needs_observed_exchange_and_exact_origin(monkeypatch):
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    register_scope(manager, "app.example.test")
    public, private = package_exchange(
        url="https://app.example.test/api/items?id=7",
        expected_origin="https://app.example.test", action_ref="navigate",
        method="GET", resource_type="xhr", status=200,
        content_type="application/json", request_body=b"", response_body=b"{}",
    )
    manager._scoped_browser_exchanges = {
        "observed-id": {"identity": "anonymous", "private": private, "public": public}
    }

    def fake_probe(baseline, true_url, false_url, nonce, **kwargs):
        assert baseline == "https://app.example.test/api/items?id=7"
        assert "%20AND%20" in true_url and true_url != false_url
        return {"target": "https://app.example.test/api/items",
                "operation": "sqli_boolean_numeric", "proof_confirmed": True,
                "nonce": nonce, "parameter": "id"}

    monkeypatch.setattr(
        "app.services.agent.scoped_assessment_tools.sqli_boolean.probe_numeric_boolean", fake_probe,
    )
    result = json.loads(await manager.scoped_numeric_sqli("observed-id", "id"))
    assert result["proof_confirmed"] and result["finding"] is False
    assert result["source_artifact_id"] == "observed-id"
    with pytest.raises(ValueError, match="Unknown browser exchange"):
        await manager.scoped_numeric_sqli("invented-id", "id")
    with pytest.raises(ValueError, match="identity"):
        await manager.scoped_numeric_sqli("observed-id", "id", identity="other")
    token = verification_run.set(VerificationRun("fresh-run", "candidate", 1, "nonce"))
    try:
        with pytest.raises(ValueError, match="fresh for this verifier run"):
            await manager.scoped_numeric_sqli("observed-id", "id")
    finally:
        verification_run.reset(token)


@pytest.mark.asyncio
async def test_post_and_owner_proofs_require_operator_policy(monkeypatch):
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    register_scope(manager, "app.example.test")
    identity_registry(manager).register("owner", "https://app.example.test")
    identity_registry(manager).register("other", "https://app.example.test")
    post_public, post_private = package_exchange(
        url="https://app.example.test/api/search",
        expected_origin="https://app.example.test", action_ref="ui-1",
        method="POST", resource_type="fetch", status=200,
        content_type="application/json", request_content_type="application/json",
        request_body=b'{"filter":"hello"}', response_body=b"{}",
    )
    get_public, get_private = package_exchange(
        url="https://app.example.test/api/owner-record",
        expected_origin="https://app.example.test", action_ref="ui-2",
        method="GET", resource_type="xhr", status=200,
        content_type="application/json", request_body=b"", response_body=b"{}",
    )
    manager._scoped_browser_exchanges = {
        "post": {"identity": "owner", "private": post_private, "public": post_public},
        "owner": {"identity": "owner", "private": get_private, "public": get_public},
    }
    with pytest.raises(ValueError, match="not approved"):
        await manager.scoped_body_probe("post", "/filter", "owner")
    with pytest.raises(ValueError, match="not declared"):
        await manager.scoped_owner_only("owner", "owner")

    manager.set_scoped_assessment_policy({
        "body_replay_paths": ["/api/search", "/api/save"],
        "owner_only_resources": [{"target": "https://app.example.test/api/owner-record",
                                  "owner_identity": "owner", "other_identity": "other"}],
    })
    def fake_body(url, mime, baseline, changed, **kwargs):
        assert baseline != changed
        return {"target": url, "inconclusive": False, "finding": False}
    def fake_owner(target, **kwargs):
        assert kwargs["owner_identity"] == "owner"
        assert kwargs["other_identity"] == "other"
        return {"target": target, "proof_confirmed": True}
    monkeypatch.setattr(
        "app.services.agent.scoped_assessment_tools.body_probe.probe_observed_body", fake_body,
    )
    monkeypatch.setattr(
        "app.services.agent.scoped_assessment_tools.authz_proof.probe_owner_only", fake_owner,
    )
    body = json.loads(await manager.scoped_body_probe("post", "/filter", "owner"))
    owner = json.loads(await manager.scoped_owner_only("owner", "owner"))
    assert body["finding"] is False
    assert owner["proof_confirmed"] and owner["finding"] is False


@pytest.mark.asyncio
async def test_post_xss_reflection_uses_capture_and_keeps_execution_unproven(monkeypatch):
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    register_scope(manager, "app.example.test")
    public, private = package_exchange(
        url="https://app.example.test/feedback",
        expected_origin="https://app.example.test", action_ref="form-1",
        method="POST", resource_type="fetch", status=200,
        content_type="text/html", request_content_type="application/x-www-form-urlencoded",
        request_body=b"message=hello", response_body=b"hello",
    )
    manager._scoped_browser_exchanges = {
        "capture-1": {"identity": "anonymous", "private": private, "public": public},
    }
    with pytest.raises(ValueError, match="not approved"):
        await manager.scoped_body_xss_reflection("capture-1", "message")
    manager.set_scoped_assessment_policy({"body_replay_paths": ["/feedback"]})

    def fake_probe(url, mime, baseline, changed, **kwargs):
        assert url == "https://app.example.test/feedback"
        assert baseline == b"message=hello"
        assert b"%3Cimg" in changed and b"onerror" in changed
        assert kwargs["payload"].startswith("<img")
        return {"target": url, "inconclusive": False, "reflection_detected": True,
                "raw_html_reflection": True, "proof_confirmed": False, "finding": False}

    monkeypatch.setattr(
        "app.services.agent.scoped_assessment_tools.body_probe.probe_observed_body_reflection",
        fake_probe,
    )
    result = json.loads(await manager.scoped_body_xss_reflection("capture-1", "message"))
    assert result["reflection_detected"] is True
    assert result["proof_confirmed"] is False
    assert result["evidence_id"]


@pytest.mark.asyncio
async def test_scoped_clean_coverage_requires_matching_negative_evidence():
    from app.services.agent.engagement_brain import EngagementBrain
    from app.services.agent.evidence_store import evidence_store

    manager = ASMToolsManager()
    manager._engagement_brain = EngagementBrain(
        target="https://app.example.test",
        surfaces=[{"method": "GET", "path": "/static/", "host": "app.example.test", "takes_input": True}],
    ).to_dict()
    artifact_id = evidence_store(manager).record(
        "scoped_http_get",
        {"operation": "http_get", "status": 200, "directory_index": False,
         "truncated": False, "redirected": False},
        target="https://app.example.test/static/", identity="anonymous",
    )
    accepted = json.loads(await manager.record_surface_coverage(
        path="/static/", host="app.example.test", identity="anonymous",
        test_type="directory_index", status="tested_clean", evidence_id=artifact_id,
    ))
    assert accepted["coverage"]["verified_checks"] == 1
    mismatch = json.loads(await manager.record_surface_coverage(
        path="/other/", host="app.example.test", identity="anonymous",
        test_type="directory_index", status="tested_clean", evidence_id=artifact_id,
    ))
    assert "does not match" in mismatch["error"]


@pytest.mark.asyncio
async def test_sqli_clean_coverage_requires_complete_stable_controls():
    from app.services.agent.engagement_brain import EngagementBrain
    from app.services.agent.evidence_store import evidence_store
    from app.services.agent.scoped_assessment.sqli_string import CHECK_ORDER

    manager = ASMToolsManager()
    manager._engagement_brain = EngagementBrain(target="https://app.example.test").to_dict()
    checks = {key: {"status": 200, "bytes_captured": 4000,
                    "redirected": False, "truncated": False} for key in CHECK_ORDER}
    payload = {"operation": "sqli_boolean_string", "parameter": "category",
               "proof_confirmed": False, "requests_sent": 8, "checks": checks}
    artifact_id = evidence_store(manager).record(
        "scoped_string_sqli", payload,
        target="https://app.example.test/catalog", identity="anonymous",
    )
    accepted = json.loads(await manager.record_surface_coverage(
        path="/catalog", host="app.example.test", identity="anonymous",
        parameter="query:category", test_type="sqli", status="tested_clean",
        evidence_id=artifact_id,
    ))
    assert accepted["row"]["status"] == "tested_clean"

    checks["true_first"]["bytes_captured"] = 8000
    changed_id = evidence_store(manager).record(
        "scoped_string_sqli", payload,
        target="https://app.example.test/catalog", identity="anonymous",
    )
    rejected = json.loads(await manager.record_surface_coverage(
        path="/catalog", host="app.example.test", identity="anonymous",
        parameter="query:category", test_type="sqli", status="tested_clean",
        evidence_id=changed_id,
    ))
    assert rejected["error"] == "SQLi response differences remain inconclusive"


@pytest.mark.asyncio
async def test_coverage_rejects_http_status_without_mutating_ledger():
    from app.services.agent.engagement_brain import EngagementBrain

    manager = ASMToolsManager()
    manager._engagement_brain = EngagementBrain(target="https://app.example.test").to_dict()
    before = manager._engagement_brain
    result = json.loads(await manager.record_surface_coverage(
        path="/catalog", status=200,
    ))
    assert "coverage status must be a string" in result["error"]
    assert manager._engagement_brain == before


@pytest.mark.asyncio
async def test_negative_boolean_recipe_cannot_close_class_level_sqli_coverage():
    from app.services.agent.engagement_brain import EngagementBrain
    from app.services.agent.evidence_store import evidence_store
    from app.services.agent.scoped_assessment.sqli_string import CHECK_ORDER

    manager = ASMToolsManager()
    manager._engagement_brain = EngagementBrain(target="https://app.example.test").to_dict()
    checks = {key: {"status": 200, "bytes_captured": 4000,
                    "redirected": False, "truncated": False} for key in CHECK_ORDER}
    receipt = evidence_store(manager).record(
        "scoped_string_sqli",
        {"operation": "sqli_boolean_string", "proof_recipe": "string_or_boolean_v1",
         "parameter": "category", "proof_confirmed": False,
         "requests_sent": len(CHECK_ORDER), "checks": checks},
        target="https://app.example.test/catalog", identity="anonymous",
    )
    result = json.loads(await manager.record_surface_coverage(
        path="/catalog", host="app.example.test", identity="anonymous",
        parameter="query:category", test_type="sqli", status="tested_clean",
        evidence_id=receipt,
    ))
    assert "does not establish clean SQLi coverage" in result["error"]


@pytest.mark.asyncio
async def test_observed_directory_becomes_assessment_coverage(monkeypatch):
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    register_scope(manager, "app.example.test")

    async def fake_browser(**kwargs):
        return ({"operation": "map", "final_origin": "https://app.example.test",
                 "final_path": "/", "status": 200,
                 "requests": [{"method": "GET", "resource_type": "script",
                               "path": "/static/app.js"}]}, None)

    monkeypatch.setattr(
        "app.services.agent.scoped_assessment_tools.browser.check_browser", fake_browser,
    )
    result = json.loads(await manager.scoped_browser_assessment(
        "map", "https://app.example.test/",
    ))
    assert result["suggested_coverage"][0]["target"] == "https://app.example.test/static/"
    summary = json.loads(await manager.scoped_assessment_summary())
    assert any(row["path"] == "/static/" for row in summary["coverage"]["untested"])
