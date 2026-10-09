"""PROWL execution primitives are available through the existing Aegis agent."""

import json

import pytest

from app.services.agent.assessment_scope import register_scope
from app.services.agent.assessment_sessions import identity_registry
from app.services.agent.evidence_store import VerificationRun, verification_run
from app.services.agent.scoped_assessment.browser_traffic import package_exchange
from app.services.agent.tools import ASMToolsManager
from app.services.agent.prompts import is_tool_allowed_in_phase


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
    assert is_tool_allowed_in_phase("scoped_numeric_sqli", "exploitation")
    assert is_tool_allowed_in_phase("scoped_text_sqli", "exploitation")
    assert not is_tool_allowed_in_phase("scoped_numeric_sqli", "informational")


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
    assert blocked["detection_funnel"]["candidate_statuses"]["confirmed"] == 1
    assert blocked["detection_funnel"]["published_findings"] == 0

    brain.candidates[0]["finding_id"] = "finding-1"
    manager._engagement_brain = brain.to_dict()
    complete = json.loads(await manager.scoped_assessment_summary())
    assert complete["complete"] is True
    assert complete["detection_funnel"]["published_findings"] == 1


def test_xml_capture_lists_fields_without_values_or_executable_proof():
    from app.services.agent.prowl_service_bridge import capability_map_from_observation

    public, private = package_exchange(
        url="https://app.example.test/catalog/product/stock",
        expected_origin="https://app.example.test", action_ref="ui-1",
        method="POST", resource_type="fetch", status=200,
        content_type="application/xml", request_content_type="application/xml",
        request_body=b"<stock><productId>123</productId><storeId>456</storeId></stock>",
        response_body=b"<quantity>8</quantity>",
    )
    assert public["body_fields_status"] == "parsed"
    assert {field["path"] for field in public["body_fields"]} == {
        "/stock/productId", "/stock/storeId",
    }
    assert "123" not in json.dumps(public) and "456" not in json.dumps(public)
    assert private
    cmap = capability_map_from_observation({
        "signal": "browser_inspect_js",
        "result": {"final_origin": "https://app.example.test", "status": 200,
                   "final_path": "/catalog", "traffic": [public]},
    })
    assert any(row["location"] == "body_xml" and row["name"] == "document"
               for row in cmap["parameter_inventory"])
    unsafe, _ = package_exchange(
        url="https://app.example.test/catalog/product/stock",
        expected_origin="https://app.example.test", action_ref="ui-2",
        method="POST", resource_type="fetch", status=200,
        content_type="application/xml", request_content_type="application/xml",
        request_body=b'<!DOCTYPE stock [<!ENTITY marker "private">]><stock>&marker;</stock>',
        response_body=b"ok",
    )
    assert unsafe["body_fields_status"] == "unsafe_xml"
    assert unsafe["body_fields"] == []


def test_browser_actions_require_exact_operator_page_policy():
    from app.services.agent.scoped_assessment.browser_actions import allowed_operator_action

    assert allowed_operator_action("Check stock")
    assert allowed_operator_action("Subscribe")
    assert not allowed_operator_action("Delete product")
    manager = ASMToolsManager()
    manager.set_scoped_assessment_policy({"browser_action_paths": ["/catalog"]})
    assert manager._scoped_browser_action_paths == {"/catalog"}
    with pytest.raises(ValueError, match="Invalid body replay path"):
        manager.set_scoped_assessment_policy({"browser_action_paths": ["https://other.test/"]})


def test_hunter_and_verifier_can_call_built_in_proof_tools():
    from app.services.agent.fireteam_service import get_specialist

    assert "scoped_text_sqli" in get_specialist("sqli").allowed_tools
    assert "scoped_browser_assessment" in get_specialist("xss").allowed_tools
    verifier = get_specialist("independent_verifier")
    assert {"scoped_browser_assessment", "scoped_text_sqli", "scoped_numeric_sqli"}.issubset(
        set(verifier.allowed_tools)
    )


@pytest.mark.asyncio
async def test_denied_tool_action_does_not_request_approval_twice(monkeypatch):
    import app.services.agent.confirmation_service as confirmation

    calls = []

    async def requires_approval(name, args, org_id, session_id):
        calls.append((name, args))
        return {"decision": "confirm", "token": "denied-token", "tool_args": args}

    async def denied(token):
        return False

    monkeypatch.setattr(confirmation, "gate", requires_approval)
    monkeypatch.setattr(confirmation, "wait_for_decision", denied)
    manager = ASMToolsManager()
    args = {"operation": "inspect_js", "url": "https://app.example.test"}
    first = await manager._execute_impl("scoped_browser_assessment", args)
    second = await manager._execute_impl("scoped_browser_assessment", args)
    assert first["error"] == "confirmation_denied"
    assert second["error"] == "previous_confirmation_denied"
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_finding_triage_accepts_hypothesis_and_requires_real_evidence():
    manager = ASMToolsManager()
    result = json.loads(await manager.validate_finding(
        title="Reflected script execution", description="The search parameter may execute script",
        severity="medium", target="https://app.example.test/catalog",
        hypothesis_id="hyp-search",
    ))
    assert result["hypothesis_id"] == "hyp-search"
    assert result["verdict"] == "IMPROVE"
    assert result["has_evidence"] is False
    assert result["questions"][4]["pass"] is False
    assert "independent_verify" not in result["next_step"]


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
async def test_text_sqli_proof_uses_captured_string_and_new_nonce(monkeypatch):
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    register_scope(manager, "app.example.test")
    public, private = package_exchange(
        url="https://app.example.test/catalog?category=shoes",
        expected_origin="https://app.example.test", action_ref="navigate",
        method="GET", resource_type="fetch", status=200,
        content_type="text/html", request_body=b"", response_body=b"items",
    )
    manager._scoped_browser_exchanges = {
        "observed-category": {"identity": "anonymous", "private": private, "public": public}
    }

    def fake_probe(baseline, true_url, false_url, nonce, **kwargs):
        assert baseline == "https://app.example.test/catalog?category=shoes"
        assert "%27%20AND%20%27" in true_url and true_url != false_url
        assert kwargs["parameter"] == "category"
        return {"target": "https://app.example.test/catalog",
                "operation": "sqli_boolean_text", "proof_confirmed": True,
                "nonce": nonce, "parameter": "category"}

    monkeypatch.setattr(
        "app.services.agent.scoped_assessment_tools.sqli_boolean.probe_text_boolean", fake_probe,
    )
    result = json.loads(await manager.scoped_text_sqli("observed-category", "category"))
    assert result["proof_confirmed"] and result["finding"] is False
    assert result["source_artifact_id"] == "observed-category"
    with pytest.raises(ValueError, match="Unknown browser exchange"):
        await manager.scoped_text_sqli("invented", "category")


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
