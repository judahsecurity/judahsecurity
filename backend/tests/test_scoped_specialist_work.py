"""Browser captures, scripts, and APIs become bounded, durable specialist work."""

import json
from urllib.parse import parse_qs, urlsplit

import pytest

from app.services.agent.assessment_scope import register_scope
from app.services.agent.scoped_assessment.browser_traffic import package_exchange
from app.services.agent.api_fingerprint import fingerprint_from_map
from app.services.agent.coverage_cells import (
    claim_coverage_cell_leases, parameter_test_funnel,
    seed_js_coverage_cells, seed_parameter_coverage_cells,
)
from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.operation_directive import directives_from_hypotheses
from app.services.agent.runtime_mapper import ingest_capability_map_operations
from app.services.agent.tools import ASMToolsManager


def test_observed_api_enters_central_ledger_with_capture_and_names():
    cmap = {
        "target": "https://app.test/", "scope": "https://app.test",
        "api_endpoints": [
            {"method": "POST", "path": "/api/items", "host": "app.test",
             "source": "browser_traffic", "artifact_id": "capture-1",
             "status": 201, "content_type": "application/json"},
            {"method": "GET", "path": "/api/admin", "host": "evil.test",
             "source": "browser_traffic", "artifact_id": "capture-evil"},
        ],
        "parameter_inventory": [
            {"method": "POST", "path": "/api/items", "name": "title",
             "location": "body_json", "source": "browser_traffic",
             "artifact_id": "capture-1"},
        ],
    }
    brain = EngagementBrain(target="https://app.test")
    ingest_capability_map_operations(brain, cmap)
    ingest_capability_map_operations(brain, cmap)
    assert len(brain.application_operations) == 1
    row = brain.application_operations[0]
    assert row["parameters"] == ["body_json:title"]
    assert row["capture_ids"] == ["capture-1"]
    assert row["status"] == 201
    assert len([h for h in brain.hypotheses if h.operation_id == row["id"]]) == 1
    assert "capture-evil" not in repr(brain.to_dict())
    report = fingerprint_from_map(cmap)
    assert report["observed_api_metadata_count"] == 1


@pytest.mark.asyncio
async def test_api_ledger_has_paged_value_free_agent_tool():
    brain = EngagementBrain(target="https://app.test")
    for index in range(3):
        ingest_capability_map_operations(brain, {
            "target": "https://app.test", "scope": "https://app.test",
            "api_endpoints": [{"method": "GET", "host": "app.test",
                               "path": f"/api/{index}", "source": "browser_request"}],
        })
    manager = ASMToolsManager()
    manager._engagement_brain = brain.to_dict()
    assert callable(manager.get_tool("get_api_operation_inventory"))
    first = json.loads(await manager.get_api_operation_inventory(limit=2))
    second = json.loads(await manager.get_api_operation_inventory(offset=first["next_offset"], limit=2))
    assert first["total"] == 3
    assert len(first["operations"]) == 2 and len(second["operations"]) == 1
    assert all("body" not in row and "headers" not in row for row in first["operations"])


@pytest.mark.asyncio
async def test_js_lease_scans_exact_script_and_records_receipt(monkeypatch):
    cmap = {"target": "https://app.test/", "scope": "https://app.test",
            "js_files": ["https://app.test/static/a.js", "https://app.test/static/b.js"],
            "js_sources": [{"url": "https://app.test/static/a.js", "artifact_id": "script-a",
                            "sha256": "abc"}]}
    brain = EngagementBrain(target="https://app.test")
    seed_js_coverage_cells(brain, cmap)
    lease = claim_coverage_cell_leases(brain, ["js_secrets"])["js_secrets"]
    assigned = next(row for row in brain.coverage_cells if row["id"] == lease.coverage_cell_id)
    seen = []

    def fake_scan(url, max_urls, *, same_origin_only):
        seen.append((url, max_urls, same_origin_only))
        return {"success": True, "downloads": [{"url": url, "ok": True,
                                                    "truncated": False, "sha256": "abc"}],
                "gitleaks_error": None, "gitleaks_findings": [],
                "regex_hints": [], "client_signing_findings": []}

    monkeypatch.setattr("app.services.js_url_secrets_service.scan_js_urls_for_secrets", fake_scan)
    saved_reviews = []
    monkeypatch.setattr(
        "app.services.sitemap_service.persist_js_review_safe",
        lambda *args: saved_reviews.append(args) or True,
    )
    manager = ASMToolsManager()
    manager._capability_map = cmap
    manager._engagement_brain = brain.to_dict()
    result = json.loads(await manager.scan_assigned_js(lease.coverage_cell_id, lease.id))
    assert result["success"] and result["summary"]["status"] == "tested_clean"
    assert result["asset_review_saved"] is True
    assert saved_reviews[0][2] == assigned["script_url"]
    assert saved_reviews[0][3]["counts"] == {"gitleaks": 0, "regex": 0,
                                            "client_signing": 0}
    assert seen == [(assigned["script_url"], 1, True)]
    assert json.loads(await manager.scan_assigned_js(lease.coverage_cell_id, lease.id))["error"] == "invalid_coverage_lease"
    closed = manager._engagement_brain["coverage_cells"]
    assert next(row for row in closed if row["id"] == lease.coverage_cell_id)["evidence_ids"]
    assert len([row for row in closed if row["status"] == "untested"]) == 1


@pytest.mark.asyncio
async def test_js_scan_error_stays_inconclusive_and_cannot_close_other_cell(monkeypatch):
    cmap = {"target": "https://app.test", "scope": "https://app.test",
            "js_files": ["https://app.test/a.js", "https://app.test/b.js"]}
    brain = EngagementBrain(target="https://app.test")
    seed_js_coverage_cells(brain, cmap)
    lease = claim_coverage_cell_leases(brain, ["js_secrets"])["js_secrets"]
    monkeypatch.setattr(
        "app.services.js_url_secrets_service.scan_js_urls_for_secrets",
        lambda url, max_urls, *, same_origin_only: {
            "success": True, "downloads": [{"url": url, "ok": True, "truncated": False}],
            "gitleaks_error": "scanner unavailable", "gitleaks_findings": [],
            "regex_hints": [], "client_signing_findings": [],
        },
    )
    manager = ASMToolsManager()
    manager._capability_map = cmap
    manager._engagement_brain = brain.to_dict()
    result = json.loads(await manager.scan_assigned_js(lease.coverage_cell_id, lease.id))
    assert result["summary"]["status"] == "inconclusive"
    rows = manager._engagement_brain["coverage_cells"]
    assert next(row for row in rows if row["id"] == lease.coverage_cell_id)["status"] == "inconclusive"
    assert len([row for row in rows if row["status"] == "untested"]) == 1


@pytest.mark.asyncio
async def test_js_scan_changed_from_browser_capture_stays_inconclusive(monkeypatch):
    cmap = {"target": "https://app.test", "scope": "https://app.test",
            "js_files": ["https://app.test/app.js"],
            "js_sources": [{"url": "https://app.test/app.js", "sha256": "original"}]}
    brain = EngagementBrain(target="https://app.test")
    seed_js_coverage_cells(brain, cmap)
    lease = claim_coverage_cell_leases(brain, ["js_secrets"])["js_secrets"]
    monkeypatch.setattr(
        "app.services.js_url_secrets_service.scan_js_urls_for_secrets",
        lambda url, max_urls, *, same_origin_only: {
            "success": True, "downloads": [{"url": url, "ok": True,
                                            "truncated": False, "sha256": "changed"}],
            "gitleaks_error": None, "gitleaks_findings": [],
            "regex_hints": [], "client_signing_findings": [],
        },
    )
    manager = ASMToolsManager()
    manager._capability_map = cmap
    manager._engagement_brain = brain.to_dict()
    result = json.loads(await manager.scan_assigned_js(lease.coverage_cell_id, lease.id))
    assert result["summary"]["status"] == "inconclusive"
    assert result["summary"]["source_matched"] is False


@pytest.mark.asyncio
async def test_coverage_followup_leases_observed_client_script(monkeypatch):
    from app.services.agent.fireteam_service import FireteamResult, SpecialistReport

    target = "https://app.test"
    cmap = {"target": target, "scope": target,
            "js_files": [target + "/client.js"],
            "js_sources": [{"url": target + "/client.js",
                            "source_leads": [{"kind": "query", "line": 1}],
                            "client_leads": [{"kind": "dom_open_redirect", "line": 2}]}]}
    manager = ASMToolsManager()
    manager._capability_map = cmap
    manager._engagement_brain = EngagementBrain(target=target).to_dict()
    monkeypatch.setattr(manager, "_cheap_llm", lambda: object())
    leased = []

    async def fake_fireteam(
        *, mission, directives, specialists, member_timeout_sec,
        wave_timeout_sec, **_kwargs,
    ):
        assert wave_timeout_sec <= 150
        assert member_timeout_sec <= 140
        assert len(specialists) == 1
        assert specialists[0].name == "spa_client"
        assert specialists[0].max_iterations <= 4
        assert specialists[0].max_tools_per_iteration <= 3
        if not directives:
            return FireteamResult(mission=mission, specialists_run=[], reports=[])
        directive = directives["spa_client"]
        leased.append(directive.coverage_cell_id)
        assert directive.js_work["url"] == target + "/client.js"
        assert directive.js_work["test_type"] == "dom_open_redirect"
        assert directive.coverage_lease_id
        return FireteamResult(mission=mission, specialists_run=["spa_client"],
                              reports=[SpecialistReport(
                                  specialist="spa_client", role="Client", mission=mission,
                                  summary="Browser proof not available", verdict="inconclusive",
                              )])

    monkeypatch.setattr("app.services.agent.fireteam_service.run_fireteam", fake_fireteam)
    result = json.loads(await manager.fireteam_dispatch(
        mission="Review observed client lead", targets=[target],
        specialists=["spa_client"], mode="coverage_followup",
    ))
    assert leased
    assert result["coverage_leases"]["spa_client"]["coverage_cell_id"]
    assert any(row["test_type"] == "dom_open_redirect" and row["status"] == "inconclusive"
               for row in manager._engagement_brain["coverage_cells"])


@pytest.mark.asyncio
async def test_assigned_probe_uses_private_capture_and_cannot_change_input(monkeypatch):
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "path": "/api/search", "host": "app.test",
        "name": "q", "location": "query", "source": "browser_traffic",
        "identity": "anonymous", "artifact_id": "capture-q", "testable": True,
    }])
    lease = claim_coverage_cell_leases(brain, ["xss"])["xss"]
    manager = ASMToolsManager()
    manager._capability_map = {"target": "https://app.test", "scope": "https://app.test"}
    manager._engagement_brain = brain.to_dict()
    calls = []

    async def fake_operation(operation, body):
        calls.append((operation, body))
        return {"success": True, "service_artifact_ids": ["probe-1"],
                "probe_result": {"executed": False}}

    monkeypatch.setattr(manager, "_scoped_assessment_operation", fake_operation)
    rejected = await manager.scoped_assessment_probe_assigned(lease.coverage_cell_id, "wrong")
    assert rejected["error"] == "invalid_coverage_lease" and not calls
    result = await manager.scoped_assessment_probe_assigned(lease.coverage_cell_id, lease.id)
    assert result["assigned_operation"] == "http_query_probe"
    assert calls == [("http_query_probe", {"artifact_id": "capture-q",
                                           "parameter": "q", "identity": "anonymous"})]
    xss = await manager.scoped_assessment_probe_assigned(
        lease.coverage_cell_id, lease.id, "xss_browser")
    assert xss["assigned_operation"] == "browser_check_xss"
    assert "%3Cimg%20src%3Dx%20onerror%3Dalert" in calls[-1][1]["url_template"]
    assert "__PROWL_NONCE__" in calls[-1][1]["url_template"]
    assert calls[-1][1]["identity"] == "anonymous"
    js = await manager.scoped_assessment_probe_assigned(
        lease.coverage_cell_id, lease.id, "xss_browser_js_single")
    assert js["assigned_operation"] == "browser_check_xss"
    assert "%27%3Balert" in calls[-1][1]["url_template"]



@pytest.mark.asyncio
async def test_captured_xss_single_quote_alias_reaches_builtin_probe(monkeypatch):
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "path": "/catalog", "host": "app.test",
        "name": "searchTerm", "location": "query", "source": "browser_traffic",
        "identity": "anonymous", "artifact_id": "capture-q", "testable": True,
    }])
    lease = claim_coverage_cell_leases(brain, ["xss"])["xss"]
    manager = ASMToolsManager()
    manager._engagement_brain = brain.to_dict()
    manager._scoped_browser_exchanges = {
        "capture-q": {"identity": "anonymous", "private": b"{}", "public": {}},
    }

    async def fake_probe(coverage_cell_id, coverage_lease_id, technique):
        return {"success": True, "operation": "scoped_browser_check_xss",
                "technique": technique}

    monkeypatch.setattr(manager, "scoped_input_probe_assigned", fake_probe)
    result = await manager.scoped_assessment_probe_assigned(
        lease.coverage_cell_id, lease.id, "xss_browser_attribute_single",
    )
    assert result["technique"] == "html_attribute_single"
    assert result["assigned_operation"] == "scoped_browser_check_xss"


@pytest.mark.asyncio
@pytest.mark.parametrize("method,location,name,value_type,expected", [
    ("GET", "query", "id", "positive_integer", "http_sqli_boolean"),
    ("POST", "body_json", "/item/title", "string", "http_body_probe"),
])
async def test_assigned_sqli_selects_service_proof_shape(
    monkeypatch, method, location, name, value_type, expected,
):
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [{
        "method": method, "path": "/api/item", "host": "app.test",
        "name": name, "location": location, "value_type": value_type,
        "source": "browser_traffic", "identity": "tester",
        "artifact_id": "capture-item", "testable": True,
    }])
    lease = claim_coverage_cell_leases(brain, ["sqli"])["sqli"]
    manager = ASMToolsManager()
    manager._engagement_brain = brain.to_dict()
    calls = []

    async def fake_operation(operation, body):
        calls.append((operation, body))
        return {"success": True, "service_artifact_ids": ["probe-item"],
                "probe_result": {"proof_confirmed": operation == "http_sqli_boolean"}}

    monkeypatch.setattr(manager, "_scoped_assessment_operation", fake_operation)
    result = await manager.scoped_assessment_probe_assigned(lease.coverage_cell_id, lease.id)
    assert result["assigned_operation"] == expected
    assert calls == [(expected, {"artifact_id": "capture-item", "parameter": name,
                                "identity": "tester"})]
    cell = next(row for row in manager._engagement_brain["coverage_cells"]
                if row["id"] == lease.coverage_cell_id)
    assert cell["service_probe_artifact_ids"] == ["probe-item"]
    assert cell["status"] == ("in_focus" if expected == "http_sqli_boolean" else "leased")


@pytest.mark.asyncio
@pytest.mark.parametrize("method,location,name,value_type,operation,proof_result", [
    ("GET", "query", "id", "positive_integer", "scoped_numeric_sqli",
     {"proof_confirmed": True, "proof_recipe": "numeric_and_boolean_v1"}),
    ("GET", "query", "q", "string", "scoped_string_sqli",
     {"proof_confirmed": True, "proof_recipe": "string_or_boolean_v1"}),
    ("POST", "body_json", "/variables/term", "string", "scoped_body_probe",
     {"changed": True, "inconclusive": False}),
])
async def test_assigned_sqli_uses_builtin_private_capture(
    monkeypatch, method, location, name, value_type, operation, proof_result,
):
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [{
        "method": method, "path": "/graphql" if method == "POST" else "/items",
        "host": "app.test", "name": name, "location": location,
        "value_type": value_type, "source": "browser_traffic",
        "identity": "tester", "artifact_id": "capture-1", "testable": True,
    }])
    lease = claim_coverage_cell_leases(brain, ["sqli"])["sqli"]
    manager = ASMToolsManager()
    manager._engagement_brain = brain.to_dict()
    manager._capability_map = {"target": "https://app.test", "scope": "https://app.test"}
    manager._scoped_browser_exchanges = {
        "capture-1": {"identity": "tester",
                      "private": b'{"url":"https://app.test/items?q=seed"}', "public": {}},
    }

    async def fake_probe(*_args, **_kwargs):
        return json.dumps({"evidence_id": "local-proof", **proof_result})

    async def remote_forbidden(*_args, **_kwargs):
        raise AssertionError("Built-in Prowl must not call the optional service")

    monkeypatch.setattr(manager, operation, fake_probe)
    monkeypatch.setattr(manager, "_scoped_assessment_operation", remote_forbidden)
    result = await manager.scoped_assessment_probe_assigned(lease.coverage_cell_id, lease.id)
    assert result["success"] and result["operation"] == operation
    assert result["evidence_id"] == "local-proof"
    assert result["proof_confirmed"] is (method == "GET")
    cell = next(row for row in manager._engagement_brain["coverage_cells"]
                if row["id"] == lease.coverage_cell_id)
    assert cell["probe_artifact_ids"] == ["local-proof"]
    assert cell["status"] == ("in_focus" if method == "GET" else "leased")


@pytest.mark.asyncio
@pytest.mark.parametrize("executed", [False, True])
async def test_assigned_link_xss_probe_records_exact_cell_receipt(monkeypatch, executed):
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "path": "/catalog", "host": "app.test",
        "name": "searchTerm", "location": "query", "source": "browser_link",
        "identity": "anonymous", "testable": True,
    }])
    lease = claim_coverage_cell_leases(brain, ["xss"])["xss"]
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.test"
    manager._capability_map = {"target": "https://app.test"}
    manager._engagement_brain = brain.to_dict()
    register_scope(manager, "app.test")
    calls = []

    async def fake_browser(operation, url, identity="anonymous"):
        calls.append((operation, url, identity))
        return json.dumps({"evidence_id": "browser-proof", "executed": executed})

    monkeypatch.setattr(manager, "scoped_browser_assessment", fake_browser)
    assert (await manager.scoped_input_probe_assigned(lease.coverage_cell_id, "wrong"))["error"] == "invalid_coverage_lease"
    assert not calls
    result = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert result["success"] and result["proof_confirmed"] is executed
    assert calls[0][0] == "check_xss" and "searchTerm=" in calls[0][1]
    assert "__PROWL_NONCE__" in calls[0][1]
    cell = next(row for row in manager._engagement_brain["coverage_cells"]
                if row["id"] == lease.coverage_cell_id)
    assert cell["probe_artifact_ids"] == cell["evidence_ids"] == ["browser-proof"]
    assert cell["status"] == ("in_focus" if executed else "leased")
    assert parameter_test_funnel(manager._engagement_brain)["probed"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("technique,encoded_fragment", [
    ("xss_browser", "%3Cimg"),
    ("xss_browser_attribute", "%22%3E%3Cimg"),
    ("xss_browser_js_single", "%27%3Balert"),
    ("xss_browser_js_double", "%22%3Balert"),
])
async def test_assigned_get_xss_accepts_service_technique_aliases(
    monkeypatch, technique, encoded_fragment,
):
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "path": "/catalog", "host": "app.test",
        "name": "searchTerm", "location": "query", "source": "browser_link",
        "identity": "anonymous", "testable": True,
    }])
    lease = claim_coverage_cell_leases(brain, ["xss"])["xss"]
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.test"
    manager._capability_map = {"target": "https://app.test"}
    manager._engagement_brain = brain.to_dict()
    register_scope(manager, "app.test")
    calls = []

    async def fake_browser(operation, url, identity="anonymous"):
        calls.append((operation, url, identity))
        return json.dumps({"evidence_id": "browser-proof", "executed": False})

    monkeypatch.setattr(manager, "scoped_browser_assessment", fake_browser)
    result = await manager.scoped_input_probe_assigned(
        lease.coverage_cell_id, lease.id, technique,
    )
    assert result["success"] is True, result
    assert calls[0][0] == "check_xss"
    assert encoded_fragment in calls[0][1]


@pytest.mark.asyncio
async def test_assigned_xss_preserves_captured_get_query_context(monkeypatch):
    observed = "https://app.test/catalog?searchTerm=ordinary&view=compact"
    public, private = package_exchange(
        url=observed, expected_origin="https://app.test", action_ref="search",
        method="GET", resource_type="xhr", status=200,
        content_type="text/html", request_body=b"", response_body=b"ok",
    )
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "path": "/catalog", "host": "app.test",
        "name": "searchTerm", "location": "query", "source": "browser_traffic",
        "artifact_id": "capture-search", "identity": "anonymous", "testable": True,
    }])
    lease = claim_coverage_cell_leases(brain, ["xss"])["xss"]
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.test"
    manager._capability_map = {"target": "https://app.test"}
    manager._engagement_brain = brain.to_dict()
    manager._scoped_browser_exchanges = {
        "capture-search": {"identity": "anonymous", "private": private,
                           "public": public, "verifier_run_id": None},
    }
    register_scope(manager, "app.test")

    async def browser(operation, url, identity="anonymous"):
        query = parse_qs(urlsplit(url).query)
        assert query["view"] == ["compact"]
        assert "__PROWL_NONCE__" in query["searchTerm"][0]
        assert "ordinary" not in query["searchTerm"][0]
        return json.dumps({"evidence_id": "xss-proof", "executed": True})

    monkeypatch.setattr(manager, "scoped_browser_assessment", browser)
    result = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert result["proof_confirmed"] is True
    assert result["probe_result"]["request_context"] == "browser_traffic"


@pytest.mark.asyncio
async def test_assigned_xss_probe_preserves_scope_denial_for_queue_receipt(monkeypatch):
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "path": "/catalog", "host": "app.test",
        "name": "searchTerm", "location": "query", "source": "browser_link",
        "identity": "anonymous", "testable": True,
    }])
    lease = claim_coverage_cell_leases(brain, ["xss"])["xss"]
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.test"
    manager._capability_map = {"target": "https://app.test"}
    manager._engagement_brain = brain.to_dict()
    register_scope(manager, "app.test")

    async def denied_browser(*_args, **_kwargs):
        return json.dumps({"error": "assessment_scope_denied", "output": "Scope expired"})

    monkeypatch.setattr(manager, "scoped_browser_assessment", denied_browser)
    result = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert result["error"] == "assessment_scope_denied"
    assert result["output"] == "Scope expired"
    assert not any(cell.get("evidence_ids") for cell in manager._engagement_brain["coverage_cells"])


@pytest.mark.asyncio
async def test_assigned_input_reports_missing_registered_scope(monkeypatch):
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "path": "/catalog", "host": "app.test",
        "name": "searchTerm", "location": "query", "source": "browser_link",
        "identity": "anonymous", "testable": True,
    }])
    lease = claim_coverage_cell_leases(brain, ["xss"])["xss"]
    manager = ASMToolsManager()
    manager._capability_map = {"target": "https://app.test"}
    manager._engagement_brain = brain.to_dict()
    monkeypatch.setattr(manager, "_scoped_origin", lambda _url: (_ for _ in ()).throw(
        ValueError("No assessment network scope is registered")))
    result = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert result["error"] == "assessment_scope_denied"
    assert "scope" in result["output"]


@pytest.mark.asyncio
async def test_assigned_link_sqli_probe_records_proof_without_closing_sibling(monkeypatch):
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "path": "/catalog", "host": "app.test",
        "name": "category", "location": "query", "source": "browser_link",
        "identity": "anonymous", "testable": True,
    }])
    lease = claim_coverage_cell_leases(brain, ["sqli"])["sqli"]
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.test"
    manager._capability_map = {"target": "https://app.test"}
    manager._engagement_brain = brain.to_dict()
    register_scope(manager, "app.test")
    calls = []

    async def fake_sqli(url, parameter, identity):
        calls.append((url, parameter, identity))
        return json.dumps({"evidence_id": "sqli-proof", "proof_confirmed": True,
                           "requests_sent": 8, "baseline_source": "observed_parameter_preflight"})

    monkeypatch.setattr(manager, "scoped_string_sqli", fake_sqli)
    result = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert result["success"] and result["proof_confirmed"]
    assert calls == [("https://app.test/catalog", "category", "anonymous")]
    cells = manager._engagement_brain["coverage_cells"]
    sqli = next(row for row in cells if row["id"] == lease.coverage_cell_id)
    xss = next(row for row in cells if row["test_type"] == "xss")
    assert sqli["probe_artifact_ids"] == ["sqli-proof"]
    assert sqli["status"] == "in_focus" and xss["status"] == "untested"
    assert parameter_test_funnel(manager._engagement_brain)["probed"] == 1


@pytest.mark.asyncio
async def test_assigned_application_operation_input_reaches_sqli_probe(monkeypatch):
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "path": "/catalog", "host": "app.test",
        "name": "category", "location": "query", "source": "application_operation",
        "identity": "anonymous", "testable": True,
    }])
    lease = claim_coverage_cell_leases(brain, ["sqli"])["sqli"]
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.test"
    manager._capability_map = {"target": "https://app.test"}
    manager._engagement_brain = brain.to_dict()
    register_scope(manager, "app.test")
    calls = []

    async def fake_sqli(url, parameter, identity):
        calls.append((url, parameter, identity))
        return json.dumps({"evidence_id": "operation-proof", "proof_confirmed": False})

    monkeypatch.setattr(manager, "scoped_string_sqli", fake_sqli)
    result = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert result["success"] is True
    assert calls == [("https://app.test/catalog", "category", "anonymous")]


@pytest.mark.asyncio
async def test_assigned_application_operation_input_reaches_xss_probe(monkeypatch):
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "path": "/catalog", "host": "app.test",
        "name": "searchTerm", "location": "query", "source": "application_operation",
        "identity": "anonymous", "testable": True,
    }])
    lease = claim_coverage_cell_leases(brain, ["xss"])["xss"]
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.test"
    manager._capability_map = {"target": "https://app.test"}
    manager._engagement_brain = brain.to_dict()
    register_scope(manager, "app.test")
    calls = []

    async def fake_browser(operation, url, **kwargs):
        calls.append((operation, url, kwargs))
        return json.dumps({"evidence_id": "xss-proof", "executed": False})

    monkeypatch.setattr(manager, "scoped_browser_assessment", fake_browser)
    result = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert result["success"] is True
    assert calls[0][0] == "check_xss"
    assert calls[0][1].startswith("https://app.test/catalog?searchTerm=")


@pytest.mark.asyncio
async def test_assigned_probe_uses_current_origin_with_explicit_default_port(monkeypatch):
    brain = EngagementBrain(target="https://ginandjuice.shop:443")
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "path": "/catalog", "host": "ginandjuice.shop",
        "name": "category", "location": "query", "source": "browser_link",
        "identity": "anonymous", "testable": True,
    }])
    lease = claim_coverage_cell_leases(brain, ["sqli"])["sqli"]
    manager = ASMToolsManager()
    manager._fallback_target = "https://ginandjuice.shop:443"
    manager._capability_map = {"target": "https://ginandjuice.shop:443"}
    manager._engagement_brain = brain.to_dict()
    register_scope(manager, "ginandjuice.shop")
    calls = []

    async def fake_sqli(url, parameter, identity):
        calls.append((url, parameter, identity))
        return json.dumps({"evidence_id": "sqli-proof", "proof_confirmed": False})

    monkeypatch.setattr(manager, "scoped_string_sqli", fake_sqli)
    result = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert result["success"]
    assert calls == [("https://ginandjuice.shop/catalog", "category", "anonymous")]


@pytest.mark.asyncio
async def test_assigned_numeric_link_uses_numeric_proof(monkeypatch):
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "path": "/catalog", "host": "app.test",
        "name": "productId", "location": "query", "source": "browser_link",
        "value_type": "positive_integer", "identity": "anonymous", "testable": True,
    }])
    lease = claim_coverage_cell_leases(brain, ["sqli"])["sqli"]
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.test"
    manager._capability_map = {"target": "https://app.test"}
    manager._engagement_brain = brain.to_dict()
    register_scope(manager, "app.test")

    async def forbidden(*_args):
        pytest.fail("String SQLi proof must not run on a numeric input")

    async def numeric(*, parameter, identity, url):
        assert (parameter, identity, url) == (
            "productId", "anonymous", "https://app.test/catalog",
        )
        return json.dumps({"evidence_id": "numeric-proof", "proof_confirmed": True,
                           "proof_recipe": "numeric_and_boolean_v1"})

    monkeypatch.setattr(manager, "scoped_string_sqli", forbidden)
    monkeypatch.setattr(manager, "scoped_numeric_sqli", numeric)
    result = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert result["success"] and result["proof_confirmed"]
    assert result["operation"] == "scoped_numeric_sqli"
    assert parameter_test_funnel(manager._engagement_brain)["probed"] == 1


@pytest.mark.asyncio
async def test_numeric_link_without_public_value_type_still_uses_numeric_proof(monkeypatch):
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "path": "/catalog", "host": "app.test",
        "name": "productId", "location": "query", "source": "browser_link",
        "identity": "anonymous", "testable": True,
    }])
    lease = claim_coverage_cell_leases(brain, ["sqli"])["sqli"]
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.test"
    manager._capability_map = {
        "target": "https://app.test",
        "discovered_links": [{"url": "https://app.test/catalog",
                              "query_keys": ["productId"]}],
    }
    manager._scoped_link_baselines = {
        "anonymous": ["https://app.test/catalog?productId=7"],
    }
    manager._engagement_brain = brain.to_dict()
    register_scope(manager, "app.test")

    async def numeric(*, parameter, identity, url):
        return json.dumps({"evidence_id": "numeric-proof", "proof_confirmed": True,
                           "proof_recipe": "numeric_and_boolean_v1"})

    async def forbidden(*_args):
        pytest.fail("String SQLi proof must not run on a numeric observed link")

    monkeypatch.setattr(manager, "scoped_numeric_sqli", numeric)
    monkeypatch.setattr(manager, "scoped_string_sqli", forbidden)
    result = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert result["success"] and result["operation"] == "scoped_numeric_sqli"
