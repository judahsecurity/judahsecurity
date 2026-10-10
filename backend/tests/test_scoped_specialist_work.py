"""Browser captures, scripts, and APIs become bounded, durable specialist work."""

import json

import pytest

from app.services.agent.assessment_scope import register_scope
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
async def test_assigned_numeric_input_rejects_string_proof(monkeypatch):
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "path": "/catalog", "host": "app.test",
        "name": "productId", "location": "query", "source": "browser_link",
        "value_type": "positive_integer", "identity": "anonymous", "testable": True,
    }])
    lease = claim_coverage_cell_leases(brain, ["sqli"])["sqli"]
    manager = ASMToolsManager()
    manager._capability_map = {"target": "https://app.test"}
    manager._engagement_brain = brain.to_dict()

    async def forbidden(*_args):
        pytest.fail("String SQLi proof must not run on a numeric input")

    monkeypatch.setattr(manager, "scoped_string_sqli", forbidden)
    result = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert result["error"] == "numeric_capture_required"
    assert parameter_test_funnel(manager._engagement_brain)["probed"] == 0
