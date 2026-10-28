"""Discovered inputs must become exact, durable specialist work items."""

import base64
import json
from types import SimpleNamespace

import pytest
from app.services.agent.capability_map import build_capability_map_from_dict
from app.services.agent.coverage_cells import (
    claim_coverage_cell_leases,
    parameter_test_funnel,
    release_coverage_cell_lease,
    scoped_replay_eligible,
    seed_parameter_coverage_cells,
)
from app.services.agent.engagement_brain import (
    EngagementBrain,
    engagement_brain_from_dict,
)
from app.services.agent.observed_input_batch import pending_first_pass_cells
from app.services.agent.operation_directive import directives_from_hypotheses
from app.services.agent.parameter_inventory import collect_parameter_inventory
from app.services.agent.scoped_assessment.body_probe import plan_observed_body
from app.services.agent.scoped_assessment.browser_traffic import package_exchange
from app.services.agent.tester_loop import OBSERVED_INPUT_SOURCES, forced_next_step
from app.services.agent.tools import ASMToolsManager


def _map():
    return build_capability_map_from_dict({
        "target": "https://app.test/",
        "scope": "https://app.test",
        "pages_visited": ["https://app.test/search?q=private-value", "https://evil.test/?offscope=1"],
        "forms": [{
            "method": "POST", "action": "/comment",
            "fields": [{"name": "message", "control_type": "textarea"},
                       {"name": "csrf_token", "control_type": "hidden"}],
        }],
        "api_endpoints": [{"method": "GET", "path": "/api/items", "query_keys": ["id", "sort"]}],
        "api_samples": [{
            "method": "POST", "url": "https://app.test/api/profile?draft=1",
            "body": {"user": {"display_name": "sensitive-value"}, "author_id": 7},
        }],
        "parameter_inventory": [{
            "method": "POST", "path": "/api/order", "name": "/items/*/sku",
            "location": "body_json", "source": "browser_traffic", "artifact_id": "capture-1",
        }],
    }).to_dict()


def test_inventory_keeps_endpoint_location_and_drops_values_and_offscope_inputs():
    rows = collect_parameter_inventory(_map())
    keys = {(r["method"], r["path"], r["location"], r["name"]) for r in rows}
    assert ("GET", "/search", "query", "q") in keys
    assert ("POST", "/comment", "body_form", "message") in keys
    assert ("GET", "/api/items", "query", "id") in keys
    assert ("POST", "/api/profile", "body_json", "/user/display_name") in keys
    assert ("POST", "/api/order", "body_json", "/items/*/sku") in keys
    assert not any(r["name"] == "offscope" for r in rows)
    assert not next(r for r in rows if r["name"] == "csrf_token")["testable"]
    assert next(r for r in rows if r["name"] == "/author_id")["testable"]
    assert "private-value" not in str(rows)
    assert "sensitive-value" not in str(rows)


def test_observed_link_query_without_query_keys_becomes_numeric_test_work():
    cmap = {"target": "https://app.test", "discovered_links": [
        {"url": "https://app.test/items?productId=17&csrf_token=secret"},
        {"url": "https://outside.test/items?offscope=1"},
    ]}
    rows = collect_parameter_inventory(cmap)
    product = next(row for row in rows if row["name"] == "productId")
    assert product["value_type"] == "positive_integer"
    assert product["source"] == "browser_link"
    assert next(row for row in rows if row["name"] == "csrf_token")["testable"] is False
    assert not any(row["name"] == "offscope" for row in rows)
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, rows)
    assert any(cell["parameter"] == "query:productId" and cell["value_type"] == "positive_integer"
               for cell in pending_first_pass_cells(brain, target="https://app.test"))
    assert "secret" not in str(rows)


def test_captured_json_fields_use_replayable_pointers_including_arrays():
    body = {"filter": {"items": [{"sku": "ABC"}, {"sku": "DEF"}]},
            "user/name": "canary"}
    cmap = {"target": "https://app.test", "api_samples": [{
        "method": "POST", "url": "https://app.test/api/search",
        "body": body, "artifact_id": "capture-1", "identity": "user_a",
    }]}
    rows = collect_parameter_inventory(cmap)
    names = {row["name"] for row in rows}
    assert {"/filter/items/0/sku", "/filter/items/1/sku", "/user~1name"} <= names
    assert all(row["artifact_id"] == "capture-1" and row["identity"] == "user_a"
               for row in rows)
    captured = json.dumps({
        "method": "POST", "resource_type": "fetch", "url": "https://app.test/api/search",
        "request_content_type": "application/json",
        "request_body_base64": base64.b64encode(json.dumps(body).encode()).decode(),
    }).encode()
    for name in names:
        _, _, original, mutated = plan_observed_body(
            captured, parameter=name, allowed_origins=["https://app.test"],
        )
        assert original != mutated
    assert "ABC" not in str(rows) and "DEF" not in str(rows)


def test_browser_json_array_fields_keep_exact_replayable_indexes():
    body = json.dumps({"items": [{"name": "one"}, {"name": "two"}]}).encode()
    public, private = package_exchange(
        url="https://app.test/api/items", expected_origin="https://app.test",
        action_ref="items", method="POST", resource_type="fetch", status=200,
        content_type="application/json", request_content_type="application/json",
        request_body=body, response_body=b"{}",
    )
    paths = {field["path"] for field in public["body_fields"]}
    assert paths == {"/items/0/name", "/items/1/name"}
    assert all("*" not in path for path in paths)
    for path in paths:
        _, _, original, mutated = plan_observed_body(
            private, parameter=path, allowed_origins=["https://app.test"],
        )
        assert original != mutated


def test_captured_json_pointer_joins_private_browser_replay():
    cmap = {"target": "https://app.test", "api_samples": [{
        "method": "POST", "url": "https://app.test/api/profile",
        "body": {"user": {"display_name": "private-value"}},
        "artifact_id": "public-sample",
    }], "parameter_inventory": [{
        "method": "POST", "path": "/api/profile", "name": "/user/display_name",
        "location": "body_json", "source": "browser_traffic",
        "artifact_id": "private-capture",
    }]}
    rows = [row for row in collect_parameter_inventory(cmap)
            if row["name"] == "/user/display_name"]
    assert len(rows) == 1
    assert rows[0]["source"] == "browser_traffic"
    assert rows[0]["artifact_id"] == "private-capture"
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, rows)
    checks = [cell for cell in pending_first_pass_cells(brain, target="https://app.test")
              if cell["parameter"] == "body_json:/user/display_name"]
    assert len(checks) == 2
    assert all(scoped_replay_eligible(cell) for cell in checks)


@pytest.mark.asyncio
async def test_discover_parameters_hands_observed_inputs_to_injection_queue(monkeypatch):
    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, _url):
            return SimpleNamespace(
                url="https://app.test/catalog?category=&sort=private-value",
                status_code=200,
                text=(
                    '<form action="/search" method="GET"><input name="searchTerm"></form>'
                    '<form action="/comment" method="POST"><textarea name="message"></textarea>'
                    '<input name="csrf_token"></form>'
                    '<form action="https://evil.test/elsewhere" method="GET">'
                    '<input name="offscope"></form>'
                    '<script>const data = {"phantom": "guess"}</script>'
                ),
            )

    monkeypatch.setattr("app.services.agent.tools.httpx.AsyncClient", lambda **_kwargs: Client())
    manager = ASMToolsManager()
    manager._capability_map = {
        "target": "https://app.test", "scope": "https://app.test",
        "parameter_inventory": [{"method": "GET", "path": "/catalog",
                                 "name": "category", "location": "query",
                                 "source": "javascript_static"}],
    }
    manager._engagement_brain = EngagementBrain(target="https://app.test").to_dict()

    result = await manager._execute_impl("discover_parameters", {
        "url": "https://app.test/catalog?category=&sort=private-value",
    })
    assert result["success"] is True
    assert result["capability_map"] == manager._capability_map
    assert json.loads(result["output"])["queued_inputs"] >= 4
    rows = collect_parameter_inventory(manager._capability_map)
    keys = {(row["method"], row["path"], row["location"], row["name"]) for row in rows}
    assert {("GET", "/catalog", "query", "category"),
            ("GET", "/catalog", "query", "sort"),
            ("GET", "/search", "query", "searchTerm"),
            ("POST", "/comment", "body_form", "message")} <= keys
    assert next(row for row in rows if row["name"] == "category")["source"] == "page_url"
    assert next(row for row in rows if row["name"] == "csrf_token")["testable"] is False
    assert not any(row["name"] in {"offscope", "phantom"} for row in rows)
    assert "private-value" not in str(result["capability_map"])

    queued = pending_first_pass_cells(manager._engagement_brain, target="https://app.test")
    assert {cell["parameter"] for cell in queued if cell["path"] == "/catalog"} >= {
        "query:category", "query:sort",
    }
    state = {
        "mode": "agent", "assessment_resume": True,
        "target_info": {"primary_target": "https://app.test"},
        "capability_map": manager._capability_map,
        "engagement_brain": manager._engagement_brain,
        "execution_trace": [],
    }
    assert forced_next_step(state)["tool_name"] == "probe_observed_input_batch"
    leases = claim_coverage_cell_leases(
        engagement_brain_from_dict(manager._engagement_brain), ["sqli", "xss"],
        allowed_observation_sources=OBSERVED_INPUT_SOURCES,
        allowed_test_types=frozenset({"sqli", "xss"}),
    )
    assert set(leases) == {"sqli", "xss"}
    assert {lease.coverage_cell_id for lease in leases.values()} <= {
        cell["id"] for cell in queued
    }


@pytest.mark.asyncio
async def test_inventory_tool_pages_specialist_worklist():
    manager = ASMToolsManager()
    manager._capability_map = _map()
    assert callable(manager.get_tool("get_parameter_inventory"))
    import json

    first = json.loads(await manager.get_parameter_inventory(specialist="xss", limit=2))
    second = json.loads(await manager.get_parameter_inventory(specialist="xss", offset=first["next_offset"], limit=2))
    assert first["total"] > 2
    assert len(first["parameters"]) == 2
    assert len(second["parameters"]) == 2
    assert all(row["testable"] for row in first["parameters"] + second["parameters"])
    assert first["parameters"] != second["parameters"]


@pytest.mark.asyncio
async def test_inventory_tool_shows_exact_checks_and_unscheduled_work_without_values():
    manager = ASMToolsManager()
    manager._capability_map = _map()
    brain = EngagementBrain(target="https://app.test")
    inventory = collect_parameter_inventory(manager._capability_map)
    seed_parameter_coverage_cells(brain, inventory)
    manager._engagement_brain = brain.to_dict()

    import json

    result = json.loads(await manager.get_parameter_inventory())
    search = next(row for row in result["parameters"] if row["path"] == "/search")
    checks = {check["test_type"]: check for check in search["checks"]}
    assert {"sqli", "xss", "crlf"} <= checks.keys()
    assert all(check["status"] == "untested" and check["coverage_cell_id"]
               for check in checks.values())
    assert result["unscheduled_checks_on_page"] == 0
    protected = next(row for row in result["parameters"] if row["name"] == "csrf_token")
    assert protected["checks"] == []
    assert "private-value" not in str(result)
    assert "sensitive-value" not in str(result)

    brain.coverage_cells = [cell for cell in brain.coverage_cells
                            if cell["id"] != checks["sqli"]["coverage_cell_id"]]
    manager._engagement_brain = brain.to_dict()
    result = json.loads(await manager.get_parameter_inventory())
    search = next(row for row in result["parameters"] if row["path"] == "/search")
    sqli = next(check for check in search["checks"] if check["test_type"] == "sqli")
    assert sqli["status"] == "not_scheduled"
    assert sqli["coverage_cell_id"] is None
    assert result["unscheduled_checks_on_page"] == 1


@pytest.mark.asyncio
async def test_central_operation_inputs_join_class_queue_without_request_values():
    manager = ASMToolsManager()
    manager._engagement_brain = EngagementBrain(target="https://app.test").to_dict()
    manager._capability_map = {
        "target": "https://app.test", "scope": "https://app.test",
        "parameter_inventory": [{"method": "GET", "path": "/catalog",
                                 "name": "category", "location": "query",
                                 "source": "javascript_static"}],
    }
    before = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(before, collect_parameter_inventory(manager._capability_map))
    manager._engagement_brain = before.to_dict()
    import json

    await manager.map_application_traffic([
        {"method": "GET", "url": "https://app.test/catalog?category=private-value&csrf_token=secret"},
        {"method": "POST", "url": "https://app.test/api/search",
         "headers": {"Content-Type": "application/json"},
         "body": {"searchTerm": "sensitive-value"}},
        {"method": "GET", "url": "https://evil.test/catalog?offscope=1"},
    ])
    result = json.loads(await manager.get_parameter_inventory())
    rows = result["parameters"]
    category = next(row for row in rows if row["name"] == "category")
    assert category["source"] == "application_operation"
    assert {check["test_type"] for check in category["checks"]} >= {"sqli", "xss"}
    assert all(check["coverage_cell_id"] and check["status"] == "untested"
               for check in category["checks"])
    search = next(row for row in rows if row["name"] == "searchTerm")
    assert search["location"] == "body_json"
    assert {check["test_type"] for check in search["checks"]} >= {"sqli", "xss"}
    assert next(row for row in rows if row["name"] == "csrf_token")["checks"] == []
    assert not any(row["name"] == "offscope" for row in rows)
    assert result["unscheduled_checks_on_page"] == 0
    queued = pending_first_pass_cells(manager._engagement_brain, target="https://app.test")
    assert any(cell["path"] == "/catalog" and cell["parameter"] == "query:category"
               for cell in queued)
    assert "private-value" not in str(result)
    assert "sensitive-value" not in str(result)


def test_parameter_cells_are_leased_exactly_and_inconclusive_cells_survive_reseed():
    brain = EngagementBrain(target="https://app.test")
    inventory = collect_parameter_inventory(_map())
    cells = seed_parameter_coverage_cells(brain, inventory)
    testable = [row for row in inventory if row["testable"]]
    assert len([c for c in cells if c["source"] == "parameter_inventory"]) >= 2 * len(testable)
    assert any(c["test_type"] == "stored_xss" and c["path"] == "/comment" for c in cells)
    assert not any("csrf_token" in c["parameter"] for c in cells)

    leases = claim_coverage_cell_leases(brain, ["xss", "sqli"])
    assert leases["xss"].coverage_cell_id != leases["sqli"].coverage_cell_id
    profiles = {
        name: SimpleNamespace(role=f"{name} specialist.", allowed_tools=["get_parameter_inventory"], max_iterations=4)
        for name in ("xss", "sqli")
    }
    directives = directives_from_hypotheses(
        brain=brain, profiles_by_name=profiles, specialists=["xss", "sqli"],
        default_target="https://app.test", coverage_leases=leases,
    )
    for name in ("xss", "sqli"):
        directive = directives[name]
        assert directive.parameter_work["name"]
        assert directive.parameter_work["path"].startswith("/")
        assert "Assigned observed input" in directive.to_prompt_block()

    closed_id = leases["xss"].coverage_cell_id
    release_coverage_cell_lease(brain, leases["xss"], verdict="killed", evidence_ids=["http-evidence"])
    seed_parameter_coverage_cells(brain, inventory)
    assert next(c for c in brain.coverage_cells if c["id"] == closed_id)["status"] == "inconclusive"
    next_lease = claim_coverage_cell_leases(brain, ["xss"])["xss"]
    assert next_lease.coverage_cell_id != leases["sqli"].coverage_cell_id


def test_parameter_funnel_counts_probes_and_verdicts_separately():
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "host": "app.test", "path": "/catalog",
        "name": "category", "location": "query", "identity": "anonymous",
        "source": "browser_link", "testable": True,
    }])
    report = parameter_test_funnel(brain)
    assert report["inputs"] == 1
    assert report["checks"] == 3
    assert report["attempted"] == report["probed"] == 0
    sqli = next(row for row in brain.coverage_cells if row["test_type"] == "sqli")
    sqli.update(attempts=1, status="in_focus", service_probe_artifact_ids=["probe-1"])
    brain.candidates = [{"id": "candidate-1", "coverage_cell_id": sqli["id"],
                         "status": "confirmed", "evidence_ids": ["proof-1"],
                         "finding_id": "finding-1"}]
    report = parameter_test_funnel(brain)
    assert report["attempted"] == report["probed"] == 1
    assert report["candidates"] == report["verified"] == report["published"] == 1
    assert report["open"] == 3


def test_specialist_lease_prioritizes_likely_input_but_keeps_other_inputs_open():
    brain = EngagementBrain(target="https://app.test")
    inventory = [
        {"method": "GET", "host": "app.test", "path": "/api", "location": "query",
         "name": "zzz", "identity": "anonymous", "source": "api_endpoint", "testable": True},
        {"method": "GET", "host": "app.test", "path": "/api", "location": "query",
         "name": "q", "identity": "anonymous", "source": "observed_form", "testable": True},
    ]
    seed_parameter_coverage_cells(brain, inventory)
    lease = claim_coverage_cell_leases(brain, ["xss"])["xss"]
    assigned = next(cell for cell in brain.coverage_cells if cell["id"] == lease.coverage_cell_id)
    assert assigned["parameter"] == "query:q"
    assert any(cell["parameter"] == "query:zzz" and cell["status"] == "untested"
               for cell in brain.coverage_cells if cell["test_type"] == "xss")


def test_likely_input_is_leased_before_unrelated_browser_capture():
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [
        {"method": "GET", "host": "app.test", "path": "/catalog",
         "location": "query", "name": "searchTerm", "identity": "anonymous",
         "source": "observed_form", "testable": True},
        {"method": "GET", "host": "app.test", "path": "/catalog/product",
         "location": "query", "name": "productId", "identity": "anonymous",
         "source": "browser_traffic", "artifact_id": "private-capture",
         "testable": True},
    ])
    leases = claim_coverage_cell_leases(brain, ["xss", "sqli"])
    for name, lease in leases.items():
        cell = next(row for row in brain.coverage_cells if row["id"] == lease.coverage_cell_id)
        assert cell["specialist"] == name
        assert cell["path"] == "/catalog"
        assert cell["parameter"] == "query:searchTerm"


def test_nonprivate_capture_does_not_advertise_scoped_probe():
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [
        {"method": "GET", "host": "app.test", "path": "/catalog",
         "location": "query", "name": "searchTerm", "identity": "anonymous",
         "source": "captured_api", "artifact_id": "public-evidence",
         "testable": True},
    ])
    lease = claim_coverage_cell_leases(brain, ["xss"])["xss"]
    profiles = {"xss": SimpleNamespace(
        role="XSS specialist.",
        allowed_tools=["scoped_assessment_probe_assigned", "compare_requests"],
        max_iterations=4,
    )}
    directive = directives_from_hypotheses(
        brain=brain, profiles_by_name=profiles, specialists=["xss"],
        default_target="https://app.test", coverage_leases={"xss": lease},
    )["xss"]
    assert directive.parameter_work["capture_id"] == "public-evidence"
    assert not directive.parameter_work["scoped_capture_id"]
    assert "scoped_assessment_probe_assigned" not in directive.allowed_tools
    assert "No PROWL private browser capture" in directive.to_prompt_block()


def test_early_wave_leases_only_browser_observed_inputs():
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [
        {"method": "GET", "host": "app.test", "path": "/static-lead",
         "location": "query", "name": "search", "identity": "anonymous",
         "source": "javascript_static", "testable": True},
        {"method": "POST", "host": "app.test", "path": "/catalog/subscribe",
         "location": "form", "name": "email", "identity": "anonymous",
         "source": "observed_form", "testable": True},
    ])
    leases = claim_coverage_cell_leases(
        brain, ["xss", "sqli"],
        allowed_observation_sources=frozenset({"observed_form"}),
    )
    assert set(leases) == {"xss", "sqli"}
    for lease in leases.values():
        cell = next(row for row in brain.coverage_cells if row["id"] == lease.coverage_cell_id)
        assert cell["path"] == "/catalog/subscribe"
        assert cell["observation_source"] == "observed_form"
