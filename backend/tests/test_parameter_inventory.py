"""Discovered inputs must become exact, durable specialist work items."""

from types import SimpleNamespace

import pytest

from app.services.agent.capability_map import build_capability_map_from_dict
from app.services.agent.coverage_cells import (
    claim_coverage_cell_leases,
    release_coverage_cell_lease,
    seed_parameter_coverage_cells,
)
from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.operation_directive import directives_from_hypotheses
from app.services.agent.parameter_inventory import collect_parameter_inventory
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
    assert ("POST", "/comment", "form", "message") in keys
    assert ("GET", "/api/items", "query", "id") in keys
    assert ("POST", "/api/profile", "body_json", "user.display_name") in keys
    assert ("POST", "/api/order", "body_json", "/items/*/sku") in keys
    assert not any(r["name"] == "offscope" for r in rows)
    assert not next(r for r in rows if r["name"] == "csrf_token")["testable"]
    assert next(r for r in rows if r["name"] == "author_id")["testable"]
    assert "private-value" not in str(rows)
    assert "sensitive-value" not in str(rows)


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


def test_parameter_cells_are_leased_exactly_and_completed_cells_survive_reseed():
    brain = EngagementBrain(target="https://app.test")
    inventory = collect_parameter_inventory(_map())
    cells = seed_parameter_coverage_cells(brain, inventory)
    testable = [row for row in inventory if row["testable"]]
    assert len([c for c in cells if c["source"] == "parameter_inventory"]) == 2 * len(testable)
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
    assert next(c for c in brain.coverage_cells if c["id"] == closed_id)["status"] == "tested_clean"
    next_lease = claim_coverage_cell_leases(brain, ["xss"])["xss"]
    assert next_lease.coverage_cell_id != closed_id


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
