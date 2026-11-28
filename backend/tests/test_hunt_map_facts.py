"""The hunt plans beyond SQLi/XSS: map facts, spa_client, bare-scope origin, repeats.

On ginandjuice.shop the only confirmed finding was the catalog SQLi. The
planner could only build on first-pass signals (SQLi/XSS on GET inputs), the
hunt had no client-side specialist, and the JS dependency and assigned XSS
browser checks failed scope_mismatch because the crawl stores a bare-host scope.
"""

import asyncio
import json
import time

import pytest

from app.core.config import settings
from app.services.agent import tester_loop
from app.services.agent.capability_map import capability_map_origin
from app.services.agent.hunt_engine import facts_from_map, hunt_fact_signature

GJ_MAP = {
    "target": "https://ginandjuice.shop/", "scope": "ginandjuice.shop",
    "js_files": [
        "https://ginandjuice.shop/resources/js/angular_1-7-7.js",
        "https://ginandjuice.shop/resources/js/deparam.js",
        "https://ginandjuice.shop/resources/js/xmlStockCheckPayload.js",
    ],
    "forms": [{"method": "GET", "action": "/blog/", "inputs": ["search"], "page": "/blog/"},
              {"action": "", "method": "GET", "loose": True, "inputs": ["x"]}],
    "api_samples": [{"method": "POST", "url": "https://ginandjuice.shop/catalog/product/stock",
                     "headers": {"content-type": "application/xml"}},
                    {"method": "GET", "url": "https://ginandjuice.shop/catalog"}],
    "reflection_observations": [{"path": "/blog/", "parameter": "search", "reflected": True},
                                {"path": "/", "parameter": "email", "reflected": False}],
}


@pytest.mark.parametrize("cmap,expected", [
    ({"target": "https://ginandjuice.shop/", "scope": "ginandjuice.shop"}, "https://ginandjuice.shop"),
    ({"target": "http://127.0.0.1:8080/x", "scope": "127.0.0.1"}, "http://127.0.0.1:8080"),
    ({"target": "https://a.test/", "scope": "https://a.test"}, "https://a.test"),
    ({"target": "https://a.test/path?q=1"}, "https://a.test"),
    ({"scope": "a.test"}, "https://a.test"),
    ({"target": "https://a.test/", "scope": "a.test/evil"}, ""),
    ({}, ""),
])
def test_capability_map_origin_handles_the_bare_crawl_scope(cmap, expected):
    assert capability_map_origin(cmap) == expected


def test_js_dependency_review_accepts_a_bare_host_scope(monkeypatch):
    from app.services import retirejs_service
    from app.services.agent.tools import ASMToolsManager

    url = "https://ginandjuice.shop/resources/js/angular_1-7-7.js"
    manager = ASMToolsManager()
    manager._capability_map = {"target": "https://ginandjuice.shop/", "scope": "ginandjuice.shop"}
    manager._engagement_brain = {"coverage_cells": [{
        "id": "cell-js", "status": "leased", "lease_id": "lease-1",
        "lease_deadline": time.time() + 300, "source": "js_inventory",
        "specialist": "spa_client", "test_type": "js_dependency_review",
        "script_url": url, "path": "/resources/js/angular_1-7-7.js",
    }]}
    calls = []

    def fake_scan(target_url, limit, same_origin_only=True):
        calls.append(target_url)
        return {"success": True, "downloads": [{"url": target_url, "ok": False}]}

    monkeypatch.setattr(retirejs_service, "scan_js_urls_for_vulns", fake_scan)
    result = json.loads(asyncio.run(manager.scan_assigned_js_dependency("cell-js", "lease-1")))
    assert result.get("error") != "scope_mismatch"
    assert calls == [url]


def test_map_facts_name_libraries_forms_bodies_and_reflections():
    facts = {row["key"].split(":")[1]: row for row in facts_from_map(GJ_MAP)}
    summaries = [row["summary"] for row in facts_from_map(GJ_MAP)]
    assert any("angular 1.7.7" in s for s in summaries)
    assert any("deparam.js" in s and "xmlStockCheckPayload.js" in s for s in summaries)
    assert any("Form GET /blog/ with inputs [search]" == s for s in summaries)
    assert any("POST /catalog/product/stock with a application/xml body" in s
               and "XXE lead" in s for s in summaries)
    assert any("Input search on /blog/ is reflected" in s for s in summaries)
    # The loose pseudo-form, GET samples and unreflected inputs are not leads.
    assert not any("[x]" in s or "email" in s for s in summaries)
    assert all(row["confidence"] == "observed" and row["source"] == "map" for row in facts.values())


def test_map_leads_start_the_hunt_without_a_first_pass_signal(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_HUNT_ENGINE", True, raising=False)
    state = {"mode": "agent", "engagement_brain": {}, "capability_map": GJ_MAP}
    step = tester_loop._hunt_engine_step(state, [], "https://ginandjuice.shop/")
    assert step and step["tool_name"] == "run_hunt_engine"
    # A map with only unversioned script names is context, not a lead.
    bare = {"mode": "agent", "engagement_brain": {}, "capability_map": {
        "target": "https://x.test/", "js_files": ["https://x.test/app.js"]}}
    assert tester_loop._hunt_engine_step(bare, [], "https://x.test/") is None


def test_spa_client_is_a_default_hunt_specialist():
    assert "spa_client" in settings.AGENT_HUNT_SPECIALISTS.split(",")


def test_repeat_hunt_on_unchanged_facts_is_refused(monkeypatch):
    from app.services.agent import hunt_engine
    from app.services.agent.tools import ASMToolsManager

    monkeypatch.setattr(settings, "AGENT_HUNT_ENGINE", True, raising=False)
    runs = []

    async def fake_run(self):
        runs.append(1)
        return {"rounds": 1, "tasks": [], "by_status": {}, "rejected": [], "facts": [],
                "todo": [], "stop_reason": "planner_done", "elapsed_seconds": 0.1}

    monkeypatch.setattr(hunt_engine.HuntEngine, "run", fake_run)
    manager = ASMToolsManager()
    manager._fallback_target = "https://ginandjuice.shop/"
    manager._capability_map = dict(GJ_MAP)
    manager._engagement_brain = {"recon_observations": []}

    first = asyncio.run(manager.run_hunt_engine())
    assert first["success"] is True and len(runs) == 1
    marker = manager._engagement_brain["recon_observations"][-1]
    assert marker["kind"] == "hunt_engine"
    assert marker["signature"] == hunt_fact_signature(
        hunt_engine.facts_from_brain(manager._engagement_brain, manager._capability_map)
        + facts_from_map(manager._capability_map))

    again = asyncio.run(manager.run_hunt_engine())
    assert again["error"] == "hunt_already_ran_on_these_facts" and len(runs) == 1

    # A new candidate is a new fact: the hunt may run again.
    manager._engagement_brain["candidates"] = [{"id": "c9", "status": "pending",
                                                "vulnerability_class": "xss",
                                                "target": "https://ginandjuice.shop/blog/"}]
    third = asyncio.run(manager.run_hunt_engine())
    assert third["success"] is True and len(runs) == 2
