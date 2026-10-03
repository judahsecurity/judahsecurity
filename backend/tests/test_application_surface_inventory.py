"""Browser action attribution and input discovery in the existing Aegis crawl."""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.services.agent.capability_map import build_capability_map_from_crawl, merge_capability_maps
from app.services.deep_crawl_service import CrawlResult, run_deep_crawl


def test_inventory_separates_live_requests_from_javascript_leads():
    crawl = CrawlResult(target="https://app.example.test/", scope="example.test")
    crawl.api_samples = [
        {
            "method": "GET",
            "url": "https://app.example.test/api/items?id=7&token=do-not-echo",
            "action_ref": "action-2",
            "headers": {},
        },
        {
            "method": "POST",
            "url": "https://app.example.test/api/search",
            "headers": {"content-type": "application/json"},
            "body": '{"filter":{"name":"private-value","items":[{"id":3}]}}',
            "action_ref": "action-3",
        },
        {"method": "GET", "url": "https://outside.test/api/items?id=9"},
    ]
    crawl.endpoints_from_js = {"/api/js-only?cursor=private-value"}
    crawl.js_endpoint_sources = {
        "/api/js-only?cursor=private-value": {"https://app.example.test/assets/lazy.js"}
    }
    cmap = build_capability_map_from_crawl(crawl)
    inventory = cmap.surface_inventory
    by_path = {row["path"]: row for row in inventory["endpoints"]}
    assert by_path["/api/items"]["sources"] == ["live_browser"]
    assert by_path["/api/items"]["action_refs"] == ["action-2"]
    assert by_path["/api/js-only"]["sources"] == ["javascript_static"]
    assert by_path["/api/js-only"]["source_refs"] == ["/assets/lazy.js"]
    assert "/api/search" in by_path
    assert all("outside" not in row["path"] for row in inventory["endpoints"])
    params = {(p["path"], p["location"], p["name"]): p for p in inventory["parameters"]}
    assert params[("/api/items", "query", "id")]["value_types"] == ["positive_integer"]
    assert params[("/api/search", "json", "/filter/name")]["value_types"] == ["string"]
    assert params[("/api/search", "json", "/filter/items/*/id")]["value_types"] == ["number"]
    assert not inventory["test_suggestions"]  # token in the same query blocks automatic suggestions
    assert inventory["finding"] is False
    encoded = json.dumps(inventory)
    assert "do-not-echo" not in encoded
    assert "private-value" not in encoded


def test_only_observed_safe_get_inputs_receive_review_suggestions():
    crawl = CrawlResult(target="https://app.example.test/", scope="example.test")
    crawl.api_samples = [
        {"method": "GET", "url": "https://app.example.test/api/items?id=7",
         "action_ref": "action-1"},
        {"method": "GET", "url": "https://app.example.test/api/delete?id=8",
         "action_ref": "action-2"},
    ]
    crawl.endpoints_from_js = {"/api/untested?id=9"}
    inventory = build_capability_map_from_crawl(crawl).surface_inventory
    assert inventory["test_suggestions"] == [{
        "kind": "numeric_boolean_review", "path": "/api/items", "method": "GET",
        "parameter": "id", "action_ref": "action-1", "priority": 1,
        "requires_fresh_proof": True, "finding": False,
    }]


def test_separate_crawls_keep_distinct_action_refs_and_inventory():
    first = CrawlResult(target="https://app.example.test/", scope="example.test")
    first.api_samples = [{"method": "GET", "url": "https://app.example.test/api/a?id=1",
                          "action_ref": "run-a-action-1"}]
    second = CrawlResult(target=first.target, scope=first.scope)
    second.api_samples = [{"method": "GET", "url": "https://app.example.test/api/b?id=2",
                           "action_ref": "run-b-action-1"}]
    merged = merge_capability_maps(build_capability_map_from_crawl(first).to_dict(),
                                   build_capability_map_from_crawl(second))
    inventory = merged["surface_inventory"]
    assert {row["path"] for row in inventory["endpoints"]} == {"/api/a", "/api/b"}
    assert {row["action_refs"][0] for row in inventory["endpoints"]} == {
        "run-a-action-1", "run-b-action-1"
    }
    assert inventory["finding"] is False


@pytest.mark.asyncio
@pytest.mark.skipif(os.environ.get("RUN_ASSESSMENT_BROWSER_TESTS") != "1",
                    reason="Opt-in local Chromium fixture")
async def test_nested_browser_controls_attribute_request_and_lazy_javascript(monkeypatch):
    from playwright.async_api import BrowserType

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path == "/":
                body = b"""<html><body><button id='tab'>Details</button><section id='panel'></section>
                <script>document.querySelector('#tab').onclick = () => {
                  document.querySelector('#panel').innerHTML = '<button id="load">Show items</button>';
                  document.querySelector('#load').onclick = () => {
                    fetch('/api/items?id=7');
                    const s = document.createElement('script'); s.src='/lazy.js';
                    document.head.appendChild(s);
                  };
                };</script></body></html>"""
                mime = "text/html"
            elif self.path == "/lazy.js":
                body = b"const route = '/api/from-lazy';"
                mime = "application/javascript"
            else:
                body = b'{"ok":true}'
                mime = "application/json"
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    executable = os.environ.get("ASSESSMENT_TEST_CHROMIUM")
    if executable:
        original = BrowserType.launch

        async def launch(self, **kwargs):
            return await original(self, **dict(kwargs, executable_path=executable))

        monkeypatch.setattr(BrowserType, "launch", launch)
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        result = await run_deep_crawl({"url": base, "allowed_origin": base,
                                       "max_pages": 1, "interact": True,
                                       "capture_js": True, "budget_sec": 60})
        assert result["success"], result
        cmap = result["capability_map"]
        actions = cmap["action_checkpoints"]
        details = next(row for row in actions if row["kind"] == "click" and row["label"] == "Details")
        nested = next(row for row in actions if row["kind"] == "click" and row["label"] == "Show items")
        assert details["status"] == nested["status"] == "completed"
        assert nested["request_count"] >= 1
        assert nested["scripts_added"] >= 1
        inventory = cmap["surface_inventory"]
        live = next(row for row in inventory["endpoints"] if row["path"] == "/api/items")
        assert nested["ref"] in live["action_refs"]
        js = next(row for row in inventory["endpoints"] if row["path"] == "/api/from-lazy")
        assert js["sources"] == ["javascript_static"]
        assert "/lazy.js" in js["source_refs"]
        assert inventory["finding"] is False
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
