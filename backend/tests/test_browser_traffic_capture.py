"""Browser traffic remains useful when a later browser action fails."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.services.agent.engagement_brain import engagement_brain_from_dict
from app.services.agent.evidence_store import evidence_store
from app.services.agent.runtime_mapper import normalize_request
from app.services.agent.tools import (
    ASMToolsManager,
    current_organization_id,
    current_session_id,
)
from app.services.agent.pilot_policy import PilotPolicy, reset_pilot, set_pilot
from app.services.browser_automation_service import (
    BrowserSessionResult, _execute_action, _page_surface_summary, _request_metadata,
)
import time


def test_page_surface_summary_keeps_same_origin_paths_and_form_names_without_values():
    html = """
    <a href="/catalog?category=juice">Catalog</a>
    <a href="https://outside.test/leave?token=secret">External</a>
    <form action="/search" method="GET"><input name="q" value="private"></form>
    <form action="/checkout" method="POST"><input name="card" value="secret"></form>
    """
    links, forms = _page_surface_summary(html, "https://app.test/")
    assert links == ["/catalog [query keys: category]"]
    assert forms == [
        {"method": "GET", "path": "/search", "input_names": ["q"]},
        {"method": "POST", "path": "/checkout", "input_names": ["card"]},
    ]
    assert "private" not in json.dumps([links, forms])
    assert "secret" not in json.dumps([links, forms])


def test_page_surface_summary_handles_failed_navigation():
    assert _page_surface_summary("<a href='/catalog'>Catalog</a>", "about:blank") == ([], [])


def test_request_metadata_keeps_method_parameter_names_and_status_slot_without_values():
    request = SimpleNamespace(
        method="POST",
        url="https://app.test/catalog/subscribe?email=private%40example.test&source=footer",
        resource_type="fetch",
    )
    row = _request_metadata(request, "https://app.test/")
    assert row == {
        "method": "POST",
        "url": "https://app.test/catalog/subscribe",
        "query_keys": ["email", "source"],
        "resource_type": "fetch",
        "in_scope": True,
    }
    assert "private" not in json.dumps(row)
    assert _request_metadata(
        SimpleNamespace(method="GET", url="https://outside.test/p", resource_type="script"),
        "https://app.test/",
    )["in_scope"] is False


@pytest.mark.parametrize("tool_name", ["execute_browser", "execute_deep_crawl"])
@pytest.mark.asyncio
async def test_failed_browser_action_still_records_in_scope_traffic(monkeypatch, tool_name):
    org = current_organization_id.set(98765)
    session = current_session_id.set("browser-traffic-regression")
    try:
        manager = ASMToolsManager()
        manager._assessment_scope.add("app.test")
        manager._fallback_target = "https://app.test/"

        class FakeMCP:
            async def call_tool(self, _name, _args):
                return {
                    "success": False,
                    "output": "Later browser action failed",
                    "error": "action_failed",
                    "network_requests": [{
                        "method": "POST", "url": "https://app.test/catalog/subscribe",
                        "query_keys": ["email"], "resource_type": "fetch",
                        "in_scope": True, "status": 400,
                    }],
                    "network_requests_total": 1,
                    "network_requests_dropped": 0,
                    "application_operations": [
                        *normalize_request({
                            "method": "POST",
                            "url": "https://app.test/catalog/subscribe?email=private%40example.test",
                            "headers": {"content-type": "application/x-www-form-urlencoded"},
                            "body": "email=private%40example.test",
                        }, source="browser"),
                        *normalize_request({
                            "method": "GET", "url": "https://outside.test/secret?token=private",
                        }, source="browser"),
                    ],
                }

        async def allow(*_args, **_kwargs):
            return {"decision": "allow"}

        monkeypatch.setattr(manager, "_get_mcp_server", lambda: FakeMCP())
        monkeypatch.setattr("app.services.agent.confirmation_service.gate", allow)
        monkeypatch.setattr(
            "app.services.agent.confirmation_service.autonomous_mode_enabled",
            lambda: True,
        )
        spec = ({"actions": [
            {"action": "navigate", "url": "https://app.test/catalog/subscribe"},
        ]} if tool_name == "execute_browser" else {"url": "https://app.test/"})
        result = await manager._execute_impl(tool_name, {"args": json.dumps(spec)})
        assert result["success"] is False
        assert result["evidence_ids"]
        assert any(
            row["path"] == "/catalog/subscribe"
            and row["name"] == "email"
            and row["location"] == "query"
            for row in result["capability_map"]["parameter_inventory"]
        )
        traffic = evidence_store(manager).records[result["evidence_ids"][0]]["payload"]
        assert traffic["requests"][0]["status"] == 400
        assert traffic["requests"][0]["query_keys"] == ["email"]
        operations = engagement_brain_from_dict(manager._engagement_brain).application_operations
        assert [(op["method"], op["path"]) for op in operations] == [
            ("POST", "/catalog/subscribe"),
        ]
        assert operations[0]["parameters"] == ["body:email", "query:email"]
        assert operations[0]["request_content_type"] == "application/x-www-form-urlencoded"
        brain = engagement_brain_from_dict(manager._engagement_brain)
        specialist_work = {(cell["parameter"], cell["test_type"])
                           for cell in brain.coverage_cells
                           if cell.get("source") == "parameter_inventory"}
        assert ("query:email", "sqli") in specialist_work
        assert ("query:email", "xss") in specialist_work
        assert ("body_form:email", "sqli") in specialist_work
        assert ("body_form:email", "xss") in specialist_work
    finally:
        current_session_id.reset(session)
        current_organization_id.reset(org)


@pytest.mark.asyncio
async def test_pilot_failed_browser_keeps_private_original_for_one_field_replay(monkeypatch):
    policy = PilotPolicy(
        target="https://ginandjuice.shop:443", source_ip="8.8.8.8",
        organization_id=1, session_id="pilot-capture",
        expires_at_ms=int(time.time() * 1000) + 60_000, web_only=True,
    )
    pilot_token = set_pilot(policy)
    org_token = current_organization_id.set(1)
    session_token = current_session_id.set("pilot-capture")
    try:
        manager = ASMToolsManager()
        manager._assessment_scope.add("ginandjuice.shop")
        manager._fallback_target = policy.target

        async def fake_browser(_args, *, capture_callback=None, capture_non_2xx=False):
            assert capture_non_2xx is True
            for method, url in (
                ("GET", "https://ginandjuice.shop/catalog?q=juice&sort=popular"),
                ("GET", "https://ginandjuice.shop/catalog?q=juice&sort=popular"),
                ("POST", "https://ginandjuice.shop/subscribe"),
                ("GET", "https://outside.test/"),
            ):
                capture_callback({"method": method, "url": url,
                                  "headers": {"accept": "text/html", "cookie": "session=private"}})
            return {
                    "success": False, "output": "DOMContentLoaded timed out",
                    "error": "navigation_timeout",
                    "network_requests": [{
                        "method": "GET", "url": "https://ginandjuice.shop/catalog",
                        "query_keys": ["q", "sort"], "resource_type": "document",
                        "in_scope": True, "status": 200,
                    }],
                }

        async def allow(*_args, **_kwargs):
            return {"decision": "allow"}

        monkeypatch.setattr(
            "app.services.browser_automation_service.execute_browser_actions",
            fake_browser,
        )
        monkeypatch.setattr("app.services.agent.confirmation_service.gate", allow)
        result = await manager._execute_impl("execute_browser", {"args": json.dumps({
            "actions": [{"action": "navigate", "url": "https://ginandjuice.shop/catalog"},
                        {"action": "get_source"}],
        })})
        assert result["success"] is False
        assert "q=juice" not in json.dumps(result)
        listed = json.loads(await manager.list_captured_requests())
        assert listed["count"] == 1
        sample = listed["samples"][0]
        assert sample["fields"] == ["q", "sort"]
        assert sample["url"] == "https://ginandjuice.shop/catalog"
        assert "q=juice" not in json.dumps(listed)
        assert "session=private" not in json.dumps(listed)

        sent = {}
        async def compare_requests(**kwargs):
            sent.update(kwargs)
            return json.dumps({"baseline": {"url": kwargs["baseline"]["url"]},
                               "mutant": {"url": kwargs["mutant"]["url"]}})

        monkeypatch.setattr(manager, "compare_requests", compare_requests)
        compared = json.loads(await manager.mutate_captured_request(
            sample_ref=sample["sample_ref"], location="query", field="q",
            value="control", use_auth_session=False,
        ))
        assert compared["baseline"]["url"].endswith("q=juice&sort=popular")
        assert compared["mutant"]["url"].endswith("q=control&sort=popular")
        assert sent["baseline"]["headers"]["Cookie"] == "session=private"
        assert sent["mutant"]["headers"]["Cookie"] == "session=private"
        assert sent["use_auth_session"] is False
    finally:
        reset_pilot(pilot_token)
        current_session_id.reset(session_token)
        current_organization_id.reset(org_token)


@pytest.mark.asyncio
async def test_navigation_timeout_with_loaded_document_is_partial_observation(monkeypatch):
    import sys

    class PlaywrightTimeoutError(Exception):
        pass

    monkeypatch.setitem(sys.modules, "playwright.async_api", SimpleNamespace(
        TimeoutError=PlaywrightTimeoutError,
    ))

    page = SimpleNamespace(
        url="https://ginandjuice.shop/catalog",
        goto=AsyncMock(side_effect=PlaywrightTimeoutError("DOMContentLoaded timed out")),
        content=AsyncMock(return_value="<html><body>" + "catalog " * 40 + "</body></html>"),
    )
    result = await _execute_action(
        page, None, "navigate", {"url": page.url},
        BrowserSessionResult(success=True, actions_executed=0),
    )
    assert result.success is True
    assert result.data["partial"] is True
    assert result.data["status"] is None
    page.url = "about:blank"
    with pytest.raises(PlaywrightTimeoutError):
        await _execute_action(
            page, None, "navigate", {"url": "https://ginandjuice.shop/catalog"},
            BrowserSessionResult(success=True, actions_executed=0),
        )
