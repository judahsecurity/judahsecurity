"""Browser traffic remains useful when a later browser action fails."""

import json
from types import SimpleNamespace

import pytest

from app.services.agent.engagement_brain import engagement_brain_from_dict
from app.services.agent.evidence_store import evidence_store
from app.services.agent.runtime_mapper import normalize_request
from app.services.agent.tools import (
    ASMToolsManager,
    current_organization_id,
    current_session_id,
)
from app.services.browser_automation_service import _request_metadata


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
