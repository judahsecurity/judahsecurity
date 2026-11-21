"""Tool guard: regex block-list checked before any agent tool executes."""

import json

import pytest

from app.services.agent import tool_guard
from app.services.agent.tool_guard import (
    DEFAULT_RULES,
    ToolGuardConfigError,
    check_tool_call,
    compile_rules,
    evaluate,
)

DEFAULTS = compile_rules(DEFAULT_RULES)


@pytest.mark.parametrize("text", [
    "https://agency.gov/login",
    "-u https://portal.army.mil -json",
    "www.gov.uk",
    "service.gov.uk",
    "gov.cn",
    "*.gov",
    "AGENCY.GOV",
    "agency.gov.",
])
def test_default_rule_blocks_government_and_military_domains(text):
    decision = evaluate("execute_curl", {"args": text}, DEFAULTS)
    assert decision.blocked
    assert decision.rule == "government-domains"


@pytest.mark.parametrize("text", [
    "https://government.example.com",
    "https://govtech.io",
    "gov.uk.example.com",
    "https://example.com/gov",
    "nuclei -tags gov",
    "https://military-surplus.com",
    "https://app.test/?q=x.government",
])
def test_default_rule_ignores_lookalikes(text):
    assert not evaluate("execute_curl", {"args": text}, DEFAULTS).blocked


def test_nested_json_string_arguments_are_inspected():
    spec = json.dumps({"actions": [{"goto": {"url": "https://irs.gov/"}}]})
    decision = evaluate("execute_browser", {"args": spec}, DEFAULTS)
    assert decision.blocked
    assert decision.match == "irs.gov"


def test_percent_encoding_is_decoded_up_to_three_rounds():
    triple = "https://x.example/?next=https%25253A%25252F%25252Fagency%25252Egov"
    assert evaluate("execute_curl", {"args": triple}, DEFAULTS).blocked


def test_keys_are_inspected_too():
    assert evaluate("mcp_call", {"arguments": {"agency.gov": 1}}, DEFAULTS).blocked


def test_custom_rule_reminder_template_and_named_group():
    rules = compile_rules([{
        "name": "no-prod",
        "pattern": r"(?P<match>prod\.acme\.com)",
        "reminder": "{tool} hit {rule} on {match}",
    }])
    decision = evaluate("execute_nuclei", {"args": "-u https://prod.acme.com"}, rules)
    assert decision.message == "execute_nuclei hit no-prod on prod.acme.com"
    result = decision.to_result("execute_nuclei")
    assert result["blocked"] is True
    assert result["success"] is False
    assert result["error"] == "blocked_by_guard"


def test_disabled_rule_is_skipped_unless_testing():
    rules = compile_rules([{"name": "off", "pattern": "acme", "enabled": False}])
    assert not evaluate("execute_curl", {"args": "acme"}, rules).blocked
    assert evaluate("execute_curl", {"args": "acme"}, rules, ignore_enabled=True).blocked


@pytest.mark.parametrize("raw, message", [
    ([{"name": "bad", "pattern": "("}], "invalid pattern"),
    ([{"name": "empty", "pattern": ""}], "non-empty pattern"),
    ([{"pattern": "x" * 5000}], "exceeds"),
    ([{"pattern": "a"}] * 101, "at most"),
])
def test_rule_validation(raw, message):
    with pytest.raises(ToolGuardConfigError, match=message):
        compile_rules(raw)


def _configure(monkeypatch, **values):
    from app.core.config import settings

    for key, value in values.items():
        monkeypatch.setattr(settings, key, value, raising=False)
    monkeypatch.setattr(tool_guard, "_cache_key", None)


def test_invalid_custom_rules_keep_default_rule(monkeypatch):
    _configure(monkeypatch, AGENT_TOOL_GUARD_ENABLED=True,
               AGENT_TOOL_GUARD_DEFAULT_RULES=True, AGENT_TOOL_GUARD_RULES="[{\"pattern\": \"(\"}]")
    assert check_tool_call("execute_curl", {"args": "https://a.gov"}).blocked


def test_settings_switches(monkeypatch):
    _configure(monkeypatch, AGENT_TOOL_GUARD_ENABLED=True,
               AGENT_TOOL_GUARD_DEFAULT_RULES=False,
               AGENT_TOOL_GUARD_RULES=json.dumps([{"name": "acme", "pattern": "acme\\.com"}]))
    assert not check_tool_call("execute_curl", {"args": "https://a.gov"}).blocked
    assert check_tool_call("execute_curl", {"args": "https://acme.com"}).rule == "acme"

    _configure(monkeypatch, AGENT_TOOL_GUARD_ENABLED=False)
    assert not check_tool_call("execute_curl", {"args": "https://acme.com"}).blocked


def test_read_only_platform_queries_are_exempt(monkeypatch):
    _configure(monkeypatch, AGENT_TOOL_GUARD_ENABLED=True,
               AGENT_TOOL_GUARD_DEFAULT_RULES=True, AGENT_TOOL_GUARD_RULES="")
    assert not check_tool_call("query_assets", {"search": "agency.gov"}).blocked
    assert check_tool_call("execute_httpx", {"args": "-u agency.gov"}).blocked


@pytest.mark.asyncio
async def test_tool_manager_blocks_before_confirmation_and_execution(monkeypatch):
    from app.services.agent import action_ledger, confirmation_service
    from app.services.agent.tools import ASMToolsManager

    _configure(monkeypatch, AGENT_TOOL_GUARD_ENABLED=True,
               AGENT_TOOL_GUARD_DEFAULT_RULES=True, AGENT_TOOL_GUARD_RULES="")
    manager = ASMToolsManager()
    gate_calls, mcp_calls = [], []

    async def gate(*args, **kwargs):
        gate_calls.append(args)
        return {"decision": "auto"}

    class FakeMcp:
        async def call_tool(self, name, args):
            mcp_calls.append(name)
            return {"success": True, "output": "sent"}

    monkeypatch.setattr(confirmation_service, "gate", gate)
    monkeypatch.setattr(manager, "_get_mcp_server", lambda: FakeMcp())
    monkeypatch.setattr(action_ledger, "append_action", lambda *_a, **_k: None)

    result = await manager.execute("execute_httpx", {"args": "-u https://agency.gov -json"})

    assert result["blocked"] is True
    assert result["error"] == "blocked_by_guard"
    assert gate_calls == [] and mcp_calls == []
