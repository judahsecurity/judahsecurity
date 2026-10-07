"""Autonomous mode must preserve analyst review for confirm-gated tools."""

import pytest
import time
import json

from app.models.project_settings import default_agent_config
from app.services.agent import confirmation_service as confirmation
from app.services.agent.pilot_policy import PilotPolicy, reset_pilot, set_pilot


def test_confirmation_preview_redacts_nested_browser_cookies():
    args = {"args": json.dumps({
        "actions": [{"action": "navigate", "url": "https://ginandjuice.shop/catalog"}],
        "storage_state": {"cookies": [{"name": "session", "value": "private-session-cookie"}]},
    })}
    preview = confirmation.preview_tool_args(args)
    assert "private-session-cookie" not in str(preview)
    assert "https://ginandjuice.shop/catalog" in str(preview)
    assert "REDACTED" in str(preview)


@pytest.mark.asyncio
async def test_autonomous_mode_waits_for_confirm_by_default(monkeypatch):
    policy = default_agent_config()
    monkeypatch.setattr(confirmation, "_load_policy", lambda _org_id: policy)
    monkeypatch.setattr(confirmation, "_roe_requires_confirmation", lambda _org_id: False)
    store = confirmation.ConfirmationStore()
    monkeypatch.setattr(confirmation, "get_store", lambda: store)
    token = confirmation.set_autonomous_mode(True)
    try:
        result = await confirmation.gate(
            "execute_sqlmap", {"args": "-u https://app.test/item?id=1"}, 7, "pilot"
        )
        assert result["decision"] == "confirm"
        assert result["tool_name"] == "execute_sqlmap"

        policy["agent_autonomous_auto_approve"] = True
        result = await confirmation.gate(
            "execute_sqlmap", {"args": "-u https://app.test/item?id=1"}, 7, "pilot"
        )
        assert result["decision"] == "auto"
    finally:
        confirmation._autonomous_mode.reset(token)


@pytest.mark.asyncio
async def test_pilot_network_tool_requires_analyst_even_with_auto_policy(monkeypatch):
    policy_config = default_agent_config()
    policy_config["agent_autonomous_auto_approve"] = True
    policy_config["tool_confirmation_policy"]["replay_http_request"] = "auto"
    monkeypatch.setattr(confirmation, "_load_policy", lambda _org_id: policy_config)
    monkeypatch.setattr(confirmation, "_roe_requires_confirmation", lambda _org_id: False)
    store = confirmation.ConfirmationStore()
    monkeypatch.setattr(confirmation, "get_store", lambda: store)
    pilot = PilotPolicy(
        target="https://app.test:443", source_ip="8.8.8.8",
        organization_id=7, session_id="pilot",
        expires_at_ms=int(time.time() * 1000) + 60_000,
    )
    pilot_token = set_pilot(pilot)
    mode_token = confirmation.set_autonomous_mode(True)
    try:
        result = await confirmation.gate(
            "replay_http_request", {"url": "https://app.test/"}, 7, "pilot",
        )
        assert result["decision"] == "confirm"
        port_result = await confirmation.gate(
            "probe_pilot_ports", {"protocol": "tcp", "ports": [80, 443]}, 7, "pilot",
        )
        assert port_result["decision"] == "confirm"
    finally:
        reset_pilot(pilot_token)
        confirmation._autonomous_mode.reset(mode_token)
