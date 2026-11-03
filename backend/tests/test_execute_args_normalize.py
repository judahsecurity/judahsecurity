"""Tests for execute_* tool arg normalization (Ollama-friendly)."""

import pytest

from app.services.agent.tools import (
    extract_seed_target,
    normalize_execute_tool_args,
    _default_args_for_tool,
)


def test_extract_seed_target_from_objective():
    text = "perform a webapplication assessment of https://www.emulate3d.com/ we are trying to find vulns"
    assert extract_seed_target(text) == "https://www.emulate3d.com/"


def test_normalize_empty_httpx_uses_fallback():
    out = normalize_execute_tool_args(
        "execute_httpx",
        {},
        fallback_target="https://www.emulate3d.com/",
    )
    assert "args" in out
    assert "-u https://www.emulate3d.com/" in out["args"]
    assert "-json" in out["args"]


def test_normalize_url_key_to_args():
    out = normalize_execute_tool_args(
        "execute_httpx",
        {"url": "https://www.emulate3d.com"},
    )
    assert out["args"].startswith("-u https://www.emulate3d.com")


def test_normalize_preserves_good_args():
    out = normalize_execute_tool_args(
        "execute_httpx",
        {"args": "-u https://x.com -json"},
        fallback_target="https://ignored.com",
    )
    assert out["args"] == "-u https://x.com -json"


def test_normalize_ignores_internal_keys_and_fills():
    out = normalize_execute_tool_args(
        "execute_httpx",
        {"_target_info": {"primary_target": "https://a.com"}, "_current_phase": "informational"},
        fallback_target="https://www.emulate3d.com/",
    )
    assert "-u https://www.emulate3d.com/" in out["args"]


def test_default_args_httpx():
    assert "-u https://t.com" in _default_args_for_tool("execute_httpx", "https://t.com")


@pytest.mark.asyncio
async def test_identical_curl_contract_error_is_not_reexecuted(monkeypatch):
    from app.services.agent import action_ledger
    from app.services.agent.tools import ASMToolsManager

    manager = ASMToolsManager()
    calls = []

    async def rejected(_name, _args):
        calls.append(1)
        return {"success": False,
                "error": "Censor rejected execute_curl.args: unsupported curl argument '-D-'"}

    monkeypatch.setattr(manager, "_execute_recorded", rejected)
    monkeypatch.setattr(action_ledger, "append_action", lambda *_args, **_kwargs: None)
    token = action_ledger.active_run_id.set("contract-test-run")
    try:
        args = {"args": "-s -D- https://app.test/"}
        first = await manager.execute("execute_curl", args)
        second = await manager.execute("execute_curl", args)
    finally:
        action_ledger.active_run_id.reset(token)

    assert len(calls) == 1
    assert first["success"] is False
    assert second["suppressed_repeat"] is True
