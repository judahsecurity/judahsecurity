"""Tests for execute_* tool arg normalization (Ollama-friendly)."""

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
