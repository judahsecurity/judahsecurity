"""Tests for execute_* tool_args normalization (empty-args failure loop fix)."""

from app.services.agent.tools import (
    _default_args_for_tool,
    extract_seed_target,
    normalize_execute_tool_args,
)


def test_extract_seed_target_from_assessment_prompt():
    text = (
        "can you performan a webapplication assessment of "
        "https://www.emulate3d.com/ we are trying to find any vulnerabilities"
    )
    assert extract_seed_target(text) == "https://www.emulate3d.com/"


def test_extract_seed_accepts_www_and_bare_domain():
    assert extract_seed_target("assess www.emulate3d.com") == "https://www.emulate3d.com"
    assert extract_seed_target("look at emulate3d.com please") == "https://emulate3d.com"


def test_normalize_empty_args_fills_httpx_from_fallback():
    out = normalize_execute_tool_args(
        "execute_httpx",
        {},
        fallback_target="https://www.emulate3d.com/",
    )
    assert "args" in out
    assert "https://www.emulate3d.com/" in out["args"]
    assert "-u" in out["args"]


def test_normalize_url_kwarg():
    out = normalize_execute_tool_args(
        "execute_httpx",
        {"url": "https://www.emulate3d.com/"},
    )
    assert out["args"].startswith("-u https://www.emulate3d.com/")


def test_normalize_preserves_explicit_args():
    out = normalize_execute_tool_args(
        "execute_httpx",
        {"args": "-u https://example.com -json"},
        fallback_target="https://other.com",
    )
    assert out["args"] == "-u https://example.com -json"


def test_normalize_null_args_uses_fallback():
    out = normalize_execute_tool_args(
        "execute_wafw00f",
        {"args": None},
        fallback_target="https://www.emulate3d.com/",
    )
    assert out["args"] == "https://www.emulate3d.com/"


def test_default_args_dns_family():
    assert "-d emulate3d.com" in _default_args_for_tool(
        "execute_subfinder", "https://www.emulate3d.com/"
    )
