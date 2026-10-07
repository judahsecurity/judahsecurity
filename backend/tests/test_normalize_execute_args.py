"""Tests for execute_* tool_args normalization (empty-args failure loop fix)."""

import json
from types import SimpleNamespace

import pytest

from app.services.agent.tools import (
    _default_args_for_tool,
    extract_seed_target,
    is_probable_file_target,
    recover_assessment_target,
    same_assessment_target,
    normalize_execute_tool_args,
)
from app.services.agent.assessment_scope import prepare_browser_scope


def test_extract_seed_target_from_assessment_prompt():
    text = (
        "can you performan a webapplication assessment of "
        "https://www.emulate3d.com/ we are trying to find any vulnerabilities"
    )
    assert extract_seed_target(text) == "https://www.emulate3d.com/"


def test_extract_seed_accepts_www_and_bare_domain():
    assert extract_seed_target("assess www.emulate3d.com") == "https://www.emulate3d.com"
    assert extract_seed_target("look at emulate3d.com please") == "https://emulate3d.com"


def test_extract_seed_skips_source_file_names():
    text = "Continue testing stockCheck.js and deparam.js on ginandjuice.shop"
    assert extract_seed_target(text) == "https://ginandjuice.shop"
    assert is_probable_file_target("https://stockcheck.js")
    assert not is_probable_file_target("https://ginandjuice.shop")


def test_follow_up_keeps_original_assessment_target():
    assert recover_assessment_target(
        "https://ginandjuice.shop", "test stockCheck.js on other.example.org"
    ) == "https://ginandjuice.shop"
    assert recover_assessment_target(
        "https://stockcheck.js", "Continue stockCheck.js on ginandjuice.shop"
    ) == "https://ginandjuice.shop"
    assert recover_assessment_target(
        "", "Read https://docs.example.net", "https://ginandjuice.shop"
    ) == "https://ginandjuice.shop"
    assert same_assessment_target("ginandjuice.shop/", "https://ginandjuice.shop")
    assert same_assessment_target("https://ginandjuice.shop:443", "https://ginandjuice.shop")
    assert not same_assessment_target("stockcheck.js", "https://ginandjuice.shop")


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


def test_browser_action_objects_remain_json_for_pilot_gate():
    actions = [{"action": "navigate", "url": "https://ginandjuice.shop/"},
               {"action": "get_source"}]
    for supplied in ({"args": {"actions": actions}}, {"actions": actions}):
        result = normalize_execute_tool_args("execute_browser", supplied)
        assert json.loads(result["args"]) == {"actions": actions}


def test_browser_url_becomes_read_only_navigation():
    result = normalize_execute_tool_args(
        "execute_browser", {"url": "https://ginandjuice.shop/"},
    )
    assert json.loads(result["args"]) == {"actions": [
        {"action": "navigate", "url": "https://ginandjuice.shop/"},
        {"action": "get_source"},
    ]}


@pytest.mark.parametrize("supplied", [
    {"args": "--url https://ginandjuice.shop/"},
    {"args": "https://ginandjuice.shop/"},
    {"args": {"url": "https://ginandjuice.shop/"}},
])
def test_browser_specialist_url_shapes_become_actions(supplied):
    result = normalize_execute_tool_args("execute_browser", supplied)
    assert json.loads(result["args"])["actions"] == [
        {"action": "navigate", "url": "https://ginandjuice.shop/"},
        {"action": "get_source"},
    ]


def test_browser_specialist_wait_and_action_aliases():
    result = normalize_execute_tool_args(
        "execute_browser", {"url": "https://ginandjuice.shop/", "wait_ms": 3000}
    )
    assert json.loads(result["args"])["actions"] == [
        {"action": "navigate", "url": "https://ginandjuice.shop/"},
        {"action": "wait", "ms": 3000},
        {"action": "get_source"},
    ]
    result = normalize_execute_tool_args("execute_browser", {"actions": [
        {"type": "goto", "url": "https://ginandjuice.shop/"},
        {"type": "evaluate", "expression": "document.title"},
    ]})
    assert json.loads(result["args"])["actions"] == [
        {"action": "navigate", "url": "https://ginandjuice.shop/"},
        {"action": "execute_js", "script": "document.title"},
    ]


def test_browser_unknown_flags_are_not_silently_discarded():
    result = normalize_execute_tool_args(
        "execute_browser", {"args": "--url https://ginandjuice.shop/ --unknown x"},
        fallback_target="https://ginandjuice.shop/",
    )
    assert result["args"] == "--url https://ginandjuice.shop/ --unknown x"


def test_agent_browser_scope_requires_registered_host_and_one_origin():
    manager = SimpleNamespace(
        _assessment_scope={"ginandjuice.shop"},
        _fallback_target="https://ginandjuice.shop/",
        _identity_registry=SimpleNamespace(identities={}),
    )
    bounded = prepare_browser_scope(manager, {"actions": [
        {"action": "navigate", "url": "https://ginandjuice.shop/"},
    ]})
    assert bounded["allowed_origin"] == "https://ginandjuice.shop/"
    with pytest.raises(ValueError, match="Out-of-scope"):
        prepare_browser_scope(manager, {"actions": [
            {"action": "navigate", "url": "https://other.example/"},
        ]})
    with pytest.raises(ValueError, match="one origin"):
        prepare_browser_scope(manager, {"actions": [
            {"action": "navigate", "url": "https://ginandjuice.shop/"},
            {"action": "check_response", "url": "http://ginandjuice.shop/"},
        ]})
