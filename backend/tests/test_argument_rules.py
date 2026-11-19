"""Argument-aware approval rules must be precise when allowing, broad when refusing."""

import pytest

from app.models.project_settings import default_agent_config
from app.services.agent import confirmation_service as confirmation
from app.services.agent.argument_rules import evaluate, parse_argv

GIT_RULES = [{"tool": "execute_git", "decision": "auto", "argv_prefix": ["push"],
              "allow_flags": ["-q"]}]
CURL_RULES = [
    {"tool": "execute_curl", "decision": "auto", "argv_prefix": ["-X", "GET"],
     "allow_flags": ["-s", "-i", "-H"]},
    {"tool": "execute_curl", "decision": "deny", "contains": ["-X", "DELETE"]},
]


def test_auto_rule_does_not_cover_unlisted_flags():
    assert evaluate("execute_git", {"args": "push -q"}, GIT_RULES).decision == "auto"
    assert evaluate("execute_git", {"args": "push --force"}, GIT_RULES).decision is None
    assert evaluate("execute_git", {"args": "push -q --force-with-lease=x"}, GIT_RULES).decision is None


def test_deny_matches_anywhere_and_beats_auto():
    args = {"args": "-X GET -s https://app.test/ -X DELETE"}
    assert evaluate("execute_curl", args, CURL_RULES).decision == "deny"
    ok = {"args": "-X GET -s -H 'Accept: text/html' https://app.test/a?x=1&y=2"}
    assert evaluate("execute_curl", ok, CURL_RULES).decision == "auto"


@pytest.mark.parametrize("raw", [
    "-X GET https://app.test/$(id)", "-X GET `id`", "-X GET x; rm -rf /",
    "-X GET 'unterminated", "-X GET a | sh",
])
def test_unparseable_or_chained_commands_go_to_an_analyst(raw):
    assert parse_argv({"args": raw}) is None
    verdict = evaluate("execute_curl", {"args": raw}, CURL_RULES)
    assert verdict.decision == "confirm" and verdict.unparseable


def test_field_rules_need_every_field_to_allow():
    rules = [{"tool": "replay_http_request", "decision": "auto", "fields": {"method": ["GET"]}}]
    assert evaluate("replay_http_request", {"method": "get", "request_id": "r1"}, rules).decision == "auto"
    assert evaluate("replay_http_request", {"method": "POST"}, rules).decision is None
    assert evaluate("replay_http_request", {"request_id": "r1"}, rules).decision is None


def test_tools_without_rules_are_unaffected():
    assert evaluate("execute_nmap", {"args": "$(id)"}, CURL_RULES).decision is None
    assert evaluate("execute_curl", {"args": "x"}, "not-a-list").decision is None


def _setup(monkeypatch, policy):
    monkeypatch.setattr(confirmation, "_load_policy", lambda _org_id: policy)
    monkeypatch.setattr(confirmation, "_roe_requires_confirmation", lambda _org_id: False)
    store = confirmation.ConfirmationStore()
    monkeypatch.setattr(confirmation, "get_store", lambda: store)


@pytest.mark.asyncio
async def test_gate_applies_argument_rules(monkeypatch):
    policy = default_agent_config()
    policy["tool_argument_rules"] = [
        {"tool": "execute_curl", "decision": "confirm", "contains": ["-X", "POST"]},
        {"tool": "execute_curl", "decision": "deny", "contains": ["-X", "DELETE"]},
        {"tool": "execute_sqlmap", "decision": "auto", "argv_prefix": ["-u"],
         "allow_flags": ["--batch"]},
    ]
    _setup(monkeypatch, policy)
    # execute_curl is "auto" by name; argument rules tighten it.
    assert (await confirmation.gate("execute_curl", {"args": "https://a.test/"}, 7, "s"))["decision"] == "auto"
    assert (await confirmation.gate("execute_curl", {"args": "-X POST https://a.test/"}, 7, "s"))["decision"] == "confirm"
    assert (await confirmation.gate("execute_curl", {"args": "-X DELETE https://a.test/"}, 7, "s"))["decision"] == "deny"
    # execute_sqlmap* is "confirm" by name; a narrow auto rule relaxes it.
    assert (await confirmation.gate("execute_sqlmap", {"args": "-u https://a.test/?id=1 --batch"}, 7, "s"))["decision"] == "auto"
    assert (await confirmation.gate("execute_sqlmap", {"args": "-u https://a.test/?id=1 --os-shell"}, 7, "s"))["decision"] == "confirm"


@pytest.mark.asyncio
async def test_unparseable_call_is_not_auto_approved_in_autonomous_mode(monkeypatch):
    policy = default_agent_config()
    policy["agent_autonomous_auto_approve"] = True
    policy["tool_argument_rules"] = [
        {"tool": "execute_nuclei", "decision": "auto", "argv_prefix": ["-u"]},
    ]
    _setup(monkeypatch, policy)
    token = confirmation.set_autonomous_mode(True)
    try:
        result = await confirmation.gate("execute_nuclei", {"args": "-u https://a.test/ ; id"}, 7, "s")
        assert result["decision"] == "confirm"
    finally:
        confirmation._autonomous_mode.reset(token)
