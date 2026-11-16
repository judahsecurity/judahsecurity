import asyncio

import pytest

from app.services.agent import confirmation_service as cs
from app.services.agent.confirmation_service import describe_policy_decision
from app.services.agent.fireteam_service import DEFAULT_SPECIALISTS, specialist_tool_list
from app.services.agent.tool_access import build_tool_access
from app.services.tool_recipes import PHASES

POLICIES = [
    {},
    {"tool_confirmation_policy": {"execute_*": "confirm", "execute_httpx": "auto"}},
    {"tool_confirmation_policy": {"execute_*": "confirm", "execute_dig": "deny"},
     "agent_autonomous_auto_approve": True},
    {"tool_confirmation_enabled": False},
    {"tool_confirmation_readonly_auto_allow": False,
     "tool_confirmation_policy": {"*": "confirm"}},
]
TOOLS = ["query_assets", "execute_httpx", "execute_sqlmap", "execute_dig", "dig_help",
         "run_intruder_batch", "compare_requests", "execute_nuclei"]


@pytest.mark.parametrize("policy", POLICIES)
@pytest.mark.parametrize("roe", [False, True])
def test_described_decision_matches_the_real_gate(monkeypatch, policy, roe):
    monkeypatch.setattr(cs, "_load_policy", lambda org_id: policy)
    monkeypatch.setattr(cs, "_roe_requires_confirmation", lambda org_id: roe)
    for autonomous in (False, True):
        token = cs.set_autonomous_mode(autonomous)
        try:
            for tool in TOOLS:
                described = describe_policy_decision(policy, tool, roe_requires_confirmation=roe)
                expected = described["autonomous" if autonomous else "interactive"]
                # args that are not bounded informational Nuclei recon
                got = asyncio.run(cs.gate(tool, {"args": "-u https://a.example -t cves/"}, 1, "s"))
                assert got["decision"] == expected, (tool, policy, roe, autonomous)
        finally:
            cs._autonomous_mode.reset(token)


def test_specialist_tool_list_keeps_runtime_additions():
    verifier = next(p for p in DEFAULT_SPECIALISTS if p.name == "independent_verifier")
    tools = specialist_tool_list(verifier, oob_allowed=False)
    assert "search_memory" in tools and "read_evidence" in tools
    assert "run_authorization_proof" in tools
    assert "execute_interactsh" not in tools
    with_oob = specialist_tool_list(verifier, oob_allowed=True)
    if "execute_interactsh" in verifier.allowed_tools:
        assert "run_oob_callback_workflow" in with_oob


def test_tool_access_view_covers_phases_specialists_and_recipes():
    view = build_tool_access({}, roe_requires_confirmation=False)
    assert view["phases"] == list(PHASES)
    rows = {t["name"]: t for t in view["tools"]}

    dig = rows["execute_dig"]
    assert dig["source"] == "recipe" and dig["registered"]
    assert dig["phases"] == list(PHASES)
    assert dig["confirmation"]["interactive"] == "auto"
    assert dig["denylist_checked"] is True
    assert rows["save_note"]["denylist_checked"] is False

    names = {s["name"] for s in view["specialists"]}
    assert {"web_recon", "independent_verifier"} <= names
    assert "web_recon" in rows["execute_httpx"]["specialists"]
    assert rows["execute_interactsh"]["requires_grant"] == "oob_callbacks"
    assert rows["query_assets"]["installed"] is None
    assert rows["execute_dig"]["installed"] in (True, False)
