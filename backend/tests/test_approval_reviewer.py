"""AI reviewer: approves routine calls or escalates; never denies; risky tools stay human."""

import asyncio
from types import SimpleNamespace

import pytest

from app.services.agent import approval_reviewer
from app.services.agent.approval_reviewer import (
    AI_REVIEWER, eligible, parse_decision, review_and_decide,
)
from app.services.agent.confirmation_service import get_store

AI = {"tool_confirmation_reviewer": "ai"}


def test_eligibility():
    assert eligible("execute_nuclei", AI)
    assert not eligible("execute_nuclei", {"tool_confirmation_reviewer": "human"})
    assert not eligible("execute_nuclei", {})
    for risky in ("run_intruder_batch", "execute_sqlmap", "run_custom_probe", "create_scan",
                  "execute_metasploit_exploit"):
        assert not eligible(risky, AI)
    custom = {**AI, "ai_reviewer_tools": ["execute_ffuf", "execute_sqlmap"]}
    assert eligible("execute_ffuf", custom)
    assert not eligible("execute_nuclei", custom)
    assert not eligible("execute_sqlmap", custom)  # never-AI wins over config


@pytest.mark.parametrize("text, decision", [
    ('{"decision": "approve", "reason": "in scope"}', "approve"),
    ('Sure! {"decision":"escalate","reason":"external host"}', "escalate"),
    ('{"decision": "deny", "reason": "bad"}', "escalate"),
    ("I think it is fine", "escalate"),
])
def test_parse_never_denies(text, decision):
    assert parse_decision(text)["decision"] == decision


class FakeLLM:
    def __init__(self, reply, delay=0.0):
        self.reply, self.delay, self.prompt = reply, delay, None

    async def ainvoke(self, messages):
        self.prompt = messages[0].content
        await asyncio.sleep(self.delay)
        return SimpleNamespace(content=self.reply)


@pytest.fixture(autouse=True)
def no_audit_db(monkeypatch):
    calls = []
    import app.services.platform_audit as platform_audit

    monkeypatch.setattr(platform_audit, "record", lambda action, **kw: calls.append((action, kw)))
    return calls


def _pending(tool="execute_nuclei"):
    return get_store().create(tool_name=tool, tool_args={"args": "-u https://app.test"},
                              organization_id=7, session_id="s", timeout_seconds=60)


@pytest.mark.asyncio
async def test_approve_decides_and_audits(no_audit_db):
    pc = _pending()
    llm = FakeLLM('{"decision":"approve","reason":"bounded nuclei on in-scope host"}')
    verdict = await review_and_decide(pc.token, llm_factory=lambda: llm, tool_name=pc.tool_name,
                                      tool_args=pc.tool_args, scope=["app.test"],
                                      objective="https://app.test", organization_id=7)
    assert verdict["decision"] == "approve"
    assert get_store().get(pc.token).status == "approved"
    assert get_store().get(pc.token).decided_by == AI_REVIEWER
    assert no_audit_db[0][0] == "agent.confirmation_ai_approve"
    assert "app.test" in llm.prompt and "untrusted" in llm.prompt


@pytest.mark.asyncio
async def test_escalate_leaves_pending_with_note():
    pc = _pending()
    llm = FakeLLM('{"decision":"escalate","reason":"targets an IP not in scope"}')
    await review_and_decide(pc.token, llm_factory=lambda: llm, tool_name=pc.tool_name,
                            tool_args=pc.tool_args, scope=["app.test"], objective="",
                            organization_id=7)
    stored = get_store().get(pc.token)
    assert stored.status == "pending"
    assert stored.ai_review == {"decision": "escalate", "reason": "targets an IP not in scope"}


@pytest.mark.asyncio
async def test_reviewer_failure_escalates():
    pc = _pending()

    def broken():
        raise RuntimeError("no model")

    verdict = await review_and_decide(pc.token, llm_factory=broken, tool_name=pc.tool_name,
                                      tool_args={}, scope=[], objective="", organization_id=7)
    assert verdict["decision"] == "escalate" and get_store().get(pc.token).status == "pending"


@pytest.mark.asyncio
async def test_human_decision_first_wins():
    pc = _pending()
    get_store().decide(pc.token, approved=False, decided_by="analyst@acme.test", reason="no")
    verdict = await review_and_decide(
        pc.token, llm_factory=lambda: FakeLLM('{"decision":"approve","reason":"ok"}'),
        tool_name=pc.tool_name, tool_args={}, scope=[], objective="", organization_id=7)
    assert verdict["decision"] == "superseded"
    assert get_store().get(pc.token).status == "denied"


@pytest.mark.asyncio
async def test_gate_marks_only_eligible_requests(monkeypatch):
    from app.services.agent import confirmation_service

    policy = {**AI, "tool_confirmation_policy": {"execute_*": "confirm"}}
    monkeypatch.setattr(confirmation_service, "_load_policy", lambda _org: policy)
    monkeypatch.setattr(confirmation_service, "_roe_requires_confirmation", lambda _org: False)
    nuclei = await confirmation_service.gate("execute_nuclei", {"args": "-u https://app.test -tags cve"}, 7, "s")
    sqlmap = await confirmation_service.gate("execute_sqlmap", {"args": "-u https://app.test"}, 7, "s")
    assert nuclei["decision"] == "confirm" and nuclei["ai_review"] is True
    assert sqlmap["decision"] == "confirm" and sqlmap["ai_review"] is False

    monkeypatch.setattr(confirmation_service, "_roe_requires_confirmation", lambda _org: True)
    monkeypatch.setattr(confirmation_service, "_load_policy",
                        lambda _org: {**AI, "tool_confirmation_policy": {"execute_*": "auto"}})
    roe = await confirmation_service.gate("execute_nuclei", {"args": "-u https://app.test -tags cve"}, 7, "s")
    assert roe["decision"] == "confirm" and roe["ai_review"] is False


@pytest.mark.asyncio
async def test_tool_manager_runs_review_while_waiting(monkeypatch):
    from app.services.agent import action_ledger, confirmation_service
    from app.services.agent.tools import ASMToolsManager, set_tenant_context

    monkeypatch.setattr(confirmation_service, "_load_policy",
                        lambda _org: {**AI, "tool_confirmation_policy": {"execute_*": "confirm"}})
    monkeypatch.setattr(confirmation_service, "_roe_requires_confirmation", lambda _org: False)
    monkeypatch.setattr(action_ledger, "append_action", lambda *_a, **_k: None)
    manager = ASMToolsManager()
    llm = FakeLLM('{"decision":"approve","reason":"ok"}')
    monkeypatch.setattr(manager, "_start_ai_review", lambda token, *a: asyncio.create_task(
        review_and_decide(token, llm_factory=lambda: llm, tool_name="execute_nuclei",
                          tool_args={}, scope=["app.test"], objective="", organization_id=7)))
    ran = []

    class FakeMcp:
        async def call_tool(self, name, args):
            ran.append(name)
            return {"success": True, "output": "scan done"}

    monkeypatch.setattr(manager, "_get_mcp_server", lambda: FakeMcp())
    set_tenant_context(1, 7, "s")
    result = await asyncio.wait_for(
        manager.execute("execute_nuclei", {"args": "-u https://app.test -tags cve -json"}), 10)
    assert ran == ["execute_nuclei"] and result["success"] is True
