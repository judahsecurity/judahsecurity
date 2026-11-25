"""Background execution of long-running agent tools."""

import asyncio

import pytest

from app.services.agent import tool_executions
from app.services.agent.tool_executions import (
    background_enabled,
    cancel_run,
    mark_running,
    start,
    take_unannounced,
    wait_until_settled,
)


def _factory(delay, result=None, *, approve_after=0.0):
    async def run():
        if approve_after:
            await asyncio.sleep(approve_after)  # confirmation gate
        mark_running()
        await asyncio.sleep(delay)
        return result or {"success": True, "output": "scan output"}
    return run


@pytest.mark.asyncio
async def test_fast_tool_returns_result_in_turn():
    execution = start(run_id="r-fast", session_id="s", tool_name="execute_nuclei",
                      factory=_factory(0.01), hard_timeout=5)
    assert await wait_until_settled(execution, budget=5, wait=1)
    assert execution.status == "completed"
    assert execution.result["output"] == "scan output"
    await cancel_run("r-fast")


@pytest.mark.asyncio
async def test_slow_tool_continues_in_background_and_is_announced():
    execution = start(run_id="r-slow", session_id="s", tool_name="execute_nmap",
                      factory=_factory(0.3), hard_timeout=5)
    assert not await wait_until_settled(execution, budget=5, wait=0.05)
    execution.backgrounded = True
    notice = tool_executions.background_notice(execution, 0.05)
    assert notice["execution_id"] == execution.id and notice["background"] is True
    assert take_unannounced("r-slow") == []

    assert await tool_executions.wait(execution, 2)
    assert execution.status == "completed"
    assert [e.id for e in take_unannounced("r-slow")] == [execution.id]
    assert take_unannounced("r-slow") == []
    await cancel_run("r-slow")


@pytest.mark.asyncio
async def test_bounded_wait_starts_after_approval():
    # Approval takes longer than the wait; the tool then finishes quickly.
    execution = start(run_id="r-approve", session_id="s", tool_name="execute_ffuf",
                      factory=_factory(0.02, approve_after=0.2), hard_timeout=5)
    assert await wait_until_settled(execution, budget=5, wait=0.1)
    assert execution.status == "completed"
    await cancel_run("r-approve")


@pytest.mark.asyncio
async def test_unapproved_call_cannot_outlast_turn_budget():
    execution = start(run_id="r-budget", session_id="s", tool_name="execute_ffuf",
                      factory=_factory(0.01, approve_after=5), hard_timeout=10)
    assert not await wait_until_settled(execution, budget=0.1, wait=1)
    await cancel_run("r-budget")
    assert execution.status == "cancelled"


@pytest.mark.asyncio
async def test_hard_timeout_and_failure_become_results():
    slow = start(run_id="r-hard", session_id="s", tool_name="execute_sqlmap",
                 factory=_factory(5), hard_timeout=0.05)
    await tool_executions.wait(slow, 2)
    assert slow.status == "hard_timeout"
    assert "time budget" in slow.result["error"]

    async def boom():
        raise RuntimeError("binary missing")

    failed = start(run_id="r-hard", session_id="s", tool_name="execute_nikto",
                   factory=boom, hard_timeout=5)
    await tool_executions.wait(failed, 2)
    assert failed.status == "failed"
    assert "binary missing" in failed.result["error"]
    await cancel_run("r-hard")


@pytest.mark.asyncio
async def test_run_end_cancels_unfinished_executions():
    execution = start(run_id="r-end", session_id="s", tool_name="execute_masscan",
                      factory=_factory(30), hard_timeout=60)
    await asyncio.sleep(0.01)
    assert await cancel_run("r-end") == 1
    assert execution.status == "cancelled"
    assert tool_executions.run_executions("r-end") == []


@pytest.mark.asyncio
async def test_executions_are_scoped_to_their_run_or_session():
    execution = start(run_id="r-a", session_id="sess-a", tool_name="execute_nmap",
                      factory=_factory(0.01), hard_timeout=5)
    assert tool_executions.get(execution.id, run_id="r-a") is execution
    assert tool_executions.get(execution.id, run_id="r-b", session_id="sess-b") is None
    assert tool_executions.get(execution.id, run_id="r-b", session_id="sess-a") is execution
    await cancel_run("r-a")


def test_background_only_for_long_scanners_outside_pilot_and_verification(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "AGENT_TOOL_WAIT_SECONDS", 120, raising=False)
    assert background_enabled("execute_nuclei")
    assert not background_enabled("execute_browser")
    assert not background_enabled("create_finding")
    monkeypatch.setattr(settings, "AGENT_TOOL_WAIT_SECONDS", 0, raising=False)
    assert not background_enabled("execute_nuclei")


@pytest.mark.asyncio
async def test_manager_tools_wait_get_cancel(monkeypatch):
    from app.services.agent.action_ledger import active_run_id
    from app.services.agent.tools import ASMToolsManager

    manager = ASMToolsManager()
    token = active_run_id.set("r-tools")
    try:
        slow = start(run_id="r-tools", session_id="s", tool_name="execute_nmap",
                     factory=_factory(0.2), hard_timeout=5)
        status = await manager.get_tool_execution(slow.id)
        assert "Call wait_tool_execution" in status
        early = await manager.wait_tool_execution(slow.id, timeout_seconds=0.01)
        assert "still" in early
        done = await manager.wait_tool_execution(slow.id, timeout_seconds=5)
        assert "completed" in done and "scan output" in done

        stuck = start(run_id="r-tools", session_id="s", tool_name="execute_ffuf",
                      factory=_factory(30), hard_timeout=60)
        await asyncio.sleep(0.01)
        assert "cancelled" in await manager.cancel_tool_execution(stuck.id)
        listing = await manager.list_tool_executions()
        assert slow.id in listing and stuck.id in listing
        assert "No background execution" in await manager.wait_tool_execution("exec_nope")
    finally:
        active_run_id.reset(token)
        await cancel_run("r-tools")


@pytest.mark.asyncio
async def test_control_tools_skip_confirmation_and_guard(monkeypatch):
    from app.services.agent import action_ledger
    from app.services.agent.confirmation_service import READONLY_TOOLS
    from app.services.agent.tool_guard import check_tool_call
    from app.services.agent.tools import ASMToolsManager

    for name in ("get_tool_execution", "wait_tool_execution",
                 "cancel_tool_execution", "list_tool_executions"):
        assert name in READONLY_TOOLS
        assert not check_tool_call(name, {"execution_id": "agency.gov"}).blocked

    manager = ASMToolsManager()
    monkeypatch.setattr(action_ledger, "append_action", lambda *_a, **_k: None)
    result = await manager.execute("list_tool_executions", {})
    assert result["success"] is True


@pytest.mark.asyncio
async def test_orchestrator_backgrounds_slow_scanner_and_announces_completion(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from app.core.config import settings
    from app.services.agent import action_ledger, evograph
    from app.services.agent.orchestrator import AgentOrchestrator

    monkeypatch.setattr(settings, "AGENT_TOOL_WAIT_SECONDS", 1, raising=False)
    monkeypatch.setattr(tool_executions, "wait_seconds", lambda: 0.05)
    monkeypatch.setattr(evograph, "record_step", lambda **_kwargs: None)
    monkeypatch.setattr(evograph, "get_session_chain", lambda _session_id, _org_id: {})

    release = asyncio.Event()

    async def execute(tool_name, tool_args):
        if tool_name == "execute_testssl":
            mark_running()
            await release.wait()
            return {"success": True, "output": "[critical] finding on target"}
        return {"success": True, "output": "quick result"}

    orchestrator = AgentOrchestrator()
    orchestrator.tool_manager = SimpleNamespace(execute=execute, _fallback_target="")
    orchestrator._emit_status = AsyncMock()

    def state(tool_name, args):
        return {
            "user_id": "1", "organization_id": 1, "session_id": "bg-orchestrator",
            "mode": "agent", "current_phase": "informational", "current_iteration": 2,
            "target_info": {"primary_target": "https://app.test"},
            "_current_step": {"iteration": 2, "phase": "informational", "thought": "scan",
                              "tool_name": tool_name, "tool_args": args},
        }

    token = action_ledger.active_run_id.set("r-orchestrator")
    try:
        first = await orchestrator._execute_tool_node(
            state("execute_testssl", {"args": "--jsonfile - https://app.test"}))
        step = first["_current_step"]
        assert step["success"] is True
        assert "execution_id=exec_" in step["tool_output"]
        [execution] = tool_executions.run_executions("r-orchestrator")
        assert execution.backgrounded and not execution.done

        release.set()
        await tool_executions.wait(execution, 2)
        second = await orchestrator._execute_tool_node(
            state("query_assets", {"search": "app.test"}))
        output = second["_current_step"]["tool_output"]
        assert output.startswith("quick result")
        assert f"execute_testssl completed (execution_id={execution.id})" in output
    finally:
        action_ledger.active_run_id.reset(token)
        await cancel_run("r-orchestrator")


@pytest.mark.asyncio
async def test_completion_blocked_until_background_result_is_read():
    from app.services.agent.tool_executions import completion_blocker, format_result

    execution = start(run_id="r-final", session_id="s", tool_name="execute_nmap",
                      factory=_factory(0.1), hard_timeout=5)
    execution.backgrounded = True
    assert "still" in completion_blocker("r-final")
    await tool_executions.wait(execution, 2)
    assert "not read yet" in completion_blocker("r-final")
    format_result(execution)
    assert completion_blocker("r-final") is None
    await cancel_run("r-final")


@pytest.mark.asyncio
async def test_cancelled_background_execution_does_not_block_completion():
    from app.services.agent.tool_executions import completion_blocker

    execution = start(run_id="r-final-c", session_id="s", tool_name="execute_ffuf",
                      factory=_factory(30), hard_timeout=60)
    execution.backgrounded = True
    await asyncio.sleep(0.01)
    tool_executions.cancel(execution)
    await tool_executions.wait(execution, 2)
    assert completion_blocker("r-final-c") is None
    await cancel_run("r-final-c")


def test_empty_final_answer_falls_back_to_report(monkeypatch):
    from app.services.agent import action_ledger
    from app.services.agent.orchestrator import AgentOrchestrator

    monkeypatch.setattr(action_ledger, "partial_report",
                        lambda run_id, reason: f"Assessment ended: {reason}.")
    response = AgentOrchestrator()._build_response(
        {"messages": [], "task_complete": True, "execution_trace": []})
    assert response.answer == "Assessment ended: empty final answer."


@pytest.mark.asyncio
async def test_live_output_tail_from_real_command(monkeypatch):
    import sys

    from app.services.agent.action_ledger import active_run_id
    from app.services.agent.tools import ASMToolsManager
    from app.services.mcp.server import get_mcp_server

    server = get_mcp_server()
    script = ("import sys,time\n"
              "print('line-1', flush=True)\n"
              "time.sleep(0.6)\n"
              "print('line-2', flush=True)\n")

    async def run():
        mark_running()
        return await server._run_command([sys.executable, "-c", script], timeout=10)

    manager = ASMToolsManager()
    token = active_run_id.set("r-tail")
    try:
        execution = start(run_id="r-tail", session_id="s", tool_name="execute_nmap",
                          factory=run, hard_timeout=10)
        for _ in range(50):
            if execution.output_bytes:
                break
            await asyncio.sleep(0.02)
        status = await manager.get_tool_execution(execution.id)
        assert "Live output tail" in status and "line-1" in status
        assert "line-2" not in status
        assert "Live output tail" not in await manager.get_tool_execution(
            execution.id, include_partial_output=False)
        done = await manager.wait_tool_execution(execution.id, timeout_seconds=5)
        assert "completed" in done and "line-1" in done and "line-2" in done
    finally:
        active_run_id.reset(token)
        await cancel_run("r-tail")


def test_tail_is_bounded():
    from app.services.agent.tool_executions import TAIL_MAX_BYTES, ToolExecution

    execution = ToolExecution(id="x", run_id="r", session_id="s", tool_name="t")
    execution.append_output(b"a" * TAIL_MAX_BYTES)
    execution.append_output(b"END")
    assert len(execution.tail) == TAIL_MAX_BYTES
    assert execution.output_tail(3) == "END"
    assert execution.output_bytes == TAIL_MAX_BYTES + 3
