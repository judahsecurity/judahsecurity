"""A scoped run must not queue an early Interceptor crawl.

Interceptor workers cannot enforce operator method and path approvals, so an
unattended early crawl would bypass the scoped assessment policy.
"""

from unittest.mock import AsyncMock

import pytest
from langchain_core.messages import HumanMessage

from app.services.agent.orchestrator import AgentOrchestrator


def _state():
    return {
        "mode": "agent", "user_id": "1", "session_id": "scoped-early-queue",
        "messages": [HumanMessage(content="Web App Assessment — https://app.test")],
    }


async def _run(monkeypatch, *, scoped: bool):
    from app.services import interceptor_service
    from app.services.agent import assessment_kickoff, recon_workers

    queue = AsyncMock(return_value={"queued": True, "job_id": "job-1", "online": [], "note": "queued"})
    spawn = AsyncMock(return_value=[])
    kickoff = AsyncMock(return_value={"success": True, "root_status": 200})
    monkeypatch.setattr(interceptor_service, "queue_early_pentester_crawl", queue)
    monkeypatch.setattr(recon_workers, "spawn_workers", spawn)
    monkeypatch.setattr(assessment_kickoff, "run_assessment_kickoff", kickoff)

    from app.services.agent.tools import ASMToolsManager

    orchestrator = AgentOrchestrator()
    orchestrator.tool_manager = ASMToolsManager()
    if scoped:
        orchestrator.tool_manager.set_scoped_assessment_policy({})
    result = await orchestrator._initialize_node(_state())
    return queue, spawn, kickoff, result


@pytest.mark.asyncio
async def test_scoped_policy_skips_early_interceptor_queue(monkeypatch):
    queue, spawn, kickoff, result = await _run(monkeypatch, scoped=True)
    queue.assert_not_awaited()
    kickoff.assert_awaited()
    # Recon streams still run; only the unenforceable worker crawl is skipped.
    spawn.assert_awaited()
    assert "Call execute_interceptor next" not in str(result)


@pytest.mark.asyncio
async def test_unscoped_run_still_queues_early_interceptor(monkeypatch):
    queue, _spawn, _kickoff, _result = await _run(monkeypatch, scoped=False)
    queue.assert_awaited()
