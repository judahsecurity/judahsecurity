"""Assessment-workflow failures seen on a live Prowl run.

1. A scoped browser routed through the assessment proxy (Caido) recorded the
   proxy's own HTTP 500 page as the target's response and marked the action
   complete. The browser must detect a proxy-generated error page and fail.
2. Kickoff early-queued a remote Interceptor crawl even though Prowl mode
   always applies the operator method policy, which that worker cannot
   enforce. The queue must be skipped (recon streams still start).
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from langchain_core.messages import HumanMessage

from app.services.agent.scoped_assessment import browser


@pytest.fixture
def proxy(monkeypatch):
    monkeypatch.setattr("app.services.agent.assessment_proxy.assessment_proxy_url",
                        lambda: "http://caido:8080")


def test_proxy_error_page_detects_caido_5xx(proxy):
    assert browser.proxy_error_page(500, "Caido", {})
    assert browser.proxy_error_page(502, "Bad gateway", {"Server": "Caido"})
    assert browser.proxy_error_page(503, "", {"X-Caido-Error": "upstream"})


def test_target_errors_and_success_pages_are_not_proxy_errors(proxy):
    # A real 500 from the target keeps its own title and headers.
    assert not browser.proxy_error_page(500, "Internal Server Error", {"Server": "nginx"})
    # A 2xx page that happens to mention Caido is not an error.
    assert not browser.proxy_error_page(200, "Caido", {})
    assert not browser.proxy_error_page(None, "Caido", {})


def test_no_proxy_configured_never_flags(monkeypatch):
    monkeypatch.setattr("app.services.agent.assessment_proxy.assessment_proxy_url", lambda: None)
    assert not browser.proxy_error_page(500, "Caido", {"Server": "Caido"})


def test_proxy_error_message_is_actionable():
    message = browser.proxy_error_message(500, "https://app.test/catalog?x=1")
    assert "AEGIS_ASSESSMENT_PROXY_URL" in message
    assert "/catalog" in message and "x=1" not in message
    assert "deep_crawl" in message


async def _kickoff(monkeypatch, *, policy_applied: bool):
    from app.services import interceptor_service
    from app.services.agent import action_ledger, assessment_kickoff, recon_workers
    from app.services.agent.orchestrator import AgentOrchestrator

    queued, streams, events = [], [], []

    async def fake_queue(seed, **kwargs):
        queued.append(seed)
        return {"queued": True, "job_id": "job-1"}

    async def fake_streams(**kwargs):
        streams.append(kwargs.get("url"))
        return []

    monkeypatch.setattr(interceptor_service, "queue_early_pentester_crawl", fake_queue)
    monkeypatch.setattr(recon_workers, "spawn_workers", fake_streams)
    monkeypatch.setattr(assessment_kickoff, "run_assessment_kickoff",
                        AsyncMock(return_value={"success": True, "brief": ""}))
    monkeypatch.setattr(action_ledger, "append_action",
                        lambda run_id, action_id, event, tool, **kw: events.append((tool, event, kw)))

    orchestrator = AgentOrchestrator()
    orchestrator._emit_status = AsyncMock()
    orchestrator.tool_manager = SimpleNamespace(
        _scoped_policy_applied=policy_applied, _fallback_target="",
        _assessment_scope=set(), _auth_session=None,
    )
    result = await orchestrator._initialize_node({
        "messages": [HumanMessage(content="Assess https://app.test")],
        "user_id": "1", "session_id": "policy-queue", "mode": "agent",
    })
    return result, queued, streams, events


@pytest.mark.asyncio
async def test_policy_bound_run_skips_interceptor_queue_but_keeps_recon(monkeypatch):
    result, queued, streams, events = await _kickoff(monkeypatch, policy_applied=True)
    assert queued == [], "remote Interceptor must not run outside the operator policy"
    assert streams, "early recon streams must still start"
    assert result.get("interceptor_job_id") is None
    queue_events = [e for tool, e, _ in events if tool == "queue_early_interceptor"]
    assert queue_events[-1] == "skipped", "a policy skip is not a failed action"


@pytest.mark.asyncio
async def test_unbound_run_still_queues_interceptor(monkeypatch):
    result, queued, streams, events = await _kickoff(monkeypatch, policy_applied=False)
    assert queued, "without a policy the early Interceptor queue is unchanged"
    assert result.get("interceptor_job_id") == "job-1"
