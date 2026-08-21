"""Operator stop/cancel registry for in-flight agent runs."""

import asyncio

from app.services.agent.run_control import (
    clear_session_controls,
    clear_stop,
    consume_compact,
    drain_load_briefs,
    drain_steers,
    get_price_limit,
    has_running_task,
    is_stop_requested,
    queue_load_brief,
    queue_steer,
    register_run,
    request_compact,
    request_stop,
    set_price_limit,
    unregister_run,
)


def test_request_stop_cancels_registered_task():
    async def _job():
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            return "cancelled"
        return "ok"

    async def _run():
        task = asyncio.create_task(_job())
        register_run("sess-1", task)
        assert has_running_task("sess-1")
        assert request_stop("sess-1") is True
        assert is_stop_requested("sess-1")
        try:
            await task
        except asyncio.CancelledError:
            pass
        unregister_run("sess-1", task)
        assert has_running_task("sess-1") is False

    asyncio.run(_run())


def test_stopped_response_skips_llm():
    from app.services.agent.orchestrator import AgentOrchestrator

    resp = AgentOrchestrator._stopped_response()
    assert resp.task_complete is True
    assert "Stopped by operator" in resp.answer
    assert resp.error is None


def test_stop_without_run_is_idempotent():
    clear_stop("missing")
    assert request_stop("missing") is False
    assert is_stop_requested("missing")
    clear_stop("missing")
    assert is_stop_requested("missing") is False


def test_steer_queues_without_cancelling_run():
    async def _job():
        await asyncio.sleep(30)

    async def _run():
        task = asyncio.create_task(_job())
        register_run("sess-steer", task)
        try:
            assert queue_steer("sess-steer", "stop fuzzing /admin") is True
            assert queue_steer("sess-steer", "use GraphQL instead") is True
            notes = drain_steers("sess-steer")
            assert notes == ["stop fuzzing /admin", "use GraphQL instead"]
            assert drain_steers("sess-steer") == []
            assert has_running_task("sess-steer") is True
            assert is_stop_requested("sess-steer") is False
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            unregister_run("sess-steer", task)
            clear_session_controls("sess-steer")

    asyncio.run(_run())


def test_compact_and_load_and_price_limit():
    request_compact("sess-ops")
    assert consume_compact("sess-ops") is True
    assert consume_compact("sess-ops") is False

    queue_load_brief("sess-ops", "prior hunt: GraphQL at /api")
    assert drain_load_briefs("sess-ops")[0].startswith("prior hunt")
    assert drain_load_briefs("sess-ops") == []

    set_price_limit("sess-ops", 2.5)
    assert get_price_limit("sess-ops") == 2.5
    clear_session_controls("sess-ops")
    assert get_price_limit("sess-ops") is None
