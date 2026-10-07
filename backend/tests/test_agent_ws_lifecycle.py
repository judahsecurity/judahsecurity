"""An agent run must outlive a temporary analyst WebSocket disconnect."""

import asyncio
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import WebSocketDisconnect

from app.api.routes import agent as agent_routes
from app.services.agent.run_control import (
    clear_stop,
    has_running_task,
    is_stop_requested,
    unregister_run,
)
from app.services.agent.state import InvokeResponse


@pytest.mark.asyncio
async def test_websocket_disconnect_keeps_run_and_persists_result(monkeypatch):
    session_id = str(uuid4())
    started = asyncio.Event()
    finish = asyncio.Event()
    saved = []

    class FakeSocket:
        def __init__(self):
            self.received = 0
            self.messages = []

        async def accept(self):
            pass

        async def send_json(self, message):
            self.messages.append(message)

        async def receive_json(self):
            self.received += 1
            if self.received == 1:
                return {"type": "init", "token": "test-token"}
            if self.received == 2:
                return {"type": "query", "question": "Assess example.test", "mode": "agent"}
            await started.wait()
            raise WebSocketDisconnect()

    class FakeSession:
        def query(self, _model):
            return self

        def filter_by(self, **_kwargs):
            return self

        def first(self):
            return None

        def close(self):
            pass

    class FakeOrchestrator:
        async def invoke(self, **_kwargs):
            started.set()
            await finish.wait()
            return InvokeResponse(answer="Assessment completed", task_complete=True)

    async def get_orchestrator(**_kwargs):
        return FakeOrchestrator()

    monkeypatch.setattr(agent_routes, "SessionLocal", FakeSession)
    monkeypatch.setattr(
        agent_routes, "_authenticate_ws_token",
        lambda _token: (SimpleNamespace(id=1), 1),
    )
    monkeypatch.setattr(agent_routes, "_check_pilot_session", lambda *_args: None)
    monkeypatch.setattr(agent_routes, "_save_conversation", lambda *args, **_kwargs: saved.append(args))
    monkeypatch.setattr(agent_routes, "get_agent_orchestrator", get_orchestrator)

    try:
        await agent_routes.agent_websocket(FakeSocket(), session_id)
        assert has_running_task(session_id)
        assert not is_stop_requested(session_id)
        assert session_id not in agent_routes.ws_manager.active_connections

        reconnected = FakeSocket()
        await agent_routes.agent_websocket(reconnected, session_id)
        assert {"type": "run_status", "run_in_progress": True} in reconnected.messages
        assert any(
            message.get("type") == "error" and "already in progress" in message.get("message", "")
            for message in reconnected.messages
        )
        assert has_running_task(session_id)

        finish.set()
        for _ in range(100):
            if any(args[4] == "agent" for args in saved):
                break
            await asyncio.sleep(0.01)
        assert any(args[4] == "agent" and args[5] == "Assessment completed" for args in saved)
    finally:
        finish.set()
        unregister_run(session_id)
        clear_stop(session_id)
