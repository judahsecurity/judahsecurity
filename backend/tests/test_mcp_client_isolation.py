"""External MCP isolation: concurrency limits and per-server circuit breaker."""

import threading

import pytest

from app.services.agent import mcp_client
from app.services.agent.mcp_client import (
    CircuitBreaker,
    McpError,
    McpTransportError,
    McpUnavailable,
)


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_breaker_opens_after_threshold_and_half_opens_after_cooldown():
    clock = Clock()
    breaker = CircuitBreaker(threshold=3, cooldown=60, clock=clock)
    for _ in range(3):
        breaker.before_call()
        breaker.record_failure()
    assert breaker.state == "open"
    with pytest.raises(McpUnavailable, match="circuit open"):
        breaker.before_call()

    clock.now += 61
    assert breaker.state == "half_open"
    breaker.before_call()  # the single trial call
    with pytest.raises(McpUnavailable):
        breaker.before_call()  # a second caller during the trial is refused
    breaker.record_success()
    assert breaker.state == "closed"


def test_failed_half_open_trial_reopens_immediately():
    clock = Clock()
    breaker = CircuitBreaker(threshold=2, cooldown=10, clock=clock)
    breaker.record_failure()
    breaker.record_failure()
    clock.now += 11
    breaker.before_call()
    breaker.record_failure()
    assert breaker.state == "open"


class FakeSession:
    def __init__(self, behaviour, per_server=4):
        self.name = "burp"
        self.url = "http://127.0.0.1:9876"
        self.transport = "http"
        self.tools = []
        self.behaviour = behaviour
        self.slots = threading.BoundedSemaphore(per_server)
        self.breaker = CircuitBreaker(threshold=2, cooldown=60)
        self.calls = 0

    def call_tool(self, name, arguments):
        self.calls += 1
        return self.behaviour(name, arguments)

    def close(self):
        pass


@pytest.fixture
def attached(monkeypatch):
    def attach(session):
        monkeypatch.setitem(mcp_client._sessions, mcp_client._key(7, "burp"), session)
        return session
    return attach


def test_transport_failures_trip_breaker_and_stop_sending(attached):
    def down(*_):
        raise McpTransportError("tools/call HTTP 502")

    session = attached(FakeSession(down))
    for _ in range(2):
        with pytest.raises(McpTransportError):
            mcp_client.call_tool(7, "burp", "send_request", {})
    with pytest.raises(McpUnavailable):
        mcp_client.call_tool(7, "burp", "send_request", {})
    assert session.calls == 2
    assert mcp_client.server_health(7) == [
        {"name": "burp", "state": "open", "consecutive_failures": 2}]


def test_tool_errors_do_not_trip_breaker(attached):
    def tool_error(*_):
        raise McpError("unknown tool")

    session = attached(FakeSession(tool_error))
    for _ in range(4):
        with pytest.raises(McpError):
            mcp_client.call_tool(7, "burp", "nope", {})
    assert session.breaker.state == "closed"
    assert session.calls == 4


def test_busy_server_refuses_after_bounded_wait(attached, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "AGENT_MCP_QUEUE_TIMEOUT_SECONDS", 0.05, raising=False)
    session = attached(FakeSession(lambda *_: {"ok": True}, per_server=1))
    session.slots.acquire()  # another call holds the only slot
    try:
        with pytest.raises(McpUnavailable, match="slots busy"):
            mcp_client.call_tool(7, "burp", "send_request", {})
    finally:
        session.slots.release()
    assert session.calls == 0
    assert mcp_client.call_tool(7, "burp", "send_request", {}) == {"ok": True}


def test_http_errors_are_transport_errors(monkeypatch):
    import httpx

    session = mcp_client.McpSession("burp", "http://127.0.0.1:1", "http")

    def refuse(*_a, **_k):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(session._client, "post", refuse)
    with pytest.raises(McpTransportError):
        session.call_tool("x", {})
    session.close()
