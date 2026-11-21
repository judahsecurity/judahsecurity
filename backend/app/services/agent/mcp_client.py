"""MCP *client* — attach Burp/Caido/other MCP servers to the agent.

The platform already *exposes* an MCP server of our scanners. CAI's edge is
consuming the tester's proxy as tools. This module is process-local: connect
during a hunt, call tools, disconnect. No generic shell.

Calls are isolated per server so one slow or broken proxy cannot stall a run:
a per-server and a process-wide concurrency limit (callers wait a bounded time
for a slot), and a per-server circuit breaker that stops sending calls after
repeated transport failures, then lets one trial call through after a cooldown.
Errors the server reports for a tool (JSON-RPC ``error``) do not trip the
breaker; only failures to reach the server do.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

_lock = threading.Lock()
# key: f"{org_id}:{name}"
_sessions: Dict[str, "McpSession"] = {}


class McpError(RuntimeError):
    pass


class McpTransportError(McpError):
    """The server could not be reached or answered with an HTTP error."""


class McpUnavailable(McpError):
    """The call was not sent: breaker open or no concurrency slot in time."""


def _setting(name: str, default: float) -> float:
    try:
        value = float(getattr(settings, name, default))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


class CircuitBreaker:
    """closed -> open after N consecutive failures -> half_open after cooldown."""

    def __init__(self, threshold: int, cooldown: float, clock=time.monotonic):
        self.threshold = max(1, int(threshold))
        self.cooldown = float(cooldown)
        self._clock = clock
        self._lock = threading.Lock()
        self.failures = 0
        self.opened_at: Optional[float] = None
        self._trial_in_flight = False

    @property
    def state(self) -> str:
        with self._lock:
            return self._state_locked()

    def _state_locked(self) -> str:
        if self.opened_at is None:
            return "closed"
        if self._clock() - self.opened_at >= self.cooldown:
            return "half_open"
        return "open"

    def before_call(self) -> None:
        with self._lock:
            state = self._state_locked()
            if state == "closed":
                return
            if state == "half_open" and not self._trial_in_flight:
                self._trial_in_flight = True
                return
            retry_in = max(0.0, self.cooldown - (self._clock() - (self.opened_at or 0)))
            raise McpUnavailable(
                f"circuit open after {self.failures} consecutive transport failures; "
                f"retry in {retry_in:.0f}s or reconnect with mcp_connect"
            )

    def record_success(self) -> None:
        with self._lock:
            self.failures = 0
            self.opened_at = None
            self._trial_in_flight = False

    def record_failure(self) -> None:
        with self._lock:
            self.failures += 1
            if self._trial_in_flight or self.failures >= self.threshold:
                self.opened_at = self._clock()
            self._trial_in_flight = False

    def release_trial(self) -> None:
        """A half-open trial ended without a transport verdict."""
        with self._lock:
            self._trial_in_flight = False

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {"state": self._state_locked(), "consecutive_failures": self.failures}


_global_slots_lock = threading.Lock()
_global_slots: Optional[threading.BoundedSemaphore] = None
_global_slots_size = 0


def _global_semaphore() -> threading.BoundedSemaphore:
    global _global_slots, _global_slots_size
    size = int(_setting("AGENT_MCP_MAX_CONCURRENT_TOTAL", 16))
    with _global_slots_lock:
        if _global_slots is None or _global_slots_size != size:
            _global_slots, _global_slots_size = threading.BoundedSemaphore(size), size
        return _global_slots


class McpSession:
    def __init__(self, name: str, url: str, transport: str):
        self.name = name
        self.url = url.rstrip("/")
        self.transport = transport  # "http" | "sse"
        self.message_url = self.url
        self.session_id = ""
        self.tools: List[Dict[str, Any]] = []
        self._id = 0
        self._id_lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(
            int(_setting("AGENT_MCP_MAX_CONCURRENT_PER_SERVER", 4))
        )
        self.breaker = CircuitBreaker(
            int(_setting("AGENT_MCP_BREAKER_FAILURES", 5)),
            _setting("AGENT_MCP_BREAKER_COOLDOWN_SECONDS", 60),
        )
        self._client = httpx.Client(
            timeout=float(getattr(settings, "AGENT_MCP_CONNECT_TIMEOUT_SECONDS", 8) or 8),
            follow_redirects=True,
        )

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:
            pass

    def _next_id(self) -> int:
        with self._id_lock:
            self._id += 1
            return self._id

    def _rpc(self, method: str, params: Optional[dict] = None, *, notify: bool = False) -> Any:
        payload: Dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        if not notify:
            payload["id"] = self._next_id()
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        try:
            resp = self._client.post(self.message_url, json=payload, headers=headers)
        except httpx.HTTPError as exc:
            raise McpTransportError(f"{method} transport error: {type(exc).__name__}: {exc}") from exc
        if resp.status_code >= 400:
            raise McpTransportError(f"{method} HTTP {resp.status_code}: {resp.text[:400]}")
        sid = resp.headers.get("mcp-session-id") or resp.headers.get("Mcp-Session-Id")
        if sid:
            self.session_id = sid
        if notify or resp.status_code == 204 or not (resp.text or "").strip():
            return None
        body = _decode_rpc_body(resp)
        if isinstance(body, dict) and body.get("error"):
            err = body["error"]
            raise McpError(str(err.get("message") or err)[:400])
        if isinstance(body, dict):
            return body.get("result", body)
        return body

    def initialize(self) -> None:
        self._rpc(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "judah-aegis", "version": "1.0"},
            },
        )
        try:
            self._rpc("notifications/initialized", {}, notify=True)
        except McpError:
            pass
        listed = self._rpc("tools/list") or {}
        tools = listed.get("tools") if isinstance(listed, dict) else listed
        self.tools = tools if isinstance(tools, list) else []

    def call_tool(self, tool_name: str, arguments: Optional[dict] = None) -> Any:
        return self._rpc(
            "tools/call",
            {"name": tool_name, "arguments": arguments or {}},
        )


def _decode_rpc_body(resp: httpx.Response) -> Any:
    ctype = (resp.headers.get("content-type") or "").lower()
    text = resp.text or ""
    if "text/event-stream" in ctype or text.startswith("event:") or "data:" in text[:40]:
        data_lines = []
        for line in text.splitlines():
            if line.startswith("data:"):
                data_lines.append(line[5:].strip())
        blob = "\n".join(data_lines).strip()
        if blob:
            try:
                return json.loads(blob)
            except json.JSONDecodeError:
                return {"raw": blob[:2000]}
    try:
        return resp.json()
    except Exception:
        return {"raw": text[:2000]}


def _key(org_id: int, name: str) -> str:
    return f"{int(org_id)}:{(name or '').strip().lower()}"


def _handshake_http(url: str, name: str) -> McpSession:
    session = McpSession(name, url, "http")
    session.initialize()
    return session


def _parse_sse_endpoint(block: str, base_url: str) -> Optional[str]:
    event = ""
    data = ""
    for line in block.splitlines():
        if line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            data += line[5:].strip()
    if event == "endpoint" and data:
        if data.startswith("http"):
            return data
        return urljoin(base_url if base_url.endswith("/") else base_url + "/", data)
    return None


def _handshake_sse(url: str, name: str) -> McpSession:
    """Classic MCP SSE: GET /sse yields an endpoint event, then POST JSON-RPC there."""
    timeout = float(getattr(settings, "AGENT_MCP_CONNECT_TIMEOUT_SECONDS", 8) or 8)
    with httpx.stream(
        "GET",
        url,
        headers={"Accept": "text/event-stream"},
        timeout=timeout,
        follow_redirects=True,
    ) as resp:
        if resp.status_code >= 400:
            raise McpError(f"SSE handshake HTTP {resp.status_code}")
        buf = ""
        endpoint = None
        for chunk in resp.iter_text():
            buf += chunk
            if "\n\n" in buf:
                block, buf = buf.split("\n\n", 1)
                endpoint = _parse_sse_endpoint(block, url)
                if endpoint:
                    break
        if not endpoint:
            raise McpError("SSE handshake did not yield an endpoint event")
    session = McpSession(name, url, "sse")
    session.message_url = endpoint
    parsed = urlparse(endpoint)
    qs = parsed.query
    if "sessionId=" in qs:
        session.session_id = qs.split("sessionId=", 1)[1].split("&", 1)[0]
    session.initialize()
    return session


def connect(org_id: int, url: str, name: str) -> Dict[str, Any]:
    name = (name or "").strip() or f"mcp-{uuid.uuid4().hex[:6]}"
    url = (url or "").strip()
    if not url:
        raise McpError("url is required")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise McpError("url must be http(s)")

    last_err: Optional[Exception] = None
    session: Optional[McpSession] = None
    for factory in (_handshake_http, _handshake_sse):
        try:
            session = factory(url, name)
            break
        except Exception as exc:
            last_err = exc
            logger.debug("MCP %s handshake failed via %s: %s", name, factory.__name__, exc)
    if session is None:
        raise McpError(f"could not connect: {last_err}")

    with _lock:
        old = _sessions.pop(_key(org_id, name), None)
        if old:
            old.close()
        _sessions[_key(org_id, name)] = session

    return {
        "ok": True,
        "name": name,
        "transport": session.transport,
        "url": url,
        "tools": [
            {"name": t.get("name"), "description": (t.get("description") or "")[:240]}
            for t in session.tools
            if isinstance(t, dict)
        ],
    }


def disconnect(org_id: int, name: str) -> bool:
    with _lock:
        session = _sessions.pop(_key(org_id, name), None)
    if not session:
        return False
    session.close()
    return True


def list_sessions(org_id: int) -> List[Dict[str, Any]]:
    prefix = f"{int(org_id)}:"
    with _lock:
        items = [s for k, s in _sessions.items() if k.startswith(prefix)]
    return [
        {
            "name": s.name,
            "url": s.url,
            "transport": s.transport,
            "tools": [t.get("name") for t in s.tools if isinstance(t, dict)],
        }
        for s in items
    ]


def call_tool(org_id: int, server: str, tool_name: str, arguments: Optional[dict] = None) -> Any:
    with _lock:
        session = _sessions.get(_key(org_id, server))
    if not session:
        raise McpError(f"not connected: {server}. Call mcp_connect first.")
    session.breaker.before_call()
    wait = _setting("AGENT_MCP_QUEUE_TIMEOUT_SECONDS", 30)
    verdict = False
    try:
        if not session.slots.acquire(timeout=wait):
            raise McpUnavailable(
                f"{server}: all per-server MCP slots busy for {wait:.0f}s; call not sent"
            )
        try:
            shared = _global_semaphore()
            if not shared.acquire(timeout=wait):
                raise McpUnavailable(f"all MCP slots busy for {wait:.0f}s; call not sent")
            try:
                try:
                    result = session.call_tool(tool_name, arguments)
                except McpTransportError:
                    verdict = True
                    session.breaker.record_failure()
                    raise
                verdict = True
                session.breaker.record_success()
                return result
            finally:
                shared.release()
        finally:
            session.slots.release()
    finally:
        if not verdict:
            session.breaker.release_trial()


def server_health(org_id: int) -> List[Dict[str, Any]]:
    """Breaker state per attached server, for mcp_list and the UI."""
    prefix = f"{int(org_id)}:"
    with _lock:
        items = [s for k, s in _sessions.items() if k.startswith(prefix)]
    return [{"name": s.name, **s.breaker.snapshot()} for s in items]
