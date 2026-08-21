"""MCP *client* — attach Burp/Caido/other MCP servers to the agent.

The platform already *exposes* an MCP server of our scanners. CAI's edge is
consuming the tester's proxy as tools. This module is process-local: connect
during a hunt, call tools, disconnect. No generic shell.
"""

from __future__ import annotations

import json
import logging
import threading
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


class McpSession:
    def __init__(self, name: str, url: str, transport: str):
        self.name = name
        self.url = url.rstrip("/")
        self.transport = transport  # "http" | "sse"
        self.message_url = self.url
        self.session_id = ""
        self.tools: List[Dict[str, Any]] = []
        self._id = 0
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
        resp = self._client.post(self.message_url, json=payload, headers=headers)
        if resp.status_code >= 400:
            raise McpError(f"{method} HTTP {resp.status_code}: {resp.text[:400]}")
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
    return session.call_tool(tool_name, arguments)
