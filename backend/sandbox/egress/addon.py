"""mitmproxy addon: scope-enforcing, recording egress for the explorer sandbox.

Each sandbox exec authenticates to this proxy with a per-assessment token as
the proxy username. The backend publishes that token's scope in Redis; this
addon enforces it (policy.py), pins the upstream connection to the address it
validated so DNS cannot change between check and connect, and records every
exchange back to Redis for the backend's evidence store.

Redis keys (all expire with the session):
  prowl:sandbox:scope:<token>      JSON SessionScope, written by the backend
  prowl:sandbox:count:<token>      requests forwarded
  prowl:sandbox:exchanges:<token>  recorded exchanges (JSON, newest last)
  prowl:sandbox:denied:<token>     denied attempts with reasons
"""

from __future__ import annotations

import base64
import json
import logging
import os
import socket
import time

import redis
from mitmproxy import http
from policy import SessionScope, decide

logger = logging.getLogger("prowl.sandbox.egress")

KEY_PREFIX = "prowl:sandbox"
BODY_LIMIT = int(os.environ.get("SANDBOX_RECORD_BODY_LIMIT", str(256 * 1024)))
LIST_LIMIT = int(os.environ.get("SANDBOX_RECORD_LIST_LIMIT", "5000"))
TOKEN_CHARS = set("0123456789abcdef")


def _token_from_header(value: str) -> str:
    try:
        scheme, encoded = (value or "").split(" ", 1)
        if scheme.lower() != "basic":
            return ""
        user = base64.b64decode(encoded.strip()).decode("utf-8", "replace").split(":", 1)[0]
    except (ValueError, UnicodeDecodeError):
        return ""
    return user if len(user) == 32 and set(user) <= TOKEN_CHARS else ""


def _resolve(host: str, port: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return []
    return list(dict.fromkeys(info[4][0] for info in infos))


def _body(content: bytes | None) -> dict:
    content = content or b""
    clipped = content[:BODY_LIMIT]
    try:
        return {"text": clipped.decode("utf-8"), "bytes": len(content),
                "truncated": len(content) > BODY_LIMIT}
    except UnicodeDecodeError:
        return {"base64": base64.b64encode(clipped).decode(), "bytes": len(content),
                "truncated": len(content) > BODY_LIMIT}


class SandboxEgress:
    def __init__(self) -> None:
        self.redis = redis.Redis.from_url(
            os.environ.get("REDIS_URL", "redis://redis:6379/0"),
            socket_timeout=2, socket_connect_timeout=2,
        )
        # HTTPS: inner requests carry no Proxy-Authorization, so remember the
        # token that authenticated each client connection's CONNECT.
        self.conn_tokens: dict[str, str] = {}

    # -- helpers ---------------------------------------------------------
    def _scope(self, token: str) -> SessionScope | None:
        if not token:
            return None
        raw = self.redis.get(f"{KEY_PREFIX}:scope:{token}")
        if not raw:
            return None
        try:
            return SessionScope.from_dict(json.loads(raw))
        except (ValueError, TypeError):
            return None

    def _ttl(self, token: str) -> int:
        ttl = self.redis.ttl(f"{KEY_PREFIX}:scope:{token}")
        return ttl if isinstance(ttl, int) and ttl > 0 else 3600

    def _deny(self, flow: http.HTTPFlow, token: str, reason: str) -> None:
        if token:
            key = f"{KEY_PREFIX}:denied:{token}"
            self.redis.rpush(key, json.dumps({
                "at": time.time(), "method": flow.request.method,
                "url": flow.request.pretty_url, "reason": reason,
            }))
            self.redis.ltrim(key, -500, -1)
            self.redis.expire(key, self._ttl(token))
        flow.response = http.Response.make(
            403, f"prowl sandbox egress denied: {reason}\n".encode(),
            {"Content-Type": "text/plain", "X-Prowl-Egress": "denied"},
        )
        flow.metadata["prowl_denied"] = True

    def _check(self, flow: http.HTTPFlow, token: str, scheme: str, host: str, port: int) -> str | None:
        """Return the validated address to pin to, or None after denying."""
        scope = self._scope(token)
        used = int(self.redis.get(f"{KEY_PREFIX}:count:{token}") or 0) if token else 0
        resolved = _resolve(host, port)
        decision = decide(scheme=scheme, host=host, port=port, resolved=resolved,
                          scope=scope, requests_used=used)
        if not decision.allowed:
            self._deny(flow, token, decision.reason)
            return None
        return resolved[0]

    # -- mitmproxy hooks -------------------------------------------------
    def http_connect(self, flow: http.HTTPFlow) -> None:
        token = _token_from_header(flow.request.headers.get("Proxy-Authorization", ""))
        flow.request.headers.pop("Proxy-Authorization", None)
        if self._check(flow, token, "https", flow.request.host, flow.request.port) is None:
            return
        self.conn_tokens[flow.client_conn.id] = token

    def client_disconnected(self, client) -> None:
        self.conn_tokens.pop(client.id, None)

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.response is not None:
            return
        token = self.conn_tokens.get(flow.client_conn.id) or _token_from_header(
            flow.request.headers.get("Proxy-Authorization", ""))
        flow.request.headers.pop("Proxy-Authorization", None)
        host = flow.request.pretty_host
        address = self._check(flow, token, flow.request.scheme, host, flow.request.port)
        if address is None:
            return
        flow.metadata["prowl_token"] = token
        flow.metadata["prowl_host"] = host
        count_key = f"{KEY_PREFIX}:count:{token}"
        self.redis.incr(count_key)
        self.redis.expire(count_key, self._ttl(token))
        # Pin the upstream connection to the validated address; keep the
        # original name for the Host header and TLS SNI.
        flow.server_conn.address = (address, flow.request.port)
        if flow.request.scheme == "https":
            flow.server_conn.sni = host

    def response(self, flow: http.HTTPFlow) -> None:
        token = flow.metadata.get("prowl_token")
        if not token or flow.metadata.get("prowl_denied"):
            return
        record = {
            "at": time.time(),
            "request": {
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "headers": list(flow.request.headers.items(multi=True)),
                "body": _body(flow.request.raw_content),
            },
            "response": {
                "status": flow.response.status_code,
                "headers": list(flow.response.headers.items(multi=True)),
                "body": _body(flow.response.raw_content),
            },
            "server_address": list(flow.server_conn.peername or ()),
        }
        key = f"{KEY_PREFIX}:exchanges:{token}"
        self.redis.rpush(key, json.dumps(record))
        self.redis.ltrim(key, -LIST_LIMIT, -1)
        self.redis.expire(key, self._ttl(token))


addons = [SandboxEgress()]
