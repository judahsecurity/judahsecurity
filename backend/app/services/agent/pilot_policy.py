"""Fail-closed, per-request controls for a bounded analyst-supervised pilot.

Only the in-process HTTP exchange and routed Playwright browser are allowed to
emit target traffic in this mode. Redis owns the shared count and pacing state
so a second API worker or an approval resume cannot reset the budget.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import os
import time
from contextvars import ContextVar
from dataclasses import dataclass
from urllib.parse import urlsplit


PILOT_NETWORK_TOOLS = frozenset({
    "execute_browser", "replay_http_request", "compare_requests",
    "mutate_captured_request", "run_intruder_batch",
})
PILOT_LOCAL_TOOLS = frozenset({
    "list_captured_requests", "plan_intruder_mutations", "get_coverage",
    "get_assessment_coverage", "record_surface_coverage",
    "submit_finding_candidate", "record_verify_verdict",
})
PILOT_ALLOWED_TOOLS = PILOT_NETWORK_TOOLS | PILOT_LOCAL_TOOLS
PILOT_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class PilotDenied(ValueError):
    """The assessment policy refused a tool or request before network I/O."""


def configured_egress_ip() -> str:
    """Read the same setting from container env or the app's local .env loader."""
    raw = (os.environ.get("AEGIS_AGENT_EGRESS_IP") or "").strip()
    if raw:
        return raw
    try:
        from app.core.config import settings
        return str(settings.AEGIS_AGENT_EGRESS_IP or "").strip()
    except Exception:
        return ""


def exact_origin(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(str(url or ""))
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.fragment):
        raise PilotDenied("Pilot requires an absolute HTTPS URL without credentials or fragment")
    try:
        port = parsed.port if parsed.port is not None else 443
    except ValueError as exc:
        raise PilotDenied("Invalid target port") from exc
    if port < 1 or port > 65535:
        raise PilotDenied("Invalid target port")
    return parsed.scheme, parsed.hostname.lower().rstrip("."), port


_RESERVE_SCRIPT = """
local key = KEYS[1]
local origin = ARGV[1]
local source_ip = ARGV[2]
local proposed_deadline = tonumber(ARGV[3])
local proposed_max = tonumber(ARGV[4])
local interval = tonumber(ARGV[5])
local now = redis.call('TIME')
local now_ms = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
local existing_origin = redis.call('HGET', key, 'origin')
if existing_origin and existing_origin ~= origin then return {-4, 0, 0} end
local existing_ip = redis.call('HGET', key, 'source_ip')
if existing_ip and existing_ip ~= source_ip then return {-4, 0, 0} end
local deadline = tonumber(redis.call('HGET', key, 'deadline')) or proposed_deadline
if proposed_deadline < deadline then deadline = proposed_deadline end
local max_count = tonumber(redis.call('HGET', key, 'max_count')) or proposed_max
if proposed_max < max_count then max_count = proposed_max end
local count = tonumber(redis.call('HGET', key, 'count')) or 0
if now_ms >= deadline then return {-3, 0, count} end
if count >= max_count then return {-2, 0, count} end
local next_ms = tonumber(redis.call('HGET', key, 'next_ms')) or 0
if now_ms < next_ms then return {0, next_ms - now_ms, count} end
count = count + 1
redis.call('HSET', key, 'origin', origin, 'source_ip', source_ip,
           'deadline', deadline, 'max_count', max_count,
           'count', count, 'next_ms', now_ms + interval)
redis.call('PEXPIREAT', key, deadline + 60000)
return {1, 0, count}
"""


@dataclass(frozen=True)
class PilotPolicy:
    target: str
    source_ip: str
    organization_id: int
    session_id: str
    expires_at_ms: int
    max_requests: int = 500
    interval_ms: int = 1000

    @classmethod
    def from_config(cls, config: dict, organization_id: int, session_id: str) -> "PilotPolicy":
        if not isinstance(config, dict):
            raise PilotDenied("Pilot target and source IP are required")
        target = str(config.get("target") or "").strip()
        scheme, host, port = exact_origin(target)
        if not host or host.startswith("*."):
            raise PilotDenied("Pilot target must be one exact host")
        source_ip = str(config.get("source_ip") or "").strip()
        try:
            parsed_ip = ipaddress.ip_address(source_ip)
        except ValueError as exc:
            raise PilotDenied("Aegis worker public egress IP is required") from exc
        configured_ip = configured_egress_ip()
        if not parsed_ip.is_global or source_ip != configured_ip:
            raise PilotDenied("Pilot requires the configured public Aegis worker egress IP")
        if not organization_id or not session_id:
            raise PilotDenied("Pilot requires organization and session IDs")
        expires_at_ms = int(config.get("expires_at_ms") or 0)
        now_ms = int(time.time() * 1000)
        if not now_ms < expires_at_ms <= now_ms + 7_200_000:
            raise PilotDenied("Pilot window must end within two hours")
        return cls(
            target=f"{scheme}://{host}:{port}", source_ip=source_ip,
            organization_id=int(organization_id), session_id=str(session_id),
            expires_at_ms=expires_at_ms,
        )

    def as_config(self) -> dict:
        return {"target": self.target, "source_ip": self.source_ip,
                "expires_at_ms": self.expires_at_ms}

    def check_request(self, url: str, method: str) -> None:
        if exact_origin(url) != exact_origin(self.target):
            raise PilotDenied("Out-of-scope pilot origin blocked")
        if str(method or "").upper() not in PILOT_METHODS:
            raise PilotDenied("Pilot first pass allows GET, HEAD, and OPTIONS only")
        if int(time.time() * 1000) >= self.expires_at_ms:
            raise PilotDenied("Pilot window expired")

    def check_tool(self, tool_name: str) -> None:
        if tool_name not in PILOT_ALLOWED_TOOLS:
            raise PilotDenied(f"Tool '{tool_name}' is unavailable in the bounded pilot")

    @property
    def budget_key(self) -> str:
        # One shared counter for this exact origin, even if an operator opens
        # another conversation or organization during the same pilot window.
        origin_hash = hashlib.sha256(self.target.encode()).hexdigest()[:24]
        return f"aegis:agent-pilot:{origin_hash}"

    async def acquire(self, url: str, method: str) -> int:
        """Reserve one actual outbound request; fail closed if Redis is unavailable."""
        self.check_request(url, method)
        try:
            import redis

            client = redis.Redis.from_url(
                os.environ.get("REDIS_URL", "redis://redis:6379/0"),
                socket_connect_timeout=1, socket_timeout=2,
            )
            while True:
                self.check_request(url, method)
                result = await asyncio.to_thread(
                    client.eval, _RESERVE_SCRIPT, 1, self.budget_key,
                    self.target, self.source_ip, self.expires_at_ms,
                    self.max_requests, self.interval_ms,
                )
                code, delay_ms, count = (int(value) for value in result)
                if code == 1:
                    return count
                if code == 0:
                    await asyncio.sleep(min(delay_ms / 1000, 1.0))
                    continue
                if code == -2:
                    raise PilotDenied("Pilot request budget exhausted")
                if code == -3:
                    raise PilotDenied("Pilot window expired")
                raise PilotDenied("Pilot budget identity changed")
        except PilotDenied:
            raise
        except Exception as exc:
            raise PilotDenied("Shared pilot request gate unavailable") from exc


_pilot_policy: ContextVar[PilotPolicy | None] = ContextVar("agent_pilot_policy", default=None)


def current_pilot() -> PilotPolicy | None:
    return _pilot_policy.get()


def set_pilot(policy: PilotPolicy | None):
    return _pilot_policy.set(policy)


def reset_pilot(token) -> None:
    _pilot_policy.reset(token)
