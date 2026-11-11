"""Execution limits carried through an opted-in scheduled agent turn."""

from __future__ import annotations

import asyncio
import time
from contextvars import ContextVar
from dataclasses import dataclass
from urllib.parse import urlsplit


# Ordered action contract. ``read``/``probe`` are the default, always-available
# tiers. ``state_change`` gates mutating probes. ``exploit_dev`` unlocks the
# open, sandboxed exploit-development tier, and ``post_exploit`` the explicit
# post-exploitation tier; both are off unless the operator grant lists them, and
# anything they find is still only a lead until the independent verifier
# reproduces it. The order is the escalation order and is preserved when a
# config is normalized so a directive renders a stable, auditable action list.
ACTION_CLASSES: tuple[str, ...] = (
    "read", "probe", "state_change", "exploit_dev", "post_exploit",
)


@dataclass(frozen=True)
class AutonomyLimits:
    max_specialist_tool_calls: int = 12
    max_specialist_seconds: int = 300
    max_parallel_specialists: int = 3
    max_parallel_tool_calls: int = 2
    allowed_hosts: tuple[str, ...] = ()
    allowed_identities: tuple[str, ...] = ("anonymous",)
    allowed_actions: tuple[str, ...] = ("read", "probe")
    max_specialist_requests: int = 12
    specialist_interval_ms: int = 1000
    max_specialist_spend_usd: float = 2.0
    max_recon_tool_starts: int = 8
    request_rate_per_second: int = 1
    # Open exploit-development tier. Zero commands keeps the tier closed even
    # when ``exploit_dev`` is granted; its wall-clock and request use are also
    # charged against max_specialist_seconds / max_specialist_requests.
    max_exploit_commands: int = 0
    max_exploit_seconds: int = 120


current_autonomy_limits: ContextVar[AutonomyLimits | None] = ContextVar(
    "current_autonomy_limits", default=None,
)


class AutonomyRequestGate:
    """Shared per-turn pacing for concurrently spawned recon tool starts."""

    def __init__(self, max_starts: int, interval_ms: int):
        self.max_starts = max_starts
        self.interval_ms = interval_ms
        self.count = 0
        self.next_at = 0.0
        self.lock = asyncio.Lock()

    async def acquire(self) -> bool:
        async with self.lock:
            if self.count >= self.max_starts:
                return False
            delay = self.next_at - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)
            self.count += 1
            self.next_at = time.monotonic() + self.interval_ms / 1000
            return True


current_autonomy_recon_gate: ContextVar[AutonomyRequestGate | None] = ContextVar(
    "current_autonomy_recon_gate", default=None,
)


def limits_from_config(config: dict | None, *, target: str = "") -> AutonomyLimits:
    cfg = config or {}

    def bounded(key: str, default: int, upper: int) -> int:
        try:
            return max(1, min(int(cfg.get(key) or default), upper))
        except (ValueError, TypeError):
            return default

    target_host = (urlsplit(target if "://" in target else f"https://{target}").hostname or "").lower().rstrip(".")
    hosts = tuple(sorted(({target_host} if target_host else set()) | {
        str(host).lower().rstrip(".") for host in (cfg.get("allowed_hosts") or [target_host])
        if isinstance(host, str) and host
    }))
    identities = tuple(sorted({
        str(identity)[:64] for identity in (cfg.get("allowed_identities") or ["anonymous"])
        if isinstance(identity, str) and identity
    }))
    requested_actions = {
        str(action) for action in (cfg.get("allowed_actions") or ["read", "probe"])
        if action in ACTION_CLASSES
    }
    actions = tuple(action for action in ACTION_CLASSES if action in requested_actions)
    try:
        spend = max(0.01, min(float(cfg.get("max_specialist_spend_usd") or 2.0), 20.0))
    except (ValueError, TypeError):
        spend = 2.0
    return AutonomyLimits(
        max_specialist_tool_calls=bounded("max_specialist_tool_calls", 12, 40),
        max_specialist_seconds=bounded("max_specialist_seconds", 300, 600),
        max_parallel_specialists=bounded("max_parallel_specialists", 3, 6),
        max_parallel_tool_calls=bounded("max_parallel_tool_calls", 2, 4),
        allowed_hosts=hosts,
        allowed_identities=identities or ("anonymous",),
        allowed_actions=actions or ("read",),
        max_specialist_requests=bounded("max_specialist_requests", 12, 100),
        specialist_interval_ms=bounded("specialist_interval_ms", 1000, 10000),
        max_specialist_spend_usd=spend,
        max_recon_tool_starts=bounded("max_recon_tool_starts", 8, 30),
        request_rate_per_second=bounded("request_rate_per_second", 1, 20),
        # Default 0 keeps the open tier closed; a grant raises it within a hard
        # ceiling so a sandbox can never outrun the operator's autonomy budget.
        max_exploit_commands=(
            max(0, min(int(cfg.get("max_exploit_commands") or 0), 25))
            if "exploit_dev" in requested_actions else 0
        ),
        max_exploit_seconds=bounded("max_exploit_seconds", 120, 300),
    )
