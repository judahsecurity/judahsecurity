"""Execution limits carried through an opted-in scheduled agent turn."""

from __future__ import annotations

import asyncio
import time
from contextvars import ContextVar
from dataclasses import dataclass
from urllib.parse import urlsplit


# Scheduled autonomy stops on spend and time, not on a small turn count. The
# turn cap remains only as a backstop against a loop that never reports cost.
DEFAULT_MAX_TURNS = 12
MAX_TURNS_CAP = 24
DEFAULT_MAX_TOTAL_SECONDS = 3600
MAX_TOTAL_SECONDS_CAP = 14400
# Re-plans allowed when a turn ends with the same open work it started with.
DEFAULT_MAX_STALLED_REPLANS = 2
MAX_STALLED_REPLANS_CAP = 4
# Share of the spend limit held back for the final verification turn.
WRAPUP_RESERVE_FRACTION = 0.15
# Do not start a verification turn with less than this much wall time left.
WRAPUP_MIN_SECONDS = 180


def _bounded_int(cfg: dict, key: str, default: int, lower: int, upper: int) -> int:
    try:
        return max(lower, min(int(cfg.get(key) or default), upper))
    except (ValueError, TypeError):
        return default


def turn_budget_from_config(config: dict | None) -> dict[str, int]:
    """Turn, time and re-plan limits for one scheduled autonomous assessment."""
    cfg = config or {}
    return {
        "max_turns": _bounded_int(cfg, "max_turns", DEFAULT_MAX_TURNS, 1, MAX_TURNS_CAP),
        "max_total_seconds": _bounded_int(
            cfg, "max_total_seconds", DEFAULT_MAX_TOTAL_SECONDS, 300, MAX_TOTAL_SECONDS_CAP,
        ),
        # 0 is a valid explicit choice here: stop on the first stalled turn.
        "max_stalled_replans": max(0, min(
            int(cfg["max_stalled_replans"]) if _is_int(cfg.get("max_stalled_replans"))
            else DEFAULT_MAX_STALLED_REPLANS,
            MAX_STALLED_REPLANS_CAP,
        )),
    }


def _is_int(value: object) -> bool:
    try:
        int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False
    return not isinstance(value, bool)


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
    max_stalled_replans: int = DEFAULT_MAX_STALLED_REPLANS


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
        if action in {"read", "probe", "state_change"}
    }
    actions = tuple(action for action in ("read", "probe", "state_change") if action in requested_actions)
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
        max_stalled_replans=turn_budget_from_config(cfg)["max_stalled_replans"],
    )
