"""Per-host request pacing with adaptive backoff for target traffic.

Agent tools talk to the target through many short-lived HTTP clients. Before
this module none of them slowed down when the target pushed back, so a WAF or
rate limiter that started answering 429/503 kept getting the same request
rate until it blocked the run outright.

Every paced request to a host first reserves a send slot from that host's
budget (a token bucket expressed as a virtual send schedule), then reports
the response status:

* 429 / 503 starts a cooldown (``Retry-After`` when the target sends one,
  otherwise exponential) and halves that host's rate;
* a run of successful responses grows the rate back towards the profile's.

Profiles set the base pace: ``quiet``, ``balanced`` (default), ``aggressive``,
or ``off`` (no pacing; used by the test suite). Deliberate burst tests such as
race-condition probes must not use these hooks.

State is per process and per host, so concurrent specialists hitting the same
target share one budget. Reservations take a thread lock only to update the
schedule; waiting happens outside it, with ``asyncio.sleep`` for async
clients and ``time.sleep`` for urllib probes running in worker threads.
"""

from __future__ import annotations

import asyncio
import contextvars
import email.utils
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Iterable, Optional

THROTTLE_STATUSES = frozenset({429, 503})
RECOVERY_SUCCESSES = 20
MIN_RATE_FACTOR = 0.1
THROTTLE_WINDOW_SECONDS = 600
HEAVY_THROTTLE_COUNT = 5
# Never hold one request longer than this, whatever the target asks for; the
# tool's own timeout would otherwise expire while it waits.
MAX_SINGLE_WAIT_SECONDS = 120.0


@dataclass(frozen=True)
class PacingProfile:
    name: str
    rate_per_second: float
    burst: int
    max_backoff_seconds: float


PROFILES: dict[str, Optional[PacingProfile]] = {
    "quiet": PacingProfile("quiet", rate_per_second=1.0, burst=2, max_backoff_seconds=120.0),
    "balanced": PacingProfile("balanced", rate_per_second=5.0, burst=10, max_backoff_seconds=60.0),
    "aggressive": PacingProfile("aggressive", rate_per_second=15.0, burst=30, max_backoff_seconds=30.0),
    "off": None,
}
DEFAULT_PROFILE = "balanced"

current_pacing_profile: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "current_pacing_profile", default=None,
)


def active_profile() -> Optional[PacingProfile]:
    """Profile for this context: explicit override, then settings, then default."""
    name = current_pacing_profile.get()
    if not name:
        try:
            from app.core.config import settings

            name = getattr(settings, "AGENT_PACING_PROFILE", "") or DEFAULT_PROFILE
        except Exception:
            name = DEFAULT_PROFILE
    name = str(name).strip().lower()
    return PROFILES.get(name, PROFILES[DEFAULT_PROFILE])


@dataclass
class _HostState:
    next_send: float = 0.0          # virtual time of the next free send slot
    cooldown_until: float = 0.0
    rate_factor: float = 1.0
    consecutive_throttles: int = 0
    successes_since_cut: int = 0
    throttle_times: list[float] = field(default_factory=list)
    last_status: int = 0


_LOCK = threading.Lock()
_HOSTS: dict[str, _HostState] = {}


def reset_pacing() -> None:
    """Forget all host state (tests, or a fresh engagement)."""
    with _LOCK:
        _HOSTS.clear()


def _key(host: str | None) -> str:
    return (host or "").strip().lower().rstrip(".")


def reserve(host: str, *, now: Optional[float] = None,
            profile: Optional[PacingProfile] = None) -> float:
    """Book the next send slot for ``host``; returns seconds to wait first."""
    profile = profile if profile is not None else active_profile()
    key = _key(host)
    if profile is None or not key:
        return 0.0
    current = time.monotonic() if now is None else now
    with _LOCK:
        state = _HOSTS.setdefault(key, _HostState())
        interval = 1.0 / max(profile.rate_per_second * state.rate_factor, 1e-6)
        tolerance = interval * max(profile.burst - 1, 0)
        earliest = max(current, state.cooldown_until)
        theoretical = max(state.next_send, earliest)
        send_at = max(earliest, theoretical - tolerance)
        state.next_send = theoretical + interval
    wait = send_at - current
    if wait < 1e-6:  # float residue from summed intervals
        return 0.0
    return min(wait, MAX_SINGLE_WAIT_SECONDS)


def _retry_after_seconds(value: Optional[str], *, now_wall: Optional[float] = None) -> Optional[float]:
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        parsed = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if parsed is None:
        return None
    wall = time.time() if now_wall is None else now_wall
    return max(0.0, parsed.timestamp() - wall)


def observe(host: str, status: int, retry_after: Optional[str] = None, *,
            now: Optional[float] = None, profile: Optional[PacingProfile] = None) -> None:
    """Record a response from ``host`` and adapt its pace."""
    profile = profile if profile is not None else active_profile()
    key = _key(host)
    if profile is None or not key:
        return
    current = time.monotonic() if now is None else now
    with _LOCK:
        state = _HOSTS.setdefault(key, _HostState())
        state.last_status = int(status or 0)
        if status in THROTTLE_STATUSES:
            state.consecutive_throttles += 1
            state.successes_since_cut = 0
            state.rate_factor = max(MIN_RATE_FACTOR, state.rate_factor / 2)
            asked = _retry_after_seconds(retry_after)
            backoff = asked if asked is not None else 2.0 ** min(state.consecutive_throttles, 6)
            backoff = min(max(backoff, 1.0), profile.max_backoff_seconds)
            state.cooldown_until = max(state.cooldown_until, current + backoff)
            state.throttle_times = [
                t for t in state.throttle_times if current - t < THROTTLE_WINDOW_SECONDS
            ] + [current]
            return
        state.consecutive_throttles = 0
        if state.rate_factor < 1.0:
            state.successes_since_cut += 1
            if state.successes_since_cut >= RECOVERY_SUCCESSES:
                state.rate_factor = min(1.0, state.rate_factor * 1.5)
                state.successes_since_cut = 0


def _in_scope(host: str, scope_hosts: Iterable[str]) -> bool:
    for scope in scope_hosts:
        scope = _key(scope)
        if scope and (host == scope or host.endswith("." + scope)):
            return True
    return False


def throttle_report(scope_hosts: Iterable[str], *, now: Optional[float] = None) -> list[dict]:
    """Hosts in ``scope_hosts`` (or their subdomains) that pushed back recently.

    State is shared across sessions in this process, so callers must pass
    their own scope: one tenant never sees another tenant's target names.
    """
    scope_hosts = [h for h in scope_hosts if _key(h)]
    if not scope_hosts:
        return []
    current = time.monotonic() if now is None else now
    rows = []
    with _LOCK:
        for host, state in _HOSTS.items():
            if not _in_scope(host, scope_hosts):
                continue
            recent = [t for t in state.throttle_times if current - t < THROTTLE_WINDOW_SECONDS]
            if not recent:
                continue
            rows.append({
                "host": host,
                "throttled_responses": len(recent),
                "rate_factor": round(state.rate_factor, 2),
                "cooling_down_seconds": round(max(0.0, state.cooldown_until - current), 1),
            })
    rows.sort(key=lambda r: (-r["throttled_responses"], r["host"]))
    return rows


def format_throttle_note(scope_hosts: Iterable[str], *, now: Optional[float] = None) -> str:
    """Prompt block for the planner when its target is rate-limiting us."""
    rows = throttle_report(scope_hosts, now=now)
    if not rows:
        return ""
    profile = active_profile()
    base = profile.rate_per_second if profile else 0
    lines = ["## Target pushback (429/503 in the last 10 minutes)"]
    for row in rows[:5]:
        pace = round(base * row["rate_factor"], 2) if base else "unpaced"
        line = (f"- {row['host']}: {row['throttled_responses']} throttled responses; "
                f"pace now {pace} req/s")
        if row["cooling_down_seconds"]:
            line += f", cooling down {row['cooling_down_seconds']}s"
        lines.append(line)
    if any(row["throttled_responses"] >= HEAVY_THROTTLE_COUNT for row in rows):
        lines.append(
            "The target is rate-limiting this run. Do not start brute-force, fuzzing or "
            "wide scanner jobs against these hosts; finish confirming existing leads with "
            "few requests, and record throttled classes as inconclusive (rate-limited)."
        )
    else:
        lines.append("Requests are paced automatically; prefer low-volume checks on these hosts.")
    return "\n".join(lines)


# --- httpx adapter -----------------------------------------------------------

async def _httpx_request_hook(request) -> None:
    wait = reserve(request.url.host)
    if wait > 0:
        await asyncio.sleep(wait)


async def _httpx_response_hook(response) -> None:
    observe(response.request.url.host, response.status_code,
            response.headers.get("retry-after"))


def pacing_event_hooks() -> dict:
    """``event_hooks`` for an ``httpx.AsyncClient`` that sends target traffic."""
    return {"request": [_httpx_request_hook], "response": [_httpx_response_hook]}


# --- urllib adapter ----------------------------------------------------------

class PacingHandler(urllib.request.BaseHandler):
    """urllib handler that paces requests and watches for 429/503.

    Runs before ``HTTPErrorProcessor`` (order 1000) so throttled responses are
    seen before urllib raises them as ``HTTPError``.
    """

    handler_order = 900

    def http_request(self, request):
        wait = reserve(request.host.split(":")[0] if request.host else "")
        if wait > 0:
            time.sleep(wait)
        return request

    https_request = http_request

    def http_response(self, request, response):
        host = request.host.split(":")[0] if request.host else ""
        headers = getattr(response, "headers", None)
        observe(host, getattr(response, "status", 0) or response.getcode(),
                headers.get("retry-after") if headers is not None else None)
        return response

    https_response = http_response
