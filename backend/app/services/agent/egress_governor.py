"""Per-host pacing and a hard request count for autonomous target traffic.

Tool-start limits do not bound how many HTTP requests a tool sends. This
module enforces pacing at the request boundary instead: every in-process
``httpx`` request, including each redirect hop, passes through
``RequestGovernor`` while an autonomous turn has one installed. Only hosts in
the turn's authorized scope are governed, so model-provider and internal calls
made during the same turn are unaffected.

Command-line tools run as subprocesses and bypass this boundary; they keep
their own rate flags. The scoped browser paces document, fetch and XHR
requests through the same governor.
"""

from __future__ import annotations

import asyncio
import logging
import time
from contextvars import ContextVar
from email.utils import parsedate_to_datetime
from typing import Iterable

import httpx

logger = logging.getLogger(__name__)

MAX_BACKOFF_SECONDS = 60.0
# Browser requests the governor paces. Static subresources load unpaced so a
# page still renders; they are bounded by the browser tools' own caps.
PACED_BROWSER_TYPES = frozenset({"document", "fetch", "xhr"})
_BACKOFF_STATUSES = frozenset({429, 503})


class RequestBudgetExceeded(httpx.TransportError):
    """Raised instead of sending once the turn's request count is spent."""


def _host_matches(host: str, allowed: str) -> bool:
    host = host.lower().rstrip(".")
    allowed = allowed.lower().rstrip(".")
    if allowed.startswith("*."):
        return host.endswith(allowed[1:])
    return host == allowed


def parse_retry_after(value: str | None, *, now: float | None = None) -> float | None:
    """Seconds to wait from a Retry-After header (delta or HTTP date)."""
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(value).timestamp()
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    return max(0.0, when - (time.time() if now is None else now))


class RequestGovernor:
    """Shared, per-host pacing for one autonomous turn."""

    def __init__(
        self,
        hosts: Iterable[str],
        *,
        rate_per_second: float = 1.0,
        max_requests: int = 0,
    ):
        self.hosts = tuple(h for h in (str(x).strip() for x in hosts) if h)
        self.interval = 1.0 / max(0.01, float(rate_per_second))
        self.max_requests = max(0, int(max_requests))
        self.total = 0
        self.denied = 0
        self.per_host: dict[str, int] = {}
        self.backoffs = 0
        self._next_at: dict[str, float] = {}
        self._streak: dict[str, int] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def governs(self, host: str | None) -> bool:
        return bool(host) and any(_host_matches(host, allowed) for allowed in self.hosts)

    def _lock(self, host: str) -> asyncio.Lock:
        lock = self._locks.get(host)
        if lock is None:
            lock = self._locks[host] = asyncio.Lock()
        return lock

    async def acquire(self, host: str) -> bool:
        """Wait for this host's slot. False when the turn's count is spent."""
        host = host.lower().rstrip(".")
        async with self._lock(host):
            if self.max_requests and self.total >= self.max_requests:
                self.denied += 1
                return False
            delay = self._next_at.get(host, 0.0) - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)
            self.total += 1
            self.per_host[host] = self.per_host.get(host, 0) + 1
            self._next_at[host] = time.monotonic() + self.interval
            return True

    def observe(self, host: str, status: int, retry_after: str | None = None) -> None:
        """Back off from a host that signals overload; reset after success."""
        host = host.lower().rstrip(".")
        if status not in _BACKOFF_STATUSES:
            self._streak[host] = 0
            return
        streak = self._streak.get(host, 0) + 1
        self._streak[host] = streak
        wait = parse_retry_after(retry_after)
        if wait is None:
            wait = 2.0 ** streak
        wait = min(MAX_BACKOFF_SECONDS, wait)
        self.backoffs += 1
        self._next_at[host] = max(self._next_at.get(host, 0.0), time.monotonic() + wait)

    def summary(self) -> dict:
        return {
            "requests": self.total,
            "denied": self.denied,
            "backoffs": self.backoffs,
            "per_host": dict(sorted(self.per_host.items())),
            "max_requests": self.max_requests,
        }


current_request_governor: ContextVar[RequestGovernor | None] = ContextVar(
    "current_request_governor", default=None,
)

_installed = False


def install_httpx_governor() -> None:
    """Route every async httpx request through the active governor (idempotent)."""
    global _installed
    if _installed:
        return
    name = "_send_single_request" if hasattr(httpx.AsyncClient, "_send_single_request") else "send"
    original = getattr(httpx.AsyncClient, name)

    async def governed(self, request, *args, **kwargs):
        governor = current_request_governor.get()
        host = request.url.host
        if governor is None or not governor.governs(host):
            return await original(self, request, *args, **kwargs)
        if not await governor.acquire(host):
            raise RequestBudgetExceeded(
                f"Autonomous request budget of {governor.max_requests} reached; "
                "no further target requests are sent this turn",
                request=request,
            )
        response = await original(self, request, *args, **kwargs)
        governor.observe(host, response.status_code, response.headers.get("retry-after"))
        return response

    governed.__wrapped__ = original  # type: ignore[attr-defined]
    setattr(httpx.AsyncClient, name, governed)
    _installed = True
