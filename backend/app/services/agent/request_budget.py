"""Hard per-run ceiling on requests sent to the assessment target.

An operator's request ceiling used to be advisory outside the bounded pilot:
a standard run on ginandjuice.shop spent ~713 browser requests crawling 12
pages against a 500-request ceiling and never reached the input checks.

One ``RequestBudget`` per session counts every target request Aegis sends
itself: the shared httpx/urllib helpers (replays, mutations, probes, the
kickoff), both browsers' request routes, and the deep crawl. Discovery
(kickoff, crawls, maps, JS inspection) may use only ``limit - reserve``; the
reserve is kept for input testing and verification, so a long crawl can no
longer spend the whole ceiling. When discovery's share is gone, crawls stop
and the pipeline moves on to testing.

Tools whose traffic Aegis cannot count (subprocess scanners, background recon
workers, the external Interceptor, the probe sandbox, MCP calls) are refused
while a ceiling is active and reported as not run.

The budget lives in-process, keyed by organization and session, so a resumed
session keeps counting. A backend restart resets it.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Deque, Dict, Optional, Tuple

DISCOVERY = "discovery"
TESTING = "testing"
_clock = time.monotonic
_sleep = time.sleep

# Tools that send target traffic outside the counted transports.
UNMETERED_TOOLS = frozenset({
    "spawn_recon_workers", "wait_recon_workers", "execute_interceptor",
    "sandbox_shell", "run_custom_probe", "run_poc_python", "mcp_call", "mcp_connect",
})
# execute_* tools that do go through counted transports.
METERED_EXECUTE_TOOLS = frozenset({"execute_deep_crawl", "execute_browser"})


class RequestBudgetExhausted(RuntimeError):
    """The operator's request ceiling (or discovery's share of it) is spent."""


@dataclass
class RequestBudget:
    limit: int
    reserve: int
    rate_per_second: int = 0
    used: int = 0
    discovery_used: int = 0
    refused: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _recent: Deque[float] = field(default_factory=deque, repr=False)

    @property
    def discovery_limit(self) -> int:
        return max(0, self.limit - self.reserve)

    @property
    def exhausted(self) -> bool:
        return self.used >= self.limit

    @property
    def discovery_exhausted(self) -> bool:
        return self.discovery_used >= self.discovery_limit or self.exhausted

    def acquire(self, phase: str = TESTING) -> int:
        """Reserve one outbound request, respecting the ceiling and peak rate."""
        while True:
            with self._lock:
                if self.used >= self.limit:
                    self.refused += 1
                    raise RequestBudgetExhausted(
                        f"Request ceiling reached: {self.used}/{self.limit} target requests used. "
                        "No further target traffic is sent in this run.")
                if phase == DISCOVERY and self.discovery_used >= self.discovery_limit:
                    self.refused += 1
                    raise RequestBudgetExhausted(
                        f"Discovery share of the request ceiling is spent ({self.discovery_used}/"
                        f"{self.discovery_limit}); the remaining {self.limit - self.used} requests are "
                        "reserved for input testing and verification.")
                delay = 0.0
                if self.rate_per_second > 0:
                    now = _clock()
                    while self._recent and now - self._recent[0] >= 1.0:
                        self._recent.popleft()
                    if len(self._recent) >= self.rate_per_second:
                        delay = max(0.001, 1.0 - (now - self._recent[0]))
                    else:
                        self._recent.append(now)
                if not delay:
                    self.used += 1
                    if phase == DISCOVERY:
                        self.discovery_used += 1
                    return self.used
            _sleep(delay)

    def snapshot(self) -> Dict[str, int]:
        with self._lock:
            return {"limit": self.limit, "used": self.used, "reserve": self.reserve,
                    "discovery_limit": self.discovery_limit,
                    "discovery_used": self.discovery_used, "refused": self.refused,
                    "rate_per_second": self.rate_per_second}


current_request_budget: ContextVar[Optional[RequestBudget]] = ContextVar(
    "current_request_budget", default=None)
_budgets: Dict[Tuple[int, str], RequestBudget] = {}
_budgets_lock = threading.Lock()


def reserve_fraction() -> float:
    from app.core.config import settings

    try:
        value = float(getattr(settings, "AGENT_TESTING_RESERVE_FRACTION", 0.6))
    except (TypeError, ValueError):
        value = 0.6
    return min(max(value, 0.0), 0.95)


def budget_for_session(organization_id: int, session_id: str, limit: int) -> RequestBudget:
    """The session's budget, created on first use and kept across resumes.

    Raising the limit on a later turn extends the same counter; nothing resets
    what earlier turns already sent.
    """
    key = (int(organization_id or 0), str(session_id))
    with _budgets_lock:
        budget = _budgets.get(key)
        reserve = int(round(limit * reserve_fraction()))
        from app.core.config import settings
        rate = max(0, int(getattr(settings, "AGENT_TARGET_REQUESTS_PER_SECOND", 0)))
        if budget is None:
            budget = RequestBudget(limit=limit, reserve=reserve, rate_per_second=rate)
            _budgets[key] = budget
        elif limit != budget.limit or rate != budget.rate_per_second:
            with budget._lock:
                budget.limit, budget.reserve, budget.rate_per_second = limit, reserve, rate
        return budget


def existing_budget(organization_id: int, session_id: str) -> Optional[RequestBudget]:
    """The session's budget if an earlier turn created one (resume paths)."""
    with _budgets_lock:
        return _budgets.get((int(organization_id or 0), str(session_id)))


def resolve_limit(policy: Optional[dict]) -> int:
    """Operator policy wins; otherwise the deployment default (0 = no ceiling)."""
    from app.core.config import settings

    value = (policy or {}).get("max_target_requests")
    if value in (None, ""):
        value = getattr(settings, "AGENT_MAX_TARGET_REQUESTS", 0)
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def active() -> Optional[RequestBudget]:
    return current_request_budget.get()


def acquire(phase: str = TESTING) -> None:
    budget = current_request_budget.get()
    if budget is not None:
        budget.acquire(phase)


def is_unmetered_tool(tool_name: str) -> bool:
    name = str(tool_name or "")
    return name in UNMETERED_TOOLS or (
        name.startswith("execute_") and name not in METERED_EXECUTE_TOOLS)


def unmetered_refusal(tool_name: str) -> Optional[dict]:
    """Tool result for an uncountable tool under an active ceiling, else None."""
    budget = current_request_budget.get()
    if budget is None or not is_unmetered_tool(tool_name):
        return None
    return {
        "success": False,
        "error": "request_ceiling_unmetered_tool",
        "output": (
            f"{tool_name} was not run: it sends target requests Aegis cannot count against "
            f"this run's request ceiling ({budget.used}/{budget.limit} used). Report it as "
            "not run because of the ceiling, not as clean coverage."
        ),
    }


def httpx_event_hooks(phase: str = TESTING) -> dict:
    """httpx event hooks that count each request against the run's budget."""
    budget = current_request_budget.get()
    if budget is None:
        return {}

    async def count(_request) -> None:
        budget.acquire(phase)

    return {"request": [count]}


def urllib_handler(phase: str = TESTING):
    """A urllib handler that counts each request, or None without a budget."""
    budget = current_request_budget.get()
    if budget is None:
        return None
    from urllib.request import BaseHandler

    class RequestBudgetHandler(BaseHandler):
        handler_order = 100

        def http_request(self, request):
            budget.acquire(phase)
            return request

        https_request = http_request

    return RequestBudgetHandler()


def reset_for_tests() -> None:
    with _budgets_lock:
        _budgets.clear()
