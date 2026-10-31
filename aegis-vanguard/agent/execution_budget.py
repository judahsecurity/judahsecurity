"""Shared execution budget: guarantee breadth before depth across hunters.

The parallel fireteam fans out specialists that each run their own ReAct loop
against the *same* attack surface. Without coordination they re-issue identical
requests and spend the whole run deepening one input while most inputs never get
a first pass. This module is the process-wide throttle that fixes both:

* **Exact-repeat suppression** — an identical ``(method, url, body)`` request is
  allowed only a small number of times; further repeats are suppressed without a
  network call. This kills the "313 exact repeat calls" failure mode.
* **GET first-pass reservation** — once the global GET budget is spent, only the
  *first* occurrence of a never-before-seen request signature is allowed. Deep
  retries of already-probed inputs stop so the remaining budget is reserved for
  unseen inputs. This is "reserve GET for one bounded pass on each eligible
  observed input; stop retries when the budget is exhausted."

Enforcement is **opt-in per assessment**: ``get_execution_budget()`` returns the
active budget only after ``activate_execution_budget()`` has been called (done
once by ``run_pentest``). Unit tests and the deterministic probe fixtures that do
not activate it see no behavior change.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from typing import Dict, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def _env_int(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, "").strip())
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def request_signature(method: str, url: str, body: str = "") -> str:
    """Canonical identity of a request for repeat detection.

    Query parameters are sorted so cosmetically reordered-but-identical requests
    collapse to one signature; the payload values are preserved so a mutated
    probe (``category=1`` vs ``category=1' --``) is correctly a *different*
    signature and never suppressed.
    """
    parts = urlsplit((url or "").strip())
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)))
    canonical_url = urlunsplit((
        parts.scheme.lower(), parts.netloc.lower(), parts.path, query, "",
    ))
    return "\n".join([(method or "GET").upper(), canonical_url, body or ""])


@dataclass
class BudgetDecision:
    allowed: bool
    reason: str = ""
    signature: str = ""
    repeat_index: int = 0


@dataclass
class ExecutionBudget:
    """Thread-safe request budget shared across concurrent hunters."""

    get_budget: int = 1500
    max_exact_repeats: int = 3
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    _seen: Dict[str, int] = field(default_factory=dict, repr=False)
    _get_spent: int = 0
    _suppressed_repeat: int = 0
    _suppressed_over_budget: int = 0
    _allowed: int = 0

    def check(self, method: str, url: str, body: str = "") -> BudgetDecision:
        """Reserve one request. Returns whether the caller may hit the network."""
        method_u = (method or "GET").upper()
        sig = request_signature(method_u, url, body)
        is_get = method_u in {"GET", "HEAD"}
        with self._lock:
            prior = self._seen.get(sig, 0)

            # Hard cap on identical requests regardless of method.
            if prior >= self.max_exact_repeats:
                self._suppressed_repeat += 1
                return BudgetDecision(
                    allowed=False,
                    reason=f"exact-repeat budget exhausted after {prior} identical calls",
                    signature=sig,
                    repeat_index=prior,
                )

            # Once the GET budget is spent, admit only brand-new signatures so
            # the remaining allowance reaches untested inputs (breadth > depth).
            if is_get and self._get_spent >= self.get_budget and prior > 0:
                self._suppressed_over_budget += 1
                return BudgetDecision(
                    allowed=False,
                    reason=(
                        "GET budget exhausted; reserved for first passes on "
                        "unseen inputs — re-probing an already-seen input is blocked"
                    ),
                    signature=sig,
                    repeat_index=prior,
                )

            self._seen[sig] = prior + 1
            self._allowed += 1
            if is_get:
                self._get_spent += 1
            return BudgetDecision(allowed=True, signature=sig, repeat_index=prior)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "get_budget": self.get_budget,
                "max_exact_repeats": self.max_exact_repeats,
                "distinct_signatures": len(self._seen),
                "get_spent": self._get_spent,
                "allowed": self._allowed,
                "suppressed_exact_repeat": self._suppressed_repeat,
                "suppressed_over_budget": self._suppressed_over_budget,
            }


_LOCK = threading.RLock()
_BUDGET: Optional[ExecutionBudget] = None


def activate_execution_budget(
    get_budget: Optional[int] = None,
    max_exact_repeats: Optional[int] = None,
) -> ExecutionBudget:
    """Create (or replace) the active budget for the current assessment."""
    global _BUDGET
    with _LOCK:
        _BUDGET = ExecutionBudget(
            get_budget=get_budget if get_budget is not None
            else _env_int("AEGIS_GET_BUDGET", 1500),
            max_exact_repeats=max_exact_repeats if max_exact_repeats is not None
            else _env_int("AEGIS_MAX_EXACT_REPEATS", 3),
        )
        return _BUDGET


def get_execution_budget() -> Optional[ExecutionBudget]:
    """Return the active budget, or None when enforcement is not activated."""
    with _LOCK:
        return _BUDGET


def deactivate_execution_budget() -> None:
    global _BUDGET
    with _LOCK:
        _BUDGET = None


__all__ = [
    "BudgetDecision",
    "ExecutionBudget",
    "activate_execution_budget",
    "deactivate_execution_budget",
    "get_execution_budget",
    "request_signature",
]
