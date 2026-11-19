"""Run purse: one spend account for every model call in a run, nested ones included.

Before this, the run's price limit was checked against the orchestrator's own
token usage, so specialist model calls inside a fireteam wave were not counted
(see docs/ASSESSMENT_RELIABILITY.md). The purse fixes that:

* Every model call goes through ``orchestrator._ledger_llm_call``, which
  records its estimated cost here. Purses are keyed by the action-ledger run
  id, which specialists inherit, so nested calls land in the same purse.
* A specialist is admitted only if the purse can **reserve** its spend cap
  next to what is already spent and what other running specialists hold.
  The reservation is released when the specialist finishes.
* A small wrap-up reserve (:data:`WRAPUP_FRACTION` of the limit) is kept back
  for the final report, so a run that hits its cap still writes one.
* On resume the purse starts from the cost already recorded in the run state.

A limit of 0 means unlimited, matching ``price_limit_usd``.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional

WRAPUP_FRACTION = 0.05
WRAPUP_KINDS = frozenset({"agent_report"})
DEFAULT_SPECIALIST_RESERVE_USD = 0.5


class RunBudgetExhausted(RuntimeError):
    """Raised instead of making a model call the run can no longer pay for."""


@dataclass
class RunPurse:
    limit_usd: float = 0.0
    spent_usd: float = 0.0
    reserved: dict[str, float] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    @property
    def unlimited(self) -> bool:
        return self.limit_usd <= 0

    def _working_limit(self) -> float:
        return self.limit_usd * (1.0 - WRAPUP_FRACTION)

    def allows_call(self, kind: str = "") -> bool:
        if self.unlimited:
            return True
        with self._lock:
            ceiling = self.limit_usd if kind in WRAPUP_KINDS else self._working_limit()
            return self.spent_usd < ceiling

    def working_budget_left(self) -> float:
        if self.unlimited:
            return float("inf")
        with self._lock:
            return self._working_limit() - self.spent_usd - sum(self.reserved.values())

    def reserve(self, holder: str, amount_usd: float) -> bool:
        if self.unlimited:
            return True
        amount = max(0.0, float(amount_usd or 0.0))
        with self._lock:
            free = self._working_limit() - self.spent_usd - sum(self.reserved.values())
            if free < amount or self.spent_usd >= self._working_limit():
                return False
            self.reserved[holder] = amount
            return True

    def release(self, holder: str) -> None:
        with self._lock:
            self.reserved.pop(holder, None)

    def record(self, cost_usd: float) -> None:
        if cost_usd and cost_usd > 0:
            with self._lock:
                self.spent_usd += float(cost_usd)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "limit_usd": self.limit_usd,
                "spent_usd": round(self.spent_usd, 6),
                "reserved_usd": round(sum(self.reserved.values()), 6),
                "holders": sorted(self.reserved),
            }


_PURSES: "OrderedDict[str, RunPurse]" = OrderedDict()
_PURSES_LOCK = threading.Lock()
_MAX_PURSES = 512


def purse_for(run_id: Optional[str], *, limit_usd: Optional[float] = None,
              spent_usd: Optional[float] = None) -> Optional[RunPurse]:
    """Get or create the purse for ``run_id`` (the action-ledger run).

    ``limit_usd`` updates the limit (an operator may change it mid-run).
    ``spent_usd`` is what the run state already recorded; the purse never goes
    below it, so a resumed run starts from its real spend.
    """
    if not run_id:
        return None
    with _PURSES_LOCK:
        purse = _PURSES.get(run_id)
        if purse is None:
            purse = RunPurse()
            _PURSES[run_id] = purse
            while len(_PURSES) > _MAX_PURSES:
                _PURSES.popitem(last=False)
        else:
            _PURSES.move_to_end(run_id)
    if limit_usd is not None:
        purse.limit_usd = max(0.0, float(limit_usd or 0.0))
    if spent_usd is not None:
        with purse._lock:
            purse.spent_usd = max(purse.spent_usd, float(spent_usd or 0.0))
    return purse


def get_purse(run_id: Optional[str]) -> Optional[RunPurse]:
    if not run_id:
        return None
    with _PURSES_LOCK:
        return _PURSES.get(run_id)


def drop_purse(run_id: Optional[str]) -> None:
    with _PURSES_LOCK:
        _PURSES.pop(run_id or "", None)


def call_cost_usd(llm, response) -> float:
    from app.services.agent.observability import (
        estimate_cost_usd, model_id, usage_from_llm_response,
    )

    usage = usage_from_llm_response(response)
    model = model_id(llm) or model_id(getattr(llm, "primary", None))
    return estimate_cost_usd(model, usage["input_tokens"], usage["output_tokens"])


__all__ = [
    "DEFAULT_SPECIALIST_RESERVE_USD",
    "RunBudgetExhausted",
    "RunPurse",
    "WRAPUP_FRACTION",
    "call_cost_usd",
    "drop_purse",
    "get_purse",
    "purse_for",
]
