"""Run Brain hypothesis review beside, rather than ahead of, specialist work.

Review tasks hold only a copy of eligible coverage cells. They never mutate the
live Brain. A later sync/dispatch applies completed results after checking the
session key, observation digest, and execution attempt count.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from app.services.agent.brain_hypothesis_planner import (
    apply_reviewed_hypotheses,
    pending_hypothesis_cells,
    plan_coverage_hypotheses,
)
from app.services.agent.engagement_brain import EngagementBrain

logger = logging.getLogger(__name__)

ReviewKey = tuple[int | None, int | None, str, str]
_MAX_JOBS = 64
_RETRY_DELAY_SECONDS = 30


@dataclass
class _ReviewJob:
    task: asyncio.Task
    queued_at: float
    count: int


class AsyncHypothesisReviews:
    """Small, session-isolated in-process queue for optional model review."""

    def __init__(self) -> None:
        self._jobs: dict[ReviewKey, _ReviewJob] = {}
        self._retry_after: dict[ReviewKey, float] = {}

    def cancel(self, key: ReviewKey) -> None:
        job = self._jobs.pop(key, None)
        self._retry_after.pop(key, None)
        if job and not job.task.done():
            job.task.cancel()

    def collect(self, key: ReviewKey, brain: EngagementBrain) -> dict[str, Any]:
        job = self._jobs.get(key)
        if job is None:
            return {"status": "unchanged", "reviewed": 0, "hypotheses": 0}
        if not job.task.done():
            return {"status": "queued", "pending": job.count}
        del self._jobs[key]
        try:
            result = job.task.result()
        except asyncio.CancelledError:
            return {"status": "cancelled", "reviewed": 0, "hypotheses": 0}
        if result["status"] != "planned":
            self._retry_after[key] = time.monotonic() + _RETRY_DELAY_SECONDS
            return result
        self._retry_after.pop(key, None)
        applied = apply_reviewed_hypotheses(brain, result["rows"])
        return {"status": "applied" if applied["reviewed"] else "stale",
                **applied, "model_ms": result["model_ms"],
                "queue_to_collect_ms": round((time.monotonic() - job.queued_at) * 1000)}

    def queue(self, key: ReviewKey, brain: EngagementBrain,
              llm_factory: Callable[[], Any]) -> dict[str, Any]:
        now = time.monotonic()
        self._retry_after = {
            review_key: deadline for review_key, deadline in self._retry_after.items()
            if deadline > now
        }
        existing = self._jobs.get(key)
        if existing:
            return {"status": "queued", "pending": existing.count}
        if key in self._retry_after:
            return {"status": "cooldown", "retry_after_ms":
                    round((self._retry_after[key] - now) * 1000)}
        pending = pending_hypothesis_cells(brain)
        if not pending:
            return {"status": "unchanged", "reviewed": 0, "hypotheses": 0}
        if len(self._jobs) >= _MAX_JOBS:
            # Abandoned sessions must not retain unlimited model tasks/results.
            oldest = min(self._jobs, key=lambda review_key: self._jobs[review_key].queued_at)
            self.cancel(oldest)
        review_brain = EngagementBrain(
            target=brain.target,
            coverage_cells=[deepcopy(cell) for cell, _packet, _digest in pending],
        )
        original_attempts = {
            cell["id"]: int(cell.get("attempts") or 0)
            for cell, _packet, _digest in pending
        }

        async def review() -> dict[str, Any]:
            started = time.monotonic()
            try:
                # Provider routing can do synchronous DB/network checks. Keep
                # it off the event loop so the first specialist starts promptly.
                llm = await asyncio.to_thread(llm_factory)
                summary = await plan_coverage_hypotheses(review_brain, llm)
            except Exception as exc:  # noqa: BLE001 - optional review cannot fail dispatch
                logger.warning("Brain hypothesis review unavailable: %s", type(exc).__name__)
                return {"status": "unavailable", "reviewed": 0, "hypotheses": 0,
                        "error_type": type(exc).__name__,
                        "model_ms": round((time.monotonic() - started) * 1000)}
            rows = [
                {"id": cell["id"],
                 "digest": cell.get("llm_review_digest", ""),
                 "attempts": original_attempts[cell["id"]],
                 "hypothesis": deepcopy(cell.get("llm_hypothesis")),
                 "priority_rank": cell.get("llm_priority_rank")}
                for cell in review_brain.coverage_cells
                if cell.get("llm_review_digest")
            ]
            return {"status": "planned", "rows": rows,
                    "reviewed": summary["reviewed"],
                    "hypotheses": summary["hypotheses"],
                    "model_ms": round((time.monotonic() - started) * 1000)}

        self._jobs[key] = _ReviewJob(
            task=asyncio.create_task(review()),
            queued_at=time.monotonic(), count=len(pending),
        )
        # A completed job is kept until this session's next tool call. It may
        # then be merged into the latest Brain; no callback writes shared state.
        return {"status": "queued", "pending": len(pending)}
