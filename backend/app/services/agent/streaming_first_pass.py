"""Test observed inputs while the crawl is still mapping the application.

The pipeline used to crawl first and test afterwards, so a long crawl could
spend the run's budget before a single input was tested. On ginandjuice.shop
the catalog ``category`` parameter was discovered early, yet its SQLi
true/false check never ran.

While ``execute_deep_crawl`` runs, the crawl reports each harvested page here.
One background task, the only writer of the engagement brain during the
crawl, turns the partial crawl into a capability map, seeds coverage cells
for new inputs, and runs a small bounded first-pass batch
(``run_observed_input_batch``) through the normal tool path, so scope,
method policy, the request ceiling and the publication gate all still apply.
Remaining inputs are tested by the normal pipeline after the crawl returns.

Gated by ``AGENT_STREAMING_FIRST_PASS``. Off in the bounded pilot.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from contextvars import ContextVar
from typing import Any, Awaitable, Callable, Dict, Optional

logger = logging.getLogger(__name__)

# Called by the deep crawl with its live CrawlResult after each harvested page.
crawl_progress_hook: ContextVar[Optional[Callable[[Any], None]]] = ContextVar(
    "crawl_progress_hook", default=None)

BATCH_CHECKS = 8
BATCH_SECONDS = 60
# After the crawl returns, let an in-flight batch finish (it holds leases).
DRAIN_SECONDS = BATCH_SECONDS + 15
# Blocks that only mean "the crawl has not captured this input's original
# request yet"; the post-crawl pass must still try these inputs.
_PREMATURE_BLOCKS = frozenset({"observed_query_baseline_missing"})


def streaming_enabled() -> bool:
    from app.core.config import settings
    from app.services.agent.pilot_policy import current_pilot

    return bool(getattr(settings, "AGENT_STREAMING_FIRST_PASS", False)) and current_pilot() is None


def report_crawl_progress(result: Any) -> None:
    hook = crawl_progress_hook.get()
    if hook is None:
        return
    try:
        hook(result)
    except Exception:  # the crawl must never fail because of the tester
        logger.debug("streaming first-pass hook failed", exc_info=True)


class StreamingFirstPass:
    def __init__(self, manager: Any, target: str):
        self.manager = manager
        self.target = target
        self.started_at = time.time()
        self._latest: Any = None
        self._event = asyncio.Event()
        self._done = False
        self._signature = ""
        self.batches = 0
        self.inputs_seen = 0
        self.results: list[dict[str, Any]] = []
        self.errors: list[str] = []

    # -- called from the crawl ------------------------------------------------
    def notify(self, crawl_result: Any) -> None:
        self._latest = crawl_result
        self._event.set()

    def crawl_done(self) -> None:
        self._done = True
        self._event.set()

    # -- background task --------------------------------------------------------
    async def run(self) -> None:
        while not self._done:
            await self._event.wait()
            self._event.clear()
            if self._done:
                break
            try:
                if self._seed_new_inputs():
                    await self._run_batch()
            except Exception as exc:
                self.errors.append(type(exc).__name__)
                logger.warning("streaming first pass step failed: %s", type(exc).__name__)

    def _seed_new_inputs(self) -> bool:
        """Merge the partial map and seed cells; True when the input set grew."""
        from app.services.agent.capability_map import (
            build_capability_map_from_crawl, merge_capability_maps,
        )
        from app.services.agent.coverage_cells import seed_parameter_coverage_cells
        from app.services.agent.engagement_brain import engagement_brain_from_dict
        from app.services.agent.parameter_inventory import collect_parameter_inventory

        if self._latest is None:
            return False
        partial = build_capability_map_from_crawl(self._latest).to_dict()
        inventory = collect_parameter_inventory(partial)
        signature = hashlib.sha256(json.dumps(
            inventory, sort_keys=True, default=str).encode()).hexdigest()[:16]
        if signature == self._signature:
            return False
        self._signature = signature
        self.inputs_seen = len(inventory) if hasattr(inventory, "__len__") else self.inputs_seen
        # Union only: the final crawl result is merged on top of this.
        self.manager._capability_map = merge_capability_maps(
            getattr(self.manager, "_capability_map", None), partial)
        brain = engagement_brain_from_dict(getattr(self.manager, "_engagement_brain", None))
        seed_parameter_coverage_cells(brain, inventory)
        self.manager._engagement_brain = brain.to_dict()
        return True

    async def _run_batch(self) -> None:
        from app.services.agent.observed_input_batch import (
            pending_first_pass_cells, run_observed_input_batch,
        )

        if not pending_first_pass_cells(getattr(self.manager, "_engagement_brain", None) or {},
                                        target=self.target):
            return
        batch = await run_observed_input_batch(
            self.manager, target=self.target, max_checks=BATCH_CHECKS,
            max_seconds=BATCH_SECONDS,
        )
        self.batches += 1
        self.results.extend(row for row in batch.get("results") or [] if isinstance(row, dict))
        self._reopen_premature_blocks()

    def _reopen_premature_blocks(self) -> None:
        from app.services.agent.engagement_brain import engagement_brain_from_dict

        brain = engagement_brain_from_dict(getattr(self.manager, "_engagement_brain", None))
        reopened = 0
        for cell in brain.coverage_cells:
            if (cell.get("first_pass_blocked_reason") in _PREMATURE_BLOCKS
                    and float(cell.get("first_pass_at") or 0) >= self.started_at):
                cell["status"] = "untested"
                for key in ("reason", "first_pass_blocked_reason", "first_pass_outcome",
                            "first_pass_reason", "first_pass_at"):
                    cell.pop(key, None)
                reopened += 1
        if reopened:
            self.manager._engagement_brain = brain.to_dict()

    def summary(self) -> Dict[str, Any]:
        outcomes: Dict[str, int] = {}
        for row in self.results:
            outcome = str(row.get("outcome") or "unknown")
            outcomes[outcome] = outcomes.get(outcome, 0) + 1
        return {
            "batches": self.batches,
            "checks": len(self.results),
            "outcomes": outcomes,
            "candidates": sorted({str(row.get("candidate_id")) for row in self.results
                                  if row.get("candidate_id")}),
            "errors": self.errors[:5],
        }


async def run_with_streaming_first_pass(
    manager: Any, target: str, crawl: Callable[[], Awaitable[Dict[str, Any]]],
) -> Dict[str, Any]:
    """Run the crawl with first-pass testing alongside; return the crawl result."""
    if not target or not streaming_enabled():
        return await crawl()
    stream = StreamingFirstPass(manager, target)
    token = crawl_progress_hook.set(stream.notify)
    tester = asyncio.create_task(stream.run())
    try:
        result = await crawl()
    finally:
        crawl_progress_hook.reset(token)
        stream.crawl_done()
        try:
            await asyncio.wait_for(asyncio.shield(tester), timeout=DRAIN_SECONDS)
        except asyncio.TimeoutError:
            tester.cancel()
            stream.errors.append("drain_timeout")
        except Exception:
            stream.errors.append("tester_failed")
    summary = stream.summary()
    if isinstance(result, dict):
        result["streaming_first_pass"] = summary
        if summary["checks"] and isinstance(result.get("output"), str):
            outcomes = ", ".join(f"{k}={v}" for k, v in sorted(summary["outcomes"].items()))
            result["output"] += (
                f"\n\n## First pass during the crawl\n{summary['checks']} input checks ran while "
                f"mapping ({outcomes}). Candidates: {', '.join(summary['candidates']) or 'none'}. "
                "Untested inputs continue in the normal first pass."
            )
    return result
