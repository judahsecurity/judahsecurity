"""
Severity worker — the scheduled job that keeps sev_score current.

Every SEVERITY_EVAL_INTERVAL_SECONDS it re-evaluates the open findings
marked dirty (a scoring input changed — see app.services.severity_dirty),
in batches, until none are left. Every SEVERITY_FULL_SWEEP_HOURS it marks
every open finding dirty, to pick up anything changed outside the ORM (bulk
SQL, imports) or evidence that ages (exploit intel, KEV listings).
"""

from __future__ import annotations

import logging
import os
import signal
import threading
import time
from typing import Any, Dict

logger = logging.getLogger(__name__)

DEFAULT_INTERVAL_SECONDS = 60
MIN_INTERVAL_SECONDS = 30
DEFAULT_FULL_SWEEP_HOURS = 24
BATCH_SIZE = 500
MAX_BATCHES_PER_TICK = 40  # ≤ 20k findings per tick; the rest carry over

_shutdown = threading.Event()


def _int_env(name: str, default: int, minimum: int) -> int:
    try:
        return max(minimum, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


def tick(session_factory) -> Dict[str, Any]:
    """One scheduled run: drain dirty findings (bounded)."""
    from app.services.severity_evaluation import run_dirty_batch

    totals = {"selected": 0, "evaluated": 0, "failed": 0}
    for _ in range(MAX_BATCHES_PER_TICK):
        result = run_dirty_batch(session_factory, BATCH_SIZE)
        for k in totals:
            totals[k] += result[k]
        # Stop when drained, or when a whole batch failed (don't spin on errors).
        if result["selected"] < BATCH_SIZE or result["evaluated"] == 0 or _shutdown.is_set():
            break
    return totals


def full_sweep(session_factory) -> int:
    from app.services.severity_dirty import mark_all_open

    db = session_factory()
    try:
        n = mark_all_open(db)
        db.commit()
        return n
    finally:
        db.close()


def _handle_signal(_signum, _frame) -> None:
    _shutdown.set()


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    import app.models  # noqa: F401 — registers models and dirty tracking
    from app.db.database import SessionLocal

    interval = _int_env("SEVERITY_EVAL_INTERVAL_SECONDS", DEFAULT_INTERVAL_SECONDS, MIN_INTERVAL_SECONDS)
    sweep_every = _int_env("SEVERITY_FULL_SWEEP_HOURS", DEFAULT_FULL_SWEEP_HOURS, 1) * 3600
    last_sweep = time.monotonic()
    logger.info("Starting severity worker (interval=%ss, full sweep every %sh)", interval, sweep_every // 3600)

    while not _shutdown.is_set():
        try:
            if time.monotonic() - last_sweep >= sweep_every:
                logger.info("Severity full sweep: %d open findings queued", full_sweep(SessionLocal))
                last_sweep = time.monotonic()
            totals = tick(SessionLocal)
            if totals["selected"]:
                logger.info("Severity worker: evaluated %(evaluated)d/%(selected)d dirty findings (%(failed)d failed)", totals)
        except Exception:
            logger.exception("Severity worker cycle failed")
        _shutdown.wait(interval)
    logger.info("Severity worker stopped")


if __name__ == "__main__":
    main()
