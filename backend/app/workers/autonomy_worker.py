"""Resume persisted tester-process turns after worker/container restarts."""

import asyncio
import logging
import os
import time

from app.services.agent.durable_hunt import run_worker_once

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Retention sweep for the append-only fact ledger, run at most hourly.
_FACT_EVENT_RETENTION_DAYS = max(1, int(os.environ.get("FACT_EVENT_RETENTION_DAYS") or 14))
_FACT_EVENT_PRUNE_INTERVAL_SECONDS = 3600.0


def _maybe_prune_fact_events(last_prune_at: float) -> float:
    """Prune consumed fact events on an hourly gate. Returns the new timestamp."""
    now = time.monotonic()
    if now - last_prune_at < _FACT_EVENT_PRUNE_INTERVAL_SECONDS:
        return last_prune_at
    try:
        from app.services.agent.fact_events import prune_consumed_fact_events

        deleted = prune_consumed_fact_events(_FACT_EVENT_RETENTION_DAYS)
        if deleted:
            logger.info("Pruned %d consumed fact events", deleted)
    except Exception:
        logger.exception("Fact event prune failed")
    return now


async def main() -> None:
    interval = max(2, min(int(os.environ.get("AUTONOMY_POLL_SECONDS") or 10), 60))
    last_prune_at = 0.0
    while True:
        try:
            result = await run_worker_once()
            if result:
                logger.info("Autonomy work: %s", result)
                continue
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Autonomy worker tick failed")
        last_prune_at = _maybe_prune_fact_events(last_prune_at)
        await asyncio.sleep(interval)


if __name__ == "__main__":
    asyncio.run(main())
