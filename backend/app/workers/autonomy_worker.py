"""Resume persisted tester-process turns after worker/container restarts."""

import asyncio
import logging
import os

from app.services.agent.durable_hunt import run_worker_once

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def main() -> None:
    interval = max(2, min(int(os.environ.get("AUTONOMY_POLL_SECONDS") or 10), 60))
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
        await asyncio.sleep(interval)


if __name__ == "__main__":
    asyncio.run(main())
