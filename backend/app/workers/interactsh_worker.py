"""Single-owner Interactsh worker shared by all API replicas.

The API sends short RPC commands through Redis. This process owns the live
Interactsh clients and resumes their encrypted session files after a restart.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import threading
import time
from typing import Any

import redis

from app.services import interactsh_service

logger = logging.getLogger(__name__)
REQUEST_QUEUE = "aegis:interactsh:requests"


def _dispatch(operation: str, arguments: dict[str, Any]) -> dict[str, Any]:
    handlers = {
        "health": interactsh_service.health,
        "register": interactsh_service.register,
        "ensure_session": interactsh_service.ensure_session,
        "poll": interactsh_service.poll,
        "list": interactsh_service.list_sessions,
        "stop": interactsh_service.stop,
    }
    handler = handlers.get(operation)
    if handler is None:
        return {"success": False, "error": f"Unsupported Interactsh operation: {operation}"}
    return handler(**arguments)


def run() -> None:
    os.environ["AEGIS_INTERACTSH_LOCAL"] = "true"
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    client = redis.Redis.from_url(
        os.environ.get("REDIS_URL", "redis://redis:6379/0"),
        decode_responses=True,
        socket_connect_timeout=5,
        socket_timeout=10,
    )
    stop_event = threading.Event()

    def stop(*_args):
        stop_event.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    recovered = interactsh_service.recover_sessions()
    logger.info("Interactsh worker ready; recovered=%s", recovered.get("recovered", 0))

    while not stop_event.is_set():
        try:
            item = client.blpop(REQUEST_QUEUE, timeout=2)
            if not item:
                continue
            request = json.loads(item[1])
            response_key = str(request.get("response_key") or "")
            if not response_key.startswith("aegis:interactsh:response:"):
                continue
            try:
                result = _dispatch(
                    str(request.get("operation") or ""),
                    request.get("arguments") if isinstance(request.get("arguments"), dict) else {},
                )
            except Exception as exc:
                logger.exception("Interactsh command failed")
                result = {"success": False, "error": str(exc)}
            client.rpush(response_key, json.dumps(result, default=str))
            client.expire(response_key, 120)
        except redis.RedisError as exc:
            logger.warning("Redis unavailable to Interactsh worker: %s", exc)
            time.sleep(2)
        except (ValueError, TypeError) as exc:
            logger.warning("Discarding invalid Interactsh RPC request: %s", exc)


if __name__ == "__main__":
    run()
