"""Single-owner Interactsh worker shared by all API replicas.

The API sends short RPC commands through Redis. This process owns the live
Interactsh clients and resumes their encrypted session files after a restart.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import os
import signal
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import redis

_SERVICE_PATH = Path(__file__).resolve().parents[1] / "services" / "interactsh_service.py"
_SPEC = importlib.util.spec_from_file_location("aegis_interactsh_worker_service", _SERVICE_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError(f"Could not load Interactsh service from {_SERVICE_PATH}")
interactsh_service = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = interactsh_service
_SPEC.loader.exec_module(interactsh_service)

logger = logging.getLogger(__name__)
REQUEST_QUEUE = "aegis:interactsh:requests"


def rpc_healthcheck(timeout_seconds: int = 8) -> bool:
    """Confirm that the long-running worker consumes and answers Redis RPC."""
    client = redis.Redis.from_url(
        os.environ.get("REDIS_URL", "redis://redis:6379/0"),
        decode_responses=True,
        socket_connect_timeout=3,
        socket_timeout=timeout_seconds + 1,
    )
    request_id = uuid.uuid4().hex
    response_key = f"aegis:interactsh:response:{request_id}"
    request = json.dumps(
        {
            "id": request_id,
            "operation": "health",
            "arguments": {},
            "response_key": response_key,
        }
    )
    try:
        client.rpush(REQUEST_QUEUE, request)
        response = client.blpop(response_key, timeout=timeout_seconds)
        if not response:
            return False
        payload = json.loads(response[1])
        return isinstance(payload, dict) and payload.get("success") is True
    except (redis.RedisError, ValueError, TypeError):
        return False
    finally:
        try:
            client.delete(response_key)
        except redis.RedisError:
            pass


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
    if "--healthcheck" in sys.argv[1:]:
        raise SystemExit(0 if rpc_healthcheck() else 1)
    run()
