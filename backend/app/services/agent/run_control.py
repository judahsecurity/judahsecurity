"""Operator stop/cancel, mid-run steer, and compact flags for in-flight runs.

The Agent WebSocket used to ``await invoke()`` inside the receive loop, so
Stop / ping messages could not be read until the run finished (and tokens
kept burning). Runs now register their asyncio Task here so the UI can cancel
them immediately.

Steer/compact queues are drained at the start of each think node so the
operator can redirect a hunt without killing it (CAI Ctrl+C analog).
"""

from __future__ import annotations

import asyncio
from typing import List, Optional

_stop_requested: set[str] = set()
_running: dict[str, asyncio.Task] = {}
_steers: dict[str, List[str]] = {}
_compact_requested: set[str] = set()
_load_briefs: dict[str, List[str]] = {}
_price_limits: dict[str, float] = {}


def register_run(session_id: str, task: Optional[asyncio.Task]) -> None:
    if not session_id or task is None:
        return
    _running[session_id] = task
    _stop_requested.discard(session_id)


def unregister_run(session_id: str, task: Optional[asyncio.Task] = None) -> None:
    if not session_id:
        return
    current = _running.get(session_id)
    if task is None or current is task:
        _running.pop(session_id, None)


def request_stop(session_id: str) -> bool:
    """Mark the session stopped and cancel its running task.

    Returns True if an in-flight task was cancelled.
    """
    if not session_id:
        return False
    _stop_requested.add(session_id)
    task = _running.get(session_id)
    if task is not None and not task.done():
        task.cancel()
        return True
    return False


def is_stop_requested(session_id: Optional[str]) -> bool:
    if not session_id:
        return False
    return session_id in _stop_requested


def clear_stop(session_id: str) -> None:
    if session_id:
        _stop_requested.discard(session_id)


def has_running_task(session_id: str) -> bool:
    task = _running.get(session_id)
    return bool(task is not None and not task.done())


def queue_steer(session_id: str, message: str) -> bool:
    """Queue an operator instruction for the next think node.

    Returns True when a run is in flight (the steer will be consumed).
    The message is still queued if no run is active so the next invoke sees it.
    """
    if not session_id or not (message or "").strip():
        return False
    _steers.setdefault(session_id, []).append(message.strip()[:4000])
    return has_running_task(session_id)


def drain_steers(session_id: Optional[str]) -> List[str]:
    if not session_id:
        return []
    notes = _steers.pop(session_id, [])
    return [n for n in notes if n]


def request_compact(session_id: str) -> None:
    if session_id:
        _compact_requested.add(session_id)


def consume_compact(session_id: Optional[str]) -> bool:
    if not session_id or session_id not in _compact_requested:
        return False
    _compact_requested.discard(session_id)
    return True


def queue_load_brief(session_id: str, brief: str) -> None:
    if not session_id or not (brief or "").strip():
        return
    _load_briefs.setdefault(session_id, []).append(brief.strip()[:12000])


def drain_load_briefs(session_id: Optional[str]) -> List[str]:
    if not session_id:
        return []
    return _load_briefs.pop(session_id, [])


def set_price_limit(session_id: str, limit_usd: float) -> None:
    if session_id:
        _price_limits[session_id] = float(limit_usd)


def get_price_limit(session_id: Optional[str]) -> Optional[float]:
    if not session_id:
        return None
    return _price_limits.get(session_id)


def clear_session_controls(session_id: str) -> None:
    """Drop steer/compact/load/limit state after a session is torn down."""
    if not session_id:
        return
    _steers.pop(session_id, None)
    _compact_requested.discard(session_id)
    _load_briefs.pop(session_id, None)
    _price_limits.pop(session_id, None)
