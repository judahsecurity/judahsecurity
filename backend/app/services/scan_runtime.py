"""Worker-local process tracking used for cooperative scan cancellation."""

from __future__ import annotations

import asyncio
import contextvars
import os
import signal
import subprocess
import threading
from collections import defaultdict
from typing import Any


_current_scan_id: contextvars.ContextVar[int | None] = contextvars.ContextVar(
    "current_scan_id", default=None
)
_processes: dict[int, list[tuple[Any, bool]]] = defaultdict(list)
_lock = threading.Lock()
_installed = False
_original_async_exec = asyncio.create_subprocess_exec
_original_async_shell = asyncio.create_subprocess_shell
_original_popen = subprocess.Popen


def set_current_scan(scan_id: int):
    return _current_scan_id.set(scan_id)


def reset_current_scan(token) -> None:
    _current_scan_id.reset(token)


def _register(process: Any, owns_process_group: bool) -> None:
    scan_id = _current_scan_id.get()
    if scan_id is None:
        return
    with _lock:
        if any(existing.pid == process.pid for existing, _group in _processes[scan_id]):
            return
        _processes[scan_id].append((process, owns_process_group))


async def _tracked_async_exec(*args, **kwargs):
    scan_id = _current_scan_id.get()
    owns_group = bool(scan_id is not None and os.name == "posix")
    if owns_group and "start_new_session" not in kwargs:
        kwargs["start_new_session"] = True
    process = await _original_async_exec(*args, **kwargs)
    _register(process, owns_group and kwargs.get("start_new_session", False))
    return process


async def _tracked_async_shell(*args, **kwargs):
    scan_id = _current_scan_id.get()
    owns_group = bool(scan_id is not None and os.name == "posix")
    if owns_group and "start_new_session" not in kwargs:
        kwargs["start_new_session"] = True
    process = await _original_async_shell(*args, **kwargs)
    _register(process, owns_group and kwargs.get("start_new_session", False))
    return process


class _TrackedPopen(_original_popen):
    def __init__(self, *args, **kwargs):
        scan_id = _current_scan_id.get()
        owns_group = bool(scan_id is not None and os.name == "posix")
        if owns_group and "start_new_session" not in kwargs:
            kwargs["start_new_session"] = True
        super().__init__(*args, **kwargs)
        _register(self, owns_group and kwargs.get("start_new_session", False))


def install_process_tracking() -> None:
    """Patch process launchers once inside the dedicated scanner worker."""
    global _installed
    if _installed:
        return
    asyncio.create_subprocess_exec = _tracked_async_exec
    asyncio.create_subprocess_shell = _tracked_async_shell
    subprocess.Popen = _TrackedPopen
    _installed = True


def _is_running(process: Any) -> bool:
    poll = getattr(process, "poll", None)
    if callable(poll):
        return poll() is None
    return getattr(process, "returncode", None) is None


def _signal_process(process: Any, owns_group: bool, sig: signal.Signals) -> None:
    if not _is_running(process):
        return
    try:
        if owns_group and os.name == "posix":
            os.killpg(process.pid, sig)
        elif sig == signal.SIGTERM:
            process.terminate()
        else:
            process.kill()
    except (ProcessLookupError, PermissionError, OSError):
        pass


async def terminate_scan_processes(scan_id: int, grace_seconds: float = 1.0) -> int:
    """Terminate, then kill, every live process attributed to ``scan_id``."""
    with _lock:
        processes = list(_processes.pop(scan_id, []))
    live = [(process, group) for process, group in processes if _is_running(process)]
    for process, group in live:
        _signal_process(process, group, signal.SIGTERM)
    if live and grace_seconds > 0:
        await asyncio.sleep(grace_seconds)
    for process, group in live:
        _signal_process(process, group, signal.SIGKILL)
    return len(live)


def discard_scan_processes(scan_id: int) -> None:
    with _lock:
        _processes.pop(scan_id, None)
