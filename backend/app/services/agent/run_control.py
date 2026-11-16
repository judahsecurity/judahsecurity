"""Operator stop/cancel, mid-run steer, and compact flags for in-flight runs.

The Agent WebSocket used to ``await invoke()`` inside the receive loop, so
Stop / ping messages could not be read until the run finished (and tokens
kept burning). Runs now register their asyncio Task here so the UI can cancel
them immediately.

Steer/compact/candidate-inbox queues are drained at the start of each think node so the
operator can redirect a hunt without killing it (CAI Ctrl+C analog).

Steers, compact flags, load briefs and price limits are in-memory only. The
external candidate inbox is durable (see "Durable candidate inbox" below)
because an accepted intake (202) is a promise to the operator that the lead
reaches the brain even if the backend restarts before the next think turn.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional

try:  # POSIX only; on other platforms the thread lock is the only guard.
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

_stop_requested: set[str] = set()
_running: dict[str, asyncio.Task] = {}
_steers: dict[str, List[str]] = {}
_compact_requested: set[str] = set()
_load_briefs: dict[str, List[str]] = {}
_price_limits: dict[str, float] = {}
_candidate_inbox: dict[str, List[Dict[str, Any]]] = {}
_inbox_orgs: dict[str, int] = {}
_inbox_lock = threading.RLock()
_MAX_INBOX = 25
_MAX_INBOX_FILE_BYTES = 1_000_000


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


# ------------------------------------------------------- durable candidate inbox
#
# Storage: one JSON-lines file per session next to the run snapshot,
# ``<run_snapshot._DIR>/{org}_{sid}.inbox.jsonl`` (0600, dir 0700), rewritten
# atomically (tmp + fsync + os.replace) under an exclusive ``fcntl.flock`` on a
# sibling ``.lock`` file plus a process-wide RLock. That makes queue/peek/ack
# safe across threads and across processes on one host. It is NOT a
# cross-host lock: ``sched-`` sessions keep their snapshot in the database
# (``AgentRunSnapshot``) but run_snapshot also always writes the file copy on
# the host that ran them, and the inbox lives on that same host. Scheduled
# runs spread over several workers would need an inbox table instead.
#
# Lifecycle (at-least-once):
#   queue_candidate     write-through: durable file first, then the in-memory copy.
#   claim_candidate_inbox  read pending items WITHOUT removing them.
#   ack_candidate_inbox    remove items by candidate_id once the caller has merged
#                       them into the brain AND the run snapshot holds them.
# A crash between merge and ack re-delivers the item on the next think turn;
# the merge dedups by candidate_id / root_cause, so it is reported as a
# duplicate and acked, never inserted twice.
#
# In-memory fast path: the raw payload stays cached in ``_candidate_inbox``.
# The file holds a copy whose free-text claim fields are passed through the
# snapshot redactor (same at-rest policy as run_snapshot). When the file is
# readable it is authoritative for *membership*; the cached raw copy is used
# for any item this process queued itself. Without an organization id (no
# snapshot path) the inbox is memory-only, as before.
#
# Run end does not clear the inbox: undrained items stay on disk and are
# drained by the next think turn of a resumed run (``_initialize_node``
# restores the brain from the snapshot; the think node then drains with the
# state's organization_id). ``clear_session_controls`` deletes them, since it
# means the session itself was torn down.

_REDACT_FIELDS = ("description", "claimed_request")


def _inbox_path(organization_id: int, session_id: str) -> Path:
    from app.services.agent import run_snapshot

    snap = run_snapshot._path(int(organization_id), session_id)
    return snap.with_name(snap.name[: -len(".json")] + ".inbox.jsonl")


def _resolve_org(session_id: str, organization_id: Optional[int]) -> Optional[int]:
    if organization_id:
        try:
            return int(organization_id)
        except (TypeError, ValueError):
            return None
    return _inbox_orgs.get(session_id)


@contextmanager
def _locked(path: Path) -> Iterator[None]:
    with _inbox_lock:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if fcntl is None:
            yield
            return
        fd = os.open(path.with_name(path.name + ".lock"), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


def _read_items(path: Path) -> List[Dict[str, Any]]:
    try:
        if path.stat().st_size > _MAX_INBOX_FILE_BYTES:
            logger.warning("candidate inbox %s exceeds %d bytes; ignored", path.name,
                           _MAX_INBOX_FILE_BYTES)
            return []
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    items: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            logger.warning("candidate inbox %s has a corrupt line; skipped", path.name)
            continue
        if isinstance(row, dict) and row:
            items.append(row)
    return items


def _write_items(path: Path, items: List[Dict[str, Any]]) -> None:
    if not items:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        return
    encoded = "".join(json.dumps(i, default=str, separators=(",", ":")) + "\n" for i in items)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _at_rest(payload: Dict[str, Any]) -> Dict[str, Any]:
    from app.services.agent.observability import redact_string

    row = dict(payload)
    for key in _REDACT_FIELDS:
        if isinstance(row.get(key), str):
            row[key] = redact_string(row[key])
    return row


def _key(payload: Dict[str, Any]) -> str:
    return str(payload.get("candidate_id") or "")


def _merged_view(session_id: str, durable: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Durable membership, raw in-memory copy where this process has one. Refreshes the cache."""
    cached = {_key(p): p for p in _candidate_inbox.get(session_id, []) if _key(p)}
    view = [dict(cached.get(_key(row)) or row) for row in durable]
    if view:
        _candidate_inbox[session_id] = [dict(p) for p in view]
    else:
        _candidate_inbox.pop(session_id, None)
    return view


def _durable_items(session_id: str, org: Optional[int]) -> Optional[List[Dict[str, Any]]]:
    """Pending items (merged view), or None when there is no durable store to read."""
    if not org:
        return None
    try:
        path = _inbox_path(org, session_id)
        with _locked(path):
            return _merged_view(session_id, _read_items(path))
    except OSError:
        logger.warning("candidate inbox read failed; using in-memory copy", exc_info=True)
        return None


def queue_candidate(
    session_id: str,
    payload: Dict[str, Any],
    organization_id: Optional[int] = None,
) -> bool:
    """Queue a validated, wrapped external candidate for the next think node.

    Write-through: with an organization id the item is appended to the durable
    inbox file before the in-memory cache, so a restart before the next think
    turn does not lose it. Returns False when the inbox (durable items
    included) is full. Raises OSError when the durable write fails so the
    caller can refuse the intake instead of promising delivery.
    """
    if not session_id or not isinstance(payload, dict):
        return False
    item = dict(payload)
    with _inbox_lock:
        org = _resolve_org(session_id, organization_id)
        if not org:
            box = _candidate_inbox.setdefault(session_id, [])
            if len(box) >= _MAX_INBOX:
                return False
            box.append(item)
            return True
        _inbox_orgs[session_id] = org
        path = _inbox_path(org, session_id)
        with _locked(path):
            durable = _read_items(path)
            if len(durable) >= _MAX_INBOX:
                _merged_view(session_id, durable)
                return False
            _write_items(path, durable + [_at_rest(item)])
            _candidate_inbox[session_id] = [
                p for p in _merged_view(session_id, durable) if _key(p) != _key(item)
            ] + [item]
        return True


def peek_candidate_inbox(
    session_id: Optional[str],
    organization_id: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Pending inbox items (durable ones included) without consuming them."""
    if not session_id:
        return []
    with _inbox_lock:
        durable = _durable_items(session_id, _resolve_org(session_id, organization_id))
        if durable is not None:
            return durable
        return [dict(p) for p in _candidate_inbox.get(session_id, [])]


def claim_candidate_inbox(
    session_id: Optional[str],
    organization_id: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Items to merge this think turn.

    Durable inbox: nothing is removed until ``ack_candidate_inbox``. Without a
    resolvable organization there is no durable copy to protect, so the
    memory-only queue is popped here (the pre-durable behaviour).
    """
    if not session_id:
        return []
    with _inbox_lock:
        if not _resolve_org(session_id, organization_id):
            return [p for p in _candidate_inbox.pop(session_id, []) if p]
        return [p for p in peek_candidate_inbox(session_id, organization_id) if p]


def ack_candidate_inbox(
    session_id: Optional[str],
    candidate_ids: Iterable[str],
    organization_id: Optional[int] = None,
) -> int:
    """Remove merged items (by candidate_id) from the durable inbox and the cache.

    Items queued after the caller's claim are kept. Returns how many were removed.
    """
    ids = {str(c) for c in candidate_ids if c}
    if not session_id or not ids:
        return 0
    with _inbox_lock:
        org = _resolve_org(session_id, organization_id)
        removed = 0
        if org:
            path = _inbox_path(org, session_id)
            with _locked(path):
                durable = _read_items(path)
                keep = [row for row in durable if _key(row) not in ids]
                removed = len(durable) - len(keep)
                if removed:
                    _write_items(path, keep)
                # A memory-only item (queued before the org was known) also goes.
                _candidate_inbox[session_id] = [
                    p for p in _candidate_inbox.get(session_id, []) if _key(p) not in ids
                ]
                _merged_view(session_id, keep)
            if not keep:
                _inbox_orgs.pop(session_id, None)
            return removed
        box = _candidate_inbox.get(session_id, [])
        keep = [p for p in box if _key(p) not in ids]
        removed = len(box) - len(keep)
        if keep:
            _candidate_inbox[session_id] = keep
        else:
            _candidate_inbox.pop(session_id, None)
        return removed


def drain_candidate_inbox(
    session_id: Optional[str],
    organization_id: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Claim and immediately ack everything (at-most-once; tests and teardown).

    The orchestrator uses claim + ack so an item survives a crash mid-merge.
    """
    if not session_id:
        return []
    with _inbox_lock:
        items = claim_candidate_inbox(session_id, organization_id)
        ack_candidate_inbox(session_id, [_key(p) for p in items], organization_id)
        return items


def clear_candidate_inbox(session_id: str, organization_id: Optional[int] = None) -> None:
    """Delete the in-memory and durable inbox for a torn-down session."""
    if not session_id:
        return
    with _inbox_lock:
        org = _resolve_org(session_id, organization_id)
        _candidate_inbox.pop(session_id, None)
        _inbox_orgs.pop(session_id, None)
        if not org:
            return
        try:
            path = _inbox_path(org, session_id)
            with _locked(path):
                _write_items(path, [])
        except OSError:
            logger.warning("candidate inbox clear failed", exc_info=True)


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


def clear_session_controls(session_id: str, organization_id: Optional[int] = None) -> None:
    """Drop steer/compact/load/limit state after a session is torn down.

    Also deletes the durable candidate inbox (org from the argument or from the
    org remembered at queue time). Not called on normal run end: undrained
    inbox items must survive until a resumed run drains them.
    """
    if not session_id:
        return
    _steers.pop(session_id, None)
    clear_candidate_inbox(session_id, organization_id)
    _compact_requested.discard(session_id)
    _load_briefs.pop(session_id, None)
    _price_limits.pop(session_id, None)
