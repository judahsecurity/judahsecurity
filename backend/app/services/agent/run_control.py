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
It has two stores behind one API (file on one host, database across hosts);
see ``_inbox_backend``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

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
_DEFAULT_CLAIM_STALE_SECONDS = 600


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
# Two stores share one API (``_inbox_backend`` picks per session):
#
# File store: one JSON-lines file per session next to the run snapshot,
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
#   queue_candidate     write-through: durable store first, then the in-memory copy.
#   claim_candidate_inbox  read pending items WITHOUT removing them (file: all of
#                       them; database: the unclaimed or stale ones, now claimed).
#   ack_candidate_inbox    remove items by candidate_id once the caller has merged
#                       them into the brain AND the run snapshot holds them.
# A crash between merge and ack re-delivers the item on the next think turn;
# the merge dedups by candidate_id / root_cause, so it is reported as a
# duplicate and acked, never inserted twice.
#
# In-memory fast path: the raw payload stays cached in ``_candidate_inbox``.
# The durable store holds a copy whose free-text claim fields are passed through the
# snapshot redactor (same at-rest policy as run_snapshot). When the store is
# readable it is authoritative for *membership*; the cached raw copy is used
# for any item this process queued itself. Without an organization id (no
# snapshot path) the inbox is memory-only, as before.
#
# Run end does not clear the inbox: undrained items stay durable and are
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


# ------------------------------------------------------------ backend selection


def _inbox_backend(session_id: str) -> str:
    """``"db"`` or ``"file"`` for this session's durable inbox.

    ``AEGIS_CANDIDATE_INBOX_BACKEND``: ``db`` (every session; use for
    multi-host deployments), ``file`` (every session; single host), or unset /
    ``auto`` (default): ``db`` for ``sched-`` sessions, whose run snapshot
    already lives in the database and whose turns may run on any worker, and
    ``file`` for everything else (unchanged behaviour).
    """
    mode = (os.environ.get("AEGIS_CANDIDATE_INBOX_BACKEND") or "auto").strip().lower()
    if mode in ("db", "database"):
        return "db"
    if mode == "file":
        return "file"
    return "db" if str(session_id).startswith("sched-") else "file"


def _claim_stale_after() -> timedelta:
    try:
        seconds = int(os.environ.get("AEGIS_CANDIDATE_INBOX_CLAIM_STALE_SECONDS")
                      or _DEFAULT_CLAIM_STALE_SECONDS)
    except ValueError:
        seconds = _DEFAULT_CLAIM_STALE_SECONDS
    return timedelta(seconds=max(0, seconds))


class InboxStoreError(OSError):
    """The durable inbox store could not be written (the intake must refuse)."""


# Tests (and callers with their own engine) may replace this with a sessionmaker.
_inbox_db_factory: Any = None


def _db_session():
    factory = _inbox_db_factory
    if factory is None:
        from app.db.database import SessionLocal

        factory = SessionLocal
    return factory()


def _db_model():
    from app.models.agent_autonomy_work import AgentCandidateInbox

    return AgentCandidateInbox


def _db_lock_session(db: Any, org: int, session_id: str) -> None:
    """Serialize queue (cap check + insert) per session across hosts on Postgres."""
    if db.get_bind().dialect.name != "postgresql":
        return
    from sqlalchemy import text

    digest = hashlib.sha256(f"agent_candidate_inbox:{org}:{session_id}".encode()).digest()
    key = int.from_bytes(digest[:8], "big", signed=True)
    db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})


def _db_rows(db: Any, org: int, session_id: str) -> List[Any]:
    model = _db_model()
    return (db.query(model)
            .filter(model.organization_id == org, model.session_id == session_id)
            .order_by(model.id).all())


def _row_payload(row: Any) -> Dict[str, Any]:
    payload = dict(row.payload or {}) if isinstance(row.payload, dict) else {}
    payload.setdefault("candidate_id", row.candidate_id)
    return payload


def _db_queue(org: int, session_id: str, item: Dict[str, Any]) -> bool:
    from sqlalchemy.exc import IntegrityError, SQLAlchemyError

    model = _db_model()
    cid = _key(item)
    if not cid:
        return False
    try:
        with _db_session() as db:
            _db_lock_session(db, org, session_id)
            count = (db.query(model)
                     .filter(model.organization_id == org, model.session_id == session_id)
                     .count())
            if count >= _MAX_INBOX:
                return False
            db.add(model(
                organization_id=org, session_id=session_id, candidate_id=cid[:128],
                root_cause=str(item.get("root_cause") or ""), payload=_at_rest(item),
                created_at=datetime.utcnow(),
            ))
            try:
                db.commit()
            except IntegrityError:
                # Same candidate id already queued (another worker won the race):
                # it is durable, which is all the caller needs.
                db.rollback()
            return True
    except SQLAlchemyError as exc:
        raise InboxStoreError(f"candidate inbox database write failed: {exc.__class__.__name__}") from exc


def _db_peek(org: int, session_id: str) -> List[Dict[str, Any]]:
    with _db_session() as db:
        return [_row_payload(r) for r in _db_rows(db, org, session_id)]


def _db_claim(org: int, session_id: str) -> List[Dict[str, Any]]:
    """Stamp unclaimed or stale rows with a fresh token and return them."""
    from sqlalchemy import or_

    model = _db_model()
    now = datetime.utcnow()
    cutoff = now - _claim_stale_after()
    token = uuid.uuid4().hex
    eligible = or_(model.claimed_at.is_(None), model.claimed_at < cutoff)
    with _db_session() as db:
        query = (db.query(model.id)
                 .filter(model.organization_id == org, model.session_id == session_id, eligible)
                 .order_by(model.id))
        if db.get_bind().dialect.name == "postgresql":
            query = query.with_for_update(skip_locked=True)
        ids = [row_id for (row_id,) in query.all()]
        if not ids:
            db.rollback()
            return []
        # Re-check eligibility in the UPDATE itself: on SQLite (no row locks) a
        # concurrent claimer that committed first leaves these rows ineligible.
        (db.query(model)
         .filter(model.id.in_(ids), eligible)
         .update({model.claimed_at: now, model.claim_token: token}, synchronize_session=False))
        rows = (db.query(model).filter(model.claim_token == token).order_by(model.id).all())
        payloads = [_row_payload(r) for r in rows]
        db.commit()
        return payloads


def _db_ack(org: int, session_id: str, ids: set) -> Tuple[int, List[Dict[str, Any]]]:
    model = _db_model()
    with _db_session() as db:
        removed = (db.query(model)
                   .filter(model.organization_id == org, model.session_id == session_id,
                           model.candidate_id.in_(sorted(ids)), model.claimed_at.isnot(None))
                   .delete(synchronize_session=False))
        db.commit()
        remaining = [_row_payload(r) for r in _db_rows(db, org, session_id)]
    return int(removed or 0), remaining


def _db_clear(org: int, session_id: str) -> None:
    model = _db_model()
    with _db_session() as db:
        (db.query(model)
         .filter(model.organization_id == org, model.session_id == session_id)
         .delete(synchronize_session=False))
        db.commit()


def _durable_items(session_id: str, org: Optional[int]) -> Optional[List[Dict[str, Any]]]:
    """Pending items (merged view), or None when there is no durable store to read."""
    if not org:
        return None
    if _inbox_backend(session_id) == "db":
        try:
            durable = _db_peek(org, session_id)
        except Exception:
            logger.warning("candidate inbox database read failed; using in-memory copy",
                           exc_info=True)
            return None
        with _inbox_lock:
            return _merged_view(session_id, durable)
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

    Write-through: with an organization id the item is written to the durable
    inbox (file or database row, see ``_inbox_backend``) before the in-memory
    cache, so a restart before the next think turn does not lose it. Returns
    False when the inbox (durable items included) is full. Raises OSError when
    the durable write fails so the caller can refuse the intake instead of
    promising delivery.
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
        if _inbox_backend(session_id) == "db":
            if not _db_queue(org, session_id, item):
                return False
            cached = [p for p in _candidate_inbox.get(session_id, []) if _key(p) != _key(item)]
            _candidate_inbox[session_id] = cached + [item]
            return True
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

    Durable inbox: nothing is removed until ``ack_candidate_inbox``. The
    database store hands each row to one claimer at a time (until the claim
    goes stale); the file store returns every pending item. Without a
    resolvable organization there is no durable copy to protect, so the
    memory-only queue is popped here (the pre-durable behaviour).
    """
    if not session_id:
        return []
    with _inbox_lock:
        org = _resolve_org(session_id, organization_id)
        if not org:
            return [p for p in _candidate_inbox.pop(session_id, []) if p]
        if _inbox_backend(session_id) != "db":
            return [p for p in peek_candidate_inbox(session_id, organization_id) if p]
    try:
        claimed = _db_claim(org, session_id)
    except Exception:
        logger.warning("candidate inbox database claim failed; retried next turn", exc_info=True)
        return []
    with _inbox_lock:
        cached = {_key(p): p for p in _candidate_inbox.get(session_id, []) if _key(p)}
        return [dict(cached.get(_key(row)) or row) for row in claimed if row]


def ack_candidate_inbox(
    session_id: Optional[str],
    candidate_ids: Iterable[str],
    organization_id: Optional[int] = None,
) -> int:
    """Remove merged items (by candidate_id) from the durable inbox and the cache.

    Items queued after the caller's claim are kept (the database store deletes
    only claimed rows). Returns how many were removed.
    """
    ids = {str(c) for c in candidate_ids if c}
    if not session_id or not ids:
        return 0
    with _inbox_lock:
        org = _resolve_org(session_id, organization_id)
        removed = 0
        if org and _inbox_backend(session_id) == "db":
            try:
                removed, keep = _db_ack(org, session_id, ids)
            except Exception:
                logger.warning("candidate inbox database ack failed; item re-delivered",
                               exc_info=True)
                return 0
            _candidate_inbox[session_id] = [
                p for p in _candidate_inbox.get(session_id, []) if _key(p) not in ids
            ]
            _merged_view(session_id, keep)
            if not keep:
                _inbox_orgs.pop(session_id, None)
            return removed
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
            if _inbox_backend(session_id) == "db":
                _db_clear(org, session_id)
                return
            path = _inbox_path(org, session_id)
            with _locked(path):
                _write_items(path, [])
        except Exception:
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
