"""Push exploit-priority changes onto Neo4j Vulnerability nodes.

The exploit-priority hook (``exploit_priority.register``) records every
finding whose score changed during a flush; after the transaction commits the
changes land here. One daemon thread batches them into a single ``UNWIND``
update, so an OPES re-score, a new VulnCheck KEV entry or an analyst's
business-impact change re-ranks graph attack paths within seconds, without
re-syncing the whole asset.

Nodes that do not exist yet are skipped: the next asset sync creates them
with current scores. When Neo4j is unreachable the batch is dropped and the
worker backs off; the periodic sync repairs anything missed.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

BATCH_WINDOW_SECONDS = 2.0
MAX_BATCH = 500
OFFLINE_BACKOFF_SECONDS = 60.0

_UPDATE = """
UNWIND $rows AS row
MATCH (v:Vulnerability {vuln_id: row.vuln_id})
SET v.exploit_score = row.exploit_score,
    v.priority_score = row.priority_score,
    v.exploit_tier = row.exploit_tier,
    v.kev = row.kev,
    v.status = coalesce(row.status, v.status)
"""

_queue: "queue.Queue[Dict]" = queue.Queue(maxsize=20_000)
_worker: Optional[threading.Thread] = None
_lock = threading.Lock()
_offline_until = 0.0


def enqueue(rows: List[Dict]) -> None:
    """Queue score rows ({vuln_id, exploit_score, priority_score, exploit_tier,
    kev, status}) for the graph. Never blocks the caller."""
    global _worker
    if not rows or time.monotonic() < _offline_until:
        return
    for row in rows:
        try:
            _queue.put_nowait(row)
        except queue.Full:
            logger.debug("graph score queue full; periodic sync will catch up")
            break
    with _lock:
        if _worker is None or not _worker.is_alive():
            _worker = threading.Thread(target=_run, name="graph-score-sync", daemon=True)
            _worker.start()


def _drain(first: Dict) -> List[Dict]:
    """Collect one batch, keeping only the latest row per vulnerability."""
    latest = {first["vuln_id"]: first}
    deadline = time.monotonic() + BATCH_WINDOW_SECONDS
    while len(latest) < MAX_BATCH:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            row = _queue.get(timeout=remaining)
        except queue.Empty:
            break
        latest[row["vuln_id"]] = row
    return list(latest.values())


def push(rows: List[Dict]) -> bool:
    """Write one batch. Returns False when Neo4j is unavailable."""
    from app.services.graph_service import get_graph_service

    graph = get_graph_service()
    if not graph._connected:
        return False
    graph.query(_UPDATE, {"rows": rows})
    return True


def _run() -> None:
    global _offline_until
    while True:
        try:
            first = _queue.get(timeout=30)
        except queue.Empty:
            return  # idle; enqueue() restarts the worker on demand
        batch = _drain(first)
        try:
            if not push(batch):
                _offline_until = time.monotonic() + OFFLINE_BACKOFF_SECONDS
                _clear()
        except Exception as exc:  # noqa: BLE001
            logger.debug("graph score push failed: %s", exc)
            _offline_until = time.monotonic() + OFFLINE_BACKOFF_SECONDS
            _clear()


def _clear() -> None:
    while True:
        try:
            _queue.get_nowait()
        except queue.Empty:
            return
