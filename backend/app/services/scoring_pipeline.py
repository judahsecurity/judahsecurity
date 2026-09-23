"""
Universal Vulnerability Scoring Pipeline.

A single, scanner-agnostic pipeline that automatically scores every
Vulnerability row the moment it is committed to the database — regardless
of which scanner, API endpoint, or code path created it.

Architecture
────────────
                ┌─────────────────────────────┐
  Any scanner   │  SQLAlchemy after_insert     │
  Any API path  │  event fires on Vulnerability│
  Manual create │  after_insert → pending dict │
                └──────────┬──────────────────┘
                           │ after_commit
                           ▼
                ┌─────────────────────────┐
                │  Priority queue          │  Critical → priority 1
                │  (thread-safe, bounded)  │  High     → priority 2
                │  dedup: no double-score  │  Medium   → priority 3
                └──────────┬──────────────┘  Low/Info → priority 4
                           │
              ┌────────────┴────────────┐
              │                         │
          Worker 0                  Worker 1  (N configurable)
              │                         │
              ▼                         ▼
    Delphi enrichment (fast)    Delphi enrichment (fast)
    Oracle OPES scoring         Oracle OPES scoring
    Severity evaluation         Severity evaluation
    Retry w/ backoff on         Retry w/ backoff on
    transient failures          transient failures
              │
    Dead-letter on max retries

Configuration (env vars)
────────────────────────
  ORACLE_SCORE_WORKERS      Number of parallel scoring workers  (default 2)
  ORACLE_SCORE_QUEUE_SIZE   Max items in the queue              (default 2000)
  ORACLE_SCORE_MAX_RETRIES  Retries per item on Oracle outage   (default 3)
  ORACLE_SCORE_RETRY_BASE   Exponential-backoff base seconds    (default 2.0)
  ORACLE_AUTO_SCORE_ENABLED Set "false" to disable auto-scoring (default true)
"""

from __future__ import annotations

import logging
import os
import queue
import threading
import time
import weakref
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Priority constants ────────────────────────────────────────────────────────

PRIORITY_CRITICAL = 1
PRIORITY_HIGH = 2
PRIORITY_NORMAL = 3
PRIORITY_LOW = 4

_SEVERITY_TO_PRIORITY: Dict[str, int] = {
    "critical": PRIORITY_CRITICAL,
    "high":     PRIORITY_HIGH,
    "medium":   PRIORITY_NORMAL,
    "low":      PRIORITY_LOW,
    "info":     PRIORITY_LOW,
    "informational": PRIORITY_LOW,
    "unknown":  PRIORITY_NORMAL,
}


@dataclass(order=True)
class _ScoringItem:
    """A single item in the scoring queue. Ordered by (priority, submitted_at)."""
    priority: int
    submitted_at: float = field(default_factory=time.monotonic)
    vuln_id: int = field(compare=False, default=0)
    force: bool = field(compare=False, default=False)
    attempt: int = field(compare=False, default=0)


# ── Tracking pending vulns per session ───────────────────────────────────────
# WeakKeyDictionary so entries are cleaned up automatically when sessions
# are garbage-collected — avoids modifying SQLAlchemy session state directly.
_session_pending: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()
_session_pending_lock = threading.Lock()


# ── Core pipeline ─────────────────────────────────────────────────────────────

class ScoringPipeline:
    """
    Universal vulnerability scoring pipeline.

    Submit a vulnerability ID and it will be enriched with:
      1. Delphi (CISA KEV + CVSS priority, fast — no LLM)
      2. Oracle (OPES score + analyst brief + attack path, via aegis-oracle)

    The pipeline is the single point of truth for scoring: deduplication
    prevents the same vulnerability from being scored twice concurrently,
    and exponential-backoff retry handles transient Oracle outages cleanly.
    """

    def __init__(
        self,
        workers: int = 2,
        queue_size: int = 2000,
        max_retries: int = 3,
        retry_base_delay: float = 2.0,
    ) -> None:
        self._q: queue.PriorityQueue[_ScoringItem] = queue.PriorityQueue(maxsize=queue_size)
        self._pending_ids: set[int] = set()
        self._lock = threading.Lock()
        self._worker_count = workers
        self._threads: list[threading.Thread] = []
        self._max_retries = max_retries
        self._retry_base = retry_base_delay
        self._running = False

        # Counters
        self._processed = 0
        self._skipped_dedup = 0
        self._skipped_cached = 0
        self._retried = 0
        self._errors = 0
        self._dead_letters: List[Dict[str, Any]] = []

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start worker threads. Call once during application startup."""
        if self._running:
            return
        self._running = True
        for i in range(self._worker_count):
            t = threading.Thread(
                target=self._worker_loop,
                name=f"oracle-scorer-{i}",
                daemon=True,
            )
            t.start()
            self._threads.append(t)
        logger.info("ScoringPipeline: started %d worker(s)", self._worker_count)

    def stop(self, timeout: float = 10.0) -> None:
        """Signal workers to stop. Best-effort drain within timeout."""
        if not self._running:
            return
        self._running = False
        for _ in self._threads:
            try:
                self._q.put_nowait(_ScoringItem(priority=99999, vuln_id=-1))
            except queue.Full:
                pass
        for t in self._threads:
            t.join(timeout=timeout / max(len(self._threads), 1))
        logger.info("ScoringPipeline: stopped")

    # ── Submission ────────────────────────────────────────────────────────────

    def submit(
        self,
        vuln_id: int,
        *,
        severity: str = "medium",
        force: bool = False,
    ) -> bool:
        """
        Enqueue a vulnerability for scoring. Thread-safe.

        Args:
            vuln_id:  Primary key of the Vulnerability row.
            severity: Scanner-reported severity — used to set queue priority
                      so critical findings are scored first.
            force:    Skip the TTL cache and re-score even if enriched recently.

        Returns:
            True if the item was enqueued, False if it was deduped or dropped.
        """
        if not self._running:
            return False

        priority = _SEVERITY_TO_PRIORITY.get((severity or "medium").lower(), PRIORITY_NORMAL)

        with self._lock:
            if vuln_id in self._pending_ids and not force:
                self._skipped_dedup += 1
                return False
            self._pending_ids.add(vuln_id)

        item = _ScoringItem(priority=priority, vuln_id=vuln_id, force=force)
        try:
            self._q.put_nowait(item)
            return True
        except queue.Full:
            with self._lock:
                self._pending_ids.discard(vuln_id)
            logger.warning("ScoringPipeline: queue full — dropped vuln_id=%s", vuln_id)
            return False

    def submit_batch(
        self,
        vuln_ids: List[int],
        *,
        severity: str = "medium",
        force: bool = False,
    ) -> Dict[str, int]:
        """Enqueue multiple vulnerabilities. Returns counts."""
        submitted = skipped = 0
        for vid in vuln_ids:
            if self.submit(vid, severity=severity, force=force):
                submitted += 1
            else:
                skipped += 1
        return {"submitted": submitted, "skipped": skipped}

    # ── Worker ────────────────────────────────────────────────────────────────

    def _worker_loop(self) -> None:
        """Main worker loop. Runs in a daemon thread."""
        # Defer imports — services import models, which must be fully loaded.
        from app.db.database import SessionLocal  # type: ignore[import]
        from app.models.vulnerability import Vulnerability  # type: ignore[import]
        from app.services.oracle_enrichment_service import (  # type: ignore[import]
            enrich_vulnerability as oracle_enrich,
            OracleUnavailable,
            OracleInputError,
        )
        from app.services.delphi_enrichment_service import get_delphi_service  # type: ignore[import]

        while self._running:
            try:
                item: _ScoringItem = self._q.get(timeout=5.0)
            except queue.Empty:
                continue

            # Sentinel for graceful shutdown
            if item.vuln_id == -1:
                self._q.task_done()
                break

            db = None
            try:
                db = SessionLocal()
                vuln: Optional[Vulnerability] = (
                    db.query(Vulnerability).filter(Vulnerability.id == item.vuln_id).first()
                )
                if vuln is None:
                    logger.debug("ScoringPipeline: vuln %s gone (deleted?)", item.vuln_id)
                    self._cleanup(item.vuln_id)
                    continue

                # ── 1. Delphi (fast, no LLM) ──────────────────────────────
                if vuln.cve_id:
                    try:
                        get_delphi_service().enrich_vulnerability(vuln)
                    except Exception as exc:  # noqa: BLE001
                        logger.debug(
                            "ScoringPipeline: Delphi failed for vuln %s: %s",
                            item.vuln_id, exc,
                        )

                # ── 2. Oracle OPES scoring ─────────────────────────────────
                oracle_enrich(db, vuln, force=item.force)

                with self._lock:
                    self._processed += 1
                logger.debug("ScoringPipeline: scored vuln %s", item.vuln_id)

            except OracleUnavailable as exc:
                self._handle_transient(item, exc)
                continue  # skip cleanup — item was re-queued

            except OracleInputError as exc:
                logger.info(
                    "ScoringPipeline: permanent skip vuln %s: %s",
                    item.vuln_id, exc,
                )

            except Exception as exc:  # noqa: BLE001
                logger.exception(
                    "ScoringPipeline: unexpected error for vuln %s: %s",
                    item.vuln_id, exc,
                )
                with self._lock:
                    self._errors += 1

            finally:
                if db is not None:
                    db.close()
                # ── 3. Severity evaluation ─────────────────────────────────
                # Runs whatever Oracle did: findings Oracle cannot analyse (or
                # while it is down) are still scored from platform evidence.
                evaluate_severity(item.vuln_id)
                self._cleanup(item.vuln_id)
                self._q.task_done()

    def _handle_transient(self, item: _ScoringItem, exc: Exception) -> None:
        """Retry with exponential backoff, or dead-letter after max retries."""
        if item.attempt < self._max_retries:
            item.attempt += 1
            delay = self._retry_base ** item.attempt
            logger.warning(
                "ScoringPipeline: Oracle unavailable for vuln %s "
                "(attempt %d/%d), retrying in %.0fs: %s",
                item.vuln_id, item.attempt, self._max_retries, delay, exc,
            )
            with self._lock:
                self._retried += 1
            # Don't call task_done — we're re-queueing the item.
            # But do sleep to give Oracle time to recover.
            time.sleep(delay)
            try:
                self._q.put_nowait(item)
            except queue.Full:
                self._dead_letter(item.vuln_id, "queue full after retry backoff")
        else:
            logger.error(
                "ScoringPipeline: max retries exhausted for vuln %s — dead letter",
                item.vuln_id,
            )
            self._dead_letter(item.vuln_id, str(exc))
        self._q.task_done()

    def _dead_letter(self, vuln_id: int, reason: str) -> None:
        with self._lock:
            self._errors += 1
            self._pending_ids.discard(vuln_id)
            if len(self._dead_letters) < 200:
                self._dead_letters.append({
                    "vuln_id": vuln_id,
                    "reason": reason,
                    "ts": time.time(),
                })

    def _cleanup(self, vuln_id: int) -> None:
        with self._lock:
            self._pending_ids.discard(vuln_id)

    # ── Observability ─────────────────────────────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        """Return current pipeline health metrics."""
        with self._lock:
            return {
                "running": self._running,
                "workers": self._worker_count,
                "queue_depth": self._q.qsize(),
                "currently_pending": len(self._pending_ids),
                "processed_total": self._processed,
                "skipped_dedup": self._skipped_dedup,
                "skipped_cached": self._skipped_cached,
                "retried": self._retried,
                "errors": self._errors,
                "dead_letter_count": len(self._dead_letters),
                "dead_letter_recent": self._dead_letters[-10:],
            }


def evaluate_severity(vuln_id: int) -> bool:
    """Run the severity evaluation for one finding in its own session.
    Never raises; returns True when the finding was evaluated."""
    from app.db.database import SessionLocal  # type: ignore[import]
    from app.models.vulnerability import Vulnerability  # type: ignore[import]
    from app.services.severity_evaluation import evaluate_finding  # type: ignore[import]

    db = SessionLocal()
    try:
        vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
        if vuln is None:
            return False
        view = evaluate_finding(db, vuln)
        db.commit()
        # Optionally ask the gap agent to estimate what the rules could not.
        from app.services import severity_agent  # type: ignore[import]
        if (
            severity_agent.auto_enabled()
            and view.get("status") == "needs_analyst"
            and not (vuln.metadata_ or {}).get("severity_eval", {}).get("agent_run_at")
        ):
            severity_agent.submit(vuln_id)
        return True
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.warning("ScoringPipeline: severity evaluation failed for vuln %s: %s", vuln_id, exc)
        return False
    finally:
        db.close()


# ── Singleton ─────────────────────────────────────────────────────────────────

_pipeline: Optional[ScoringPipeline] = None


def get_scoring_pipeline() -> ScoringPipeline:
    """Return the global ScoringPipeline singleton, creating it if needed."""
    global _pipeline
    if _pipeline is None:
        _pipeline = ScoringPipeline(
            workers=int(os.getenv("ORACLE_SCORE_WORKERS", "2")),
            queue_size=int(os.getenv("ORACLE_SCORE_QUEUE_SIZE", "2000")),
            max_retries=int(os.getenv("ORACLE_SCORE_MAX_RETRIES", "3")),
            retry_base_delay=float(os.getenv("ORACLE_SCORE_RETRY_BASE", "2.0")),
        )
    return _pipeline


# ── SQLAlchemy event hooks ────────────────────────────────────────────────────

def register_hooks() -> None:
    """
    Register SQLAlchemy event listeners that automatically submit every
    new Vulnerability to the scoring pipeline after its session commits.

    This is the "universal hook" — it fires regardless of which scanner,
    API endpoint, or service created the Vulnerability. No scanner service
    needs to explicitly call enrich/score functions.

    Call once at application startup, after all models have been imported.
    """
    enabled = os.getenv("ORACLE_AUTO_SCORE_ENABLED", "true").lower() not in ("false", "0", "no")
    if not enabled:
        logger.info("ScoringPipeline: auto-scoring disabled via ORACLE_AUTO_SCORE_ENABLED")
        return

    from sqlalchemy import event
    from sqlalchemy.orm import Session as _OrmSession
    from app.models.vulnerability import Vulnerability  # type: ignore[import]

    @event.listens_for(Vulnerability, "after_insert")
    def _on_vuln_insert(mapper, connection, target: Vulnerability) -> None:
        """
        Record the new vulnerability ID to be scored after the session commits.
        Runs during flush() — data is written but not yet committed.
        """
        session = _OrmSession.object_session(target)
        if session is None:
            return
        severity = (
            target.severity.value
            if hasattr(target.severity, "value")
            else str(target.severity or "medium")
        )
        with _session_pending_lock:
            bucket = _session_pending.setdefault(session, [])
            bucket.append({"id": target.id, "severity": severity})

    @event.listens_for(_OrmSession, "after_commit")
    def _on_session_commit(session: _OrmSession) -> None:
        """
        After a successful commit, submit all pending vulnerability IDs to
        the scoring queue. Data is now durable — Oracle can read it safely.
        """
        with _session_pending_lock:
            pending = _session_pending.pop(session, [])
        if not pending:
            return
        pipeline = get_scoring_pipeline()
        if not pipeline._running:
            return
        for item in pending:
            pipeline.submit(item["id"], severity=item["severity"])

    @event.listens_for(_OrmSession, "after_rollback")
    def _on_session_rollback(session: _OrmSession) -> None:
        """Clear pending IDs — rolled-back rows were never written."""
        with _session_pending_lock:
            _session_pending.pop(session, None)

    logger.info(
        "ScoringPipeline: auto-score hooks registered — "
        "every new Vulnerability will be scored automatically"
    )
