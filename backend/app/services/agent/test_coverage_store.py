"""Durable agent test coverage: brain coverage cells <-> ``agent_test_coverage``.

Coverage cells (``coverage_cells.py``) are the agent's per-session record of
each unit of testing. They live in the engagement brain, a JSON blob that only
resumes for the same session, so every new session used to start coverage
from zero and nothing tied a test to a platform asset.

This module makes them durable and asset-aware:

* ``persist`` upserts cells into ``agent_test_coverage`` on every run save
  (only cells that changed since the last save), resolving each cell's host
  to an organization ``Asset``.
* ``seed_brain`` loads the organization's prior coverage for the hosts in
  scope into a new session's brain. Recent conclusive results (finding,
  nothing found, ruled out, not applicable) are carried as already-tested so
  the agent spends its budget on what is still open; ``needs_follow_up``
  rows come back as open cells with the earlier reason. Results older than
  ``AGENT_COVERAGE_REUSE_DAYS`` (default 30; 0 disables reuse) are retested.
* ``asset_coverage`` summarises one asset: what was tested, with what
  outcome, and when; including "tested, nothing found".
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

HISTORY_LIMIT = 10
SEED_LIMIT = 5_000
_FINGERPRINTS: Dict[Tuple[int, str], Dict[str, str]] = {}
_FP_LOCK = threading.Lock()
_FP_SESSION_LIMIT = 200


def reuse_days() -> int:
    try:
        return max(0, int(os.environ.get("AGENT_COVERAGE_REUSE_DAYS", "30")))
    except ValueError:
        return 30


def _text(value: Any, limit: int = 0) -> str:
    out = str(value or "").strip()
    return out[:limit] if limit else out


def outcome_for(cell: Dict[str, Any]) -> str:
    """Map a coverage cell status onto the durable outcome vocabulary."""
    status = _text(cell.get("status")).lower()
    prior = _text(cell.get("prior_outcome"))
    if cell.get("source") == "prior_session" and prior and _SEED_STATUS.get(prior) == status:
        return prior
    if status == "finding" or (status == "tested_clean" and _text(cell.get("finding_id"))):
        return "reported"
    if status == "tested_clean":
        return "ruled_out" if _text(cell.get("candidate_id")) else "no_issue_found"
    if status == "skipped":
        return "not_applicable"
    if status in ("inconclusive", "blocked"):
        return "needs_follow_up"
    if status in ("leased", "in_focus"):
        return "in_progress"
    return "untested"


# Outcome -> cell status when carried into a new session.
_SEED_STATUS = {
    "reported": "finding",
    "no_issue_found": "tested_clean",
    "ruled_out": "tested_clean",
    "not_applicable": "skipped",
    "needs_follow_up": "untested",
}


def _cells(brain: Any) -> List[Dict[str, Any]]:
    raw = brain.get("coverage_cells") if isinstance(brain, dict) else getattr(brain, "coverage_cells", None)
    return [c for c in (raw or []) if isinstance(c, dict) and c.get("id")]


def _fingerprint(cell: Dict[str, Any], outcome: str) -> str:
    key = [outcome, _text(cell.get("status")), int(cell.get("attempts") or 0),
           _text(cell.get("finding_title")), _text(cell.get("reason"), 200),
           len(cell.get("evidence_ids") or [])]
    return hashlib.sha1(json.dumps(key).encode()).hexdigest()[:16]


def _changed_cells(org_id: int, session_id: str, cells: List[Dict[str, Any]]) -> List[Tuple[Dict[str, Any], str]]:
    with _FP_LOCK:
        if len(_FINGERPRINTS) > _FP_SESSION_LIMIT:
            _FINGERPRINTS.clear()
        seen = _FINGERPRINTS.setdefault((org_id, session_id), {})
        out = []
        for cell in cells:
            outcome = outcome_for(cell)
            fp = _fingerprint(cell, outcome)
            if seen.get(cell["id"]) == fp:
                continue
            out.append((cell, outcome))
        return out


def _mark_saved(org_id: int, session_id: str, rows: Iterable[Tuple[Dict[str, Any], str]]) -> None:
    with _FP_LOCK:
        seen = _FINGERPRINTS.setdefault((org_id, session_id), {})
        for cell, outcome in rows:
            seen[cell["id"]] = _fingerprint(cell, outcome)


def _host_of(value: str) -> str:
    return _text(value).lower().split("@")[-1].split(":")[0].rstrip(".")


def _resolve_assets(db, org_id: int, hosts: Iterable[str]) -> Dict[str, Optional[int]]:
    from app.models.asset import Asset

    wanted = sorted({h for h in hosts if h})
    found: Dict[str, Optional[int]] = {h: None for h in wanted}
    for i in range(0, len(wanted), 500):
        chunk = wanted[i:i + 500]
        rows = db.query(Asset.id, Asset.value).filter(
            Asset.organization_id == org_id, Asset.value.in_(chunk)
        ).all()
        for asset_id, value in rows:
            key = _host_of(value)
            if found.get(key) is None:
                found[key] = asset_id
    return found


def persist(organization_id: Optional[int], session_id: Optional[str], brain: Any, db=None) -> int:
    """Upsert this session's changed coverage cells. Returns rows written."""
    if not organization_id or not session_id or not brain:
        return 0
    org_id, session_id = int(organization_id), str(session_id)[:128]
    changed = _changed_cells(org_id, session_id, _cells(brain))
    if not changed:
        return 0

    from app.models.agent_test_coverage import AgentTestCoverage

    own = db is None
    if own:
        from app.db.database import SessionLocal
        db = SessionLocal()
    try:
        assets = _resolve_assets(db, org_id, (_host_of(c.get("host")) for c, _ in changed))
        keys = [c["id"][:64] for c, _ in changed]
        existing: Dict[str, AgentTestCoverage] = {}
        for i in range(0, len(keys), 500):
            for row in db.query(AgentTestCoverage).filter(
                AgentTestCoverage.organization_id == org_id,
                AgentTestCoverage.cell_key.in_(keys[i:i + 500]),
            ):
                existing[row.cell_key] = row
        now = datetime.utcnow()
        for cell, outcome in changed:
            key = cell["id"][:64]
            row = existing.get(key)
            if row is None:
                row = AgentTestCoverage(
                    organization_id=org_id, cell_key=key, first_session_id=session_id,
                    first_seen_at=now, history=[], evidence_ids=[],
                )
                db.add(row)
                existing[key] = row
            host = _host_of(cell.get("host"))
            previous = row.outcome
            row.asset_id = assets.get(host) or row.asset_id
            row.host = host[:255]
            row.method = _text(cell.get("method"), 16) or "GET"
            row.path = _text(cell.get("path"), 1024) or "/"
            row.surface_key = _text(cell.get("surface_key"), 1300)
            row.parameter = _text(cell.get("parameter"), 255) or "endpoint"
            row.identity = _text(cell.get("identity"), 128) or "unspecified"
            row.operation_id = _text(cell.get("operation_id"), 255)
            row.tenant = _text(cell.get("tenant"), 128)
            row.risk_area = _text(cell.get("test_type"), 64).lower() or "surface_review"
            row.cell_status = _text(cell.get("status"), 24) or "untested"
            row.outcome = outcome
            row.reason = _text(cell.get("reason"), 2000)
            row.specialist = _text(cell.get("specialist"), 64)
            row.finding_title = _text(cell.get("finding_title"), 500)
            row.evidence_ids = list(dict.fromkeys(
                [*(row.evidence_ids or []), *(_text(e) for e in cell.get("evidence_ids") or [] if _text(e))]
            ))[-50:]
            row.attempts = max(int(row.attempts or 0), int(cell.get("attempts") or 0))
            row.last_session_id = session_id
            if outcome not in ("untested", "in_progress") and (previous != outcome or not row.last_tested_at):
                row.last_tested_at = now
            if previous != outcome:
                row.history = [*(row.history or []), {
                    "session_id": session_id, "outcome": outcome, "at": now.isoformat(),
                }][-HISTORY_LIMIT:]
        db.commit()
        _mark_saved(org_id, session_id, changed)
        return len(changed)
    except Exception:
        db.rollback()
        raise
    finally:
        if own:
            db.close()


def _in_scope(host: str, scope_hosts: Iterable[str]) -> bool:
    from app.services.agent.recon_observation_adapter import _allowed

    return _allowed(host, scope_hosts)


def prior_rows(db, organization_id: int, scope_hosts: Iterable[str], *, now: Optional[datetime] = None):
    """Prior coverage for the hosts in scope that a new session should inherit."""
    from app.models.agent_test_coverage import AgentTestCoverage, TERMINAL_OUTCOMES

    days = reuse_days()
    if not days:
        return []
    scope = [str(h).lower().rstrip(".") for h in scope_hosts if str(h).strip()]
    if not scope:
        return []
    cutoff = (now or datetime.utcnow()) - timedelta(days=days)
    rows = (
        db.query(AgentTestCoverage)
        .filter(
            AgentTestCoverage.organization_id == int(organization_id),
            AgentTestCoverage.outcome.in_([*TERMINAL_OUTCOMES, "needs_follow_up"]),
            AgentTestCoverage.last_tested_at >= cutoff,
        )
        .order_by(AgentTestCoverage.last_tested_at.desc())
        .limit(SEED_LIMIT * 4)
        .all()
    )
    return [r for r in rows if _in_scope(r.host, scope)][:SEED_LIMIT]


def seed_brain(brain: Any, rows: Iterable[Any], *, organization_id: Optional[int] = None,
               session_id: Optional[str] = None) -> int:
    """Add prior coverage to a brain without overriding this session's cells.

    With organization/session, the seeded cells are marked as already saved so
    ``persist`` writes them again only once this session changes them.
    """
    from app.services.agent.coverage_cells import MAX_COVERAGE_CELLS, _new_cell

    cells = brain.coverage_cells
    present = {c.get("id") for c in cells if isinstance(c, dict)}
    seeded: List[Dict[str, Any]] = []
    added = 0
    for row in rows:
        if row.cell_key in present or len(cells) >= MAX_COVERAGE_CELLS:
            continue
        status = _SEED_STATUS.get(row.outcome)
        if not status:
            continue
        when = row.last_tested_at.date().isoformat() if row.last_tested_at else "earlier"
        reason = (f"Follow-up from session {row.last_session_id} ({when}): {row.reason}"
                  if row.outcome == "needs_follow_up"
                  else f"{row.outcome.replace('_', ' ')} in session {row.last_session_id} ({when})"
                       + (f": {row.reason}" if row.reason else ""))
        cell = _new_cell(
            brain, method=row.method, path=row.path, host=row.host,
            operation_id=row.operation_id, identity=row.identity, tenant=row.tenant,
            parameter=row.parameter, test_type=row.risk_area, status=status,
            source="prior_session", reason=reason, evidence_ids=row.evidence_ids or [],
            finding_title=row.finding_title,
        )
        cell["id"] = row.cell_key
        cell["prior_outcome"] = row.outcome
        cell["prior_session_id"] = row.last_session_id
        cell["asset_id"] = row.asset_id
        cells.append(cell)
        present.add(row.cell_key)
        seeded.append(cell)
        added += 1
    if organization_id and session_id and seeded:
        _mark_saved(int(organization_id), str(session_id)[:128],
                    [(c, outcome_for(c)) for c in seeded])
    return added


def asset_coverage(db, organization_id: int, asset_id: int, limit: int = 500) -> Dict[str, Any]:
    """What the agent tested on one asset, grouped by outcome and risk area."""
    from app.models.agent_test_coverage import AgentTestCoverage, COVERAGE_OUTCOMES

    rows = (
        db.query(AgentTestCoverage)
        .filter(AgentTestCoverage.organization_id == organization_id,
                AgentTestCoverage.asset_id == asset_id)
        .order_by(AgentTestCoverage.last_tested_at.desc().nullslast(), AgentTestCoverage.id.desc())
        .limit(limit)
        .all()
    )
    by_outcome = {o: 0 for o in COVERAGE_OUTCOMES}
    by_area: Dict[str, Dict[str, int]] = {}
    for r in rows:
        by_outcome[r.outcome] = by_outcome.get(r.outcome, 0) + 1
        area = by_area.setdefault(r.risk_area, {})
        area[r.outcome] = area.get(r.outcome, 0) + 1
    tested = sum(by_outcome[o] for o in ("reported", "no_issue_found", "ruled_out", "not_applicable"))
    return {
        "asset_id": asset_id,
        "total": len(rows),
        "tested": tested,
        "by_outcome": by_outcome,
        "by_risk_area": by_area,
        "last_tested_at": max((r.last_tested_at for r in rows if r.last_tested_at), default=None),
        "cells": [{
            "surface": r.surface_key or f"{r.method} {r.host}{r.path}",
            "parameter": r.parameter,
            "identity": r.identity,
            "risk_area": r.risk_area,
            "outcome": r.outcome,
            "reason": r.reason[:300],
            "finding_title": r.finding_title,
            "attempts": r.attempts,
            "last_session_id": r.last_session_id,
            "last_tested_at": r.last_tested_at,
            "history": r.history or [],
        } for r in rows],
    }
