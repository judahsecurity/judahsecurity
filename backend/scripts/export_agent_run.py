"""Export one finished Prowl run as JSON for scoring (read-only).

Run inside the backend container, where the run snapshot and database live:

  sudo docker exec asm_backend python -m scripts.export_agent_run --target ginandjuice.shop > run.json
  sudo docker exec asm_backend python -m scripts.export_agent_run --session-id <id> > run.json

``--target`` picks the most recent run whose objective names that host. The
output holds the candidates with the verifier's status, a summary of coverage,
which tools ran, and the run's status and duration. It carries no credentials:
the snapshot is already redacted and credentials are dropped from it.
Score it with ``harness``: ``python -m local_harness.benchmark.ginandjuice_scorecard run.json``.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from typing import Any, Dict, Optional

CANDIDATE_FIELDS = ("id", "title", "vulnerability_class", "severity", "target", "status",
                    "specialist", "verifier_summary", "parameter", "evidence_ids")


def _find_run(db: Any, session_id: Optional[str], target: Optional[str]):
    from app.models.agent_run_ledger import AgentRunLedger

    query = db.query(AgentRunLedger)
    if session_id:
        query = query.filter(AgentRunLedger.session_id == session_id)
    elif target:
        query = query.filter(AgentRunLedger.objective.ilike(f"%{target}%"))
    return query.order_by(AgentRunLedger.started_at.desc()).first()


def _raw_snapshot(organization_id: int, session_id: str) -> Dict[str, Any]:
    """The saved snapshot exactly as written. load_run_snapshot() would run
    restart recovery, which reopens unfinished leases and can demote verdicts;
    a scorecard needs the run's final state, unchanged."""
    from app.services.agent import run_snapshot

    if str(session_id).startswith("sched-"):
        try:
            from app.db.database import SessionLocal
            from app.models.agent_autonomy_work import AgentRunSnapshot

            with SessionLocal() as db:
                row = db.get(AgentRunSnapshot, str(session_id))
                if row and row.organization_id == int(organization_id):
                    return dict(row.payload or {})
        except Exception:
            pass
    path = run_snapshot._path(int(organization_id), session_id)
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def export_run(session_id: Optional[str] = None, target: Optional[str] = None) -> Dict[str, Any]:
    from app.db.database import SessionLocal
    from app.models.agent_conversation import AgentConversation
    from app.models.agent_run_ledger import AgentActionReceipt

    with SessionLocal() as db:
        run = _find_run(db, session_id, target)
        if run is None and session_id:
            conversation = db.query(AgentConversation).filter(
                AgentConversation.session_id == session_id).one_or_none()
            if conversation is None:
                raise SystemExit(f"No run or conversation for session {session_id}")
            org_id, sid = conversation.organization_id, session_id
            run_info: Dict[str, Any] = {}
            actions = []
        elif run is None:
            raise SystemExit(f"No run whose objective mentions {target!r}")
        else:
            org_id, sid = run.organization_id, run.session_id
            ended = run.ended_at
            run_info = {
                "run_id": run.id, "status": run.status, "reason": run.reason,
                "objective": run.objective, "started_at": str(run.started_at),
                "ended_at": str(ended) if ended else None,
                "duration_s": (ended - run.started_at).total_seconds() if ended else None,
            }
            actions = db.query(AgentActionReceipt).filter(
                AgentActionReceipt.run_id == run.id).order_by(AgentActionReceipt.id).all()

    snapshot = _raw_snapshot(org_id, sid)
    brain = snapshot.get("engagement_brain") or {}
    cmap = snapshot.get("capability_map") or {}
    candidates = [{k: c.get(k) for k in CANDIDATE_FIELDS if k in c}
                  for c in brain.get("candidates") or [] if isinstance(c, dict)]
    cells = [c for c in brain.get("coverage_cells") or [] if isinstance(c, dict)]
    tool_runs = Counter(a.tool_name for a in actions if a.event == "started")
    tool_failures = Counter(a.tool_name for a in actions if a.event == "failed")
    first_tool_seconds: Dict[str, float] = {}
    if actions:
        start = actions[0].created_at
        for action in actions:
            if action.event == "started" and action.tool_name not in first_tool_seconds:
                first_tool_seconds[action.tool_name] = (action.created_at - start).total_seconds()
    return {
        "schema": "prowl-run-export/1",
        "session_id": sid,
        "run": run_info,
        "candidates": candidates,
        "coverage": {
            "cells": len(cells),
            "by_test_type": dict(Counter(str(c.get("test_type") or "") for c in cells)),
            "by_first_pass_outcome": dict(Counter(str(c.get("first_pass_outcome") or "untested")
                                                  for c in cells)),
            "tested_test_types": sorted({str(c.get("test_type") or "") for c in cells
                                         if c.get("first_pass_outcome")}),
        },
        "map": {
            "pages": len(cmap.get("pages_visited") or []),
            "api_endpoints": len(cmap.get("api_endpoints") or []),
            "forms": len(cmap.get("forms") or []),
            "value_flows": len(cmap.get("value_flows") or []),
        },
        "tools": {"runs": dict(tool_runs), "failures": dict(tool_failures),
                  "first_started_after_s": first_tool_seconds},
        # Why actions failed, from the ledger (already redacted, 300 chars).
        "failed_actions": [
            {"tool": a.tool_name, "event": a.event, "detail": a.detail,
             "after_s": round((a.created_at - actions[0].created_at).total_seconds(), 1)}
            for a in actions if a.event in ("failed", "interrupted")
        ][:60],
        "notes": [str(n)[:300] for n in (brain.get("notes") or [])[-20:]],
    }


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--session-id")
    group.add_argument("--target", help="host named in the run objective, e.g. ginandjuice.shop")
    args = parser.parse_args(argv)
    json.dump(export_run(args.session_id, args.target), sys.stdout, indent=1, default=str)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
