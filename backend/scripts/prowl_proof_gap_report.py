"""Read-only report: where Prowl candidates and coverage cells get stuck.

Answers three questions from saved scheduled-run state:
  1. Which vulnerability classes end inconclusive, and why?
  2. Which coverage cells stay open (blocking completion), by test type?
  3. How do autonomy runs end?

Usage (on the Compose host):
  docker compose exec -T backend python scripts/prowl_proof_gap_report.py
  docker compose exec -T backend python scripts/prowl_proof_gap_report.py --json
  ... --org 3 --since 2026-10-01

The report never prints targets, titles, evidence, or request data: only
classes, statuses, counts, and the verifier's proof-gap reason text (which is
truncated and redacted).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime
from typing import Any, Iterable


def _class_of(candidate: dict) -> str:
    from app.services.agent.proof_policy import inferred_vulnerability_class

    explicit = str(candidate.get("vulnerability_class") or "").strip().lower()
    if explicit:
        return explicit
    probe = type("C", (), {"title": candidate.get("title") or "",
                           "description": candidate.get("description") or ""})
    return inferred_vulnerability_class(probe) or "unclassified"


def _reason_bucket(text: str) -> str:
    """Collapse a proof-gap reason to a stable, comparable prefix."""
    from app.services.agent.observability import redact_string

    text = redact_string(str(text or "")).strip()
    text = re.sub(r"[0-9a-f]{12,}", "<id>", text)
    text = re.sub(r"\d+", "N", text)
    return (text[:90] or "(no reason recorded)")


def summarize(snapshots: Iterable[dict], works: Iterable[dict]) -> dict[str, Any]:
    from app.services.agent.coverage_cells import CELL_TERMINAL, coverage_gap_code
    from app.services.agent.proof_policy import PROOFS_BY_CLASS

    by_class: dict[str, Counter] = {}
    reasons: Counter = Counter()
    cells: dict[str, Counter] = {}
    gaps: Counter = Counter()
    runs_with_open_cells = 0
    snapshot_count = 0
    for payload in snapshots:
        brain = (payload or {}).get("engagement_brain") or {}
        snapshot_count += 1
        for cand in brain.get("candidates") or []:
            if not isinstance(cand, dict):
                continue
            cls = _class_of(cand)
            by_class.setdefault(cls, Counter())[str(cand.get("status") or "pending")] += 1
            if cand.get("status") == "inconclusive":
                gap = cand.get("proof_gap") if isinstance(cand.get("proof_gap"), dict) else {}
                reasons[(cls, _reason_bucket(gap.get("reason") or cand.get("verifier_summary")))] += 1
        open_here = 0
        for cell in brain.get("coverage_cells") or []:
            if not isinstance(cell, dict):
                continue
            status = str(cell.get("status") or "untested")
            cells.setdefault(str(cell.get("test_type") or "unknown"), Counter())[status] += 1
            gap = coverage_gap_code(cell)
            if gap:
                gaps[gap] += 1
            open_here += status not in CELL_TERMINAL and not gap
        runs_with_open_cells += open_here > 0

    stops: Counter = Counter()
    statuses: Counter = Counter()
    for work in works:
        statuses[str(work.get("status") or "")] += 1
        stops[_reason_bucket(work.get("stop_reason") or "") if work.get("stop_reason") else "(none)"] += 1

    class_rows = []
    for cls, counts in sorted(by_class.items(), key=lambda kv: -sum(kv[1].values())):
        total = sum(counts.values())
        class_rows.append({
            "class": cls,
            "total": total,
            **{k: counts.get(k, 0) for k in ("confirmed", "refuted", "inconclusive", "pending")},
            "inconclusive_pct": round(100 * counts.get("inconclusive", 0) / total, 1) if total else 0.0,
            "proof_kinds": sorted(PROOFS_BY_CLASS.get(cls, ())),
            "can_confirm": bool(PROOFS_BY_CLASS.get(cls)),
        })
    cell_rows = []
    for test, counts in sorted(cells.items(), key=lambda kv: -sum(kv[1].values())):
        total = sum(counts.values())
        open_n = sum(n for status, n in counts.items() if status not in CELL_TERMINAL)
        cell_rows.append({"test_type": test, "total": total, "open": open_n,
                          "open_pct": round(100 * open_n / total, 1) if total else 0.0,
                          "by_status": dict(counts)})
    return {
        "snapshots": snapshot_count,
        "candidates_by_class": class_rows,
        "top_inconclusive_reasons": [
            {"class": cls, "reason": reason, "count": n}
            for (cls, reason), n in reasons.most_common(25)
        ],
        "coverage_cells_by_test_type": cell_rows,
        "runs_with_open_cells": runs_with_open_cells,
        "coverage_gaps": dict(gaps.most_common()),
        "work_status": dict(statuses),
        "stop_reasons": [{"reason": r, "count": n} for r, n in stops.most_common(15)],
    }


def _print_text(report: dict) -> None:
    print(f"Snapshots read: {report['snapshots']}  "
          f"(with actionable open cells: {report['runs_with_open_cells']})\n")
    print("Candidates by class")
    print(f"  {'class':28} {'total':>5} {'conf':>5} {'refut':>5} {'inconc':>6} {'pend':>5} {'%inc':>6}  proof kinds")
    for row in report["candidates_by_class"]:
        kinds = ", ".join(row["proof_kinds"]) or "NONE - can never confirm"
        print(f"  {row['class'][:28]:28} {row['total']:>5} {row['confirmed']:>5} {row['refuted']:>5} "
              f"{row['inconclusive']:>6} {row['pending']:>5} {row['inconclusive_pct']:>5}%  {kinds[:60]}")
    print("\nTop inconclusive reasons")
    for row in report["top_inconclusive_reasons"]:
        print(f"  {row['count']:>4}  [{row['class']}] {row['reason']}")
    print("\nCoverage cells by test type (open = not terminal; includes gaps)")
    for row in report["coverage_cells_by_test_type"]:
        print(f"  {row['test_type'][:28]:28} {row['total']:>6} total {row['open']:>6} open ({row['open_pct']}%)  {row['by_status']}")
    print(f"Coverage gaps (accounted, untested, not clean): {report['coverage_gaps']}")
    print(f"\nWork status: {report['work_status']}")
    print("Stop reasons")
    for row in report["stop_reasons"]:
        print(f"  {row['count']:>4}  {row['reason']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--org", type=int, help="Limit to one organization id")
    parser.add_argument("--since", help="Only snapshots/work updated on or after YYYY-MM-DD")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of tables")
    args = parser.parse_args(argv)

    from app.db.database import SessionLocal
    from app.models.agent_autonomy_work import AgentAutonomyWork, AgentRunSnapshot

    since = datetime.fromisoformat(args.since) if args.since else None
    db = SessionLocal()
    try:
        snaps = db.query(AgentRunSnapshot)
        works = db.query(AgentAutonomyWork)
        if args.org is not None:
            snaps = snaps.filter(AgentRunSnapshot.organization_id == args.org)
            works = works.filter(AgentAutonomyWork.organization_id == args.org)
        if since:
            snaps = snaps.filter(AgentRunSnapshot.updated_at >= since)
            works = works.filter(AgentAutonomyWork.updated_at >= since)
        report = summarize(
            (row.payload for row in snaps.yield_per(50)),
            ({"status": row.status, "stop_reason": row.stop_reason} for row in works.yield_per(200)),
        )
    finally:
        db.close()
    if args.json:
        json.dump(report, sys.stdout, indent=2)
        print()
    else:
        _print_text(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
