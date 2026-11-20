"""Score completed product-agent lab runs by bug class.

Each case is an isolated positive or negative target. Ground truth stays outside
the agent prompt; this module only reads the exported run artifacts afterward.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from .benchmark.judge import judge_heuristic
from .findings import load_findings


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _validate_case(case: dict, seen: set[str]) -> None:
    name = case.get("id")
    if not isinstance(name, str) or not name or name in seen:
        raise ValueError("Case IDs must be present and unique")
    seen.add(name)
    for field in ("bug_class", "polarity", "run_dir", "target", "specialist"):
        if not isinstance(case.get(field), str) or not case[field].strip():
            raise ValueError(f"{name}: {field} is required")
    if case["polarity"] not in {"positive", "negative"}:
        raise ValueError(f"{name}: polarity must be positive or negative")
    expected = case.get("expected_findings")
    if not isinstance(expected, list) or (case["polarity"] == "positive") != bool(expected):
        raise ValueError(f"{name}: positive cases need expected findings; negative cases need none")
    for finding in expected:
        if not all(finding.get(key) for key in ("id", "category", "endpoint")):
            raise ValueError(f"{name}: expected findings need id, category, and endpoint")


# Why a case did not pass, ordered from earliest pipeline stage to latest. The
# reason points at the fix: reach the surface, spend more budget, try better
# payloads, or publish what was already proven.
MISS_REASONS = (
    "incomplete_run",          # the assessment never reached a completed ledger
    "surface_not_reached",     # no hypothesis for the class was ever created
    "skipped_by_budget",       # hypotheses queued but the run's budget ran out
    "blocked",                 # hypotheses blocked by policy or a missing prerequisite
    "interrupted",             # a test started but its run stopped mid-way
    "not_attempted",           # hypotheses existed but nothing was tried
    "found_not_published",     # a hypothesis was proven but no verified finding shipped
    "tested_no_signal",        # tests ran and found nothing (probe/payload gap)
    "false_positive",          # an unexpected finding was published
    "negative_not_evidenced",  # a safe twin was not rejected with evidence
)


def miss_reason(*, polarity: str, completed: bool, hypotheses: list[dict],
                metrics: dict, expected_count: int) -> str | None:
    """Attribute a failed case to the earliest stage that lost the bug."""
    if not completed:
        return "incomplete_run"
    if polarity == "negative":
        if metrics["false_positives"]:
            return "false_positive"
        if not any(h.get("state") == "negative_with_evidence" for h in hypotheses):
            return "negative_not_evidenced"
        return None
    if metrics["verified_true_positives"] == expected_count and not metrics["false_positives"]:
        return None
    if metrics["verified_true_positives"] == expected_count:
        return "false_positive"
    if not hypotheses:
        return "surface_not_reached"
    states = {str(h.get("state") or "") for h in hypotheses}
    if states & {"proven_with_evidence", "proven_unverified"}:
        return "found_not_published"
    if not any(int(h.get("attempts") or 0) > 0 for h in hypotheses):
        for state in ("skipped_by_budget", "blocked", "interrupted"):
            if state in states:
                return state
        return "not_attempted"
    if "interrupted" in states:
        return "interrupted"
    return "tested_no_signal"


def score_case(case: dict, root: Path) -> dict:
    run_dir = (root / case["run_dir"]).resolve()
    assessment = _read_json(run_dir / "product_assessment.json")
    ledger = _read_json(run_dir / "agent_ledger.json")
    findings = load_findings(run_dir / "findings.jsonl", strict=True)
    if not isinstance(ledger, list):
        raise ValueError("agent_ledger.json must be a list")
    if assessment.get("target") != case["target"]:
        raise ValueError("run target does not match ground truth")
    if case.get("scope") and assessment.get("scope") != case["scope"]:
        raise ValueError("run scope does not match ground truth")

    receipt_complete = bool((assessment.get("ledger_metrics") or {}).get("receipt_complete"))
    final_run_status = (
        ledger[-1].get("status") if ledger and isinstance(ledger[-1], dict) else None
    )
    completed = bool(assessment.get("complete") and not assessment.get("error")
                     and receipt_complete and final_run_status == "completed")
    hypotheses = [
        hypothesis
        for run in ledger if isinstance(run, dict)
        for hypothesis in (run.get("hypotheses") or [])
        if isinstance(hypothesis, dict) and hypothesis.get("specialist") == case["specialist"]
    ]
    observed = bool(hypotheses)
    attempted = any(int(h.get("attempts") or 0) > 0 for h in hypotheses)
    evidence = any(h.get("evidence_ids") for h in hypotheses)
    negative_proven = any(h.get("state") == "negative_with_evidence" for h in hypotheses)
    judged = judge_heuristic(findings, case["expected_findings"])
    metrics = judged.metrics()
    if case["polarity"] == "positive":
        quality_pass = (
            metrics["verified_true_positives"] == len(case["expected_findings"])
            and metrics["false_positives"] == 0
        )
    else:
        quality_pass = negative_proven and metrics["false_positives"] == 0
    reason = miss_reason(
        polarity=case["polarity"], completed=completed, hypotheses=hypotheses,
        metrics=metrics, expected_count=len(case["expected_findings"]),
    )

    return {
        "id": case["id"],
        "bug_class": case["bug_class"],
        "polarity": case["polarity"],
        "known_gap": case.get("known_gap"),
        "complete": completed,
        "final_run_status": final_run_status,
        "eligible_surface_observed": observed,
        "test_attempted": attempted,
        "evidence_captured": evidence,
        "negative_with_evidence": negative_proven,
        "metrics": metrics,
        "detected": judged.detected,
        "missed": judged.missed,
        "false_positives": judged.false_positives,
        "cost_usd": assessment.get("cost_usd"),
        "duration_seconds": (assessment.get("ledger_metrics") or {}).get("duration_seconds"),
        "test_actions": (assessment.get("ledger_metrics") or {}).get("test_actions"),
        "miss_reason": reason,
        "budget": {key: assessment.get(key) for key in
                   ("max_turns", "max_iterations", "price_limit_usd", "assessment_mode")},
        "model_routes": {
            str(task): sorted({str(call.get("model")) for call in
                               ((assessment.get("token_usage") or {}).get("calls") or [])
                               if isinstance(call, dict) and call.get("task") == task
                               and call.get("model")})
            for task in {call.get("task") for call in
                         ((assessment.get("token_usage") or {}).get("calls") or [])
                         if isinstance(call, dict) and call.get("task")}
        },
        "status": "incomplete" if not completed else "pass" if (
            observed and attempted and evidence and quality_pass
        ) else "fail",
    }


def score_corpus(corpus_path: Path) -> dict:
    corpus = _read_json(corpus_path)
    if not isinstance(corpus, dict) or not isinstance(corpus.get("cases"), list):
        raise ValueError("Corpus must contain a cases list")
    seen: set[str] = set()
    cases = []
    for case in corpus["cases"]:
        if not isinstance(case, dict):
            raise ValueError("Every case must be an object")
        _validate_case(case, seen)
        try:
            cases.append(score_case(case, corpus_path.parent))
        except (OSError, ValueError, TypeError, KeyError) as exc:
            cases.append({
                "id": case["id"], "bug_class": case["bug_class"],
                "polarity": case["polarity"], "known_gap": case.get("known_gap"),
                "status": "artifact_error",
                "error": str(exc),
            })
    classes: dict[str, list[dict]] = defaultdict(list)
    for case in cases:
        classes[case["bug_class"]].append(case)
    by_class = {}
    for name, rows in sorted(classes.items()):
        scored = [r for r in rows if r["status"] in {"pass", "fail"}]
        tp = sum(r["metrics"]["true_positives"] for r in scored)
        verified_tp = sum(r["metrics"]["verified_true_positives"] for r in scored)
        fp = sum(r["metrics"]["false_positives"] for r in scored)
        fn = sum(r["metrics"]["false_negatives"] for r in scored)
        budgets_match = len({json.dumps(r.get("budget"), sort_keys=True) for r in rows}) == 1
        common_tasks = set.intersection(
            *(set(r.get("model_routes", {})) for r in rows)
        ) if rows else set()
        model_routes_match = all(
            len({tuple(r["model_routes"][task]) for r in rows}) == 1
            for task in common_tasks
        )
        reasons: dict[str, int] = defaultdict(int)
        for r in rows:
            if r.get("status") != "pass" and r.get("miss_reason"):
                reasons[r["miss_reason"]] += 1
        known_gaps = sorted({str(r["known_gap"]) for r in rows if r.get("known_gap")})
        by_class[name] = {
            "known_gap": known_gaps[0] if len(known_gaps) == 1 else "; ".join(known_gaps) or None,
            "cases": len(rows),
            "passed": sum(r["status"] == "pass" for r in rows),
            "incomplete_or_error": sum(r["status"] in {"incomplete", "artifact_error"} for r in rows),
            "eligible_surfaces_observed": sum(bool(r.get("eligible_surface_observed")) for r in scored),
            "tests_attempted": sum(bool(r.get("test_attempted")) for r in scored),
            "cases_with_evidence": sum(bool(r.get("evidence_captured")) for r in scored),
            "negative_rejections_with_evidence": sum(bool(r.get("negative_with_evidence"))
                                                     for r in scored if r["polarity"] == "negative"),
            "cost_usd": round(sum(float(r.get("cost_usd") or 0) for r in scored), 4),
            "duration_seconds": round(sum(float(r.get("duration_seconds") or 0) for r in scored), 1),
            "true_positives": tp,
            "verified_true_positives": verified_tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": round(tp / (tp + fp), 4) if tp + fp else 0.0,
            "recall": round(tp / (tp + fn), 4) if tp + fn else 0.0,
            "verified_recall": round(verified_tp / (tp + fn), 4) if tp + fn else 0.0,
            "miss_reasons": dict(sorted(reasons.items())),
            "comparable_runs": budgets_match and model_routes_match,
            "pass": len(rows) >= 2 and {r["polarity"] for r in rows} == {"positive", "negative"}
                    and budgets_match and model_routes_match
                    and all(r["status"] == "pass" for r in rows),
        }
    totals: dict[str, int] = defaultdict(int)
    for row in by_class.values():
        for reason, count in row["miss_reasons"].items():
            totals[reason] += count
    return {"cases": cases, "by_class": by_class,
            "miss_reasons": {r: totals[r] for r in MISS_REASONS if totals.get(r)}}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path, help="JSON case manifest with local run_dir paths")
    parser.add_argument("--out", type=Path, help="Write the report to this JSON file")
    args = parser.parse_args(argv)
    try:
        report = score_corpus(args.corpus)
    except (OSError, ValueError, TypeError) as exc:
        parser.error(str(exc))
    rendered = json.dumps(report, indent=2)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    if any(c["status"] in {"incomplete", "artifact_error"} for c in report["cases"]):
        return 3
    # Known-gap classes are reported (and may pass) but do not gate the exit code.
    gating = [c for c in report["by_class"].values() if not c.get("known_gap")]
    return 0 if report["by_class"] and all(c["pass"] for c in gating) else 2


if __name__ == "__main__":
    raise SystemExit(main())
