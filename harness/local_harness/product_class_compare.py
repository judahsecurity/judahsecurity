"""Gate a product-agent change on equal-budget bug-class quality and cost.

Usage: python -m local_harness.product_class_compare BASELINE.json CANDIDATE.json
Both inputs are reports from product_class_benchmark over the same case IDs.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any


def _cases(report: dict) -> dict[str, dict]:
    rows = report.get("cases")
    if not isinstance(rows, list) or not rows:
        raise ValueError("Each report needs scored cases")
    cases = {row.get("id"): row for row in rows if isinstance(row, dict)}
    if len(cases) != len(rows) or None in cases:
        raise ValueError("Scored case IDs must be unique and present")
    return cases


def _cost(row: dict) -> float:
    value = row.get("cost_usd")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{row.get('id')}: measured cost_usd is required")
    cost = float(value)
    if not math.isfinite(cost) or cost < 0:
        raise ValueError(f"{row.get('id')}: cost_usd must be finite and nonnegative")
    return cost


def compare_product_class_reports(
    baseline: dict, candidate: dict, *, min_cost_saving: float = 0.01,
) -> dict[str, Any]:
    """Require the same cases and model budgets before comparing quality."""
    if not 0 <= min_cost_saving < 1:
        raise ValueError("min_cost_saving must be between 0 and 1")
    old_cases = _cases(baseline)
    new_cases = _cases(candidate)
    if old_cases.keys() != new_cases.keys():
        raise ValueError("Baseline and candidate must contain the same case IDs")
    reasons: list[str] = []
    baseline_cost = candidate_cost = 0.0
    for case_id in sorted(old_cases):
        old = old_cases[case_id]
        new = new_cases[case_id]
        for field in ("bug_class", "polarity", "budget", "model_routes"):
            if old.get(field) != new.get(field):
                raise ValueError(f"{case_id}: {field} differs between runs")
        if old.get("status") not in {"pass", "fail"} or new.get("status") not in {"pass", "fail"}:
            reasons.append(f"{case_id}: incomplete run or missing artifact")
            continue
        baseline_cost += _cost(old)
        candidate_cost += _cost(new)
        for field in ("eligible_surface_observed", "test_attempted", "evidence_captured"):
            if old.get(field) and not new.get(field):
                reasons.append(f"{case_id}: {field} regressed")
        if old.get("negative_with_evidence") and not new.get("negative_with_evidence"):
            reasons.append(f"{case_id}: evidenced negative result regressed")
        old_metrics = old.get("metrics") or {}
        new_metrics = new.get("metrics") or {}
        for field, direction in (("verified_true_positives", "min"),
                                 ("false_positives", "max"),
                                 ("false_negatives", "max")):
            old_value, new_value = old_metrics.get(field), new_metrics.get(field)
            if not isinstance(old_value, int) or not isinstance(new_value, int):
                raise ValueError(f"{case_id}: {field} count is missing")
            if (direction == "min" and new_value < old_value) or (
                direction == "max" and new_value > old_value
            ):
                reasons.append(f"{case_id}: {field} regressed")
        if new.get("status") != "pass":
            reasons.append(f"{case_id}: candidate did not meet the bug-class proof gate")

    classes = candidate.get("by_class") or {}
    expected_classes = {row.get("bug_class") for row in new_cases.values()}
    if not isinstance(classes, dict) or classes.keys() != expected_classes or not all(
        isinstance(row, dict) and row.get("pass") is True for row in classes.values()
    ):
        reasons.append("candidate class-level proof gate did not pass")
    quality_pass = not reasons
    cost_pass = baseline_cost > 0 and candidate_cost <= baseline_cost * (1 - min_cost_saving)
    if not cost_pass:
        reasons.append("measured cost saving is below the required threshold")
    return {
        "quality_pass": quality_pass,
        "cost_pass": cost_pass,
        "adopt": quality_pass and cost_pass,
        "baseline_cost_usd": round(baseline_cost, 4),
        "candidate_cost_usd": round(candidate_cost, 4),
        "cost_saving_fraction": round(
            (baseline_cost - candidate_cost) / baseline_cost, 4
        ) if baseline_cost else None,
        "reasons": reasons,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--min-cost-saving", type=float, default=0.01)
    args = parser.parse_args(argv)
    try:
        baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
        candidate = json.loads(args.candidate.read_text(encoding="utf-8"))
        result = compare_product_class_reports(
            baseline, candidate, min_cost_saving=args.min_cost_saving,
        )
    except (OSError, ValueError, TypeError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))
    return 0 if result["adopt"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
