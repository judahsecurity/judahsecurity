"""Deterministic, skill-aware release gate for benchmark reports."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional


@dataclass(frozen=True)
class GateResult:
    passed: bool
    failures: tuple[str, ...]
    skill_id: str
    thresholds: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "skill_id": self.skill_id,
            "failures": list(self.failures),
            "thresholds": dict(self.thresholds),
        }


def evaluate_report(
    report: Mapping[str, Any],
    *,
    skill_id: str,
    suites: Mapping[str, Any],
) -> GateResult:
    defaults = dict(suites.get("defaults") or {})
    thresholds = {**defaults, **dict((suites.get("suites") or {}).get(skill_id) or {})}
    aggregate = dict(report.get("aggregate") or {})
    findings = dict(aggregate.get("findings") or {})
    failures: list[str] = []

    _minimum(failures, "verified_recall", findings, thresholds)
    _minimum(failures, "verified_precision", findings, thresholds)
    _minimum(failures, "recall", findings, thresholds)
    _minimum(failures, "precision", findings, thresholds)
    _maximum(failures, "guardrail_blocks", aggregate, thresholds)

    cost = dict(aggregate.get("cost") or {})
    _maximum(failures, "cost_usd", cost, thresholds)
    _maximum(failures, "cost_per_true_positive", cost, thresholds)

    scan_errors = len(report.get("scan_errors") or [])
    maximum_errors = thresholds.get("max_scan_errors")
    if maximum_errors is not None and scan_errors > int(maximum_errors):
        failures.append(f"scan_errors {scan_errors} > max_scan_errors {maximum_errors}")

    return GateResult(not failures, tuple(failures), skill_id, thresholds)


def load_suites(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _minimum(
    failures: list[str],
    metric: str,
    observed: Mapping[str, Any],
    thresholds: Mapping[str, Any],
) -> None:
    expected = thresholds.get(f"min_{metric}")
    if expected is None:
        return
    actual = float(observed.get(metric) or 0)
    if actual < float(expected):
        failures.append(f"{metric} {actual:.4f} < min_{metric} {float(expected):.4f}")


def _maximum(
    failures: list[str],
    metric: str,
    observed: Mapping[str, Any],
    thresholds: Mapping[str, Any],
) -> None:
    expected = thresholds.get(f"max_{metric}")
    if expected is None:
        return
    raw = observed.get(metric)
    if raw is None:
        return
    actual = float(raw)
    if actual > float(expected):
        failures.append(f"{metric} {actual:.4f} > max_{metric} {float(expected):.4f}")


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Apply a skill-specific gate to a benchmark report.")
    parser.add_argument("report", type=Path, help="benchmark_report.json")
    parser.add_argument("--skill", required=True, help="Skill manifest evaluation_suite/id")
    parser.add_argument(
        "--suites",
        type=Path,
        default=root / "evals" / "skill_suites.json",
        help="Skill suite thresholds JSON.",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable output.")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    report = json.loads(args.report.read_text(encoding="utf-8"))
    result = evaluate_report(report, skill_id=args.skill, suites=load_suites(args.suites))
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    elif result.passed:
        print(f"PASS: {args.skill}")
    else:
        print(f"FAIL: {args.skill}")
        for failure in result.failures:
            print(f"  - {failure}")
    return 0 if result.passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
