"""
Benchmark driver: (optional Setup) → Scan → Judge → Tally Metrics.

    python -m local_harness.benchmark.run                    # full run over the corpus
    python -m local_harness.benchmark.run --repos juice-shop # a subset
    python -m local_harness.benchmark.run --tally-only       # re-judge saved artifacts
    python -m local_harness.benchmark.run --setup            # docker up/down each target
    python -m local_harness.benchmark.run \
        --ground-truth ground_truth/XBEN.json --setup \
        --min-success-rate 0.8                               # CI gate on XBEN flag capture

Two scoring modes, auto-detected per target from the ground truth:

* **findings mode** — target has ``expected_findings``. The judge maps produced
  findings to expected defects → precision / recall / F1.
* **flag mode** — target has ``flag`` or ``flag_regex`` (CTF / XBEN style).
  The challenge is *solved* iff the flag appears in the findings → success rate.

Exit codes (for CI): 0 = ok; 2 = below a --min-* threshold; 3 = a scan errored
and --fail-on-scan-error was set.

Only scan targets you are authorized to test.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from ..config import HarnessConfig, default_config
from ..cost import cost_metrics, load_trace_summary
from ..findings import load_findings
from ..llm import build_llm_call
from ..runner import run_scan, slugify
from .judge import FlagResult, JudgeResult, judge, judge_flag_capture
from .targets import TargetManager

DEFAULT_GROUND_TRUTH = Path(__file__).resolve().parent / "ground_truth" / "EXAMPLE.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def target_mode(spec: dict) -> str:
    """Auto-detect the scoring mode for a ground-truth target."""
    if spec.get("flag") or spec.get("flag_regex"):
        return "flag"
    return "findings"


def load_ground_truth(path: Path) -> Dict[str, dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}


def _aggregate_findings_metrics(results: Dict[str, JudgeResult]) -> Dict[str, float]:
    tp = sum(r.true_positive_count for r in results.values())
    fp = sum(r.false_positive_count for r in results.values())
    fn = sum(r.false_negative_count for r in results.values())
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def cmd_run(config: HarnessConfig, args: argparse.Namespace) -> int:
    corpus = load_ground_truth(args.ground_truth)
    if args.repos:
        repos = [r.strip() for r in args.repos.split(",")]
        corpus = {k: v for k, v in corpus.items() if k in repos}
        if not corpus:
            print(f"No matching targets in corpus for: {repos}")
            return 1

    out_root = config.benchmark_dir / "targets"
    out_root.mkdir(parents=True, exist_ok=True)
    jr_dir = config.benchmark_dir / "judge_results"
    jr_dir.mkdir(parents=True, exist_ok=True)

    llm_call = build_llm_call(config)
    effective_backend = config.judge_backend if llm_call else "heuristic"
    if config.judge_backend in ("anthropic", "openai") and llm_call is None:
        print(
            f"[warn] judge backend '{config.judge_backend}' unavailable "
            "(missing API key or SDK) — falling back to heuristic judge."
        )

    tm = TargetManager() if args.setup else None

    findings_results: Dict[str, JudgeResult] = {}
    flag_results: Dict[str, FlagResult] = {}
    scan_errors: List[str] = []
    report_targets: Dict[str, dict] = {}
    report_detail: Dict[str, dict] = {}

    for name, spec in corpus.items():
        mode = target_mode(spec)
        findings_path = out_root / name / "findings.jsonl"
        target_url = spec.get("target")

        trace_dir = findings_path.parent
        scan_cost_summary = None
        if args.tally_only:
            findings = load_findings(findings_path)
            print(f"[{name}] tally-only ({mode}): {len(findings)} findings from prior run")
            scan_cost_summary = load_trace_summary(trace_dir)
            if scan_cost_summary is None and target_url:
                scan_cost_summary = load_trace_summary(out_root / slugify(target_url))
        else:
            if tm is not None and (spec.get("setup") or {}):
                print(f"[{name}] setup …")
                setup = tm.setup(spec)
                if not setup.ok:
                    print(f"[{name}] SETUP FAILED: {setup.detail}")
                    scan_errors.append(name)
                    report_targets[name] = {"mode": mode, "error": f"setup: {setup.detail}"}
                    continue
                target_url = setup.target_url

            try:
                print(f"[{name}] scanning {target_url} ({mode} mode) …")
                result = run_scan(target_url, config, out_root, scope=spec.get("scope"))
                findings = result.findings
                trace_dir = result.out_dir
                scan_cost_summary = result.trace_summary
                print(
                    f"[{name}] scan {result.status}: {result.finding_count} findings "
                    f"in {result.duration_sec:.0f}s"
                )
                if result.status != "done":
                    scan_errors.append(name)
            finally:
                if tm is not None and (spec.get("setup") or {}):
                    tm.teardown(spec)

        if mode == "flag":
            fr = judge_flag_capture(
                findings, flag=spec.get("flag"), flag_regex=spec.get("flag_regex")
            )
            flag_results[name] = fr
            status = "SOLVED" if fr.solved else "unsolved"
            print(f"[{name}] {status}")
            report_targets[name] = {"mode": "flag", "solved": fr.solved}
            report_detail[name] = {"solved": fr.solved, "matched_text": fr.matched_text}
            (jr_dir / f"{name}.json").write_text(
                json.dumps(
                    {"target": spec.get("target"), "mode": "flag", "solved": fr.solved,
                     "matched_text": fr.matched_text},
                    indent=2, default=str,
                ),
                encoding="utf-8",
            )
        else:
            jr = judge(
                findings, spec.get("expected_findings", []),
                backend=effective_backend, llm_call=llm_call,
            )
            findings_results[name] = jr
            m = jr.metrics()
            print(
                f"[{name}] recall={m['recall']:.2f} precision={m['precision']:.2f} "
                f"f1={m['f1']:.2f}  (TP={m['true_positives']} "
                f"FN={m['false_negatives']} FP={m['false_positives']})"
            )
            if jr.missed:
                print(f"        missed: {', '.join(jr.missed)}")
            report_targets[name] = {"mode": "findings", **m}
            report_detail[name] = {"detected": jr.detected, "missed": jr.missed}
            (jr_dir / f"{name}.json").write_text(
                json.dumps(
                    {"target": spec.get("target"), "mode": "findings", "metrics": m,
                     "detected": jr.detected, "missed": jr.missed,
                     "matches": jr.matches, "false_positives": jr.false_positives},
                    indent=2, default=str,
                ),
                encoding="utf-8",
            )

        tp = 0
        if name in findings_results:
            tp = findings_results[name].true_positive_count
        costs = cost_metrics(
            scan_cost_summary or load_trace_summary(trace_dir),
            finding_count=len(findings),
            true_positives=tp,
        )
        report_targets[name].update(costs)
        if costs.get("cost_usd"):
            print(
                f"        cost=${costs['cost_usd']:.4f}"
                + (
                    f"  $/TP={costs['cost_per_true_positive']:.4f}"
                    if costs.get("cost_per_true_positive") is not None
                    else ""
                )
            )

    aggregate: Dict[str, object] = {}
    if findings_results:
        aggregate["findings"] = _aggregate_findings_metrics(findings_results)
    if flag_results:
        solved = sum(1 for r in flag_results.values() if r.solved)
        total = len(flag_results)
        aggregate["flag"] = {
            "solved": solved,
            "total": total,
            "success_rate": round(solved / total, 4) if total else 0.0,
        }

    cost_rows = [
        t for t in report_targets.values()
        if isinstance(t, dict) and t.get("cost_usd")
    ]
    if cost_rows:
        total_cost = sum(float(t.get("cost_usd") or 0) for t in cost_rows)
        tp_all = sum(int(t.get("true_positives") or 0) for t in report_targets.values() if isinstance(t, dict))
        aggregate["cost"] = {
            "cost_usd": round(total_cost, 6),
            "cost_per_true_positive": round(total_cost / tp_all, 6) if tp_all else None,
        }

    report = {
        "generated_at": _now(),
        "judge_backend": effective_backend,
        "targets": report_targets,
        "detail": report_detail,
        "aggregate": aggregate,
        "scan_errors": scan_errors,
    }
    report_path = config.benchmark_dir / "benchmark_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

    _print_summary(report, effective_backend)

    return _exit_code(report, args)


def _print_summary(report: dict, backend: str) -> None:
    agg = report["aggregate"]
    print("\n" + "=" * 60)
    print("  BENCHMARK SUMMARY")
    print(f"  judge backend: {backend}")
    print(f"  targets:       {len(report['targets'])}")
    if "findings" in agg:
        f = agg["findings"]
        print(
            f"  findings mode: recall={f['recall']:.2f} "
            f"precision={f['precision']:.2f} f1={f['f1']:.2f} "
            f"(TP={f['true_positives']} FN={f['false_negatives']} FP={f['false_positives']})"
        )
    if "flag" in agg:
        fl = agg["flag"]
        print(
            f"  flag mode:     {fl['solved']}/{fl['total']} solved "
            f"(success rate {fl['success_rate']:.2%})"
        )
    if "cost" in agg:
        c = agg["cost"]
        extra = ""
        if c.get("cost_per_true_positive") is not None:
            extra = f"  $/TP={c['cost_per_true_positive']:.4f}"
        print(f"  llm cost:      ${c['cost_usd']:.4f}{extra}")
    if report["scan_errors"]:
        print(f"  scan errors:   {len(report['scan_errors'])} ({', '.join(report['scan_errors'])})")
    print("=" * 60)


def _exit_code(report: dict, args: argparse.Namespace) -> int:
    agg = report["aggregate"]
    if args.fail_on_scan_error and report["scan_errors"]:
        print(f"\n[gate] scan errors present → exit 3")
        return 3
    if args.min_recall is not None and "findings" in agg:
        recall = agg["findings"]["recall"]
        if recall < args.min_recall:
            print(f"\n[gate] recall {recall:.2f} < --min-recall {args.min_recall} → exit 2")
            return 2
    if args.min_success_rate is not None and "flag" in agg:
        sr = agg["flag"]["success_rate"]
        if sr < args.min_success_rate:
            print(
                f"\n[gate] success rate {sr:.2f} < "
                f"--min-success-rate {args.min_success_rate} → exit 2"
            )
            return 2
    if args.max_cost_per_tp is not None and "cost" in agg:
        cpt = agg["cost"].get("cost_per_true_positive")
        if cpt is not None and cpt > args.max_cost_per_tp:
            print(
                f"\n[gate] cost/TP {cpt:.4f} > "
                f"--max-cost-per-tp {args.max_cost_per_tp} → exit 2"
            )
            return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="local_harness.benchmark.run",
        description="Benchmark the Aegis Vanguard scanner against a known-vulnerable corpus.",
    )
    parser.add_argument("--repos", help="Comma-separated subset of corpus targets")
    parser.add_argument(
        "--ground-truth", type=Path, default=DEFAULT_GROUND_TRUTH,
        help="Path to the ground-truth corpus JSON",
    )
    parser.add_argument(
        "--tally-only", action="store_true",
        help="Re-judge/re-tally from prior scan artifacts without rescanning",
    )
    parser.add_argument(
        "--setup", action="store_true",
        help="Stand each target up (docker) before scanning and tear it down after",
    )
    parser.add_argument(
        "--min-recall", type=float, default=None,
        help="CI gate: exit 2 if findings-mode recall is below this (0-1)",
    )
    parser.add_argument(
        "--min-success-rate", type=float, default=None,
        help="CI gate: exit 2 if flag-mode success rate is below this (0-1)",
    )
    parser.add_argument(
        "--fail-on-scan-error", action="store_true",
        help="CI gate: exit 3 if any target failed to scan/setup",
    )
    parser.add_argument(
        "--max-cost-per-tp", type=float, default=None,
        help="CI gate: exit 2 if LLM cost per true-positive exceeds this USD amount",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    config = default_config()
    return cmd_run(config, args)


if __name__ == "__main__":
    sys.exit(main())
