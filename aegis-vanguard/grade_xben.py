#!/usr/bin/env python3
"""
XBEN grader — turn a benchmark run into a pass/fail measurement.

A benchmark is only useful if it has a grader. This one grades a completed
Aegis Vanguard run against ground truth: PASS iff the expected flag appears in
a REAL tool response captured during the run (recorded by agent.flag_oracle),
never from the agent's report prose. Exit 0 = all PASS, 2 = any FAIL.

Single run:
    python3 grade_xben.py --captures results/.../flag_captures_<sid>.json \\
                          --expected 'FLAG{...}'

Whole suite (measure precision across benchmarks):
    python3 grade_xben.py --suite xben_manifest.json

    where xben_manifest.json is:
    {
      "XBEN-020-24": {"captures": "runs/xben020/flag_captures.json",
                      "expected": "FLAG{6e5d...}"},
      "XBEN-021-24": {"captures": "runs/xben021/flag_captures.json",
                      "expected": "FLAG{ab12...}"}
    }
"""

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent.flag_oracle import grade, _load_captured_flags  # noqa: E402


def _grade_file(captures_path: str, expected_flag):
    with open(captures_path) as fh:
        payload = json.load(fh)
    return grade(expected_flag, _load_captured_flags(payload))


def _grade_single(args) -> int:
    verdict = _grade_file(args.captures, args.expected)
    print(json.dumps(verdict.to_dict(), indent=2))
    # NO_EXPECTED_FLAG is not a failure of the target, but it is not a graded
    # pass either — surface it as a non-zero "cannot grade" only if asked to be
    # strict; by default treat it as 0 so ungraded runs don't break pipelines.
    if verdict.status == "PASS":
        return 0
    if verdict.status == "FAIL":
        return 2
    return 0 if not args.require_expected else 3


def _grade_suite(args) -> int:
    with open(args.suite) as fh:
        manifest = json.load(fh)

    base = Path(args.suite).resolve().parent
    rows, passed, failed, ungraded = [], 0, 0, 0

    for bench_id, spec in manifest.items():
        cap = spec.get("captures", "")
        cap_path = cap if os.path.isabs(cap) else str(base / cap)
        expected = spec.get("expected")
        try:
            verdict = _grade_file(cap_path, expected)
            status = verdict.status
        except FileNotFoundError:
            status = "NO_CAPTURES"
        except json.JSONDecodeError:
            status = "BAD_CAPTURES"

        if status == "PASS":
            passed += 1
        elif status == "FAIL":
            failed += 1
        else:
            ungraded += 1
        rows.append((bench_id, status))

    graded = passed + failed
    print(f"{'BENCHMARK':<24} VERDICT")
    print("-" * 40)
    for bench_id, status in rows:
        mark = {"PASS": "✅", "FAIL": "❌"}.get(status, "—")
        print(f"{bench_id:<24} {mark} {status}")
    print("-" * 40)
    rate = (passed / graded * 100) if graded else 0.0
    print(f"PASS {passed}/{graded} graded ({rate:.0f}%)   "
          f"ungraded/errored: {ungraded}")

    if args.out:
        Path(args.out).write_text(json.dumps(
            {
                "passed": passed, "failed": failed, "ungraded": ungraded,
                "graded": graded, "pass_rate": rate,
                "results": {b: s for b, s in rows},
            },
            indent=2,
        ))

    return 0 if failed == 0 else 2


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="grade_xben",
        description="Grade Aegis Vanguard benchmark run(s) against ground-truth flags.",
    )
    p.add_argument("--captures", help="Path to a run's flag_captures JSON.")
    p.add_argument("--expected", default=os.environ.get("AEGIS_EXPECTED_FLAG"),
                   help="Expected flag (default: AEGIS_EXPECTED_FLAG).")
    p.add_argument("--require-expected", action="store_true",
                   help="Exit non-zero when no expected flag is configured (single mode).")
    p.add_argument("--suite", help="Path to a suite manifest JSON for batch grading.")
    p.add_argument("--out", help="Write suite summary JSON to this path (suite mode).")
    args = p.parse_args(argv)

    if args.suite:
        return _grade_suite(args)
    if args.captures:
        return _grade_single(args)
    p.error("provide --captures (single run) or --suite (batch)")


if __name__ == "__main__":
    raise SystemExit(main())
