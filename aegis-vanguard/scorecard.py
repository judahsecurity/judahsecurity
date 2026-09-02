#!/usr/bin/env python3
"""
Agent performance scorecard CLI.

Score a directory of run artifacts (findings_<sid>.json + grade_<sid>.json) into
objective performance metrics, and optionally diff against a baseline scorecard
so a change that makes the agent worse fails CI instead of shipping.

    # Score a suite of runs
    python3 scorecard.py --runs results/ --out scorecard.json

    # Gate a change: fail (exit 1) if any metric regressed vs the last scorecard
    python3 scorecard.py --runs results/ --baseline scorecard.json
"""

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent.scorecard import aggregate, compare, load_runs, render_markdown  # noqa: E402


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="scorecard",
        description="Score agent run artifacts into performance metrics.")
    p.add_argument("--runs", required=True,
                   help="Directory of run artifacts (findings_*.json / grade_*.json).")
    p.add_argument("--out", help="Write the aggregate scorecard JSON here.")
    p.add_argument("--baseline", help="Prior scorecard JSON to diff against.")
    p.add_argument("--tolerance", type=float, default=0.0,
                   help="Metric change smaller than this is not a regression.")
    args = p.parse_args(argv)

    scores = load_runs(args.runs)
    if not scores:
        print(f"no run artifacts found in {args.runs}", file=sys.stderr)
        return 1

    agg = aggregate(scores)
    print(render_markdown(agg))

    if args.out:
        Path(args.out).write_text(json.dumps(agg, indent=2, default=str))

    if args.baseline:
        try:
            base = json.loads(Path(args.baseline).read_text())
        except (OSError, json.JSONDecodeError) as e:
            print(f"could not read baseline: {e}", file=sys.stderr)
            return 1
        diff = compare(agg, base, tolerance=args.tolerance)
        if diff["improvements"]:
            print("Improvements:")
            for i in diff["improvements"]:
                print(f"  ↑ {i}")
        if diff["regressions"]:
            print("REGRESSIONS:")
            for r in diff["regressions"]:
                print(f"  ↓ {r}")
            return 1
        print("No regressions vs baseline.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
