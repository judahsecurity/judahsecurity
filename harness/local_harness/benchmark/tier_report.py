"""Score product-agent findings per verification tier against ground truth.

The product agent publishes findings at several levels of proof (see
docs/ASSESSMENT_RELIABILITY.md): ``exploit_verified`` (class-specific proof),
``reproduced`` (generic differential replay), ``analyst_verified`` (promoted by
a person) and ``unverified`` (inconclusive with hunter evidence). This report
answers one question: do the looser tiers recover real bugs, or mostly add
noise?

It judges cumulative tiers, strictest first, with the same heuristic judge the
benchmark uses, and reports recall, false positives and which expected defects
each step added::

    python -m local_harness.benchmark.tier_report \\
        --ground-truth local_harness/benchmark/ground_truth/REAL_WORLD.json \\
        --target juice-shop --findings runs/juice-shop/findings.jsonl

Exit code 2 when ``--min-recall`` (applied to the loosest tier) is not met.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..findings import NormalizedFinding, load_findings
from .judge import judge_heuristic

# Strictest first. "other" covers findings published without a verification
# level (for example low-severity observations) and older sink records.
TIERS = ("exploit_verified", "reproduced", "analyst_verified", "source_verified", "unverified", "other")
_KNOWN = set(TIERS) - {"other"}


def finding_tier(finding: NormalizedFinding) -> str:
    raw = finding.raw or {}
    level = str(raw.get("verification_level") or "").strip().lower()
    if level in _KNOWN:
        return level
    for tag in finding.tags or []:
        if str(tag).lower() in _KNOWN:
            return str(tag).lower()
    if finding.is_confirmed:
        return "exploit_verified"
    return "other"


def tier_report(findings: List[NormalizedFinding], expected: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts = {tier: 0 for tier in TIERS}
    for finding in findings:
        counts[finding_tier(finding)] += 1
    steps: List[Dict[str, Any]] = []
    included: List[str] = []
    previous: set = set()
    previous_fp: List[str] = []
    for tier in TIERS:
        included.append(tier)
        subset = [f for f in findings if finding_tier(f) in included]
        result = judge_heuristic(subset, expected)
        detected = set(result.detected)
        fp_titles = [fp["title"] for fp in result.false_positives]
        remaining = list(previous_fp)
        added_fp = []
        for title in fp_titles:
            if title in remaining:
                remaining.remove(title)
            else:
                added_fp.append(title)
        total = len(expected)
        steps.append({
            "through_tier": tier,
            "findings": len(subset),
            "detected": len(detected),
            "recall": round(len(detected) / total, 4) if total else 0.0,
            "false_positives": len(fp_titles),
            "added_defects": sorted(detected - previous),
            "added_false_positives": added_fp[:50],
        })
        previous, previous_fp = detected, fp_titles
    loosest = steps[-1]
    return {
        "expected_defects": len(expected),
        "findings_by_tier": counts,
        "cumulative": steps,
        "missed": sorted({e["id"] for e in expected} - previous),
        "recovered_by_looser_tiers": sorted(previous - set(steps[0]["added_defects"])),
        "final_recall": loosest["recall"],
    }


def _expected_for(ground_truth: Dict[str, Any], target: str) -> List[Dict[str, Any]]:
    entry = ground_truth.get(target)
    if not isinstance(entry, dict) or not isinstance(entry.get("expected_findings"), list):
        raise SystemExit(f"Target {target!r} has no expected_findings in the ground truth")
    return entry["expected_findings"]


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="local_harness.benchmark.tier_report", description=__doc__.split("\n\n")[0])
    parser.add_argument("--ground-truth", type=Path, required=True)
    parser.add_argument("--target", required=True, help="Key of the target in the ground-truth JSON")
    parser.add_argument("--findings", type=Path, required=True, help="AEGIS_FINDINGS_SINK JSONL from the run")
    parser.add_argument("--out", type=Path, help="Write the report JSON here as well")
    parser.add_argument("--min-recall", type=float, default=None,
                        help="Exit 2 if recall through the loosest tier is below this (0-1)")
    args = parser.parse_args(argv)
    ground_truth = json.loads(args.ground_truth.read_text(encoding="utf-8"))
    report = tier_report(load_findings(args.findings), _expected_for(ground_truth, args.target))
    report["target"] = args.target
    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text + "\n", encoding="utf-8")
    if args.min_recall is not None and report["final_recall"] < args.min_recall:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
