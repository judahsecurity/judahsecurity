"""Compare equal-budget product-agent runs from two harness output folders.

Usage: python -m local_harness.ledger_compare BASELINE_DIR CANDIDATE_DIR
Both folders must contain product_assessment.json with complete ledger metrics.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .agent_eval import compare_ledger_assessments


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline_dir", type=Path)
    parser.add_argument("candidate_dir", type=Path)
    args = parser.parse_args(argv)
    baseline = json.loads((args.baseline_dir / "product_assessment.json").read_text())
    candidate = json.loads((args.candidate_dir / "product_assessment.json").read_text())
    print(json.dumps(compare_ledger_assessments(baseline, candidate), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
