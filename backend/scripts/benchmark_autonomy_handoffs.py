"""Offline lead and verified-result benchmark for sanitized autonomy cases.

Usage: PYTHONPATH=backend python backend/scripts/benchmark_autonomy_handoffs.py
Optional --results JSON: {"cases":[{"id":"case_id","verified_candidates":1}]}
Only independently verified Prowl candidates belong in verified_candidates.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.recon_observation_adapter import ingest_dnsx_cnames, ingest_js_api_paths

DEFAULT_FIXTURES = Path(__file__).resolve().parents[1] / "tests/fixtures/autonomy_handoffs.json"


def evaluate(fixtures: dict[str, Any], verified_results: dict[str, int] | None = None) -> dict[str, Any]:
    rows = []
    lead_expected = lead_detected = false_leads = 0
    verified_expected = verified_detected = 0
    verified_covered = 0
    for case in fixtures.get("cases") or []:
        brain = EngagementBrain(target=str(case["target"]))
        scope = case.get("scope_hosts") or []
        ingest_dnsx_cnames(brain, str(case.get("dnsx_output") or ""), scope_hosts=scope)
        ingest_js_api_paths(
            brain, {"target": case["target"], "js_endpoints": case.get("js_endpoints") or []},
            scope_hosts=scope,
        )
        expected = {
            (str(item["specialist"]), str(item["target"]))
            for item in case.get("expected_leads") or []
        }
        actual = {(h.specialist, h.target) for h in brain.hypotheses}
        matched = len(expected & actual)
        extras = len(actual - expected)
        lead_expected += len(expected)
        lead_detected += matched
        false_leads += extras
        expected_verified = int(case.get("expected_verified") or 0)
        verified_expected += expected_verified
        observed_verified = None
        if verified_results is not None and case["id"] in verified_results:
            observed_verified = max(0, int(verified_results[case["id"]]))
            verified_detected += min(expected_verified, observed_verified)
            verified_covered += expected_verified
        rows.append({
            "id": case["id"], "lead_expected": len(expected), "lead_detected": matched,
            "false_leads": extras, "verified_expected": expected_verified,
            "verified_detected": observed_verified,
        })
    return {
        "cases": rows,
        "lead_recall": lead_detected / lead_expected if lead_expected else None,
        "false_leads": false_leads,
        "verified_recall": verified_detected / verified_covered if verified_covered else None,
        "verified_expected": verified_expected,
        "verified_covered": verified_covered,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES)
    parser.add_argument("--results", type=Path)
    args = parser.parse_args()
    fixtures = json.loads(args.fixtures.read_text(encoding="utf-8"))
    results = None
    if args.results:
        payload = json.loads(args.results.read_text(encoding="utf-8"))
        results = {
            str(row["id"]): int(row["verified_candidates"])
            for row in payload.get("cases") or []
        }
    print(json.dumps(evaluate(fixtures, results), indent=2))


if __name__ == "__main__":
    main()
