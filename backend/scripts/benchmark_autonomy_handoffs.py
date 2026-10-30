"""Offline observation recall and optional pilot-outcome benchmark.

Usage: PYTHONPATH=backend python backend/scripts/benchmark_autonomy_handoffs.py
Optional --results JSON: {"cases":[{"id":"case_id","candidates":1,
"verified_candidates":1,"false_positives":0,"requests":10,
"time_seconds":30,"spend_usd":0.25}]}
Only receipt-backed Prowl counts belong in verified_candidates.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.recon_observation_adapter import (
    ingest_capability_observations, ingest_dnsx_cnames, ingest_httpx_observations,
)

DEFAULT_FIXTURES = Path(__file__).resolve().parents[1] / "tests/fixtures/autonomy_handoffs.json"


def evaluate(fixtures: dict[str, Any], verified_results: dict[str, Any] | None = None) -> dict[str, Any]:
    rows = []
    lead_expected = lead_detected = false_leads = 0
    assets_expected = assets_detected = 0
    endpoints_expected = endpoints_detected = 0
    candidates_expected = candidates_detected = candidates_covered = 0
    verified_expected = verified_detected = 0
    verified_covered = 0
    requests = time_seconds = spend_usd = false_positives = 0
    measured_cases = 0
    for case in fixtures.get("cases") or []:
        brain = EngagementBrain(target=str(case["target"]))
        scope = case.get("scope_hosts") or []
        ingest_dnsx_cnames(brain, str(case.get("dnsx_output") or ""), scope_hosts=scope)
        ingest_httpx_observations(brain, str(case.get("httpx_output") or ""), scope_hosts=scope)
        ingest_capability_observations(brain, {
            "target": case["target"], "js_endpoints": case.get("js_endpoints") or [],
            "api_endpoints": case.get("api_endpoints") or [],
            "js_files": case.get("js_files") or [],
        }, scope_hosts=scope)
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
        actual_assets = {
            str(row.get("host")) for row in brain.recon_observations
            if row.get("kind") in {"dns_cname", "live_host"}
        }
        expected_assets = set(case.get("expected_assets") or [])
        assets_expected += len(expected_assets)
        assets_detected += len(expected_assets & actual_assets)
        actual_endpoints = {
            str(row.get("target")) for row in brain.recon_observations
            if row.get("kind") in {"js_api_endpoint", "api_endpoint"}
        }
        expected_endpoints = set(case.get("expected_endpoints") or [])
        endpoints_expected += len(expected_endpoints)
        endpoints_detected += len(expected_endpoints & actual_endpoints)
        expected_candidates = int(case.get("expected_candidates") or 0)
        candidates_expected += expected_candidates
        expected_verified = int(case.get("expected_verified") or 0)
        verified_expected += expected_verified
        outcome = (verified_results or {}).get(case["id"])
        if isinstance(outcome, int):
            outcome = {"verified_candidates": outcome}
        observed_verified = None
        observed_candidates = None
        if isinstance(outcome, dict):
            measured_cases += 1
            if "candidates" in outcome:
                observed_candidates = max(0, int(outcome["candidates"]))
                candidates_detected += min(expected_candidates, observed_candidates)
                candidates_covered += expected_candidates
            requests += max(0, int(outcome.get("requests") or 0))
            time_seconds += max(0, float(outcome.get("time_seconds") or 0))
            spend_usd += max(0, float(outcome.get("spend_usd") or 0))
            false_positives += max(0, int(outcome.get("false_positives") or 0))
        if isinstance(outcome, dict) and "verified_candidates" in outcome:
            observed_verified = max(0, int(outcome["verified_candidates"]))
            verified_detected += min(expected_verified, observed_verified)
            verified_covered += expected_verified
        rows.append({
            "id": case["id"], "lead_expected": len(expected), "lead_detected": matched,
            "false_leads": extras, "verified_expected": expected_verified,
            "verified_detected": observed_verified,
            "asset_expected": len(expected_assets), "asset_detected": len(expected_assets & actual_assets),
            "endpoint_expected": len(expected_endpoints), "endpoint_detected": len(expected_endpoints & actual_endpoints),
            "candidate_expected": expected_candidates, "candidate_detected": observed_candidates,
        })
    return {
        "cases": rows,
        "asset_recall": assets_detected / assets_expected if assets_expected else None,
        "endpoint_recall": endpoints_detected / endpoints_expected if endpoints_expected else None,
        "lead_recall": lead_detected / lead_expected if lead_expected else None,
        "false_leads": false_leads,
        "candidate_recall": candidates_detected / candidates_covered if candidates_covered else None,
        "candidate_expected": candidates_expected,
        "verified_recall": verified_detected / verified_covered if verified_covered else None,
        "verified_expected": verified_expected,
        "verified_covered": verified_covered,
        "false_positives": false_positives if measured_cases else None,
        "requests": requests if measured_cases else None,
        "time_seconds": time_seconds if measured_cases else None,
        "spend_usd": spend_usd if measured_cases else None,
        "measured_cases": measured_cases,
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
        results = {str(row["id"]): row for row in payload.get("cases") or []}
    print(json.dumps(evaluate(fixtures, results), indent=2))


if __name__ == "__main__":
    main()
