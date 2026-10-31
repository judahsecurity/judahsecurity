import json

from scripts.benchmark_autonomy_handoffs import DEFAULT_FIXTURES, evaluate


def test_sanitized_benchmark_separates_leads_and_verified_results():
    fixtures = json.loads(DEFAULT_FIXTURES.read_text(encoding="utf-8"))
    baseline = evaluate(fixtures)
    assert baseline["lead_recall"] == 1.0
    assert baseline["asset_recall"] == 1.0
    assert baseline["endpoint_recall"] == 1.0
    assert baseline["false_leads"] == 0
    assert baseline["verified_expected"] == 1
    assert baseline["verified_recall"] is None
    assert baseline["candidate_recall"] is None
    assert baseline["requests"] is None

    results = evaluate(fixtures, {"nanoclaw_takeover_pattern": 0})
    assert results["verified_recall"] == 0.0
    results = evaluate(fixtures, {"nanoclaw_takeover_pattern": 1})
    assert results["verified_recall"] == 1.0
    measured = evaluate(fixtures, {"nanoclaw_takeover_pattern": {
        "candidates": 1, "verified_candidates": 1, "false_positives": 0,
        "requests": 9, "time_seconds": 12.5, "spend_usd": 0.3,
    }})
    assert measured["candidate_recall"] == 1.0
    assert measured["requests"] == 9
    assert measured["time_seconds"] == 12.5
    assert measured["spend_usd"] == 0.3
