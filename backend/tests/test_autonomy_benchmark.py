import json

from scripts.benchmark_autonomy_handoffs import DEFAULT_FIXTURES, evaluate


def test_sanitized_benchmark_separates_leads_and_verified_results():
    fixtures = json.loads(DEFAULT_FIXTURES.read_text(encoding="utf-8"))
    baseline = evaluate(fixtures)
    assert baseline["lead_recall"] == 1.0
    assert baseline["false_leads"] == 0
    assert baseline["verified_expected"] == 1
    assert baseline["verified_recall"] is None

    results = evaluate(fixtures, {"nanoclaw_takeover_pattern": 0})
    assert results["verified_recall"] == 0.0
    results = evaluate(fixtures, {"nanoclaw_takeover_pattern": 1})
    assert results["verified_recall"] == 1.0
