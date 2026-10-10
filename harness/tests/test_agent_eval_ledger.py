"""Product-agent evaluation compares actual work under matching budgets."""

import pytest

from local_harness.agent_eval import compare_ledger_assessments, summarize_run_ledgers


def _assessment(test_actions, *, target="https://lab.example"):
    return {
        "target": target, "scope": target, "max_turns": 2,
        "max_iterations": 30, "price_limit_usd": 5.0,
        "ledger_metrics": {
            "receipt_complete": True, "actions": test_actions + 1,
            "test_actions": test_actions, "repeated_tool_target_actions": 0,
            "fingerprinted_tool_calls": test_actions,
            "exact_repeated_tool_calls": 0,
            "timeout_runs": 0, "published_findings": 0,
            "duration_seconds": 30,
        },
    }


def test_ledger_metrics_detect_complete_and_incomplete_runs():
    complete = summarize_run_ledgers([{
        "run_id": "run-1", "status": "partial",
        "actions": [{"id": "a", "status": "completed"}],
        "coverage": {"actions": 1, "model_calls": 1, "test_actions": 0,
                     "fingerprinted_tool_calls": 1, "exact_repeated_tool_calls": 0,
                     "duration_seconds": 30},
    }])
    assert complete["receipt_complete"] is True
    assert complete["actions"] == 1
    assert complete["fingerprinted_tool_calls"] == 1
    assert summarize_run_ledgers([{
        "run_id": "run-2", "status": "timeout",
        "actions": [{"id": "a", "status": "running"}],
        "coverage": {"actions": 1},
    }])["receipt_complete"] is False


def test_comparison_rejects_different_targets_or_budgets():
    baseline = _assessment(1)
    candidate = _assessment(3)
    assert compare_ledger_assessments(baseline, candidate)["delta"]["test_actions"] == 2
    with pytest.raises(ValueError, match="target"):
        compare_ledger_assessments(baseline, _assessment(3, target="https://other.example"))
    candidate["price_limit_usd"] = 10.0
    with pytest.raises(ValueError, match="price_limit_usd"):
        compare_ledger_assessments(baseline, candidate)
