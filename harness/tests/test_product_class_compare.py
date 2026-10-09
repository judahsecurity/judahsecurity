from copy import deepcopy

import pytest

from local_harness.product_class_compare import compare_product_class_reports


def _report(cost=0.5):
    case_base = {
        "bug_class": "xss", "budget": {"max_turns": 4},
        "model_routes": {"offensive": ["model-a"]},
        "status": "pass", "eligible_surface_observed": True,
        "test_attempted": True, "evidence_captured": True,
        "metrics": {"verified_true_positives": 1, "false_positives": 0,
                    "false_negatives": 0},
        "cost_usd": cost,
    }
    positive = {**case_base, "id": "xss-positive", "polarity": "positive",
                "negative_with_evidence": False}
    negative = {**case_base, "id": "xss-negative", "polarity": "negative",
                "negative_with_evidence": True,
                "metrics": {"verified_true_positives": 0, "false_positives": 0,
                            "false_negatives": 0}}
    return {"cases": [positive, negative], "by_class": {"xss": {"pass": True}}}


def test_equal_budget_candidate_can_save_cost_without_losing_proof():
    old, new = _report(), _report(0.4)
    result = compare_product_class_reports(old, new)
    assert result["adopt"] is True
    assert result["quality_pass"] is True
    assert result["cost_saving_fraction"] == 0.2


def test_cost_saving_cannot_hide_missing_attempt_or_negative_evidence():
    old, new = _report(), _report(0.1)
    new["cases"][0]["test_attempted"] = False
    new["cases"][1]["negative_with_evidence"] = False
    new["cases"][0]["metrics"]["verified_true_positives"] = 0
    result = compare_product_class_reports(old, new)
    assert result["cost_pass"] is True
    assert result["adopt"] is False
    assert any("test_attempted" in reason for reason in result["reasons"])
    assert any("negative result" in reason for reason in result["reasons"])


def test_comparison_rejects_changed_budget_model_or_incomplete_receipt():
    old, new = _report(), _report(0.4)
    new["cases"][0]["budget"] = {"max_turns": 2}
    with pytest.raises(ValueError, match="budget differs"):
        compare_product_class_reports(old, new)
    new = _report(0.4)
    new["cases"][0]["model_routes"] = {"offensive": ["model-b"]}
    with pytest.raises(ValueError, match="model_routes differs"):
        compare_product_class_reports(old, new)
    new = deepcopy(_report(0.4))
    new["cases"][0]["status"] = "incomplete"
    assert compare_product_class_reports(old, new)["adopt"] is False
