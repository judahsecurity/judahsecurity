from local_harness.cost import cost_metrics


def test_cost_metrics_tolerates_redacted_tokens():
    metrics = cost_metrics(
        {"estimated_cost_usd": 2.5, "tokens": "[redacted]"},
        finding_count=2,
        true_positives=1,
    )

    assert metrics["cost_usd"] == 2.5
    assert metrics["input_tokens"] == 0
    assert metrics["output_tokens"] == 0
    assert metrics["cost_per_true_positive"] == 2.5
