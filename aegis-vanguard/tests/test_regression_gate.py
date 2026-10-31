from agent.regression_gate import evaluate_regression_gate, format_gate


def _full_coverage():
    return {"planned_total": 10, "planned_tested": 10,
            "states": {"pending": 0, "in_progress": 0}}


def _reproduced(cls):
    return {
        "lifecycle_state": "validated",
        "vuln_type": cls,
        "independent_reproduction": {"reproduced": True, "class": cls},
    }


def test_gate_passes_when_all_criteria_met():
    result = evaluate_regression_gate(
        _full_coverage(),
        [_reproduced("sqli"), _reproduced("xss")],
        tool_errors=0, lease_errors=0,
    )
    assert result["passed"] is True
    assert all(c["passed"] for c in result["checks"])


def test_gate_fails_on_untested_inputs():
    cov = {"planned_total": 10, "planned_tested": 4,
           "states": {"pending": 6, "in_progress": 0}}
    result = evaluate_regression_gate(cov, [_reproduced("sqli"), _reproduced("xss")])
    breadth = next(c for c in result["checks"] if c["name"] == "first_pass_breadth")
    assert breadth["passed"] is False
    assert result["passed"] is False


def test_gate_fails_on_tool_or_lease_errors():
    result = evaluate_regression_gate(
        _full_coverage(), [_reproduced("sqli"), _reproduced("xss")],
        tool_errors=3, lease_errors=2,
    )
    assert result["passed"] is False
    names = {c["name"] for c in result["checks"] if not c["passed"]}
    assert {"no_tool_format_errors", "no_lease_errors"} <= names


def test_gate_fails_when_a_required_class_not_reproduced():
    # SQLi reproduced, XSS only asserted (not independently reproduced).
    asserted_only = {
        "lifecycle_state": "validated", "vuln_type": "xss",
        "independent_reproduction": {"reproduced": None, "class": "xss"},
    }
    result = evaluate_regression_gate(
        _full_coverage(), [_reproduced("sqli"), asserted_only],
    )
    repro = next(c for c in result["checks"] if c["name"] == "independent_reproduction")
    assert repro["passed"] is False
    assert "xss" in repro["detail"]
    assert result["passed"] is False


def test_gate_counts_only_validated_reproductions():
    demoted = {
        "lifecycle_state": "candidate", "vuln_type": "sqli",
        "independent_reproduction": {"reproduced": True, "class": "sqli"},
    }
    result = evaluate_regression_gate(
        _full_coverage(), [demoted, _reproduced("xss")],
        require_reproduced=("sqli",),
    )
    # A reproduced-but-demoted finding does not satisfy the gate.
    assert result["passed"] is False


def test_format_gate_renders_marks():
    result = evaluate_regression_gate(
        _full_coverage(), [_reproduced("sqli"), _reproduced("xss")],
    )
    text = format_gate(result)
    assert "Regression gate: PASS" in text
    assert "first_pass_breadth" in text
