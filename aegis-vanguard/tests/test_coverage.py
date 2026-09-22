from agent.coverage import CoverageLedger


def _surface(method="POST", params=None):
    return {
        "success": True,
        "forms": [{
            "action_url": "https://example.test/orders?tracking=ignored",
            "method": method,
            "content_type": "application/x-www-form-urlencoded",
            "eligible_parameters": params or ["order_id", "redirect_url"],
        }],
        "request_templates": [],
    }


def test_plan_is_parameter_class_and_identity_aware():
    ledger = CoverageLedger.from_input_surface(
        _surface(),
        identities=[{"label": "owner"}, {"label": "other"}],
    )
    rows = ledger.snapshot()

    assert any(
        row["parameter"] == "form:order_id"
        and row["vulnerability_class"] == "authz"
        and row["identity"] == "other"
        for row in rows
    )
    assert any(
        row["parameter"] == "form:redirect_url"
        and row["vulnerability_class"] == "open_redirect"
        for row in rows
    )
    assert all("?" not in row["endpoint"] for row in rows)
    assert ledger.summary()["coverage_rate"] == 0.0


def test_generic_probe_marks_exact_planned_row_tested():
    ledger = CoverageLedger.from_input_surface(_surface(method="GET", params=["q"]))

    touched = ledger.record_probe_result(
        {
            "probe": "xss",
            "target": "https://example.test/orders",
            "method": "GET",
            "tested_params": ["query:q"],
            "candidates": [],
        },
        source="xss_hunter",
    )

    assert touched == 1
    row = next(
        row for row in ledger.snapshot()
        if row["vulnerability_class"] == "xss" and row["parameter"] == "query:q"
    )
    assert row["state"] == "tested_negative"
    assert ledger.summary()["planned_tested"] == 1


def test_sqli_coverage_preserves_candidate_and_negative_states():
    ledger = CoverageLedger.from_input_surface(_surface(params=["name", "email"]))

    ledger.record_probe_result(
        {
            "url": "https://example.test/orders",
            "method": "POST",
            "params_tested": ["form:name", "form:email"],
            "coverage": [
                {"parameter_spec": "form:name", "status": "candidate", "signals": ["sql_error"]},
                {"parameter_spec": "form:email", "status": "tested_negative", "signals": []},
            ],
        },
        source="injection_hunter",
    )

    states = {
        row["parameter"]: row["state"]
        for row in ledger.snapshot()
        if row["vulnerability_class"] == "sqli"
    }
    assert states == {"form:email": "tested_negative", "form:name": "candidate"}


def test_unspecified_identity_does_not_claim_identity_specific_coverage():
    ledger = CoverageLedger.from_input_surface(
        _surface(params=["order_id"]),
        identities=[{"label": "owner"}, {"label": "other"}],
    )

    ledger.record_probe_result(
        {
            "probe": "authz",
            "target": "https://example.test/orders",
            "method": "POST",
            "tested_params": ["form:order_id"],
            "candidates": [],
        },
        source="authz_hunter",
    )

    rows = [
        row for row in ledger.snapshot()
        if row["vulnerability_class"] == "authz" and row["parameter"] == "form:order_id"
    ]
    assert {row["identity"] for row in rows if row["planned"]} == {"owner", "other"}
    assert all(row["state"] == "pending" for row in rows if row["planned"])
    assert any(
        row["identity"] == "unspecified" and row["state"] == "tested_negative"
        for row in rows
    )
