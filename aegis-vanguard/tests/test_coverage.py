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


def test_coverage_event_can_attribute_each_tested_identity():
    ledger = CoverageLedger.from_input_surface(
        _surface(params=["order_id"]),
        identities=[{"label": "owner"}, {"label": "other"}],
    )

    ledger.record_probe_result(
        {
            "probe": "authz",
            "target": "https://example.test/orders",
            "method": "POST",
            "coverage": [
                {"parameter_spec": "form:order_id", "identity": "owner",
                 "status": "tested_negative"},
                {"parameter_spec": "form:order_id", "identity": "other",
                 "status": "candidate", "signals": ["idor"]},
            ],
        },
        source="identity_authz_diff",
    )

    states = {
        row["identity"]: row["state"]
        for row in ledger.snapshot()
        if row["vulnerability_class"] == "authz"
        and row["parameter"] == "form:order_id"
        and row["planned"]
    }
    assert states == {"owner": "tested_negative", "other": "candidate"}


def test_plan_includes_observed_non_sqli_classes_and_endpoint_checks():
    ledger = CoverageLedger.from_input_surface({
        "forms": [
            {"action_url": "https://example.test/api/orders", "method": "POST",
             "content_type": "application/json",
             "eligible_parameters": ["json:filter", "json:template", "json:comment"]},
            {"action_url": "https://example.test/import.xml", "method": "POST",
             "content_type": "application/xml", "eligible_parameters": []},
        ],
    })
    rows = {(row["endpoint"], row["parameter"], row["vulnerability_class"])
            for row in ledger.snapshot() if row["planned"]}
    assert ("https://example.test/api/orders", "json:filter", "nosql") in rows
    assert ("https://example.test/api/orders", "json:template", "ssti") in rows
    assert ("https://example.test/api/orders", "json:comment", "stored_xss") in rows
    assert ("https://example.test/api/orders", "endpoint", "prototype_pollution") in rows
    assert ("https://example.test/import.xml", "endpoint", "xxe") in rows


def test_post_probe_result_matches_planned_class_and_method():
    ledger = CoverageLedger.from_input_surface({"forms": [{
        "action_url": "https://example.test/api/orders", "method": "POST",
        "content_type": "application/json", "eligible_parameters": ["json:filter"],
    }]})
    touched = ledger.record_probe_result({
        "probe": "nosql", "target": "https://example.test/api/orders",
        "method": "POST", "tested_params": ["json:filter"], "candidates": [],
    }, source="injection_hunter")
    assert touched == 1
    assert next(row for row in ledger.snapshot()
                if row["vulnerability_class"] == "nosql"
                and row["parameter"] == "json:filter")["state"] == "tested_negative"
    assert any(row["vulnerability_class"] == "sqli" and row["state"] == "pending"
               for row in ledger.snapshot())


def test_bounded_pending_list_includes_multiple_classes():
    ledger = CoverageLedger.from_input_surface({"forms": [{
        "action_url": f"https://example.test/api/search/{index}",
        "method": "GET", "eligible_parameters": ["q", "redirect_url", "template"],
    } for index in range(30)]})
    classes = {row["vulnerability_class"] for row in ledger.pending(limit=10)}
    assert len(classes) >= 6


def test_validated_finding_closes_its_planned_cell_despite_identity_drift():
    # A proven finding rarely echoes endpoint/identity exactly as planned.
    # It must still close its matching planned cell, not fork a new one.
    ledger = CoverageLedger.from_input_surface({"forms": [{
        "action_url": "https://example.test/catalog", "method": "GET",
        "eligible_parameters": ["category"],
    }]})
    ledger.apply_findings([{
        "vuln_type": "sqli",
        "endpoint": "https://example.test/catalog?category=1",  # echoes query string
        "parameter": "category",                                # plain, not location-aware
        "method": "GET",
        "identity": "unspecified",                              # drift from planned "anonymous"
        "evidence": "sqlmap confirmed",
    }], "validated", source="exploit_validation")

    sqli_rows = [r for r in ledger.snapshot() if r["vulnerability_class"] == "sqli"]
    validated = [r for r in sqli_rows if r["state"] == "validated"]
    assert len(validated) == 1
    assert validated[0]["planned"] is True
    assert validated[0]["parameter"] == "query:category"
    assert ledger.summary()["unplanned_observations"] == 0
    assert ledger.summary()["planned_tested"] == 1


def test_proof_does_not_close_a_different_parameter_cell():
    ledger = CoverageLedger.from_input_surface({"forms": [{
        "action_url": "https://example.test/catalog", "method": "GET",
        "eligible_parameters": ["category", "q"],
    }]})
    ledger.apply_findings([{
        "vuln_type": "sqli", "endpoint": "https://example.test/catalog",
        "parameter": "q", "method": "GET", "identity": "anonymous",
    }], "validated", source="exploit_validation")

    by_param = {r["parameter"]: r["state"] for r in ledger.snapshot()
                if r["vulnerability_class"] == "sqli"}
    assert by_param["query:q"] == "validated"
    assert by_param["query:category"] == "pending"


def test_proof_does_not_cross_method_boundary():
    ledger = CoverageLedger.from_input_surface({"forms": [{
        "action_url": "https://example.test/item", "method": "POST",
        "content_type": "application/x-www-form-urlencoded",
        "eligible_parameters": ["name"],
    }]})
    # A GET-proven finding must not close the POST-planned cell.
    ledger.apply_findings([{
        "vuln_type": "sqli", "endpoint": "https://example.test/item",
        "parameter": "name", "method": "GET", "identity": "anonymous",
    }], "validated", source="exploit_validation")
    planned_post = [r for r in ledger.snapshot()
                    if r["planned"] and r["method"] == "POST"
                    and r["vulnerability_class"] == "sqli"]
    assert planned_post and planned_post[0]["state"] == "pending"


def _multi_surface(n=6):
    return {"forms": [{
        "action_url": f"https://example.test/p{i}", "method": "GET",
        "eligible_parameters": ["q"],
    } for i in range(n)]}


def test_leases_are_disjoint_across_concurrent_owners():
    ledger = CoverageLedger.from_input_surface(_multi_surface(n=6))
    a = ledger.lease(classes=["sqli"], limit=3, owner="hunterA")
    b = ledger.lease(classes=["sqli"], limit=3, owner="hunterB")
    a_keys = {(c["endpoint"], c["parameter"]) for c in a["cells"]}
    b_keys = {(c["endpoint"], c["parameter"]) for c in b["cells"]}
    assert a_keys and b_keys
    assert a_keys.isdisjoint(b_keys)          # breadth: no overlap
    assert all(c["state"] == "in_progress" for c in a["cells"] + b["cells"])


def test_lease_excludes_already_validated_cells():
    ledger = CoverageLedger.from_input_surface(_multi_surface(n=3))
    ledger.apply_findings([{
        "vuln_type": "sqli", "endpoint": "https://example.test/p0",
        "parameter": "q", "method": "GET", "identity": "anonymous",
    }], "validated", source="x")
    leased = ledger.lease(classes=["sqli"], limit=10, owner="h")
    assert "https://example.test/p0" not in {c["endpoint"] for c in leased["cells"]}


def test_release_returns_unworked_cells_to_pending():
    ledger = CoverageLedger.from_input_surface(_multi_surface(n=3))
    lease = ledger.lease(classes=["sqli"], limit=10, owner="failing_hunter")
    assert all(r["state"] == "pending" for r in ledger.snapshot()
               if r["vulnerability_class"] == "sqli") is False  # now in_progress
    reverted = ledger.release("failing_hunter")
    assert reverted == len(lease["cells"])
    assert all(r["state"] == "pending" for r in ledger.snapshot()
               if r["vulnerability_class"] == "sqli")


def test_release_keeps_cells_that_gathered_evidence():
    ledger = CoverageLedger.from_input_surface(_multi_surface(n=2))
    ledger.lease(classes=["sqli"], limit=10, owner="h")
    # Evidence arrives for p0 while the lease is open.
    ledger.record_probe_result({
        "probe": "sqli", "target": "https://example.test/p0", "method": "GET",
        "params_tested": ["query:q"], "candidates": [],
    }, source="h")
    ledger.release("h")
    by_ep = {r["endpoint"]: r["state"] for r in ledger.snapshot()
             if r["vulnerability_class"] == "sqli"}
    assert by_ep["https://example.test/p0"] == "tested_negative"  # evidence kept
    assert by_ep["https://example.test/p1"] == "pending"          # unworked, released


def test_coverage_classes_for_mapping():
    from agent.coverage import coverage_classes_for
    assert "sqli" in coverage_classes_for("injection")
    assert "xss" in coverage_classes_for("xss")
    assert coverage_classes_for("nonexistent") == frozenset()
