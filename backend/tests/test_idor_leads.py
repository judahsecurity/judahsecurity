"""IDOR/BOLA lead extraction stays value-free, leads-only, and well-ordered."""

from app.services.agent.scoped_assessment.idor_leads import (
    MAX_LEADS,
    identifier_leads,
    summarize_leads,
)


def _row(method, path, name, location="query", value_type="", identity="owner", testable=True):
    return {
        "method": method, "host": "app.example.test", "path": path, "name": name,
        "location": location, "source": "browser_traffic", "value_type": value_type,
        "identity": identity, "artifact_id": "", "testable": testable,
    }


def test_numeric_query_parameter_is_a_read_lead():
    leads = identifier_leads([_row("GET", "/api/orders", "id", value_type="positive_integer")])
    assert len(leads) == 1
    lead = leads[0]
    assert lead["identifier"] == {"location": "query", "name": "id", "position": None, "kind": "numeric"}
    assert lead["access"] == "read" and lead["enumerable"] is True and lead["lead_only"] is True
    assert lead["identities_observed"] == ["owner"]
    assert "_identity" not in lead


def test_path_segment_id_is_templated_with_collection():
    leads = identifier_leads(None, [{"method": "GET", "path": "/api/users/42/orders", "identity": "owner"}])
    assert len(leads) == 1
    lead = leads[0]
    assert lead["path_template"] == "/api/users/{id}/orders"
    assert lead["path"] == "/api/users/42/orders"  # concrete path (already in the ledger)
    assert lead["identifier"]["location"] == "path" and lead["identifier"]["kind"] == "numeric"
    assert lead["collection"] == "users"


def test_two_identities_merge_into_one_lead():
    rows = [
        _row("GET", "/api/orders", "id", value_type="positive_integer", identity="owner"),
        _row("GET", "/api/orders", "id", value_type="positive_integer", identity="attacker"),
    ]
    leads = identifier_leads(rows)
    assert len(leads) == 1
    assert sorted(leads[0]["identities_observed"]) == ["attacker", "owner"]


def test_uuid_and_objectid_path_segments_classified():
    uuid = "123e4567-e89b-12d3-a456-426614174000"
    oid = "0123456789abcdef01234567"
    leads = identifier_leads(None, [
        {"method": "GET", "path": f"/v1/accounts/{uuid}", "identity": "owner"},
        {"method": "GET", "path": f"/v1/files/{oid}", "identity": "owner"},
    ])
    kinds = {lead["identifier"]["kind"] for lead in leads}
    assert kinds == {"uuid", "objectid"}
    assert all(lead["enumerable"] is False for lead in leads)  # opaque ids aren't enumerable


def test_protected_and_non_id_parameters_are_skipped():
    rows = [
        _row("GET", "/account", "csrf_token", value_type="", testable=False),
        _row("GET", "/account", "csrf", value_type="positive_integer", testable=False),
        _row("GET", "/search", "q", value_type="string"),  # not id-shaped
    ]
    assert identifier_leads(rows) == []


def test_name_hinted_reference_without_integer_value():
    rows = [_row("GET", "/api/profile", "account_id", value_type="string")]
    leads = identifier_leads(rows)
    assert len(leads) == 1
    assert leads[0]["identifier"]["kind"] == "name_hint"
    assert leads[0]["enumerable"] is False


def test_write_methods_are_write_access_and_sorted_first():
    rows = [
        _row("GET", "/api/orders", "id", value_type="positive_integer"),
        _row("DELETE", "/api/orders", "id", value_type="positive_integer"),
    ]
    leads = identifier_leads(rows)
    assert leads[0]["method"] == "DELETE" and leads[0]["access"] == "write"
    assert leads[1]["access"] == "read"


def test_body_json_pointer_name_hint():
    rows = [_row("POST", "/api/transfer", "/payload/account_id",
                 location="body_json", value_type="string")]
    leads = identifier_leads(rows)
    assert len(leads) == 1
    assert leads[0]["identifier"]["location"] == "body"
    assert leads[0]["access"] == "write"


def test_no_request_values_leak_into_leads():
    rows = [_row("GET", "/api/orders", "id", value_type="positive_integer")]
    text = repr(identifier_leads(rows))
    # Lead records expose names/paths/kinds only; never a captured value or cookie.
    assert "'kind': 'numeric'" in text  # the classified id *kind* is allowed
    assert "Cookie" not in text and "set-cookie" not in text.lower()


def test_summary_counts_and_leads_only_note():
    rows = [
        _row("GET", "/api/orders", "id", value_type="positive_integer"),
        _row("PUT", "/api/orders", "id", value_type="positive_integer"),
    ]
    summary = summarize_leads(identifier_leads(rows))
    assert summary["lead_count"] == 2
    assert summary["write_access_count"] == 1
    assert summary["enumerable_count"] == 2
    assert "proof" in summary["note"].lower()


def test_lead_cap_is_enforced():
    rows = [_row("GET", f"/api/thing{i}", "id", value_type="positive_integer")
            for i in range(MAX_LEADS + 50)]
    assert len(identifier_leads(rows)) == MAX_LEADS
