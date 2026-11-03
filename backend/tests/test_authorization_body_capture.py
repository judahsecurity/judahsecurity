"""POST form, nested JSON and GraphQL proof capture stays request-faithful."""

import json
import pytest

from app.services.agent.captured_proof import (
    bind_captured_object_body,
    matrix_parameter_for_object,
    render_captured_body,
)
from app.services.agent.request_capture import RequestCaptureStore


def test_post_form_capture_and_encoded_object_binding():
    store = RequestCaptureStore()
    public = store.record(
        {
            "method": "POST",
            "url": "https://app.test/lookup",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": "view=full&record=a%2Bb&sort=asc",
        },
        identity="owner", source="browser",
    )
    assert public["body_format"] == "form"
    assert public["body_fields"] == ["record", "sort", "view"]
    assert "a%2Bb" not in json.dumps(public)
    assert any(row["reference"] == "form:record" for row in public["authorization_references"])
    attack = store.get(public["id"])["request"]
    assert bind_captured_object_body(attack, "form:record", "", "form") == "form:record"
    assert attack["body"] == "view=full&record={{object_id}}&sort=asc"
    assert render_captured_body(attack["body"], {"object_id": "new+id"}, "form") == (
        "view=full&record=new%2Bid&sort=asc"
    )
    assert matrix_parameter_for_object("form:record") == "body:record"


def test_nested_json_reference_capture_and_binding():
    store = RequestCaptureStore()
    public = store.record(
        {
            "method": "POST",
            "url": "https://app.test/lookup",
            "headers": {"Content-Type": "application/json"},
            "body": {"input": {"record": 7, "mode": "full"}, "view": "details"},
        },
        identity="owner", source="browser",
    )
    assert public["body_format"] == "json"
    assert any(row["reference"] == "body:/input/record" for row in public["authorization_references"])
    attack = store.get(public["id"])["request"]
    assert bind_captured_object_body(attack, "body:/input/record", "", "json") == "body:/input/record"
    assert attack["body"] == {
        "input": {"record": "{{object_id}}", "mode": "full"}, "view": "details"
    }
    assert matrix_parameter_for_object("body:/input/record") == "body:input"


def test_graphql_variable_capture_accepts_one_query_or_mutation():
    store = RequestCaptureStore()
    for operation in ("query", "mutation"):
        public = store.record(
            {
                "method": "POST",
                "url": "https://app.test/graphql",
                "headers": {"Content-Type": "application/json"},
                "body": {
                    "query": f"{operation} Read($input: ItemInput!) {{ item(input:$input) {{ id }} }}",
                    "variables": {"input": {"record": "7", "mode": "full"}},
                },
            },
            identity="owner", source="browser",
        )
        assert public["protocol"] == "graphql"
        assert public["graphql_kind"] == operation
        assert any(
            row["reference"] == "variable:/input/record"
            for row in public["authorization_references"]
        )
        attack = store.get(public["id"])["request"]
        bind_captured_object_body(attack, "variable:/input/record", "", "json")
        assert attack["body"]["variables"]["input"]["record"] == "{{object_id}}"
        assert matrix_parameter_for_object("variable:/input/record") == "variable:input"
    assert store.record(
        {
            "method": "POST", "url": "https://app.test/graphql",
            "headers": {"Content-Type": "application/json"},
            "body": {"query": "subscription Listen { event { id } }"},
        }, identity="owner", source="browser",
    ) is None
    assert store.record(
        {
            "method": "POST", "url": "https://app.test/graphql",
            "headers": {"Content-Type": "application/json"},
            "body": {"query": "query First { item { id } } query Second { item { id } }"},
        }, identity="owner", source="browser",
    ) is None


def test_duplicate_form_reference_cannot_be_bound_even_with_one_matching_value():
    attack = {"body": "record=7&record=8&view=full"}
    with pytest.raises(ValueError, match="occur once"):
        bind_captured_object_body(attack, "form:record", "7", "form")
