"""Value-set write replay primitives validate captured writes and bound the canary."""

import base64
import json

import pytest

from app.services.agent.scoped_assessment.body_probe import (
    plan_observed_write,
)

ALLOWED = ["https://app.example.test"]


def _capture(method="PUT", mime="application/json", body=b'{"note":"hello","id":7}',
             resource_type="xhr", url="https://app.example.test/api/orders/7",
             graphql_type=""):
    return json.dumps({
        "url": url, "method": method, "resource_type": resource_type,
        "request_content_type": mime, "graphql_operation_type": graphql_type,
        "request_body_base64": base64.b64encode(body).decode(),
    }).encode()


def test_sets_json_field_to_exact_canary():
    url, method, mime, body = plan_observed_write(
        _capture(), parameter="/note", allowed_origins=ALLOWED, value="canaryABC123")
    assert method == "PUT" and mime == "application/json"
    assert json.loads(body) == {"note": "canaryABC123", "id": 7}


def test_sets_form_field_to_exact_canary():
    cap = _capture(mime="application/x-www-form-urlencoded", body=b"note=hello&id=7")
    url, method, mime, body = plan_observed_write(
        cap, parameter="note", allowed_origins=ALLOWED, value="canaryABC123")
    assert body == b"note=canaryABC123&id=7"


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH"])
def test_accepts_all_write_methods(method):
    _, got, _, _ = plan_observed_write(
        _capture(method=method), parameter="/note", allowed_origins=ALLOWED, value="canaryABC123")
    assert got == method


def test_rejects_get_capture():
    with pytest.raises(ValueError):
        plan_observed_write(_capture(method="GET"), parameter="/note",
                            allowed_origins=ALLOWED, value="canaryABC123")


def test_rejects_graphql_mutation():
    with pytest.raises(ValueError):
        plan_observed_write(_capture(graphql_type="mutation"), parameter="/note",
                            allowed_origins=ALLOWED, value="canaryABC123")


def test_rejects_out_of_scope_url():
    with pytest.raises(ValueError):
        plan_observed_write(_capture(url="https://evil.example.test/x"),
                            parameter="/note", allowed_origins=ALLOWED, value="canaryABC123")


def test_rejects_non_alphanumeric_or_short_canary():
    for bad in ("short", "has space", "semi;colon", "a" * 65, "quote'x"):
        with pytest.raises(ValueError):
            plan_observed_write(_capture(), parameter="/note",
                                allowed_origins=ALLOWED, value=bad)


def test_rejects_unknown_field():
    with pytest.raises(ValueError):
        plan_observed_write(_capture(), parameter="/missing",
                            allowed_origins=ALLOWED, value="canaryABC123")


def test_rejects_boolean_field():
    cap = _capture(body=b'{"note":"x","active":true}')
    with pytest.raises(ValueError):
        plan_observed_write(cap, parameter="/active", allowed_origins=ALLOWED, value="canaryABC123")
