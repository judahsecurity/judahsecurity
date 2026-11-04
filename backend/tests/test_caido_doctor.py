"""caido-doctor reports clear pass/fail for the Caido readback wiring."""

import base64
import json
import time

from app.services.agent import caido_doctor
from app.services.agent.caido_history import graphql_error_reason

URL = "http://localhost:8083/graphql"


def _jwt(exp_offset):
    body = base64.urlsafe_b64encode(json.dumps({"exp": int(time.time()) + exp_offset}).encode()).decode().rstrip("=")
    return f"eyJhbGciOiJIUzI1NiJ9.{body}.sig"


def _schema(*names):
    return {"data": {"__schema": {"queryType": {"fields": [{"name": n} for n in names]}}}}


def _auth_error():
    return {"data": None, "errors": [{"message": "Operation error",
            "extensions": {"CAIDO": {"reason": "INVALID_TOKEN", "code": "AUTHORIZATION"}}}]}


def _data(n):
    return {"data": {"requestsByOffset": {"edges": [
        {"node": {"host": "app.example.test", "port": 443, "path": "/x",
                  "query": "", "method": "GET", "isTls": True}} for _ in range(n)]}}}


def test_auth_error_is_detected_not_silently_empty():
    assert graphql_error_reason(_auth_error()) == "caido_auth_invalid_or_expired"
    assert graphql_error_reason(_data(0)) == ""
    assert graphql_error_reason({"errors": [{"message": "boom"}]}) == "caido_graphql_error"


def test_token_expiry_decodes_exp():
    assert caido_doctor.token_expiry(_jwt(-10))["expired"] is True
    good = caido_doctor.token_expiry(_jwt(86400 * 3))
    assert good["expired"] is False and good["days_left"] >= 2
    assert caido_doctor.token_expiry("not.a.jwt")["known"] is False


def test_diagnose_unconfigured():
    report = caido_doctor.diagnose("", "")
    assert report["ok"] is False
    assert report["checks"][0] == {"name": "configured", "ok": False,
                                   "detail": "AEGIS_ASSESSMENT_CAIDO_GRAPHQL_URL is unset"}


def test_diagnose_happy_path():
    calls = []

    def fake_post(url, body, token):
        calls.append(token)
        if "introspection" in body or "__schema" in body:
            return 200, _schema("request", "requestsByOffset")
        return 200, _data(1)

    report = caido_doctor.diagnose(URL, _jwt(86400 * 5), post=fake_post)
    assert report["ok"] is True
    names = {c["name"]: c["ok"] for c in report["checks"]}
    assert names["reachable"] and names["requestsByOffset_present"]
    assert names["token_unexpired"] and names["data_call"]
    assert calls == ["", _jwt(86400 * 5)]  # introspection unauth, data authed


def test_diagnose_invalid_token():
    def fake_post(url, body, token):
        if "__schema" in body:
            return 200, _schema("requestsByOffset")
        return 200, _auth_error()

    report = caido_doctor.diagnose(URL, _jwt(86400 * 5), post=fake_post)
    assert report["ok"] is False
    data_check = next(c for c in report["checks"] if c["name"] == "data_call")
    assert data_check["ok"] is False and "INVALID_TOKEN" in data_check["detail"]


def test_diagnose_missing_field_in_schema():
    def fake_post(url, body, token):
        if "__schema" in body:
            return 200, _schema("request", "requests")  # no requestsByOffset
        return 200, _data(0)

    report = caido_doctor.diagnose(URL, _jwt(86400), post=fake_post)
    assert report["ok"] is False
    present = next(c for c in report["checks"] if c["name"] == "requestsByOffset_present")
    assert present["ok"] is False


def test_diagnose_missing_token():
    def fake_post(url, body, token):
        return 200, _schema("requestsByOffset")

    report = caido_doctor.diagnose(URL, "", post=fake_post)
    assert report["ok"] is False
    assert any(c["name"] == "token_present" and not c["ok"] for c in report["checks"])


def test_format_report_renders_pass_fail():
    report = caido_doctor.diagnose("", "")
    text = caido_doctor.format_report(report)
    assert "FAIL" in text and "configured" in text
