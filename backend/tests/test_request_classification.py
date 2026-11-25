"""Response classification, hints, class filters and stored-exchange diffs.

Ported from Vanguard tests/test_request_ledger.py (classify, diff).
"""

import json

import pytest

from app.services.agent.request_capture import RequestCaptureStore
from app.services.agent.response_classification import (
    RESPONSE_CLASSES,
    adaptive_hints,
    classify_response,
    diff_exchanges,
)
from app.services.agent.tools import ASMToolsManager


def test_classifies_status_and_body_signals():
    request = {"method": "GET", "url": "https://app.test/search?q=needle42"}
    assert "authentication_required" in classify_response(request, {"status": 401, "body": "login"})
    assert "access_denied" in classify_response(request, {"status": 403, "body": "no"})
    assert "rate_limited" in classify_response(request, {"status": 429, "body": "slow"})
    assert "redirect" in classify_response(request, {"status": 302, "body": ""})
    assert "server_error" in classify_response(request, {"status": 500, "body": "oops"})
    assert "sql_error" in classify_response(
        request, {"status": 500, "body": "You have an error in your SQL syntax near"})
    assert "template_error" in classify_response(
        request, {"status": 500, "body": "jinja2.exceptions.TemplateSyntaxError"})
    assert "debug_error" in classify_response(
        request, {"status": 500, "body": "Traceback (most recent call last):"})
    assert "filter_blocked" in classify_response(
        request, {"status": 403, "body": "Request blocked by WAF"})
    assert "input_reflected" in classify_response(
        request, {"status": 200, "body": "results for needle42"})
    assert "empty_body" in classify_response(request, {"status": 204, "body": "", "length": 0})
    assert "request_error" in classify_response(request, {"error": "timeout"})
    assert classify_response(request, {"status": 200, "body": "fine"}) == []


def test_reflection_reads_json_and_form_bodies_and_ignores_short_values():
    json_req = {"method": "POST", "url": "https://app.test/api", "body": '{"name": "zebra77"}'}
    assert "input_reflected" in classify_response(json_req, {"status": 200, "body": "hi zebra77"})
    form_req = {"method": "POST", "url": "https://app.test/f", "body": "a=xyz&comment=walrus9"}
    assert "input_reflected" in classify_response(form_req, {"status": 200, "body": "walrus9!"})
    short = {"method": "GET", "url": "https://app.test/?q=ab&flag=true"}
    assert "input_reflected" not in classify_response(short, {"status": 200, "body": "ab true"})


def test_labels_are_only_known_classes():
    labels = classify_response({"url": "https://app.test/?token=supersecretvalue"},
                               {"status": 500, "body": "supersecretvalue SQLSTATE[42000]"})
    assert set(labels) <= set(RESPONSE_CLASSES)
    assert "supersecretvalue" not in json.dumps(labels)


def test_adaptive_hints_follow_classes():
    assert adaptive_hints([]) == []
    hints = adaptive_hints(["sql_error", "input_reflected"])
    assert any("SQLi" in hint for hint in hints)
    assert any("reflection context" in hint for hint in hints)
    assert any("identity" in hint.lower() for hint in adaptive_hints(["authentication_required"]))


def _exchange(status, body, elapsed_s=0.1, headers=None, url="https://app.test/admin"):
    return {"request": {"method": "GET", "url": url},
            "response": {"status": status, "body": body, "length": len(body),
                         "elapsed_s": elapsed_s, "headers": headers or {}}}


def test_diff_classifies_authorization_and_content_difference():
    diff = diff_exchanges(_exchange(403, "Access denied"),
                          _exchange(200, "Welcome administrator " + "x" * 80))
    assert {"status_change", "authorization_difference", "content_difference"} <= set(diff["signals"])
    assert diff["interesting"] is True
    assert "access_denied" in diff["removed_classes"]


def test_diff_classifies_timing_signal_and_new_error():
    diff = diff_exchanges(_exchange(200, "same", 0.1),
                          _exchange(200, "same", 2.3))
    assert diff["signals"] == ["timing_signal"]
    err = diff_exchanges(_exchange(200, "ok"), _exchange(200, "ok ORA-00933 at line"))
    assert "new_error_signal" in err["signals"]
    assert "sql_error" in err["added_classes"]


def test_diff_reports_header_names_not_values():
    diff = diff_exchanges(
        _exchange(200, "a", headers={"Set-Cookie": "sid=old", "X-A": "1"}),
        _exchange(200, "a", headers={"Set-Cookie": "sid=new-secret", "X-B": "2"}),
    )
    assert diff["header_delta"] == {"added": ["x-b"], "removed": ["x-a"], "changed": ["set-cookie"]}
    assert "new-secret" not in json.dumps(diff)


def test_identical_exchanges_are_not_interesting():
    diff = diff_exchanges(_exchange(200, "same body"), _exchange(200, "same body"))
    assert diff["signals"] == [] and diff["interesting"] is False
    assert diff["body_similarity"] == 1.0


def test_capture_store_keeps_classes_and_filters():
    store = RequestCaptureStore()
    first = store.record({"method": "GET", "url": "https://app.test/api/items?id=1"},
                         identity="owner", source="http_exchange",
                         response_classes=["sql_error", "not-a-class"])
    second = store.record({"method": "GET", "url": "https://app.test/api/users?id=2"},
                          identity="owner", source="http_exchange")
    assert first["response_classes"] == ["sql_error"]
    assert second["response_classes"] == []
    assert [row["id"] for row in store.list(classification="sql_error")] == [first["id"]]
    assert store.classify(second["id"], ["input_reflected"]) is True
    assert store.classify("missing", ["sql_error"]) is False
    assert [row["id"] for row in store.list(classification="input_reflected")] == [second["id"]]
    assert len(store.list()) == 2


@pytest.mark.asyncio
async def test_list_captured_requests_reports_and_filters_classes(monkeypatch):
    manager = ASMToolsManager()
    ok = {"method": "GET", "url": "https://app.example.com/search?q=first", "status": 200}
    denied = {"method": "GET", "url": "https://app.example.com/admin?x=1", "status": 403}
    manager._capability_map = {"target": "https://app.example.com", "api_samples": [ok, denied]}
    listed = json.loads(await manager.list_captured_requests())
    by_url = {row["url"]: row for row in listed["samples"]}
    assert by_url[denied["url"]]["classes"] == ["access_denied"]
    assert by_url[denied["url"]]["adaptive_hints"]
    assert by_url[ok["url"]]["classes"] == []

    async def compare_requests(**kwargs):
        return json.dumps({"classification": {"baseline": [], "mutant": ["sql_error"]}})

    monkeypatch.setattr(manager, "compare_requests", compare_requests)
    ref = by_url[ok["url"]]["sample_ref"]
    await manager.mutate_captured_request(sample_ref=ref, location="query", field="q", value="'")
    filtered = json.loads(await manager.list_captured_requests(classification="sql_error"))
    assert [row["sample_ref"] for row in filtered["samples"]] == [ref]
    assert filtered["samples"][0]["index"] == 0
    bad = json.loads(await manager.list_captured_requests(classification="nope"))
    assert bad["ok"] is False


@pytest.mark.asyncio
async def test_diff_stored_exchanges_needs_no_network():
    manager = ASMToolsManager()
    index = manager._record_probe_exchanges([
        {"request": {"method": "GET", "url": "https://app.example.com/item?id=1"},
         "response": {"status": 200, "body": '{"item": 1}', "length": 11,
                      "headers": {"Content-Type": "application/json"}}},
        {"request": {"method": "GET", "url": "https://app.example.com/item?id=1'"},
         "response": {"status": 500, "body": "SQLSTATE[42000]: syntax error", "length": 30,
                      "headers": {"Content-Type": "text/html"}}},
    ])
    assert index[1]["classes"] == ["server_error", "sql_error"]
    result = json.loads(await manager.diff_stored_exchanges(
        index[0]["evidence_id"], index[1]["evidence_id"]))
    assert result["ok"] is True
    assert {"status_change", "new_error_signal"} <= set(result["signals"])
    assert result["header_delta"]["changed"] == ["content-type"]
    assert result["status"] == {"baseline": 200, "candidate": 500}
    missing = json.loads(await manager.diff_stored_exchanges(index[0]["evidence_id"], "nope"))
    assert missing["ok"] is False and missing["missing"] == ["nope"]


def test_diff_tool_is_registered_and_documented():
    from app.services.agent import prompts

    assert "diff_stored_exchanges" in ASMToolsManager()._register_tools()
    assert "**diff_stored_exchanges**" in prompts.get_phase_tools("exploitation")
    assert "diff_stored_exchanges" in prompts.TOOL_PHASE_MAP
