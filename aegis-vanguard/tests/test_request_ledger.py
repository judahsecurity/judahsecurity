"""Shared request ledger, response classification, replay, and diff tests."""

import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _ledger():
    os.environ["AEGIS_LEDGER_SESSION"] = "test-request-ledger"
    from agent.request_ledger import get_request_ledger
    ledger = get_request_ledger()
    ledger.clear()
    return ledger


def test_records_redacted_public_view_but_preserves_raw_replay_state():
    ledger = _ledger()
    record = ledger.record(
        "POST", "https://example.test/login?token=url-secret", {"Cookie": "sid=secret"},
        "username=alice&password=hunter2", True,
        {"status": 401, "headers": {}, "body": "login required", "elapsed_ms": 20},
    )

    public = ledger.get(record["request_id"])
    assert public["request_headers"]["Cookie"] == "[REDACTED]"
    assert "url-secret" not in public["url"]
    assert "hunter2" not in public["request_body"]
    assert "authentication_required" in public["classes"]
    raw = ledger.get_raw(record["request_id"])
    assert raw["request"]["headers"]["Cookie"] == "sid=secret"


def test_diff_classifies_authorization_and_content_difference():
    ledger = _ledger()
    baseline = ledger.record(
        "GET", "https://example.test/admin", {}, "", True,
        {"status": 403, "headers": {}, "body": "Access denied", "elapsed_ms": 15},
    )
    candidate = ledger.record(
        "GET", "https://example.test/admin", {"X-Role": "admin"}, "", True,
        {"status": 200, "headers": {}, "body": "Welcome administrator: FLAG{" + "a" * 64 + "}",
         "elapsed_ms": 18},
    )

    diff = ledger.diff(baseline["request_id"], candidate["request_id"])
    assert "authorization_difference" in diff["signals"]
    assert "objective_found" in diff["signals"]
    assert diff["interesting"] is True


def test_diff_classifies_timing_signal():
    ledger = _ledger()
    baseline = ledger.record(
        "GET", "https://example.test/search?q=a", {}, "", True,
        {"status": 200, "headers": {}, "body": "same", "elapsed_ms": 100},
    )
    candidate = ledger.record(
        "GET", "https://example.test/search?q=b", {}, "", True,
        {"status": 200, "headers": {}, "body": "same", "elapsed_ms": 2300},
    )
    diff = ledger.diff(baseline["request_id"], candidate["request_id"])
    assert "timing_signal" in diff["signals"]


def test_scanner_records_exchange_and_returns_request_id(monkeypatch):
    ledger = _ledger()
    import scanners

    class Result:
        stdout = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello marker123"

    monkeypatch.setattr(scanners, "_tool_available", lambda name: True)
    monkeypatch.setattr(scanners, "_run", lambda *args, **kwargs: Result())
    result = scanners.run_send_http_request(
        "GET", "https://example.test/?q=marker123", "{}", "", True, None,
    )

    assert result["request_id"].startswith("req-")
    assert "input_reflected" in result["response_classes"]
    assert ledger.get(result["request_id"])["status"] == 200


def test_scanner_uses_final_response_after_redirect(monkeypatch):
    _ledger()
    import scanners

    class Result:
        stdout = (
            "HTTP/1.1 302 Found\r\nLocation: /final\r\n\r\n"
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nfinal body"
        )

    monkeypatch.setattr(scanners, "_tool_available", lambda name: True)
    monkeypatch.setattr(scanners, "_run", lambda *args, **kwargs: Result())
    result = scanners.run_send_http_request(
        "GET", "https://example.test/start", "{}", "", True, None,
    )
    assert result["status"] == 200
    assert result["body"] == "final body"
    assert "Content-Type: text/plain" in result["raw_headers"]


def test_replay_tool_preserves_auth_and_returns_diff(monkeypatch):
    ledger = _ledger()
    baseline = ledger.record(
        "POST", "https://example.test/profile", {"Cookie": "sid=abc"},
        "user=alice", True,
        {"status": 403, "headers": {}, "body": "denied", "elapsed_ms": 10},
    )
    import agent.agents as agents

    captured = {}

    def fake_send(**kwargs):
        captured.update(kwargs)
        record = ledger.record(
            kwargs["method"], kwargs["url"], json.loads(kwargs["headers_json"]),
            kwargs["body"], kwargs["follow_redirects"],
            {"status": 200, "headers": {}, "body": "profile", "elapsed_ms": 12},
        )
        return {"status": 200, "body": "profile", "request_id": record["request_id"]}

    import scanners
    monkeypatch.setattr(scanners, "run_send_http_request", fake_send)
    result = json.loads(agents.replay_http_request(
        baseline["request_id"], "https://example.test/profile?user=admin",
        headers_json='{"X-Test":"1"}',
    ))

    assert json.loads(captured["headers_json"])["Cookie"] == "sid=abc"
    assert json.loads(captured["headers_json"])["X-Test"] == "1"
    assert "authorization_difference" in result["diff"]["signals"]
    assert captured["follow_redirects"] is False
    assert "disabled" in result["redirect_policy"]


def test_replay_rejects_origin_change():
    ledger = _ledger()
    baseline = ledger.record(
        "GET", "https://example.test/a", {"Cookie": "sid=abc"}, "", True,
        {"status": 200, "headers": {}, "body": "ok"},
    )
    from agent.agents import replay_http_request
    result = json.loads(replay_http_request(
        baseline["request_id"], "https://evil.test/a",
    ))
    assert "preserve" in result["error"]


def test_replay_accepts_explicit_default_port(monkeypatch):
    ledger = _ledger()
    baseline = ledger.record(
        "GET", "https://example.test/a", {}, "", True,
        {"status": 200, "headers": {}, "body": "ok"},
    )
    import scanners

    def fake_send(**kwargs):
        record = ledger.record(
            kwargs["method"], kwargs["url"], json.loads(kwargs["headers_json"]),
            kwargs["body"], kwargs["follow_redirects"],
            {"status": 200, "headers": {}, "body": "ok"},
        )
        return {"status": 200, "body": "ok", "request_id": record["request_id"]}

    monkeypatch.setattr(scanners, "run_send_http_request", fake_send)
    from agent.agents import replay_http_request
    result = json.loads(replay_http_request(
        baseline["request_id"], "https://example.test:443/b",
    ))
    assert "error" not in result


def test_ledger_tools_are_registered_and_hunters_receive_protocol():
    import agent.agents  # noqa: F401
    from agent.tools import ToolRegistry
    from agent.owasp_hunters import create_hunters_for_engagement

    registry = ToolRegistry()
    for name in (
        "list_http_requests", "get_http_request", "diff_http_requests",
        "replay_http_request",
    ):
        assert registry.get(name) is not None

    hunters = create_hunters_for_engagement(
        max_turns=5, include_api_framework=False, include_enterprise=False,
    )
    assert hunters
    assert all("## Adaptive Request Protocol" in hunter.instructions for hunter in hunters)
    assert all("replay_http_request" in (hunter.tool_names or []) for hunter in hunters)


def test_parallel_records_are_unique_and_session_isolated():
    ledger = _ledger()

    def record(index):
        return ledger.record(
            "GET", f"https://example.test/{index}", {}, "", True,
            {"status": 200, "headers": {}, "body": str(index)},
        )["request_id"]

    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = list(pool.map(record, range(100)))
    assert len(ids) == len(set(ids)) == 100
    assert len(ledger.list(limit=200)) == 100

    os.environ["AEGIS_LEDGER_SESSION"] = "another-assessment"
    ledger.clear()
    assert ledger.list(limit=200) == []
    assert ledger.get(ids[0]) is None
