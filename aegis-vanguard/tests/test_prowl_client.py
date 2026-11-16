"""prowl_client.py, scope.py and dedup.py: offline behaviour (no network)."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / ".claude" / "skills" / "_lib"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


client = _load("prowl_client", ROOT / "prowl_client.py")
scope = _load("vanguard_scope", LIB / "scope.py")
dedup = _load("vanguard_dedup", LIB / "dedup.py")


@pytest.fixture
def scope_file(tmp_path):
    path = tmp_path / "scope.txt"
    path.write_text("app.example.com\n*.api.example.com\n!admin.api.example.com\nexample.org:8443\n")
    return path


def test_scope_rules(scope_file):
    s = scope.load(scope_file)
    assert scope.in_scope(s, "https://app.example.com/x?y=1")
    assert scope.in_scope(s, "v2.api.example.com")
    assert not scope.in_scope(s, "api.example.com")  # wildcard excludes apex
    assert not scope.in_scope(s, "admin.api.example.com")
    assert not scope.in_scope(s, "evil.com")
    assert scope.in_scope(s, "https://example.org:8443/")
    assert not scope.in_scope(s, "https://example.org/")
    assert scope.wildcards(s) == ["api.example.com"]


def test_dedup_clusters_by_root_cause():
    rows = [
        {"id": "a", "title": "IDOR on order", "category": "idor", "severity": "medium",
         "endpoint": "https://App.Example.com/api/orders/123?x=1", "parameter": "id"},
        {"id": "b", "title": "Different title", "category": "bola", "severity": "high",
         "endpoint": "https://app.example.com:443/api/orders/9f1c2d3e-0000-4000-8000-000000000001/",
         "parameter": "id"},
        {"id": "c", "title": "IDOR on order", "category": "idor", "severity": "medium",
         "endpoint": "https://app.example.com/api/invoices/1", "parameter": "id"},
    ]
    clusters = dedup.cluster(rows)
    assert len(clusters) == 2
    orders = next(c for c in clusters if c["endpoint"].endswith("orders/{id}"))
    assert orders["vuln_class"] == "authorization"
    assert orders["endpoint"] == "app.example.com/api/orders/{id}"
    assert orders["primary"] == "b" and orders["duplicates"] == ["a"]
    assert dedup.normalize_endpoint("src/app/views.py:120 get_order") == "src/app/views.py get_order"


def test_resolve_class_aliases():
    assert client.resolve_class("IDOR") == "authorization"
    assert client.resolve_class("lfi") == "path_traversal"
    assert client.resolve_class("sqli") == "sql_injection"
    assert client.resolve_class("nosql") is None


def test_redact_and_question():
    finding = {"id": "f1", "title": "SQLi", "category": "sqli", "endpoint": "https://app.example.com/a",
               "evidence": "GET /a\nCookie: session=abcdef\nAuthorization: Bearer abcdefghijkl\n"}
    q = client.verification_question(finding, client.load_classes())
    assert "abcdef" not in q and "abcdefghijkl" not in q
    assert "numeric_boolean_sqli" in q
    assert client.redact({"api_key": "x", "n": [{"token": "y"}]}) == {"api_key": "[REDACTED]", "n": [{"token": "[REDACTED]"}]}
    note = client.with_operator_note("h", "x" * 5000)
    assert "\nOperator note: " in note and len(note) < 4000


def test_ledger_verdict_mapping():
    done = {"is_active": False}
    published = {"status": "completed", "actions": [
        {"tool_name": "create_finding", "status": "completed", "detail": "finding_published", "evidence_ids": ["e1"]}]}
    assert client.ledger_verdict(done, published)["status"] == "confirmed"
    refuted = {"status": "completed", "actions": [
        {"tool_name": "independent_verify", "status": "completed", "detail": "refuted: control matched"}]}
    assert client.ledger_verdict(done, refuted)["status"] == "refuted"
    empty = {"status": "completed", "actions": []}
    verdict = client.ledger_verdict(done, empty)
    assert verdict["status"] == "improve" and verdict["next_step"]
    assert client.ledger_verdict({"is_active": True}, {"status": "running"})["status"] == "pending"


def test_start_refuses_out_of_scope(scope_file, monkeypatch):
    monkeypatch.setenv("AEGIS_API_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("AEGIS_API_TOKEN", "t")
    calls = []
    monkeypatch.setattr(client, "request", lambda *a, **k: calls.append(a) or {})
    rc = client.main(["start", "--target", "https://evil.com", "--scope-file", str(scope_file)])
    assert rc == 2 and not calls
    rc = client.main(["tool", "--scope-file", str(scope_file), "--name", "execute_nmap", "--args", "app.example.com"])
    assert rc == 2 and not calls


def test_start_posts_agent_query(scope_file, monkeypatch, tmp_path):
    seen = {}

    def fake(method, path, body=None, **kw):
        seen.update(method=method, path=path, body=body)
        return {"session_id": "s1", "running": True}

    monkeypatch.setattr(client, "request", fake)
    rc = client.main(["start", "--target", "https://app.example.com/login", "--scope-file", str(scope_file),
                      "--run-dir", str(tmp_path)])
    assert rc == 0
    assert seen["path"] == "/agent/query" and seen["body"]["mode"] == "agent"
    assert seen["body"]["target"] == "https://app.example.com"
    assert json.loads((tmp_path / "prowl_run.json").read_text())["session_id"] == "s1"
