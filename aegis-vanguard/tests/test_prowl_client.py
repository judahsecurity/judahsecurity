"""prowl_client.py, scope.py and dedup.py: offline behaviour (no network)."""

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

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
    assert client.resolve_class("nosql") == "nosql"
    assert client.resolve_class("graphql") is None


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


def _run_dir(tmp_path, finding):
    (tmp_path / "findings.json").write_text(json.dumps({"findings": [finding]}))
    return tmp_path


FINDING = {"id": "f1", "title": "IDOR on invoice", "category": "idor", "severity": "high",
           "endpoint": "/api/invoices/42", "parameter": "invoice_id",
           "evidence": "GET /api/invoices/42\nCookie: session=abcdef"}


def test_verify_uses_candidate_intake_on_live_session(scope_file, monkeypatch, tmp_path):
    run_dir = _run_dir(tmp_path, FINDING)
    calls = []

    def fake(method, path, body=None, **kw):
        calls.append((method, path, body))
        if path.endswith("/candidates"):
            return {"accepted": True, "candidate": {"id": "c-1", "status": "pending"}}
        return {"session_id": "s1", "running": True}

    monkeypatch.setattr(client, "request", fake)
    rc = client.main(["verify", "--run-dir", str(run_dir), "--finding-id", "f1",
                      "--target", "https://app.example.com", "--scope-file", str(scope_file),
                      "--session", "s1"])
    assert rc == 0
    (m1, p1, b1), (m2, p2, b2) = calls
    assert p1 == "/agent/sessions/s1/candidates"
    assert b1["vulnerability_class"] == "authorization"
    assert b1["target"] == "https://app.example.com/api/invoices/42"
    assert "abcdef" not in json.dumps(b1)
    assert p2 == "/agent/query" and b2["session_id"] == "s1" and "c-1" in b2["question"]
    assert "playbook_id" not in b2
    record = json.loads((run_dir / "prowl_verify" / "f1.json").read_text())
    assert record["mode"] == "intake" and record["candidate_id"] == "c-1"


def test_verify_queued_intake_steers_instead_of_resuming(scope_file, monkeypatch, tmp_path):
    run_dir = _run_dir(tmp_path, FINDING)
    calls = []

    def fake(method, path, body=None, **kw):
        calls.append((method, path, body))
        if path.endswith("/candidates"):
            return {"accepted": True, "queued": True,
                    "candidate": {"id": "c-2", "status": "queued"}}
        return {"ok": True, "queued": True}

    monkeypatch.setattr(client, "request", fake)
    rc = client.main(["verify", "--run-dir", str(run_dir), "--finding-id", "f1",
                      "--target", "https://app.example.com", "--scope-file", str(scope_file),
                      "--session", "s1"])
    assert rc == 0
    paths = [p for _, p, _ in calls]
    assert paths == ["/agent/sessions/s1/candidates", "/agent/sessions/s1/steer"]
    assert "/agent/query" not in paths
    assert "c-2" in calls[1][2]["message"] and calls[1][2]["session_id"] == "s1"
    record = json.loads((run_dir / "prowl_verify" / "f1.json").read_text())
    assert record["mode"] == "intake_queued" and record["candidate_id"] == "c-2"
    assert record["steered"] is True and "resumed" not in record
    verdict = client.candidate_verdict({"id": "c-2", "status": "queued"}, True)
    assert verdict["status"] == "pending"
    assert client.candidate_verdict({"id": "c-2", "status": "queued"}, False)["status"] == "pending"


def test_verify_falls_back_to_playbook_on_409(scope_file, monkeypatch, tmp_path):
    run_dir = _run_dir(tmp_path, FINDING)
    calls = []

    def fake(method, path, body=None, **kw):
        calls.append(path)
        if path.endswith("/candidates"):
            raise client.ProwlError("busy", 409)
        return {"session_id": "s2", "running": True}

    monkeypatch.setattr(client, "request", fake)
    rc = client.main(["verify", "--run-dir", str(run_dir), "--finding-id", "f1",
                      "--target", "https://app.example.com", "--scope-file", str(scope_file),
                      "--session", "s1"])
    assert rc == 0 and calls == ["/agent/sessions/s1/candidates", "/agent/query"]
    record = json.loads((run_dir / "prowl_verify" / "f1.json").read_text())
    assert record["mode"] == "playbook" and record["session_id"] == "s2"
    assert "intake_error" in record


def test_verdict_reads_candidate_status(monkeypatch, tmp_path):
    (tmp_path / "prowl_verify").mkdir()
    (tmp_path / "prowl_verify" / "f1.json").write_text(json.dumps(
        {"finding_id": "f1", "session_id": "s1", "candidate_id": "c-1", "mode": "intake"}))
    listing = {"run_in_progress": False, "candidates": [
        {"id": "c-1", "status": "refuted", "verifier_summary": "control matched"}]}
    monkeypatch.setattr(client, "request", lambda m, p, b=None, **k: listing)
    assert client.main(["verdict", "--run-dir", str(tmp_path), "--finding-id", "f1"]) == 0
    record = json.loads((tmp_path / "prowl_verify" / "f1.json").read_text())
    assert record["verdict"]["status"] == "refuted"
    assert client.candidate_verdict({"id": "c", "status": "pending"}, True)["status"] == "pending"
    assert client.candidate_verdict({"id": "c", "status": "pending"}, False)["status"] == "improve"
    assert client.candidate_verdict({"id": "c", "status": "confirmed"}, False)["status"] == "confirmed"
    assert client.candidate_verdict(None, False)["status"] == "improve"


def test_classes_remote_and_candidates(monkeypatch):
    seen = []
    monkeypatch.setattr(client, "request", lambda m, p, b=None, **k: seen.append(p) or {
        "classes": {"authorization": {"proof_kinds": ["owner_only"]}}, "candidates": []})
    assert client.main(["classes", "--remote", "--resolve", "idor"]) == 0
    assert client.main(["candidates", "--session", "s1"]) == 0
    assert seen == ["/agent/proof-classes", "/agent/sessions/s1/candidates"]


# ---------------------------------------------------------------- identity handoff

LOGIN_HTML = ('<form action="/session" method="post"><input name="email" type="email">'
              '<input name="password" type="password"></form>')


def _identity_file(tmp_path, rows):
    path = tmp_path / "identities.json"
    path.write_text(json.dumps(rows))
    return str(path)


def _login_transport(method, url, headers, body, follow_redirects):
    if url.endswith("/login"):
        return {"status": 200, "body": LOGIN_HTML, "headers": {}}
    if url.endswith("/session"):
        ok = "password=right" in body
        return {"status": 302 if ok else 200, "body": "" if ok else "Invalid password",
                "raw_headers": ("HTTP/1.1 302 Found\r\nLocation: /home\r\n"
                                "Set-Cookie: sid=private-cookie; HttpOnly\r\n\r\n") if ok else ""}
    if url.endswith("/me"):
        return {"status": 200, "body": "signed in as owner", "headers": {}}
    return {"status": 200, "body": "Welcome", "headers": {}}


def test_identities_log_in_locally_and_hand_over_sessions_only(scope_file, monkeypatch, tmp_path):
    path = _identity_file(tmp_path, [
        {"label": "owner", "role": "admin", "username": "a@example.com", "password": "right",
         "login": {"url": "https://app.example.com/login"}},
        {"label": "wrong", "username": "b@example.com", "password": "nope",
         "login": {"url": "https://app.example.com/login"}},
        {"label": "api_user", "headers": {"Authorization": "Bearer header-token"},
         "login": {"verify_url": "https://app.example.com/me", "success_marker": "signed in"}},
    ])
    posted = []

    def fake(method, path_, body=None, **kw):
        posted.append((method, path_, body))
        return {"origin": body["origin"], "headers": sorted(body["headers"]),
                "cookies": len(body["cookies"])}

    monkeypatch.setattr(client, "request", fake)
    prepared = client.prepare_identities(path, "https://app.example.com", transport=_login_transport)
    rows = client.send_identities("s1", prepared)

    assert [p[1] for p in posted] == ["/agent/sessions/s1/identities"] * 2
    owner, api_user = posted[0][2], posted[1][2]
    assert owner["identity"] == "owner" and owner["role"] == "admin"
    assert owner["cookies"] == {"sid": "private-cookie"} and owner["origin"] == "https://app.example.com"
    assert "password" not in json.dumps(posted) and "right" not in json.dumps(owner)
    assert api_user["headers"] == {"Authorization": "Bearer header-token"}

    by_name = {row["identity"]: row for row in rows}
    assert by_name["owner"]["sent"] and by_name["api_user"]["sent"]
    assert not by_name["wrong"]["sent"] and by_name["wrong"]["state"] == "rejected"
    printed = json.dumps(rows)
    assert "private-cookie" not in printed and "header-token" not in printed


def test_identities_refuse_out_of_scope_and_bad_labels(scope_file, monkeypatch, tmp_path):
    monkeypatch.setattr(client, "request", lambda *a, **k: pytest.fail("no request expected"))
    path = _identity_file(tmp_path, [{"label": "owner", "headers": {"Authorization": "Bearer x"}}])
    rc = client.main(["identities", "--session", "s1", "--target", "https://evil.com",
                      "--scope-file", str(scope_file), "--identity-file", path])
    assert rc == 2
    bad = _identity_file(tmp_path, [{"label": "legacy", "headers": {"Authorization": "Bearer x"}}])
    with pytest.raises(client.ProwlError):
        client.prepare_identities(bad, "https://app.example.com", transport=_login_transport)


def test_unverified_identity_needs_explicit_flag(tmp_path):
    path = _identity_file(tmp_path, [{"label": "plain", "headers": {"Authorization": "Bearer x"}}])
    [(row, payload)] = client.prepare_identities(path, "https://app.example.com",
                                                 transport=_login_transport)
    assert row["state"] == "ready_unverified" and payload is None and "--allow-unverified" in row["skipped"]
    [(row, payload)] = client.prepare_identities(path, "https://app.example.com",
                                                 allow_unverified=True, transport=_login_transport)
    assert payload["headers"] == {"Authorization": "Bearer x"}


def test_start_logs_in_before_starting_and_hands_over(scope_file, monkeypatch, tmp_path):
    path = _identity_file(tmp_path, [
        {"label": "owner", "username": "a@example.com", "password": "right",
         "login": {"url": "https://app.example.com/login"}}])
    calls = []
    real_prepare = client.prepare_identities
    monkeypatch.setattr(client, "prepare_identities",
                        lambda *a, **k: real_prepare(*a, **k, transport=_login_transport))

    def fake(method, path_, body=None, **kw):
        calls.append(path_)
        if path_ == "/agent/query":
            return {"session_id": "s9", "running": True}
        return {"origin": body["origin"], "headers": [], "cookies": 1}

    monkeypatch.setattr(client, "request", fake)
    rc = client.main(["start", "--target", "https://app.example.com", "--scope-file", str(scope_file),
                      "--identity-file", path])
    assert rc == 0 and calls == ["/agent/query", "/agent/sessions/s9/identities"]


# ---------------------------------------------------------------- probe (operator intents)

def _probe(scope_file, *extra):
    return client.build_parser().parse_args([
        "probe", "--session", "sess-1", "--scope-file", str(scope_file), *extra])


def test_probe_posts_intent_for_unobserved_header(scope_file, monkeypatch):
    seen = []
    monkeypatch.setattr(client, "request",
                        lambda m, p, b=None, **k: seen.append((m, p, b)) or {"accepted": True})
    args = _probe(scope_file, "--target", "https://app.example.com/render?lang=en",
                  "--test-type", "template-injection", "--parameter", "X-Template",
                  "--location", "header", "--note", "seen in a JS bundle")
    assert args.fn(args) == {"accepted": True}
    method, path, body = seen[0]
    assert (method, path) == ("POST", "/agent/sessions/sess-1/intents")
    assert body == {"target": "https://app.example.com/render?lang=en", "test_type": "ssti",
                    "parameter": "X-Template", "location": "header", "method": "GET",
                    "identity": "", "note": "seen in a JS bundle"}


@pytest.mark.parametrize("spec,location,parameter", [
    ("header:X-Diagnostic", "header", "X-Diagnostic"),
    ("cookie:diagnostic", "cookie", "diagnostic"),
    ("json:profile.name", "body_json", "/profile/name"),
    ("form:file", "body_form", "file"),
])
def test_probe_accepts_vanguard_mutation_specs(scope_file, monkeypatch, spec, location, parameter):
    seen = []
    monkeypatch.setattr(client, "request", lambda m, p, b=None, **k: seen.append(b) or {})
    method = "POST" if location.startswith("body") else "GET"
    args = _probe(scope_file, "--target", "https://app.example.com/x", "--test-type", "cmdi",
                  "--parameter", spec, "--method", method)
    args.fn(args)
    assert seen[0]["location"] == location and seen[0]["parameter"] == parameter
    assert seen[0]["test_type"] == "command_injection"


@pytest.mark.parametrize("extra,match", [
    (["--target", "https://evil.com/x", "--test-type", "ssti"], "out of scope"),
    (["--target", "https://admin.api.example.com/x", "--test-type", "ssti"], "out of scope"),
    (["--target", "https://u:p@app.example.com/x", "--test-type", "ssti"], "credentials"),
    (["--target", "https://app.example.com/x#f", "--test-type", "ssti"], "fragment"),
    (["--target", "/relative", "--test-type", "ssti"], "absolute"),
    (["--target", "https://app.example.com/x", "--test-type", "idor-ish"], "unknown test type"),
    (["--target", "https://app.example.com/x", "--test-type", "ssti",
      "--parameter", "q", "--location", "smoke"], "--location"),
    (["--target", "https://app.example.com/x", "--test-type", "ssti", "--parameter", "q"],
     "go together"),
    (["--target", "https://app.example.com/x", "--test-type", "ssti", "--method", "TRACE"],
     "--method"),
    (["--target", "https://app.example.com/x", "--test-type", "ssti",
      "--parameter", "name", "--location", "body_json"], "POST"),
    (["--target", "https://app.example.com/x", "--test-type", "ssti",
      "--parameter", "fragment:q"], "client-side"),
    (["--target", "https://app.example.com/x", "--test-type", "xss",
      "--parameter", "q", "--location", "query", "--method", "POST"], "GET navigation"),
    (["--target", "https://app.example.com/x", "--test-type", "xss",
      "--parameter", "json:note.text", "--method", "PUT"], "intercepted browser request"),
    (["--target", "https://app.example.com/x", "--test-type", "xss",
      "--parameter", "header:X-Theme", "--method", "DELETE"], "intercepted browser request"),
    (["--target", "https://app.example.com/u/alice", "--test-type", "xss",
      "--parameter", "path:1", "--method", "POST"], "intercepted GET"),
    (["--target", "https://app.example.com/x", "--test-type", "xss",
      "--parameter", "form:q"], "POST"),
    (["--target", "https://app.example.com/x", "--test-type", "ssti",
      "--parameter", "xml:1bad", "--method", "POST"], "element name"),
    (["--target", "https://app.example.com/x", "--test-type", "ssti",
      "--parameter", "path:a/b"], "segment"),
])
def test_probe_refuses_before_any_request(scope_file, monkeypatch, extra, match):
    monkeypatch.setattr(client, "request", lambda *a, **k: pytest.fail("no request expected"))
    args = _probe(scope_file, *extra)
    with pytest.raises(client.ProwlError, match=match):
        args.fn(args)


@pytest.mark.parametrize("spec,method,test_type,location,parameter", [
    ("xml:order.note", "POST", "cmdi", "body_xml", "/order/note"),
    ("xml:doc", "PUT", "ssti", "body_xml", "doc"),
    ("path:2", "GET", "sqli", "path", "2"),
    ("path:alice", "GET", "sql", "path", "alice"),
    ("json:profile.bio", "PATCH", "ssti", "body_json", "/profile/bio"),
    ("fragment:q", "GET", "xss", "fragment", "q"),
    ("header:X-Theme", "GET", "xss", "header", "X-Theme"),
    ("cookie:lang", "GET", "xss", "cookie", "lang"),
    ("json:note.text", "POST", "xss", "body_json", "/note/text"),
    ("xml:note.text", "POST", "xss", "body_xml", "/note/text"),
    ("form:q", "POST", "xss", "body_form", "q"),
    ("path:2", "GET", "xss", "path", "2"),
    ("query:q", "DELETE", "redirect", "query", "q"),
])
def test_probe_new_locations_and_write_methods(scope_file, monkeypatch, spec, method,
                                               test_type, location, parameter):
    seen = []
    monkeypatch.setattr(client, "request", lambda m, p, b=None, **k: seen.append(b) or {})
    args = _probe(scope_file, "--target", "https://app.example.com/api/users/alice",
                  "--test-type", test_type, "--parameter", spec, "--method", method)
    args.fn(args)
    assert (seen[0]["location"], seen[0]["parameter"], seen[0]["method"]) == (
        location, parameter, method)


NOTES_ENDPOINT = {
    "create_path": "/api/notes", "create_body": {"title": "__PROWL_NONCE__"},
    "content_type": "json", "record_path": "/api/notes/{id}", "id_source": "location",
    "write_methods": ["PUT", "DELETE"], "cleanup": "delete", "cleanup_delete_approved": True,
}


def test_policy_file_test_record_endpoints_checked_locally(tmp_path):
    form = {"create_path": "/api/items", "create_body": "name=__PROWL_NONCE__",
            "content_type": "form", "record_path": "/api/items/{id}",
            "id_source": "json:item.id", "write_methods": ["PATCH"], "cleanup": "none"}
    ok = tmp_path / "ok.json"
    ok.write_text(json.dumps({"test_record_endpoints": [NOTES_ENDPOINT, form]}))
    args = SimpleNamespace(policy_file=str(ok), oob=False)
    assert client.assessment_policy(args)["test_record_endpoints"][1]["cleanup"] == "none"
    for bad, match in (
            ({"write_method_paths": [{"method": "PUT", "path": "/api/profile"}]}, "not supported"),
            ({"test_record_endpoints": [NOTES_ENDPOINT] * 5}, "at most 4"),
            ({"test_record_endpoints": [NOTES_ENDPOINT, NOTES_ENDPOINT]}, "repeat"),
            ({"test_record_endpoints": [{**NOTES_ENDPOINT, "record_path": "/api/notes/42"}]},
             "one \\{id\\}"),
            ({"test_record_endpoints": [{**NOTES_ENDPOINT, "record_path": "/a/{id}/{id}"}]},
             "one \\{id\\}"),
            ({"test_record_endpoints": [{**NOTES_ENDPOINT, "create_path": "/api/notes?x=1"}]},
             "create_path"),
            ({"test_record_endpoints": [{**NOTES_ENDPOINT, "create_body": {"t": "x"}}]},
             "__PROWL_NONCE__"),
            ({"test_record_endpoints": [{**NOTES_ENDPOINT, "id_source": "header"}]}, "id_source"),
            ({"test_record_endpoints": [{**NOTES_ENDPOINT, "write_methods": ["POST"]}]},
             "write_methods"),
            ({"test_record_endpoints": [{**NOTES_ENDPOINT, "cleanup_delete_approved": False}]},
             "cleanup_delete_approved"),
            ({"test_record_endpoints": [{**form, "cleanup_delete_approved": True}]},
             "cleanup_delete_approved")):
        path = tmp_path / "bad.json"
        path.write_text(json.dumps(bad))
        with pytest.raises(client.ProwlError, match=match):
            client.assessment_policy(SimpleNamespace(policy_file=str(path), oob=False))


def test_probe_write_method_refuses_path_location(scope_file, monkeypatch):
    monkeypatch.setattr(client, "request", lambda *a, **k: pytest.fail("no request expected"))
    args = _probe(scope_file, "--target", "https://app.example.com/api/notes/42",
                  "--test-type", "ssti", "--parameter", "path:2", "--method", "PUT")
    with pytest.raises(client.ProwlError, match="own test record"):
        args.fn(args)


def test_intents_listing(monkeypatch):
    seen = []
    monkeypatch.setattr(client, "request",
                        lambda m, p, b=None, **k: seen.append((m, p)) or {"intents": []})
    args = client.build_parser().parse_args(["intents", "--session", "s 1"])
    assert args.fn(args) == {"intents": []}
    assert seen == [("GET", "/agent/sessions/s%201/intents")]



@pytest.mark.parametrize("extra,expected", [
    (["--test-type", "sqli", "--parameter", "json:item.id", "--method", "POST",
      "--baseline-value", "7"], "7"),
    (["--test-type", "sqli", "--parameter", "json:item.id", "--method", "POST",
      "--body-sample", '{"item":{"id":42,"x":"y"}}'], "42"),
    (["--test-type", "sqli", "--parameter", "form:id", "--method", "POST",
      "--body-sample", "id=9&q=a"], "9"),
    (["--test-type", "nosql", "--parameter", "header:X-Filter",
      "--baseline-value", '{"user":"alice"}'], '{"user":"alice"}'),
    (["--test-type", "sqli", "--parameter", "query:lang", "--baseline-value", "en"], "en"),
])
def test_probe_sends_validated_baseline_value(scope_file, monkeypatch, extra, expected):
    seen = []
    monkeypatch.setattr(client, "request", lambda m, p, b=None, **k: seen.append(b) or {})
    args = _probe(scope_file, "--target", "https://app.example.com/api/items?lang=en", *extra)
    args.fn(args)
    assert seen[0]["baseline_value"] == expected


@pytest.mark.parametrize("extra,match", [
    (["--test-type", "nosql", "--parameter", "header:X-Filter"], "JSON"),
    (["--test-type", "nosql", "--parameter", "header:X-Filter", "--baseline-value", "alice"],
     "JSON object"),
    (["--test-type", "sqli", "--parameter", "query:lang", "--baseline-value", "de"], "differs"),
    (["--test-type", "sqli", "--parameter", "query:q", "--baseline-value", "a\nb"], "printable"),
    (["--test-type", "xss", "--parameter", "fragment:q", "--baseline-value", "x"],
     "server-side"),
    (["--test-type", "sqli", "--parameter", "json:id", "--method", "POST",
      "--body-sample", '{"other":1}'], "no field"),
    (["--test-type", "sqli", "--parameter", "json:id", "--method", "POST",
      "--body-sample", '{"id":1}', "--baseline-value", "1"], "not both"),
    (["--test-type", "sqli", "--parameter", "query:q", "--body-sample", "q=1"], "body param"),
])
def test_probe_refuses_bad_baseline_before_any_request(scope_file, monkeypatch, extra, match):
    monkeypatch.setattr(client, "request", lambda *a, **k: pytest.fail("no request expected"))
    args = _probe(scope_file, "--target", "https://app.example.com/api/items?lang=en", *extra)
    with pytest.raises(client.ProwlError, match=match):
        args.fn(args)
