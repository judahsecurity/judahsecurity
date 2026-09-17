import json
import subprocess
from urllib.parse import parse_qsl

import scanners


class DummyBridge:
    def __init__(self):
        self.vulnerabilities = []
        self.urls = []
        self.flush_count = 0

    def submit_vulnerability(self, **finding):
        self.vulnerabilities.append(finding)

    def submit_url(self, url, **metadata):
        self.urls.append((url, metadata))

    def flush(self):
        self.flush_count += 1


FORM_HTML = """
<form action="send.php" method="POST">
  <input name="fullname">
  <input type="hidden" name="csrf" value="token-123">
  <button name="submit">Send</button>
</form>
"""


def test_augment_form_body_restores_hidden_and_submit_controls():
    body, restored = scanners._augment_form_body(
        "http://example.test/send.php",
        "POST",
        "fullname=Alice&email=a%40example.test",
        fetch_html=lambda _url: FORM_HTML,
    )

    assert dict(parse_qsl(body, keep_blank_values=True)) == {
        "fullname": "Alice",
        "email": "a@example.test",
        "csrf": "token-123",
        "submit": "",
    }
    assert restored == {"csrf", "submit"}


def test_augment_form_body_never_overwrites_existing_controls():
    original = "fullname=Alice&csrf=caller-token&submit=go"
    body, restored = scanners._augment_form_body(
        "http://example.test/send.php",
        "POST",
        original,
        fetch_html=lambda _url: FORM_HTML,
    )

    assert body == original
    assert restored == set()


def test_probe_sqli_preserves_restored_controls_on_every_request(monkeypatch):
    recorded_bodies = []

    monkeypatch.setattr(
        scanners,
        "_augment_form_body",
        lambda _url, _method, body: (body + "&submit=", {"submit"}),
    )

    def fake_http_probe(method, url, *, body="", headers=None, timeout=25):
        recorded_bodies.append(body)
        return {"status": 200, "body": "stable response", "elapsed_ms": 10}

    monkeypatch.setattr(scanners, "_http_probe", fake_http_probe)
    result = scanners.run_probe_sqli_params(
        "http://example.test/send.php",
        DummyBridge(),
        method="POST",
        body="fullname=Alice&email=a%40example.test",
        params="fullname",
    )

    assert recorded_bodies
    assert all("submit=" in body for body in recorded_bodies)
    assert "submit=" in result["normalized_body"]
    assert result["form_controls_restored"] == ["submit"]


def test_sqlmap_nonzero_exit_is_an_explicit_error(monkeypatch):
    captured = {}
    monkeypatch.setattr(scanners, "_tool_available", lambda _name: True)
    monkeypatch.setattr(
        scanners,
        "_augment_form_body",
        lambda _url, _method, body: (body + "&submit=", {"submit"}),
    )

    def fake_run(cmd, timeout=600):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(
            cmd, 127, stdout="", stderr="/usr/bin/env: 'python': No such file or directory"
        )

    monkeypatch.setattr(scanners, "_run", fake_run)
    result = scanners.run_sqlmap(
        "http://example.test/send.php",
        DummyBridge(),
        data="fullname=Alice",
        method="POST",
        param="fullname",
    )

    assert result["status"] == "error"
    assert result["exit_code"] == 127
    assert not result["vulnerable"]
    assert "--smart" not in captured["cmd"]


def test_sqlmap_uses_restored_body_and_reports_confirmation(monkeypatch):
    captured = {}
    bridge = DummyBridge()
    monkeypatch.setattr(scanners, "_tool_available", lambda _name: True)
    monkeypatch.setattr(
        scanners,
        "_augment_form_body",
        lambda _url, _method, body: (body + "&submit=", {"submit"}),
    )

    def fake_run(cmd, timeout=600):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout="POST parameter 'fullname' is vulnerable\nType: error-based",
            stderr="",
        )

    monkeypatch.setattr(scanners, "_run", fake_run)
    result = scanners.run_sqlmap(
        "http://example.test/send.php",
        bridge,
        data="fullname=Alice",
        param="fullname",
    )

    data_index = captured["cmd"].index("--data") + 1
    assert captured["cmd"][data_index] == "fullname=Alice&submit="
    method_index = captured["cmd"].index("--method") + 1
    assert captured["cmd"][method_index] == "POST"
    assert result["status"] == "ok"
    assert result["vulnerable"]
    assert result["count"] == 1
    assert bridge.vulnerabilities[0]["source"] == "sqlmap"


def test_sqlmap_preserves_json_content_type_and_normalizes_parameter_spec(monkeypatch):
    captured = {}
    monkeypatch.setattr(scanners, "_tool_available", lambda _name: True)

    def fake_run(cmd, timeout=600):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(
            cmd, 0, stdout="POST parameter 'job_type' is vulnerable", stderr=""
        )

    monkeypatch.setattr(scanners, "_run", fake_run)
    result = scanners.run_sqlmap(
        "http://example.test/jobs",
        DummyBridge(),
        data='{"job_type":"aegis"}',
        param="json:job_type",
        headers_json='{"Content-Type":"application/json","X-Test":"assessment"}',
        method="POST",
    )

    assert captured["cmd"][captured["cmd"].index("-p") + 1] == "job_type"
    headers = captured["cmd"][captured["cmd"].index("--headers") + 1]
    assert "Content-Type: application/json" in headers
    assert "X-Test: assessment" in headers
    assert result["vulnerable"]
    assert result["form_controls_restored"] == []


def test_arjun_timeout_is_capped(monkeypatch):
    captured = {}
    monkeypatch.setattr(scanners, "_tool_available", lambda _name: True)

    def fake_run(cmd, timeout=600):
        captured.update(cmd=cmd, timeout=timeout)
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({}), stderr="")

    monkeypatch.setattr(scanners, "_run", fake_run)
    assert scanners.run_arjun("http://example.test/", DummyBridge(), timeout=300) == []
    assert captured["timeout"] == 60
    assert captured["cmd"][captured["cmd"].index("-T") + 1] == "5"


def test_nested_json_and_graphql_mutation_preserve_request_shape():
    nested = scanners._mutate_body_param(
        '{"filter":{"job":{"type":"public"}},"limit":10}',
        "filter.job.type",
        "aegis' OR '1'='1",
        "application/json",
    )
    assert json.loads(nested) == {
        "filter": {"job": {"type": "aegis' OR '1'='1"}},
        "limit": 10,
    }

    graphql = scanners._mutate_graphql_param(
        '{"query":"query { jobs(jobType: \\"public\\") { id } }"}',
        "jobType",
        "aegis' OR '1'='1",
    )
    assert "aegis' OR '1'='1" in json.loads(graphql)["query"]


def test_probe_detects_repeatable_string_boolean_json_signal(monkeypatch):
    requests = []

    def fake_http_probe(method, url, *, body="", headers=None, timeout=25):
        requests.append((method, url, body, headers))
        value = json.loads(body)["job_type"]
        response_body = '[{"id":1,"type":"private"}]' if " OR '1'='1" in value else "[]"
        return {"status": 200, "body": response_body, "elapsed_ms": 10}

    monkeypatch.setattr(scanners, "_http_probe", fake_http_probe)
    result = scanners.run_probe_sqli_params(
        "http://example.test/jobs",
        DummyBridge(),
        method="POST",
        body='{"job_type":"aegis"}',
        headers_json='{"Content-Type":"application/json"}',
        params="json:job_type",
    )

    assert result["vulnerable"]
    assert result["candidates"][0]["location"] == "json"
    assert result["candidates"][0]["parameter"] == "job_type"
    assert result["candidates"][0]["signals"] == ["boolean_diff"]
    assert result["coverage"] == [{
        "parameter_spec": "json:job_type",
        "location": "json",
        "parameter": "job_type",
        "status": "candidate",
        "signals": ["boolean_diff"],
    }]
    assert all(request[3]["Content-Type"] == "application/json" for request in requests)


def test_probe_mutates_cookie_and_header_locations(monkeypatch):
    observed = []

    def fake_http_probe(method, url, *, body="", headers=None, timeout=25):
        observed.append(dict(headers or {}))
        injected = "'" in str(headers)
        response_body = "SQL syntax error" if injected else "stable"
        return {"status": 200, "body": response_body, "elapsed_ms": 10}

    monkeypatch.setattr(scanners, "_http_probe", fake_http_probe)
    cookie_result = scanners.run_probe_sqli_params(
        "http://example.test/account",
        DummyBridge(),
        params="cookie:session",
        headers_json='{"Cookie":"theme=dark; session=abc"}',
    )
    header_result = scanners.run_probe_sqli_params(
        "http://example.test/account",
        DummyBridge(),
        params="header:X-Filter",
        headers_json='{"X-Filter":"public"}',
    )

    assert cookie_result["candidates"][0]["location"] == "cookie"
    assert header_result["candidates"][0]["location"] == "header"
    assert any("session='" in request.get("Cookie", "") for request in observed)
    assert any(request.get("X-Filter") == "'" for request in observed)


def test_probe_reports_explicit_parameter_budget(monkeypatch):
    monkeypatch.setattr(
        scanners,
        "_http_probe",
        lambda *args, **kwargs: {
            "status": 200,
            "body": "SQL syntax error" if "%'" in kwargs.get("body", "") else "stable",
            "elapsed_ms": 10,
        },
    )
    result = scanners.run_probe_sqli_params(
        "http://example.test/search",
        DummyBridge(),
        method="POST",
        body="a=1&b=2&c=3",
        params="form:a,form:b,form:c",
        max_params=2,
    )

    assert result["params_tested"] == ["form:a", "form:b"]
    assert result["skipped_parameters"] == ["form:c"]
    assert not result["coverage_complete"]


def test_probe_auto_classifies_form_and_nested_json_parameters(monkeypatch):
    monkeypatch.setattr(
        scanners,
        "_http_probe",
        lambda *args, **kwargs: {
            "status": 200, "body": "SQL syntax error", "elapsed_ms": 10
        },
    )
    monkeypatch.setattr(
        scanners, "_augment_form_body", lambda _url, _method, body: (body, set())
    )

    form = scanners.run_probe_sqli_params(
        "http://example.test/login", DummyBridge(), method="POST",
        body="username=aegis&password=test",
    )
    nested_json = scanners.run_probe_sqli_params(
        "http://example.test/jobs", DummyBridge(), method="POST",
        body='{"filter":{"type":"public"}}',
        headers_json='{"Content-Type":"application/json"}',
    )

    assert {item["parameter_spec"] for item in form["coverage"]} == {
        "form:username", "form:password"
    }
    assert nested_json["coverage"][0]["parameter_spec"] == "json:filter.type"
