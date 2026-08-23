"""Demonstrated-compromise chain normalization and auto-attach."""

from __future__ import annotations

from app.services.agent.demonstrated_chain import (
    build_agent_detection,
    normalize_chain,
    parse_args,
    select_proof_invocations,
    should_record_tool,
    summarize_output,
)


def test_parse_args_splits_cli_string():
    assert parse_args("-s -k -D- https://db.example.com:3443/") == [
        "-s",
        "-k",
        "-D-",
        "https://db.example.com:3443/",
    ]


def test_should_skip_judge_and_query_tools():
    assert not should_record_tool("create_finding")
    assert not should_record_tool("validate_finding")
    assert not should_record_tool("query_assets")
    assert not should_record_tool("nuclei_help")
    assert should_record_tool("execute_curl")
    assert should_record_tool("probe_registry_anonymous")


def test_summarize_http_401_json_error():
    stdout = (
        "HTTP/2 401\n"
        'content-type: application/json\n\n'
        '{"error":"unauthorized","reason":"Authentication required."}'
    )
    summary, outcome = summarize_output(
        "execute_curl",
        ["-s", "-k", "https://db.example.com/"],
        stdout,
        "",
        0,
    )
    assert "401" in outcome
    assert "unauthorized" in outcome.lower()
    assert summary


def test_normalize_agent_supplied_chain():
    raw = [
        {
            "summary": "Unauthenticated GET to CouchDB root",
            "outcome": "HTTP 401 Authentication required",
            "tool": "execute_curl",
            "args": ["-s", "-k", "https://db.example.com/"],
            "result": {
                "stdout": "HTTP/2 401\n",
                "stderr": "",
                "exit_code": 0,
            },
        }
    ]
    steps = normalize_chain(raw)
    assert len(steps) == 1
    assert steps[0]["step"] == 1
    assert steps[0]["tool"] == "execute_curl"
    assert steps[0]["args"][0] == "-s"
    assert steps[0]["result"]["exit_code"] == 0


def test_normalize_chain_from_json_string():
    steps = normalize_chain(
        '[{"tool":"execute_curl","args":"-s https://x","stdout":"HTTP/1.1 200 OK"}]'
    )
    assert len(steps) == 1
    assert steps[0]["result"]["stdout"].startswith("HTTP/1.1 200")


def test_select_proof_prefers_target_and_curl():
    invocations = [
        {"tool": "execute_subfinder", "args": "-d other.com", "output": "a.other.com"},
        {"tool": "execute_curl", "args": "-s https://db.example.com/", "output": "HTTP/2 401"},
        {"tool": "execute_curl", "args": "-s https://db.example.com/_all_dbs", "output": "HTTP/2 200"},
        {"tool": "query_assets", "args": "", "output": "[]"},
    ]
    chosen = select_proof_invocations(invocations, target="db.example.com", limit=8)
    tools = [c["tool"] for c in chosen]
    assert tools == ["execute_curl", "execute_curl"]


def test_redact_keeps_username_strips_password():
    from app.services.agent.demonstrated_chain import redact_secrets

    text = "curl -u kevin:kevin https://db.example.com/\nAuthorization: Basic a2V2aW46a2V2aW4="
    out = redact_secrets(text)
    assert "kevin:kevin" not in out
    assert "kevin:[REDACTED]" in out
    assert "[REDACTED]" in out
    assert "a2V2aW46a2V2aW4=" not in out


def test_redact_authsession_and_couch_secret():
    from app.services.agent.demonstrated_chain import redact_secrets, summarize_output

    text = (
        "Secret: 958091a1a3459818d44249c165b19c52\n"
        "Forged cookie: AuthSession=QWFyb24gWmhlbjo2QTQxMjUxQjo1YWJhZDAzY2I5YjVkZjVm\n"
        '{"ok":true,"userCtx":{"name":"ADESHPA4","roles":["_admin","Administrator"]}}'
    )
    out = redact_secrets(text)
    assert "958091a1a3459818d44249c165b19c52" not in out
    assert "QWFyb24gWmhlbjo" not in out
    assert "AuthSession=[REDACTED]" in out
    assert "ADESHPA4" in out

    summary, outcome = summarize_output("execute_curl", [], out, "", 0)
    assert "_admin" in summary.lower() or "_admin" in outcome.lower()
    assert "ADESHPA4" in summary or "ADESHPA4" in outcome


def test_build_auto_attaches_when_chain_omitted():
    invocations = [
        {
            "tool": "execute_curl",
            "args": "-s -k https://app.example.com/",
            "output": "HTTP/2 401\n{\"error\":\"unauthorized\"}",
            "exit_code": 0,
        },
        {
            "tool": "execute_curl",
            "args": "-s -k -u kevin:kevin https://app.example.com/",
            "output": 'HTTP/2 200\n{"couchdb":"Welcome","version":"2.1.1"}',
            "exit_code": 0,
        },
    ]
    payload = build_agent_detection(
        invocations=invocations,
        target="app.example.com",
        context="CouchDB 2.1.1 required auth.",
        not_demonstrated="Did not crack hashes.",
        references="https://docs.couchdb.org/en/stable/config/auth.html",
        session_id="sess-1",
    )
    assert payload["source"] == "agent"
    assert payload["step_count"] == 2
    assert payload["session_id"] == "sess-1"
    assert "Welcome" in payload["chain"][1]["result"]["stdout"] or "200" in payload["chain"][1]["outcome"]
    assert payload["not_demonstrated"].startswith("Did not")
    assert payload["references"][0].startswith("https://")


def test_summarize_elasticsearch_root_welcome():
    stdout = (
        "HTTP/1.1 200 OK\n"
        'content-type: application/json\n\n'
        '{\n'
        '  "name" : "klblrserv26",\n'
        '  "cluster_name" : "Single-Waste-Plastic-Management",\n'
        '  "version" : { "number" : "7.16.3" },\n'
        '  "tagline" : "You Know, for Search"\n'
        '}'
    )
    summary, outcome = summarize_output(
        "execute_curl",
        ["-sS", "-D-", "http://es.example.com:9200/"],
        stdout,
        "",
        0,
    )
    assert "unauthenticated" in summary.lower() or "elasticsearch" in summary.lower()
    assert "7.16.3" in outcome
    assert "klblrserv26" in outcome
    assert "Single-Waste-Plastic-Management" in outcome


def test_summarize_elasticsearch_write_ack():
    stdout = 'HTTP/1.1 200 OK\n\n{"acknowledged":true,"shards_acknowledged":true,"index":"aegis_test_index"}'
    summary, outcome = summarize_output(
        "execute_curl",
        ["-sS", "-X", "PUT", "http://es.example.com:9200/aegis_test_index"],
        stdout,
        "",
        0,
    )
    assert "write" in summary.lower() or "created" in summary.lower()
    assert "acknowledged" in outcome.lower()


def test_redact_azure_function_env_keys():
    from app.services.agent.demonstrated_chain import redact_secrets, summarize_output

    text = (
        'HTTP/1.1 200 OK\n'
        '{"AzureWebJobsStorage":"DefaultEndpointsProtocol=https;AccountName=ex;'
        'AccountKey=abc123SECRETKEYVALUE==;EndpointSuffix=core.windows.net",'
        '"MACHINEKEY_DecryptionKey":"DEADBEEFDEADBEEFDEADBEEFDEADBEEF",'
        '"WEBSITE_AUTH_SIGNING_KEY":"0123456789abcdef0123456789abcdef"}'
    )
    out = redact_secrets(text)
    assert "abc123SECRETKEYVALUE==" not in out
    assert "DEADBEEFDEADBEEFDEADBEEFDEADBEEF" not in out
    assert "0123456789abcdef0123456789abcdef" not in out
    assert "[REDACTED]" in out
    summary, outcome = summarize_output("execute_curl", ["-s", "https://app.azurewebsites.net/api/Tester"], out, "", 0)
    assert "runtime environment" in summary.lower() or "Function App" in outcome


def test_parse_asset_urls_keeps_scheme_host_and_port():
    from app.services.agent.demonstrated_chain import parse_asset_urls

    urls = parse_asset_urls("https://db.example.com:3443/")
    assert urls == ["https://db.example.com:3443/"]
    urls = parse_asset_urls(None, fallback="db.example.com:3443")
    assert urls == ["https://db.example.com:3443"]


def test_normalize_click_and_request_claims():
    from app.services.agent.demonstrated_chain import normalize_chain

    steps = normalize_chain([
        {
            "summary": "Authenticated as BSPCB via login form",
            "outcome": "Login successful, cookie issued, dashboard loaded showing 9 sites",
            "tool": "execute_browser",
            "result": {
                "dom_changed": True,
                "elements": [
                    {"selector": 'a[href="#landing"]', "text": "Dashboard", "type": "link"},
                ],
                "new_preview": [
                    {
                        "method": "POST",
                        "status_code": 200,
                        "url": "https://app.example.com/glens/userManagement/api/v3.0/loginCheckRequest",
                    }
                ],
                "new_requests": 20,
                "status": "ok",
            },
        },
        {
            "summary": "POST /glens/summaryDashboard/api/v3.0/dashboard_summary with userType=Admin",
            "outcome": "Sites: 4347 vs 9 as Regulator",
            "tool": "replay_http_request",
            "result": {
                "ok": True,
                "raw_body": "eyJTaXRlcyI6ICI0MzQ3In0=",
                "response_headers": {"content-type": "text/plain"},
                "status": 200,
                "url": "https://app.example.com/glens/summaryDashboard/api/v3.0/dashboard_summary",
            },
        },
    ])
    assert steps[0]["display_tool"] == "click"
    assert steps[0]["result"]["dom_changed"] is True
    assert "stdout" not in steps[0]["result"]
    assert steps[1]["display_tool"] == "request"
    assert steps[1]["result"]["status"] == 200
    assert "dashboard_summary" in steps[1]["result"]["url"]
