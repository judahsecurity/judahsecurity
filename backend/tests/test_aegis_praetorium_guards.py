from aegis_praetorium.censor import Censor
from aegis_praetorium.config import PraetoriumConfig, get_config, set_config
from aegis_praetorium.lictor import HookContext, enforce_scope
from aegis_praetorium.scope import (
    HostListResolver,
    get_scope_resolver,
    set_scope_resolver,
)


def test_http_payloads_are_data_not_shell_commands():
    censor = Censor()
    payload = "fullname=' OR 1=1 -- &email=test@example.com\nmessage=$probe"

    verdict = censor.validate(
        "send_http_request",
        {
            "method": "POST",
            "url": "http://host.docker.internal:52490/send.php?a=1&b=2",
            "headers_json": '{"Content-Type":"application/x-www-form-urlencoded"}',
            "body": payload,
        },
    )

    assert verdict.ok, verdict.error


def test_sqli_tools_accept_structured_payloads():
    censor = Censor()
    common = {
        "target_url": "http://host.docker.internal:52490/send.php",
        "method": "POST",
    }
    probe = censor.validate(
        "probe_sqli_params",
        {
            **common,
            "body": '{"filter":{"name":"aegis\' OR 1=1 -- "}}',
            "params": "json:filter.name,header:X-Filter",
            "headers_json": '{"Content-Type":"application/json"}',
            "max_params": 50,
        },
    )
    confirm = censor.validate(
        "sql_injection_test",
        {
            **common,
            "data": '{"fullname":"\' OR 1=1 -- "}',
            "param": "json:fullname",
            "headers_json": '{"Content-Type":"application/json"}',
        },
    )

    assert probe.ok, probe.error
    assert confirm.ok, confirm.error


def test_confirm_poc_accepts_raw_attack_evidence_as_structured_data():
    verdict = Censor().validate(
        "confirm_vulnerability_poc",
        {
            "host": "host.docker.internal:52490",
            "finding_title": "SQL Injection in POST /send.php (fullname)",
            "vuln_type": "sqli",
            "endpoint": "http://host.docker.internal:52490/send.php",
            "payload": "fullname=' OR 1=1 -- &email=test@example.com;$probe",
            "request_raw": (
                "POST /send.php HTTP/1.1\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
                "fullname=' OR 1=1 -- &email=test@example.com"
            ),
            "response_snippet": "SQLSTATE[42000]: syntax error near '<proof>'\n",
            "current_severity": "high",
            "tool": "probe_sqli_params",
        },
    )

    assert verdict.ok, verdict.error


def test_report_accepts_json_containing_attack_evidence():
    evidence = '{"payload":"\u0027 OR 1=1 -- &x=$probe","request":"POST /send.php"}'
    verdict = Censor().validate(
        "generate_report",
        {
            "target_url": "http://host.docker.internal:52490/",
            "scope_domain": "host.docker.internal:52490",
            "pre_recon": "{}",
            "discovery": evidence,
            "vuln_analysis": evidence,
            "exploit_validation": evidence,
        },
    )

    assert verdict.ok, verdict.error


def test_cli_fallback_still_blocks_command_chaining():
    verdict = Censor().validate("unknown_tool", {"args": "safe; whoami"})
    assert not verdict.ok


def test_non_shell_agent_data_is_not_treated_as_cli():
    censor = Censor()
    verdicts = [
        censor.validate(
            "run_custom_probe",
            {
                "source": "payload = \"' OR 1=1 -- &x=$probe\"\nprint(payload)",
                "allowed_hosts": "host.docker.internal",
                "timeout_sec": 20,
            },
        ),
        censor.validate("brain_add_note", {"note": "SQLi: ' OR 1=1; $probe"}),
        censor.validate(
            "brain_add_payload",
            {"category": "sqli", "payload": "' UNION SELECT 1,2 -- &x=$probe"},
        ),
        censor.validate(
            "search_prior_art",
            {"query": "SSTI ${7*7}\nSQLi ' OR 1=1; --", "category": "injection", "top_k": 6},
        ),
    ]

    assert all(verdict.ok for verdict in verdicts), [verdict.error for verdict in verdicts]


def test_scan_nuclei_uses_structured_schema():
    verdict = Censor().validate(
        "scan_nuclei",
        {
            "target": "http://host.docker.internal:52490/",
            "templates": "tags=sqli",
            "severity": "medium,high,critical",
            "timeout": 60,
        },
    )
    assert verdict.ok, verdict.error


def test_port_qualified_scope_is_exact_endpoint():
    resolver = HostListResolver(["host.docker.internal:52490"])

    assert resolver.is_in_scope("http://host.docker.internal:52490/send.php")
    assert not resolver.is_in_scope("host.docker.internal")
    assert not resolver.is_in_scope("host.docker.internal:3000")
    assert not resolver.is_in_scope("http://host.docker.internal:8000/")


def test_domain_scope_keeps_subdomain_compatibility():
    resolver = HostListResolver(["example.com"])
    assert resolver.is_in_scope("api.example.com")
    assert resolver.is_in_scope("https://deep.api.example.com:8443/path")
    assert not resolver.is_in_scope("example.net")


def test_lictor_retains_port_when_enforcing_url_scope():
    old_config = get_config()
    old_resolver = get_scope_resolver()
    try:
        set_config(PraetoriumConfig(enforce_scope=True))
        set_scope_resolver(HostListResolver(["host.docker.internal:52490"]))

        allowed = enforce_scope(HookContext(
            tool_name="send_http_request",
            args="",
            parsed_args=["POST", "http://host.docker.internal:52490/send.php"],
            command=["send_http_request"],
        ))
        blocked = enforce_scope(HookContext(
            tool_name="send_http_request",
            args="",
            parsed_args=["GET", "http://host.docker.internal:3000/"],
            command=["send_http_request"],
        ))

        assert allowed.allowed
        assert not blocked.allowed
        assert "host.docker.internal:3000" in (blocked.reason or "")
    finally:
        set_config(old_config)
        set_scope_resolver(old_resolver)
