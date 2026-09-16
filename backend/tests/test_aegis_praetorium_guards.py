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
        {**common, "body": "fullname=' OR 1=1 -- &message=x", "params": "fullname"},
    )
    confirm = censor.validate(
        "sql_injection_test",
        {**common, "data": "fullname=' OR 1=1 -- &message=x", "param": "fullname"},
    )

    assert probe.ok, probe.error
    assert confirm.ok, confirm.error


def test_cli_fallback_still_blocks_command_chaining():
    verdict = Censor().validate("unknown_tool", {"args": "safe; whoami"})
    assert not verdict.ok


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
