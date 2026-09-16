from agent.guardrails import GuardrailEngine


def test_port_qualified_scope_blocks_cross_port_pivot():
    guard = GuardrailEngine(scope_domains=["host.docker.internal:52490"])

    assert guard.check_tool_call(
        "send_http_request",
        {"url": "http://host.docker.internal:52490/send.php"},
    ) is None

    violation = guard.check_tool_call(
        "scan_ports",
        {"target": "host.docker.internal", "ports": "top-1000"},
    )
    assert violation is not None
    assert violation.rule == "scope_violation"

    violation = guard.check_tool_call(
        "send_http_request",
        {"url": "http://host.docker.internal:3000/"},
    )
    assert violation is not None
    assert violation.rule == "scope_violation"


def test_domain_scope_still_allows_subdomains_and_ports():
    guard = GuardrailEngine(scope_domains=["example.com"])
    assert guard.check_tool_call(
        "send_http_request",
        {"url": "https://api.example.com:8443/v1"},
    ) is None
