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


def test_active_request_blocks_destructive_sql_even_when_url_encoded():
    guard = GuardrailEngine(scope_domains=["example.test"])
    violation = guard.check_tool_call(
        "send_http_request",
        {
            "method": "POST",
            "url": "http://example.test/send.php",
            "body": "fullname=test%27%3B%20DROP%20TABLE%20users%3B--",
        },
    )

    assert violation is not None
    assert violation.rule == "destructive_sql"


def test_active_request_allows_read_only_sqli_evidence():
    guard = GuardrailEngine(scope_domains=["example.test"])

    assert guard.check_tool_call(
        "send_http_request",
        {
            "method": "POST",
            "url": "http://example.test/send.php",
            "body": "fullname=1%27%20AND%20SLEEP(2)--&submit=",
        },
    ) is None


def test_replay_request_keeps_scope_and_destructive_sql_guards():
    guard = GuardrailEngine(scope_domains=["example.test:8443"])
    assert guard.check_tool_call(
        "replay_http_request",
        {"request_id": "req-1", "url": "https://example.test:8443/admin"},
        "medium",
    ) is None

    violation = guard.check_tool_call(
        "replay_http_request",
        {"request_id": "req-1", "url": "https://example.test/admin"},
        "medium",
    )
    assert violation is not None
    assert violation.rule == "scope_violation"

    violation = guard.check_tool_call(
        "replay_http_request",
        {
            "request_id": "req-1",
            "url": "https://example.test:8443/admin",
            "body": "q=1%27%3BDELETE%20FROM%20users%3B--",
        },
        "medium",
    )
    assert violation is not None
    assert violation.rule == "destructive_sql"
