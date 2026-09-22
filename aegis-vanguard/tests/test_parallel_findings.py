import json
from types import SimpleNamespace

from agent.parallel_subagents import ParallelVulnPhase


def test_finding_key_collapses_same_sqli_from_multiple_tools():
    findings = [
        {
            "title": "SQLi candidate in 'fullname' (sql_error)",
            "url": "http://example.test/send.php",
            "vuln_type": "sqli",
            "severity": "critical",
        },
        {
            "title": "SQL Injection in parameter 'fullname'",
            "url": "http://example.test/send.php",
            "tags": ["sqli", "sqlmap"],
            "severity": "high",
        },
        {
            "title": "SQL Injection in POST /send.php (fullname parameter)",
            "matched_at": "http://example.test/send.php",
            "vuln_type": "sqli",
            "severity": "medium",
        },
    ]

    keys = {ParallelVulnPhase._finding_key(finding) for finding in findings}

    assert len(keys) == 1


def test_finding_key_keeps_different_parameters_distinct():
    fullname = {
        "title": "SQL Injection in parameter 'fullname'",
        "url": "http://example.test/send.php",
        "vuln_type": "sqli",
    }
    email = {
        "title": "SQL Injection in parameter 'email'",
        "url": "http://example.test/send.php",
        "vuln_type": "sqli",
    }

    assert ParallelVulnPhase._finding_key(fullname) != ParallelVulnPhase._finding_key(email)


def test_extract_coverage_events_keeps_structured_probe_evidence():
    payload = {
        "probe": "xss",
        "target": "https://example.test/search",
        "tested_params": ["query:q"],
        "candidates": [],
    }
    result = SimpleNamespace(messages=[{
        "role": "user",
        "content": [{"type": "tool_result", "content": json.dumps(payload)}],
    }])

    assert ParallelVulnPhase._extract_coverage_events(result) == [payload]
