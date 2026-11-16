"""ffuf/sqlmap output normalizes to bounded, in-scope leads (not findings)."""

import json

from app.services.agent.scoped_assessment.scanner_leads import (
    ffuf_rows,
    scanner_rows,
    sqlmap_rows,
)

HOSTS = {"app.example.test"}


def _ffuf(results):
    return json.dumps({"commandline": "ffuf ...", "results": results})


def test_ffuf_keeps_in_scope_hits_and_drops_misses_and_offscope():
    output = _ffuf([
        {"url": "https://app.example.test/admin", "status": 200},
        {"url": "https://app.example.test/login", "status": 401},
        {"url": "https://app.example.test/missing", "status": 404},
        {"url": "https://evil.example/admin", "status": 200},
        {"url": "https://app.example.test/search?q=x", "status": 200},
    ])
    rows = ffuf_rows(output, allowed_hosts=HOSTS)
    paths = sorted(r["url"] for r in rows)
    assert paths == [
        "https://app.example.test/admin",
        "https://app.example.test/login",
    ]
    assert all(r["source"] == "ffuf_discovery" and r["name"] == "endpoint"
               and r["method"] == "GET" and r["location"] == "query" for r in rows)


def test_ffuf_requires_known_hosts_and_valid_json():
    good = _ffuf([{"url": "https://app.example.test/x", "status": 200}])
    assert ffuf_rows(good, allowed_hosts=set()) == []
    assert ffuf_rows("not json", allowed_hosts=HOSTS) == []
    assert ffuf_rows(json.dumps({"results": "nope"}), allowed_hosts=HOSTS) == []


def test_ffuf_dedups_repeated_paths():
    output = _ffuf([
        {"url": "https://app.example.test/admin", "status": 200},
        {"url": "https://app.example.test/admin", "status": 200},
    ])
    assert len(ffuf_rows(output, allowed_hosts=HOSTS)) == 1


SQLMAP_OUTPUT = """
[*] starting @ 12:00:00

sqlmap identified the following injection point(s) with a total of 120 HTTP(s) requests:
---
URL: https://app.example.test/items.php?id=1
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1=1
Parameter: cat (POST)
    Type: error-based
    Title: MySQL >= 5.0 error-based
    Payload: cat=1 AND GTID_SUBSET(...)
---
[*] shutting down
"""


def test_sqlmap_emits_sql_injection_leads_per_parameter():
    rows = sqlmap_rows(SQLMAP_OUTPUT, allowed_hosts=HOSTS)
    by_name = {r["name"]: r for r in rows}
    assert set(by_name) == {"id", "cat"}
    assert by_name["id"]["location"] == "query" and by_name["id"]["method"] == "GET"
    assert by_name["cat"]["location"] == "body_form" and by_name["cat"]["method"] == "POST"
    assert all(r["source"] == "sqlmap_lead" for r in rows)
    assert all(r["url"] == "https://app.example.test/items.php" for r in rows)


def test_sqlmap_drops_results_without_an_in_scope_url():
    off = SQLMAP_OUTPUT.replace("app.example.test", "evil.example")
    assert sqlmap_rows(off, allowed_hosts=HOSTS) == []
    # No URL line at all: cannot anchor a path, so no rows.
    no_url = "\n".join(line for line in SQLMAP_OUTPUT.splitlines()
                        if not line.startswith("URL:"))
    assert sqlmap_rows(no_url, allowed_hosts=HOSTS) == []


def test_sqlmap_keeps_cookie_and_header_injection_points():
    output = """
URL: https://app.example.test/
Parameter: site_Language_Preference (Cookie)
    Type: UNION query
Parameter: User-Agent (User-Agent)
    Type: time-based blind
Parameter: session (COOKIE)
    Type: boolean-based blind
"""
    rows = sqlmap_rows(output, allowed_hosts=HOSTS)
    by_name = {row["name"]: row for row in rows}
    assert by_name["site_Language_Preference"]["location"] == "cookie"
    assert by_name["User-Agent"]["location"] == "header"
    # Emitted as a lead; the inventory marks the session cookie untestable.
    assert by_name["session"]["location"] == "cookie"
    from app.services.agent.parameter_inventory import collect_parameter_inventory
    inventory = collect_parameter_inventory({
        "target": "https://app.example.test/", "parameter_inventory": rows,
    })
    testable = {row["name"]: row["testable"] for row in inventory if row["location"] == "cookie"}
    assert testable == {"site_Language_Preference": True, "session": False}


def test_scanner_rows_dispatches_by_tool_name():
    ffuf_out = _ffuf([{"url": "https://app.example.test/a", "status": 200}])
    assert len(scanner_rows("execute_ffuf", ffuf_out, allowed_hosts=HOSTS)) == 1
    assert len(scanner_rows("sqlmap", SQLMAP_OUTPUT, allowed_hosts=HOSTS)) == 2
    assert scanner_rows("nmap", "whatever", allowed_hosts=HOSTS) == []
