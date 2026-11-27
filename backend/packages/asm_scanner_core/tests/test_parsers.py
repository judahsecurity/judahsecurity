"""Golden-output tests for the scanner parser registry (hand-written fixtures, no network)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from asm_scanner_core.parsers import PARSERS, Observation, canonical_tool, parse_tool_output
from asm_scanner_core.parsers.tlsx import grade_cert, normalize_tls_version

FIXTURES = Path(__file__).resolve().parent / "fixtures"
NOW = datetime(2026, 11, 20, tzinfo=timezone.utc)


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def parse(tool: str, name: str, exit_code=0, **kwargs):
    result = parse_tool_output(tool, fixture(name), exit_code, **kwargs)
    assert result is not None
    return result


def titles(result, kind=None):
    return [o.title for o in result.observations if kind is None or o.kind == kind]


# ------------------------------------------------------------------ registry

def test_registry_covers_ported_tools_and_strips_prefixes():
    for tool in ("nikto", "wafw00f", "cmseek", "wpscan", "testssl", "tlsx", "httpx",
                 "sqlmap", "arjun", "xsstrike", "katana"):
        assert tool in PARSERS
    assert canonical_tool("execute_nikto") == "nikto"
    assert canonical_tool("run_testssl.sh") == "testssl"
    assert parse_tool_output("execute_curl", "anything") is None


def test_missing_binary_is_unavailable():
    result = parse_tool_output("execute_nikto", "/bin/sh: 1: nikto: not found\ncommand not found", 127)
    assert result.status == "unavailable"
    assert result.observations == []


def test_parser_crash_is_inconclusive(monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("bad")
    monkeypatch.setitem(PARSERS, "nikto", boom)
    result = parse_tool_output("nikto", "x", 0)
    assert result.status == "inconclusive"
    assert "parser error" in result.reason


def test_to_dict_is_bounded_and_sorted_by_severity():
    result = parse("nikto", "nikto.json")
    out = result.to_dict(max_observations=2)
    assert [o["severity"] for o in out["observations"]] == ["high", "medium"]
    assert out["observations_omitted"] == 3
    assert out["counts"]["observations"] == 5
    json.dumps(out)


def test_observation_redacts_and_bounds_text():
    obs = Observation(kind="x", title="see https://u:pw@h.test/a?token=abc&x=1 Authorization: Bearer abc.def",
                      detail="Cookie: session=supersecret; path=/" + "A" * 1000)
    assert "pw@" not in obs.title and "token=abc" not in obs.title and "abc.def" not in obs.title
    assert "supersecret" not in obs.detail
    assert len(obs.detail) <= 300


# ------------------------------------------------------------------ nikto

def test_nikto_json_maps_severity_per_item():
    result = parse("nikto", "nikto.json")
    assert result.status == "ok"
    sev = {o.title: o.severity for o in result.observations}
    assert sev["Site appears vulnerable to the 'shellshock' vulnerability."] == "high"
    assert sev["Directory indexing found."] == "medium"
    assert sev["The anti-clickjacking X-Frame-Options header is not present."] == "low"
    assert sev["Apache default file found."] == "info"
    shellshock = next(o for o in result.observations if "shellshock" in o.title)
    assert shellshock.target == "shop.example.test:443/cgi-bin/status"
    assert shellshock.attributes["references"] == "CVE-2014-6271"


def test_nikto_text_skips_scan_header_lines():
    result = parse("nikto", "nikto.txt")
    assert result.status == "ok"
    joined = " ".join(titles(result))
    assert "Target IP" not in joined and "Start Time" not in joined and "host(s) tested" not in joined
    assert titles(result, "technology") == ["Server: Apache/2.4.29 (Ubuntu)"]
    by_target = {o.target: o.severity for o in result.observations if o.target}
    assert by_target["/phpmyadmin/"] == "medium"
    assert by_target["/"] == "low"
    assert by_target["/icons/README"] == "info"


def test_nikto_timeout_with_items_is_partial():
    assert parse("nikto", "nikto.txt", exit_code=None, timed_out=True).status == "partial"
    assert parse_tool_output("nikto", "", None, timed_out=True).status == "inconclusive"


# ------------------------------------------------------------------ wafw00f

@pytest.mark.parametrize("name", ["wafw00f_cloudflare.txt", "wafw00f.json"])
def test_wafw00f_vendor_without_suffix_or_ansi(name):
    result = parse("wafw00f", name)
    assert result.status == "ok"
    [obs] = result.observations
    assert obs.attributes["vendor"] == "Cloudflare"
    assert obs.attributes["manufacturer"] == "Cloudflare Inc."
    assert obs.target == "https://shop.example.test"
    assert obs.title == "WAF detected: Cloudflare"


def test_wafw00f_generic_and_none():
    generic = parse("wafw00f", "wafw00f_generic.txt")
    assert generic.observations[0].attributes["generic"] is True
    none = parse("wafw00f", "wafw00f_none.txt")
    assert none.status == "ok" and none.observations == []
    assert parse_tool_output("wafw00f", "[*] Checking https://x.test\n", 0).status == "inconclusive"


# ------------------------------------------------------------------ cmseek

def test_cmseek_console_reads_name_not_detection_method():
    [obs] = parse("cmseek", "cmseek.txt").observations
    assert obs.attributes["cms"] == "WordPress"
    assert obs.attributes["cms_id"] == "wp"
    assert obs.attributes["detection_method"] == "generator"
    assert obs.attributes["version"] == "6.2.1"
    assert obs.target == "blog.example.test"


def test_cmseek_json_and_failed_detection():
    [obs] = parse("cmseek", "cmseek_cms.json").observations
    assert obs.title == "CMS detected: Joomla 3.9.28"
    none = parse("cmseek", "cmseek_none.txt")
    assert none.status == "ok" and none.observations == []


# ------------------------------------------------------------------ wpscan

def test_wpscan_reads_findings_and_component_vulns_exit_5_is_ok():
    result = parse("wpscan", "wpscan.json", exit_code=5)
    assert result.status == "ok"
    assert result.counts["vulnerabilities"] == 2
    vulns = {o.title: o for o in result.observations if o.kind == "vulnerability"}
    core = vulns["WordPress < 5.8.3 - SQL Injection via WP_Query"]
    assert core.severity == "high" and core.attributes["cve"] == ["CVE-2022-21661"]
    plugin = vulns["Contact Form 7 < 5.3.2 - Unrestricted File Upload"]
    assert plugin.attributes["name"] == "contact-form-7" and plugin.attributes["fixed_in"] == "5.3.2"
    interesting = {o.attributes["type"]: o.severity for o in result.observations if o.kind == "interesting_finding"}
    assert interesting == {"headers": "info", "xmlrpc": "info", "debug_log": "medium"}
    assert "WordPress theme twentytwentyone 1.4" in titles(result, "technology")


def test_wpscan_abort_is_inconclusive_and_bad_exit_is_not_ok():
    assert parse("wpscan", "wpscan_aborted.json", exit_code=4).status == "inconclusive"
    assert parse("wpscan", "wpscan.json", exit_code=4).status == "partial"


# ------------------------------------------------------------------ testssl

def test_testssl_flat_levels_and_warn():
    result = parse("testssl", "testssl_flat.json", exit_code=3)
    assert result.status == "ok"
    assert {k: result.counts[k] for k in ("critical", "high", "medium", "low", "warn")} == {
        "critical": 1, "high": 1, "medium": 1, "low": 2, "warn": 1}
    warn = next(o for o in result.observations if o.kind == "scan_warning")
    assert warn.title == "engine_problem" and warn.severity == "info"
    robot = next(o for o in result.observations if o.title == "ROBOT")
    assert robot.target == "tls.example.test:443" and robot.attributes["cve"] == "CVE-2017-17382"
    assert "heartbleed" not in titles(result)


def test_testssl_pretty_flattens_sections():
    result = parse("testssl", "testssl_pretty.json")
    assert sorted(titles(result)) == ["BREACH", "LUCKY13", "TLS1_1", "cert_trust"]


def test_testssl_json_from_file_text():
    result = parse_tool_output("testssl", "Start 2026-11-20 ... (text console output)", 0,
                               json_text=fixture("testssl_pretty.json"))
    assert result.status == "ok" and result.counts["high"] == 1
    assert parse_tool_output("testssl", "plain text only", 0).status == "inconclusive"
    assert parse_tool_output("testssl", "", 250).status == "inconclusive"


# ------------------------------------------------------------------ tlsx

def test_tlsx_grades_and_expiry():
    result = parse("tlsx", "tlsx.jsonl", now=NOW)
    rows = {o.target: o for o in result.observations}
    assert rows["good.example.test:443"].attributes["grade"] == "A"
    assert rows["good.example.test:443"].attributes["days_to_expiry"] == 65
    legacy = rows["legacy.example.test:8443"]
    assert legacy.attributes["grade"] == "C" and legacy.severity == "medium"
    assert legacy.attributes["tls_version"] == "tls1.0"
    bad = rows["selfsigned.example.test:443"]
    assert bad.attributes["grade"] == "F" and bad.severity == "high"
    assert bad.attributes["days_to_expiry"] == -19
    assert result.counts == {"hosts": 3, "grade_A": 1, "grade_C": 1, "grade_F": 1}


def test_tlsx_version_normalization_feeds_grade():
    assert normalize_tls_version("tls11") == "tls1.1"
    assert normalize_tls_version("TLSv1.2") == "tls1.2"
    assert normalize_tls_version("ssl30") == "ssl3"
    assert grade_cert({"tls_version": "tls11"}) == "B"
    assert grade_cert({"tls_version": "tls13", "public_key_size": 1024}) == "B"


# ------------------------------------------------------------------ httpx headers / CORS

def test_httpx_security_headers_and_cors_scoring():
    result = parse("httpx", "httpx_headers.jsonl")
    assert result.counts["hosts"] == 3 and result.counts["cors_policies"] == 3
    headers = {o.target: o for o in result.observations if o.kind == "security_headers"}
    app = headers["https://app.example.test"]
    assert app.attributes["missing"] == ["referrer-policy", "permissions-policy"]
    assert "x-frame-options" in app.attributes["present"]  # via CSP frame-ancestors
    assert app.attributes["score"] == 80 and app.attributes["grade"] == "B"
    legacy = headers["http://legacy.example.test"]
    assert "strict-transport-security" not in legacy.attributes["missing"]  # not expected on http
    assert legacy.attributes["grade"] == "F"
    assert headers["https://api.example.test"].attributes["grade"] == "A"
    cors = {o.target: o for o in result.observations if o.kind == "cors"}
    assert cors["https://api.example.test"].severity == "medium"
    assert cors["http://legacy.example.test"].attributes["wildcard"] is True
    assert "abc123secret" not in json.dumps(result.to_dict())


def test_httpx_without_headers_reports_reason():
    result = parse_tool_output("execute_httpx", '{"url":"https://a.test","status_code":200}\n', 0)
    assert result.status == "ok" and result.observations == []
    assert "include-response-header" in result.reason


# ------------------------------------------------------------------ sqlmap

def test_sqlmap_injection_point_technique_and_dbms():
    result = parse("sqlmap", "sqlmap_vulnerable.txt")
    assert result.status == "ok"
    [obs] = result.observations
    assert obs.parameter == "id" and obs.attributes["place"] == "GET"
    assert obs.attributes["techniques"] == ["boolean-based blind", "time-based blind"]
    assert obs.attributes["technique_letters"] == "BT"
    assert obs.attributes["dbms"] == "MySQL >= 5.0.12"
    assert "s3cr3t" not in json.dumps(result.to_dict())  # payloads are not returned
    assert "sort" not in {o.parameter for o in result.observations}


def test_sqlmap_negative_verdict_is_clean_not_detected():
    result = parse("sqlmap", "sqlmap_clean.txt")
    assert result.status == "ok"
    assert result.observations == []


def test_sqlmap_unreachable_and_timeout():
    assert parse("sqlmap", "sqlmap_unreachable.txt").status == "inconclusive"
    assert parse("sqlmap", "sqlmap_vulnerable.txt", exit_code=None, timed_out=True).status == "partial"


# ------------------------------------------------------------------ arjun

def test_arjun_dict_and_legacy_json():
    result = parse("arjun", "arjun.json")
    assert [o.parameter for o in result.observations] == ["q", "page", "debug"]
    assert {"params", "method", "headers"}.isdisjoint({o.parameter for o in result.observations})
    legacy = parse("arjun", "arjun_legacy.json")
    assert [o.parameter for o in legacy.observations] == ["id", "lang"]


def test_arjun_console_and_none():
    result = parse("arjun", "arjun.txt", target="https://app.example.test/")
    assert [o.parameter for o in result.observations] == ["user", "redirect"]
    assert result.observations[0].target == "https://app.example.test/"
    none = parse("arjun", "arjun_none.txt")
    assert none.status == "ok" and none.counts["parameters"] == 0


def test_arjun_timeout_and_unstable_target_are_inconclusive():
    assert parse("arjun", "arjun_unstable.txt").status == "inconclusive"
    timed_out = parse_tool_output("arjun", "[*] Probing the target for stability\n", None, timed_out=True)
    assert timed_out.status == "inconclusive" and timed_out.observations == []


# ------------------------------------------------------------------ xsstrike

def test_xsstrike_complete_run():
    result = parse("xsstrike", "xsstrike_complete.txt", target="https://app.example.test/?q=1")
    assert result.status == "ok"
    [candidate] = [o for o in result.observations if o.kind == "xss_candidate"]
    assert candidate.parameter == "q"
    assert candidate.attributes["efficiency"] == 100  # Vanguard's [5-9]\d missed 100
    assert candidate.attributes["verified_in_browser"] is False
    assert any(o.kind == "dom_sink" for o in result.observations)
    assert not any(o.kind == "waf" for o in result.observations)  # "WAF Status: Offline"


def test_xsstrike_partial_vs_inconclusive():
    partial = parse("xsstrike", "xsstrike_partial.txt", exit_code=None, timed_out=True)
    assert partial.status == "partial"
    assert partial.observations[0].parameter == "name"
    stuck = parse_tool_output("xsstrike", "\tXSStrike v3.1.5\n[~] Checking for DOM vulnerabilities\n",
                              None, timed_out=True)
    assert stuck.status == "inconclusive"
    clean = parse("xsstrike", "xsstrike_clean.txt")
    assert clean.status == "ok" and clean.observations == []
    errored = parse("xsstrike", "xsstrike_clean.txt", exit_code=1)
    assert errored.status == "inconclusive"


# ------------------------------------------------------------------ katana

def test_katana_forms_deduplicated_and_endpoints_counted():
    result = parse("katana", "katana.jsonl")
    assert result.counts == {"endpoints": 3, "forms": 2}
    login = next(o for o in result.observations if o.attributes["method"] == "POST")
    assert login.target == "https://app.example.test/login"
    assert login.attributes["inputs"] == ["username", "password", "csrf_token"]
    assert login.attributes["enctype"] == "application/x-www-form-urlencoded"


def test_katana_plain_urls():
    result = parse_tool_output("katana", "https://a.test/\nhttps://a.test/x\n[INF] done\n", 0)
    assert result.counts == {"endpoints": 2, "forms": 0} and result.status == "ok"
