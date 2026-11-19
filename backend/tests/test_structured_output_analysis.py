"""Tool output that code can read does not need a second model call."""

import json

from app.services.agent.structured_output import analyze_without_model

HTTPX = "\n".join([
    json.dumps({"url": "https://app.test", "input": "app.test", "port": "443",
                "scheme": "https", "status_code": 200, "title": "Login",
                "webserver": "nginx/1.25.3", "tech": ["Nginx:1.25.3", "PHP:8.2", "jQuery"]}),
    json.dumps({"url": "http://app.test:8080", "port": "8080", "scheme": "http",
                "status_code": 302, "tech": ["Jetty"]}),
])

NUCLEI = "\n".join([
    "[INF] Using Nuclei Engine 3.3.0",
    json.dumps({"template-id": "git-config", "matched-at": "https://app.test/.git/config",
                "info": {"name": "Git Config Disclosure", "severity": "medium"}}),
    json.dumps({"template-id": "CVE-2023-1234", "matched-at": "https://app.test/api",
                "info": {"name": "Example RCE", "severity": "critical",
                         "classification": {"cve-id": ["CVE-2023-1234"]}}}),
    json.dumps({"template-id": "tech-detect", "matched-at": "https://app.test",
                "info": {"name": "nginx", "severity": "info"}}),
])


def test_httpx_jsonl_fills_target_model() -> None:
    analysis = analyze_without_model("execute_httpx", HTTPX, True)
    assert analysis is not None
    info = analysis.extracted_info
    assert info.ports == [443, 8080]
    assert "PHP:8.2" in info.technologies and "Jetty" in info.technologies
    assert "nginx/1.25.3" in info.services
    assert info.primary_target == "https://app.test"
    assert "2 live endpoint" in analysis.interpretation


def test_nuclei_jsonl_orders_by_severity_and_keeps_info_out_of_vulns() -> None:
    analysis = analyze_without_model("execute_nuclei", NUCLEI, True)
    assert analysis is not None
    vulns = analysis.extracted_info.vulnerabilities
    assert vulns[0].startswith("[critical] Example RCE (CVE-2023-1234)")
    assert any(v.startswith("[medium] Git Config Disclosure") for v in vulns)
    assert not any("nginx" in v for v in vulns)
    assert analysis.extracted_info.technologies == ["nginx"]
    assert len(analysis.actionable_findings) == 2
    assert "leads until proven" in analysis.interpretation


def test_naabu_jsonl_records_ports() -> None:
    out = "\n".join(json.dumps({"host": "app.test", "ip": "10.0.0.1", "port": p})
                    for p in (22, 443, 443, 8443))
    analysis = analyze_without_model("execute_naabu", out, True)
    assert analysis.extracted_info.ports == [22, 443, 8443]


def test_plain_text_scanner_output_still_goes_to_the_model() -> None:
    text = "https://app.test [200] [Login] [nginx]\nhttp://app.test:8080 [302]"
    assert analyze_without_model("execute_httpx", text, True) is None
    assert analyze_without_model("execute_nmap", "22/tcp open ssh", True) is None
    assert analyze_without_model("execute_httpx", HTTPX, False) is None


def test_bookkeeping_result_is_summarised_from_its_fields() -> None:
    out = json.dumps({"row": {"status": "tested_clean", "path": "/search"},
                      "coverage": {"verified_checks": 3, "untested": 7},
                      "engagement_brain": {"hypotheses": []}})
    analysis = analyze_without_model("record_surface_coverage", out, True)
    assert analysis.interpretation.startswith("record_surface_coverage ok")
    assert "verified_checks=3" in analysis.interpretation
    assert analysis.extracted_info.ports == []


def test_bookkeeping_error_is_flagged() -> None:
    out = json.dumps({"error": "This route is closed as tested_clean (paired controls)."})
    analysis = analyze_without_model("record_surface_coverage", out, True)
    assert analysis.interpretation.startswith("record_surface_coverage FAILED: error=This route")


def test_cli_help_needs_no_analysis() -> None:
    analysis = analyze_without_model("nuclei_help", "Usage:\n  nuclei [flags]\n", True)
    assert "reference text" in analysis.interpretation


def test_non_json_bookkeeping_output_falls_back_to_the_model() -> None:
    assert analyze_without_model("save_note", "Saved.", True) is None
    assert analyze_without_model("query_assets", json.dumps({"assets": []}), True) is None
