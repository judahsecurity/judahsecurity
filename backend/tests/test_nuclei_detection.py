"""Scanner Detection payload from Nuclei request/response dumps."""

from app.services.nuclei_detection import (
    build_nuclei_detection,
    build_nuclei_oast_proof,
    detection_from_evidence,
    extract_match_criteria,
    scanner_detection_for_vulnerability,
)
from app.services.nuclei_service import NucleiResult


TIME_BASED_SQLI_YAML = """
id: time-based-sqli
info:
  name: Time-Based Blind SQL Injection
  severity: critical
http:
- method: GET
  path:
  - '{{BaseURL}}'
  matchers:
  - type: dsl
    dsl:
    - duration<=7
    internal: true
- raw:
  - |
    GET / HTTP/1.1
    Host: {{Hostname}}
  matchers:
  - type: dsl
    dsl:
    - duration>=7 && duration <=16
""".strip()

OAST_YAML = """
id: blind-ssrf-oast
info:
  name: Blind SSRF
  severity: high
http:
- raw:
  - |
    GET /fetch?url=http://{{interactsh-url}} HTTP/1.1
    Host: {{Hostname}}
  matchers:
  - type: word
    part: interact_protocol
    words:
    - dns
""".strip()


def test_extract_match_criteria_prefers_confirming_matcher():
    text = extract_match_criteria(TIME_BASED_SQLI_YAML)
    assert "duration>=7 && duration <=16" in text
    assert "duration<=7" not in text
    assert text.startswith("dsl :")


def test_extract_match_criteria_falls_back_to_matcher_name():
    assert extract_match_criteria(None, "duration") == "matcher :\nduration"


def test_nuclei_result_from_json_captures_request_response():
    result = NucleiResult.from_json(
        {
            "template-id": "time-based-sqli",
            "template-path": "/templates/time-based-sqli.yaml",
            "info": {"name": "Time-Based Blind SQL Injection", "severity": "critical"},
            "host": "https://uniqo.asem.it",
            "matched-at": "https://uniqo.asem.it/help",
            "curl-command": "curl -X GET 'https://uniqo.asem.it/help'",
            "request": "GET /help HTTP/1.1\nHost: uniqo.asem.it",
            "response": "HTTP/1.1 200 OK\n\nok",
            "matcher-name": "",
        }
    )
    assert result.request.startswith("GET /help")
    assert result.response.startswith("HTTP/1.1 200 OK")
    assert result.curl_command.startswith("curl")
    assert result.template_path.endswith("time-based-sqli.yaml")


def test_build_nuclei_detection_includes_request_curl_response():
    result = NucleiResult(
        template_id="time-based-sqli",
        template_name="Time-Based Blind SQL Injection",
        severity="critical",
        host="https://uniqo.asem.it",
        matched_at='https://uniqo.asem.it/help/Index.html?path=")+or+sleep(7)="',
        curl_command="curl -X GET 'https://uniqo.asem.it/help/Index.html'",
        request='GET /help/Index.html HTTP/1.1\nHost: uniqo.asem.it',
        response="HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html></html>",
        matcher_name="",
        template_yaml=TIME_BASED_SQLI_YAML,
    )
    detection = build_nuclei_detection(result)
    assert detection["request"].startswith("GET /help/Index.html")
    assert detection["curl_command"].startswith("curl -X GET")
    assert detection["response"].startswith("HTTP/1.1 200 OK")
    assert detection["match"].startswith("https://uniqo.asem.it/help/")
    assert "duration>=7" in detection["match_criteria"]
    assert "id: time-based-sqli" in detection["template_yaml"]


def test_nuclei_interactsh_match_builds_publishable_oast_proof():
    result = NucleiResult(
        template_id="blind-ssrf-oast",
        template_name="Blind SSRF",
        severity="high",
        host="https://app.test",
        matched_at="https://app.test/fetch",
        request=(
            "GET /fetch?url=http://abc123456789.oast.fun HTTP/1.1\n"
            "Host: app.test"
        ),
        matcher_name="interact-dns",
        matcher_status=True,
        template_yaml=OAST_YAML,
    )
    proof = build_nuclei_oast_proof(result)
    assert proof["kind"] == "oob_callback"
    assert proof["source"] == "nuclei_interactsh"
    assert proof["confirmed"] is True
    assert proof["protocols"] == ["dns"]
    assert proof["callback_domains"] == ["abc123456789.oast.fun"]
    assert len(proof["request_sha256"]) == 64


def test_non_oast_nuclei_match_does_not_claim_callback_proof():
    result = NucleiResult(
        template_id="time-based-sqli",
        template_name="Time-Based SQLi",
        severity="high",
        host="https://app.test",
        matched_at="https://app.test/help",
        matcher_status=True,
        template_yaml=TIME_BASED_SQLI_YAML,
    )
    assert build_nuclei_oast_proof(result) == {}


def test_legacy_evidence_reconstructs_curl_and_match():
    evidence = (
        "Nuclei template time-based-sqli matched (matcher: duration)\n\n"
        "Reproduction:\n```\ncurl -X GET 'https://uniqo.asem.it/help'\n```"
    )
    detection = detection_from_evidence(
        evidence=evidence,
        matcher_name="duration",
        template_id="time-based-sqli",
        metadata={"nuclei_matched_at": "https://uniqo.asem.it/help"},
    )
    assert detection["curl_command"] == "curl -X GET 'https://uniqo.asem.it/help'"
    assert detection["match"] == "https://uniqo.asem.it/help"
    assert detection["match_criteria"] == "matcher :\nduration"


class _Vuln:
    def __init__(self, **kwargs):
        self.detected_by = kwargs.get("detected_by", "nuclei")
        self.template_id = kwargs.get("template_id", "time-based-sqli")
        self.matcher_name = kwargs.get("matcher_name", "")
        self.evidence = kwargs.get("evidence", "")
        self.metadata_ = kwargs.get("metadata_", {})


def test_scanner_detection_skips_agent_findings():
    assert scanner_detection_for_vulnerability(_Vuln(detected_by="agent")) is None


def test_scanner_detection_uses_stored_metadata():
    vuln = _Vuln(
        metadata_={
            "detection": {
                "request": "GET / HTTP/1.1",
                "curl_command": "curl https://example.com",
                "match": "https://example.com/",
            }
        }
    )
    detection = scanner_detection_for_vulnerability(vuln)
    assert detection["request"] == "GET / HTTP/1.1"
    assert detection["curl_command"].startswith("curl")
