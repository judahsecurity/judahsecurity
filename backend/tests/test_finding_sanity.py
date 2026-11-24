"""Deterministic service/port sanity check shared by native revalidation and Vanguard."""

import asyncio

import pytest

from asm_scanner_core.finding_sanity import extract_port, logical_sanity_check
from app.services import finding_revalidation_service as svc

LDAP = {"title": "LDAP Anonymous Bind", "template_id": "ldap-anonymous-login", "tags": ["ldap"],
        "detected_by": "nuclei", "source_kind": "web"}


@pytest.mark.parametrize("target, mismatch", [
    ("https://host.example.com", True),          # 443
    ("http://host.example.com:8080", True),
    ("host.example.com:389", False),             # LDAP's own port
    ("host.example.com:10389", False),           # off-range but not a web port: no auto-kill
])
def test_ldap_on_web_port_is_a_logical_false_positive(target, mismatch):
    verdict = logical_sanity_check(LDAP, target)
    assert bool(verdict) is mismatch
    if verdict:
        assert verdict["verdict"] == "false_positive" and verdict["logical_mismatch"] is True
        assert verdict["sanity_flags"] and verdict["template_logic_issue"]


def test_port_precedence_metadata_then_url_then_scheme():
    assert extract_port({"metadata": {"port": "636"}}, "https://h") == 636
    assert extract_port({}, "https://h:8443/x") == 8443
    assert extract_port({}, "http://h") == 80
    assert extract_port({"target": "h:6379"}, "h:6379") == 6379


def test_service_names_need_word_boundaries():
    assert logical_sanity_check({"title": "Gladly accepted SMTPish banner", "template_id": "x"},
                                "https://h") is None


def test_native_revalidation_short_circuits_template_mismatch(monkeypatch):
    async def must_not_replay(_finding):
        raise AssertionError("template replay should be skipped")

    monkeypatch.setattr(svc, "_revalidate_nuclei", must_not_replay)
    verdict = asyncio.run(svc.revalidate_finding({**LDAP, "target": "https://host.example.com"}))
    assert verdict["verdict"] == "false_positive" and verdict["method"] == "logical_sanity"
    assert verdict["logical_mismatch"] is True and verdict["template_logic_issue"]
    assert verdict["detected_by"] == "nuclei"


@pytest.mark.parametrize("finding", [
    {"title": "Redis password exposed in app.js", "detected_by": "agent", "source_kind": "web"},
    {"title": "Redis password exposed in app.js", "detected_by": "js_secrets",
     "source_kind": "secret", "template_id": "redis-creds"},
    {"title": "Exposed LDAP admin note", "detected_by": "manual", "source_kind": "manual",
     "template_id": "x"},
])
def test_free_text_findings_are_not_auto_rejected(finding):
    assert svc._logical_sanity_verdict({**finding, "target": "https://host.example.com"}) is None
