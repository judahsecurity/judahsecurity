"""Native verifiers that replace the LLM validator for non-HTTP findings,
manual replays and template-logic diagnosis. No network: every transport,
nmap call and LLM call is faked."""

import asyncio
import json

import pytest

from app.services import finding_revalidation_service as svc
from app.services import native_verifiers as nv
from app.services.secret_safety import secret_descriptor
from app.workers.scanner_worker import route_finding_validation

SECRET = "AKIAZZZZEXAMPLE7777Q"
DESC = secret_descriptor(SECRET)
JS_URL = "https://cdn.example.com/static/app.js"


def _http(responses, calls=None):
    """Fake HttpCall: url -> (status, body) or Exception."""
    def call(method, url, headers, body, timeout):
        if calls is not None:
            calls.append((method, url, headers, body))
        r = responses.get(url)
        if isinstance(r, Exception) or r is None:
            return {"status": None, "body": "", "headers": {}, "error": "ConnectError"}
        return {"status": r[0], "body": r[1], "headers": {}, "error": None}
    return call


def _never_http(*a, **k):
    raise AssertionError("no HTTP expected")


def _nmap_state(state, port):
    return type("R", (), {"returncode": 0, "stderr": "", "stdout": (
        f'<nmaprun><host><ports><port protocol="tcp" portid="{port}">'
        f'<state state="{state}" /></port></ports></host></nmaprun>')})()


# ── secret ─────────────────────────────────────────────────────────────────────

def _secret_finding(**kw):
    f = {
        "title": "JavaScript Secret: regex.aws_access_key", "severity": "high",
        "detected_by": "js_secret_scan", "source_kind": "secret",
        "template_id": "js-secret-abc", "target": "cdn.example.com",
        "metadata": {"kind": "regex.aws_access_key", "source_url": JS_URL,
                     "fingerprint": DESC["fingerprint"]},
    }
    f.update(kw)
    return f


def test_secret_still_served_is_confirmed_and_open():
    body = f'var cfg={{k:"{SECRET}",region:"us-east-1"}};'
    v = nv.verify_secret(_secret_finding(), http_call=_http({JS_URL: (200, body)}))
    assert v["verdict"] == "confirmed" and v["still_open"] is True
    assert v["remediation_state"] == "open" and v["native_verifier"] == "secret"
    assert SECRET not in json.dumps(v)  # never echoes the secret


def test_secret_gone_is_remediated_not_never_real():
    v = nv.verify_secret(_secret_finding(), http_call=_http({JS_URL: (200, "var cfg={};")}))
    v = nv.finalize_verdict(v, _secret_finding())
    assert v["still_open"] is False and v["remediation_state"] == "remediated"
    assert v["is_false_positive"] is False


def test_secret_location_unknown_needs_more_evidence_without_http():
    f = _secret_finding(metadata={"fingerprint": DESC["fingerprint"]}, target="cdn.example.com")
    v = nv.verify_secret(f, http_call=_never_http)
    assert v["verdict"] == "needs_more_evidence" and v["native_verifier"] == "secret"


def test_secret_found_inside_larger_token_with_length_hint():
    body = f"x=prefix{SECRET}suffix;"
    f = _secret_finding(metadata={**_secret_finding()["metadata"], "length": DESC["length"]})
    v = nv.verify_secret(f, http_call=_http({JS_URL: (200, body)}))
    assert v["verdict"] == "confirmed"


def test_trufflehog_raw_hash_is_a_fingerprint():
    raw_hash = DESC["fingerprint"].split(":", 1)[1]
    f = {"detected_by": "trufflehog", "source_kind": "secret", "severity": "high",
         "metadata": {"raw_hash": raw_hash, "url": JS_URL}}
    v = nv.verify_secret(f, http_call=_http({JS_URL: (200, f"'{SECRET}'")}))
    assert v["verdict"] == "confirmed"


def test_secret_routing_skips_template_replay(monkeypatch):
    async def no_nuclei(finding):
        raise AssertionError("secret findings must not replay a synthetic template id")
    monkeypatch.setattr(svc, "_revalidate_nuclei", no_nuclei)
    v = asyncio.run(svc.revalidate_finding(
        _secret_finding(), http_call=_http({JS_URL: (404, "")})))
    assert v["method"] == "secret_fingerprint_recheck" and v["remediation_state"] == "remediated"


# ── network service ────────────────────────────────────────────────────────────

def _net_finding(**kw):
    f = {"title": "Unauthenticated Redis Exposure", "severity": "high", "detected_by": "agent",
         "source_kind": "network_service", "asset": "203.0.113.10",
         "target": "203.0.113.10:6379", "metadata": {"port": 6379, "protocol": "tcp"}}
    f.update(kw)
    return f


def _run_net(monkeypatch, finding, state, observed):
    monkeypatch.setattr(svc.subprocess, "run", lambda *a, **k: _nmap_state(state, finding["metadata"]["port"]))
    probe_calls = []

    def probe(host, port, proto):
        probe_calls.append((host, port))
        return observed
    v = asyncio.run(svc.revalidate_finding(finding, service_probe=probe))
    return v, probe_calls


def test_claimed_protocol_not_answering_is_never_real(monkeypatch):
    v, calls = _run_net(monkeypatch, _net_finding(template_id="redis-unauth"), "open",
                        {"name": "http", "product": "nginx"})
    # template_id triggers nuclei replay first; force it out of the way
    assert calls or v["method"] != "nmap_port_verify"


def test_wrong_service_on_open_port_is_false_positive(monkeypatch):
    v, calls = _run_net(monkeypatch, _net_finding(), "open", {"name": "http", "product": "nginx"})
    assert calls == [("203.0.113.10", 6379)]
    assert v["verdict"] == "false_positive" and v["logical_mismatch"] is True
    assert v["remediation_state"] == "never_real" and v["still_open"] is False
    assert v["port_state"] == "open" and v["native_verifier"] == "network_service"


def test_claimed_service_answers_but_vuln_claim_unproven(monkeypatch):
    v, _ = _run_net(monkeypatch, _net_finding(), "open", {"name": "redis", "product": "Redis key-value store"})
    assert v["verdict"] == "needs_more_evidence" and v["native_verifier"] == "network_service"
    assert "matching the claimed redis" in v["reasoning"]


def test_port_scanner_exposure_with_matching_service_confirmed(monkeypatch):
    f = {"title": "[Port 22/tcp] SSH Service Exposed", "severity": "medium",
         "detected_by": "port_scanner", "source_kind": "network_service",
         "asset": "203.0.113.10", "target": "203.0.113.10:22", "metadata": {"port": 22}}
    v, _ = _run_net(monkeypatch, f, "open", {"name": "ssh", "product": "OpenSSH", "version": "9.6"})
    assert v["verdict"] == "confirmed" and v["remediation_state"] == "open"


def test_closed_port_scanner_finding_is_remediated(monkeypatch):
    f = {"title": "[Port 22/tcp] SSH Service Exposed", "severity": "medium",
         "detected_by": "port_scanner", "source_kind": "network_service",
         "asset": "203.0.113.10", "target": "203.0.113.10:22", "metadata": {"port": 22}}
    v, calls = _run_net(monkeypatch, f, "closed", {"name": "ssh"})
    assert calls == []  # no service probe on a closed port
    assert v["verdict"] == "false_positive" and v["remediation_state"] == "remediated"
    assert v["is_false_positive"] is False and v["still_open"] is False


def test_closed_port_for_unconfirmed_agent_claim_is_not_called_remediated(monkeypatch):
    v, _ = _run_net(monkeypatch, _net_finding(), "filtered", {})
    assert v["verdict"] == "false_positive" and v["remediation_state"] == "unknown"


def test_unidentified_service_keeps_port_verdict(monkeypatch):
    v, _ = _run_net(monkeypatch, _net_finding(), "open", {"name": "tcpwrapped"})
    assert v["verdict"] == "needs_more_evidence" and v["logical_mismatch"] is False


def test_nmap_missing_is_not_claimed_by_native(monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError("nmap")
    monkeypatch.setattr(svc.subprocess, "run", boom)
    v = asyncio.run(svc.revalidate_finding(_net_finding(), service_probe=lambda *a: {}))
    assert v["verdict"] == "needs_more_evidence" and not v.get("native_verifier")


def test_default_service_probe_parses_nmap_xml(monkeypatch):
    xml = ('<nmaprun><host><ports><port protocol="tcp" portid="6379"><state state="open"/>'
           '<service name="redis" product="Redis key-value store" version="7.2"/></port>'
           '</ports></host></nmaprun>')
    monkeypatch.setattr(nv.subprocess, "run", lambda *a, **k: type(
        "R", (), {"returncode": 0, "stdout": xml, "stderr": ""})())
    out = nv.default_service_probe("203.0.113.10", 6379)
    assert out["name"] == "redis" and out["version"] == "7.2"


# ── manual ─────────────────────────────────────────────────────────────────────

APP = "https://app.example.com"


def _manual(**kw):
    f = {"title": "Stored XSS in profile name", "severity": "high", "detected_by": "manual",
         "source_kind": "manual", "is_manual": True, "target": f"{APP}/profile",
         "asset": "app.example.com",
         "steps_to_reproduce": (
             "1. Log in as any user\n"
             f"2. curl -s -H 'Cookie: sid=abc' '{APP}/profile?id=7'\n"
             "3. Expected: response contains \"<script>alert(1)</script>\"\n"),
         }
    f.update(kw)
    return f


def test_manual_replay_still_reproduces():
    calls = []
    http = _http({f"{APP}/profile?id=7": (200, "<h1>Hi <script>alert(1)</script></h1>")}, calls)
    v = nv.verify_manual(_manual(), http_call=http)
    assert v["verdict"] == "confirmed" and v["remediation_state"] == "open"
    assert calls[0][0] == "GET" and calls[0][2]["Cookie"] == "sid=abc"


def test_manual_replay_no_longer_shows_indicator_is_remediated():
    http = _http({f"{APP}/profile?id=7": (200, "<h1>Hi &lt;script&gt;</h1>")})
    v = nv.finalize_verdict(nv.verify_manual(_manual(), http_call=http), _manual())
    assert v["verdict"] == "false_positive" and v["remediation_state"] == "remediated"
    assert v["is_false_positive"] is False and v["native_verifier"] == "manual"


def test_manual_raw_http_block_and_state_changing_methods_skipped():
    steps = ("POST /api/search HTTP/1.1\nHost: app.example.com\nContent-Type: application/json\n\n"
             '{"q": "\' OR 1=1--"}\n\n'
             "DELETE /api/users/9 HTTP/1.1\nHost: app.example.com\n\n"
             "Response contains: 'SQLSTATE[42000]'\n")
    calls = []
    http = _http({f"{APP}/api/search": (500, "error SQLSTATE[42000] near OR")}, calls)
    v = nv.verify_manual(_manual(steps_to_reproduce=steps), http_call=http)
    assert [c[0] for c in calls] == ["POST"] and calls[0][3] == '{"q": "\' OR 1=1--"}'
    assert any("DELETE" in s for s in v["skipped"])
    assert v["verdict"] == "confirmed"


def test_manual_requests_to_other_hosts_are_not_replayed():
    steps = "curl https://evil.example.net/steal\nExpected: \"pwned\""
    v = nv.verify_manual(_manual(steps_to_reproduce=steps), http_call=_never_http)
    assert v["verdict"] == "needs_more_evidence" and not v.get("native_verifier")


def test_manual_without_indicator_is_left_to_a_deeper_retest():
    steps = f"curl '{APP}/profile?id=7'"
    v = nv.verify_manual(_manual(steps_to_reproduce=steps),
                         http_call=_http({f"{APP}/profile?id=7": (200, "ok")}))
    assert v["verdict"] == "needs_more_evidence" and not v.get("native_verifier")


def test_manual_prose_only_falls_back_to_endpoint_probe():
    assert nv.verify_manual(_manual(steps_to_reproduce="Open the profile page and look."),
                            http_call=_never_http) is None


# ── template diagnosis ─────────────────────────────────────────────────────────

YAML = """id: weak-ldap
info: {name: LDAP anon, severity: high}
tcp:
  - inputs: [{data: "\\n"}]
    matchers: [{type: word, words: ["ldap"]}]
"""


def _tpl_finding():
    return {"title": "LDAP anonymous bind", "template_id": "weak-ldap", "template_yaml": YAML,
            "target": "ldap.example.com:389", "severity": "high", "detected_by": "nuclei",
            "evidence": "matched word ldap"}


FP = {"verdict": "false_positive", "method": "nuclei_template_replay",
      "nuclei_recheck": {"ran": True, "still_fires": False}}


def test_diagnosis_parses_structured_answer_and_bounds_prompt():
    seen = {}

    async def llm(system, user):
        seen["user"] = user
        return ('Here: ```json\n{"template_logic_issue": "Matches the word ldap in any banner",'
                ' "cause": "template_logic", "confidence": "high", "reasoning": "weak word"}\n```')
    big = {**_tpl_finding(), "template_yaml": YAML + ("#" * 50000), "evidence": "e" * 50000}
    d = asyncio.run(nv.diagnose_template_logic(big, dict(FP), llm_call=llm))
    assert d["template_logic_issue"].startswith("Matches the word") and d["cause"] == "template_logic"
    assert len(seen["user"]) < 12000
    v = nv.finalize_verdict(nv.apply_diagnosis(dict(FP), d), big)
    assert v["template_logic_issue"] and v["remediation_state"] == "never_real"
    assert v["is_false_positive"] is True


def test_diagnosis_target_changed_sets_no_issue():
    async def llm(system, user):
        return '{"template_logic_issue": "x", "cause": "target_changed", "confidence": "medium"}'
    d = asyncio.run(nv.diagnose_template_logic(_tpl_finding(), dict(FP), llm_call=llm))
    assert d["template_logic_issue"] is None


@pytest.mark.parametrize("behaviour", ["raise", "garbage", "timeout"])
def test_diagnosis_llm_failure_returns_none(behaviour):
    async def llm(system, user):
        if behaviour == "raise":
            raise RuntimeError("provider down")
        if behaviour == "timeout":
            await asyncio.sleep(5)
        return "not json at all"
    d = asyncio.run(nv.diagnose_template_logic(_tpl_finding(), dict(FP), llm_call=llm, timeout_sec=0.05))
    assert d is None


def test_diagnosis_only_for_unconfirmed_template_findings():
    async def llm(system, user):
        raise AssertionError("must not call the LLM")
    assert asyncio.run(nv.diagnose_template_logic(
        _tpl_finding(), {"verdict": "confirmed"}, llm_call=llm)) is None
    assert asyncio.run(nv.diagnose_template_logic(
        {**_tpl_finding(), "template_yaml": None}, dict(FP), llm_call=llm)) is None
    assert asyncio.run(nv.diagnose_template_logic(
        _tpl_finding(), {**FP, "remediation_state": "remediated"}, llm_call=llm)) is None


def test_revalidate_finding_tolerates_llm_failure(monkeypatch):
    async def replay(finding):
        return dict(FP, confidence="high", template_logic_issue=None, native_verifier="template")
    monkeypatch.setattr(svc, "_revalidate_nuclei", replay)

    async def llm(system, user):
        raise RuntimeError("boom")
    v = asyncio.run(svc.revalidate_finding(_tpl_finding(), llm_call=llm))
    assert v["verdict"] == "false_positive" and v["template_logic_issue"] is None


def test_revalidate_finding_attaches_diagnosis(monkeypatch):
    async def replay(finding):
        return dict(FP, confidence="high", template_logic_issue=None, native_verifier="template")
    monkeypatch.setattr(svc, "_revalidate_nuclei", replay)

    async def llm(system, user):
        return '{"template_logic_issue": "banner-only matcher", "cause": "template_logic"}'
    v = asyncio.run(svc.revalidate_finding(_tpl_finding(), llm_call=llm))
    assert v["template_logic_issue"] == "banner-only matcher"


def test_previously_confirmed_template_no_longer_firing_is_remediated(monkeypatch):
    import app.services.custom_template_ai as ai

    async def recheck(yaml, target, timeout_sec=90):
        return {"ran": True, "still_fires": False, "match_count": 0, "error": None}
    monkeypatch.setattr(ai, "recheck_template_against_target", recheck)

    async def llm(system, user):
        raise AssertionError("remediated findings need no diagnosis")
    f = {**_tpl_finding(), "last_validation_verdict": "confirmed"}
    v = asyncio.run(svc.revalidate_finding(f, llm_call=llm))
    assert v["remediation_state"] == "remediated" and v["is_false_positive"] is False


def test_default_llm_not_used_without_configuration(monkeypatch):
    monkeypatch.setattr(nv, "_llm_configured", lambda: False)

    async def boom(*a):
        raise AssertionError("default LLM must not run")
    monkeypatch.setattr(nv, "_default_llm_call", boom)
    assert asyncio.run(nv.diagnose_template_logic(_tpl_finding(), dict(FP))) is None


# ── routing ────────────────────────────────────────────────────────────────────

def _route(native, prowl=None):
    calls = []

    async def run_native():
        calls.append("native")
        return dict(native)

    async def run_prowl():
        calls.append("prowl")
        return prowl

    async def run_vanguard(kind):
        calls.append("vanguard")
        return {"verdict": "confirmed"}
    v = asyncio.run(route_finding_validation(
        "auto", run_native=run_native, run_prowl=run_prowl, run_vanguard=run_vanguard,
        prowl_enabled=True, vanguard_fallback="docker"))
    return v, calls


@pytest.mark.parametrize("kind", ["network_service", "secret", "manual", "template"])
def test_auto_does_not_escalate_findings_a_native_verifier_owns(kind):
    v, calls = _route({"verdict": "needs_more_evidence", "native_verifier": kind})
    assert calls == ["native", "prowl"] and v["native_verifier"] == kind


def test_auto_still_prefers_prowl_over_native_inconclusive():
    v, calls = _route({"verdict": "needs_more_evidence", "native_verifier": "manual"},
                      prowl={"verdict": "confirmed", "method": "prowl_independent_verify"})
    assert calls == ["native", "prowl"] and v["method"] == "prowl_independent_verify"


def test_auto_escalates_only_unowned_findings():
    _, calls = _route({"verdict": "needs_more_evidence", "method": "agent_steps_replay"})
    assert calls == ["native", "prowl", "vanguard"]
