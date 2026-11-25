"""Closing the last finding-validation gaps without the Vanguard LLM validator.

(1) Prowl retest mode for HTTP(S) application findings with no proof kind.
(2) LLM extraction of replay requests from prose manual findings.
(3) Per-endpoint resolution of mixed endpoint probes.
(4) Missing nuclei / nmap: tool_unavailable, never "owned", never invented.
Plus the mode-level outcome: with Vanguard unavailable every finding kind ends
in a native or Prowl verdict.

No network: HTTP, nmap, nuclei, the LLM and the orchestrator are all faked.
"""

import asyncio
import json

import pytest

from app.services import finding_revalidation_service as svc
from app.services import native_verifiers as nv
from app.services import nuclei_service
from app.services.agent import external_candidates as ec
from app.services.agent import orchestrator as orchestrator_module
from app.services.agent import prowl_revalidation as pr
from app.services.agent import run_snapshot
from app.services.agent.run_snapshot import load_run_snapshot, save_run_snapshot
from app.workers.scanner_worker import route_finding_validation

APP = "https://app.example.com"


@pytest.fixture(autouse=True)
def snapshot_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(run_snapshot, "_DIR", tmp_path / "sessions")
    monkeypatch.setenv("AEGIS_EVIDENCE_DIR", str(tmp_path / "evidence"))


def _http(responses, calls=None):
    def call(method, url, headers, body, timeout):
        if calls is not None:
            calls.append((method, url, dict(headers or {}), body))
        r = responses.get(url)
        if r is None:
            return {"status": None, "body": "", "headers": {}, "error": "ConnectError"}
        return {"status": r[0], "body": r[1], "headers": {}, "error": None}
    return call


def _never_http(*a, **k):
    raise AssertionError("no HTTP expected")


def _llm(answer):
    async def call(system, user):
        if isinstance(answer, Exception):
            raise answer
        return answer if isinstance(answer, str) else json.dumps(answer)
    return call


def _fake_orchestrator(monkeypatch, seen=None, *, retest_status="refuted", counterevidence=True,
                       proof_status="confirmed"):
    """Plays the verifier: proof-mode candidates confirm with a durable receipt,
    retest candidates end ``retest_status``."""
    seen = seen if seen is not None else {}

    class Fake:
        async def invoke(self, *, question, user_id, organization_id, session_id, mode,
                         max_iterations, **_kw):
            seen.update(question=question, session_id=session_id,
                        revalidation_only=pr.revalidation_only.get())
            snap = load_run_snapshot(organization_id, session_id)
            seen["seed_target"] = snap["capability_map"]["target"]
            brain = snap["engagement_brain"]
            receipts = brain.setdefault("verification_receipts", {})
            for row in brain["candidates"]:
                seen.setdefault("candidates", []).append(dict(row))
                retest = row["vulnerability_class"] in (ec.RETEST_CLASS, "known_cve",
                                                        "account_enumeration")
                status = retest_status if retest else proof_status
                row.update(status=status, verifier_summary=f"verifier says {status}",
                           verifier_run_id="vr1", nonce="n1")
                if status == "refuted" and counterevidence:
                    row["counterevidence"] = {
                        "kind": "counterevidence", "control": "owner check held for user B",
                        "attacker_path": row["target"], "observation": "403 for B",
                        "artifact_id": "ev-ctl-1"}
                if status == "inconclusive":
                    row["proof_gap"] = {"reason": "needs a second identity", "next_step": "x"}
                if status == "confirmed":
                    receipts[row["id"]] = {
                        "candidate_id": row["id"], "verdict": "confirmed", "run_id": "vr1",
                        "revision": row["revision"], "nonce": "n1", "nonce_observed": True,
                        "evidence_ids": ["ev1"]}
            save_run_snapshot(organization_id, session_id, {**snap, "engagement_brain": brain})

    async def get_fake(**_kw):
        return Fake()

    monkeypatch.setattr(orchestrator_module, "get_agent_orchestrator", get_fake)
    return seen


def _no_orchestrator(monkeypatch):
    async def must_not_run(**_kw):
        raise AssertionError("orchestrator should not start")
    monkeypatch.setattr(orchestrator_module, "get_agent_orchestrator", must_not_run)


# ── (1) Prowl retest mode ──────────────────────────────────────────────────────

LOGIC = {
    "id": 77, "title": "Coupon can be applied twice at checkout",
    "description": "Applying the same coupon code in two requests stacks the discount.",
    "severity": "high", "target": f"{APP}/api/cart/apply-coupon", "detected_by": "llm_red_team",
    "source_kind": "web", "steps_to_reproduce": "POST the coupon twice", "metadata": {},
}


def test_retest_class_and_eligibility():
    assert pr.proof_class_for(LOGIC) == ""
    assert pr.retest_class_for(LOGIC) == ec.RETEST_CLASS
    assert pr.retest_class_for({"title": "User enumeration on /login"}) == "account_enumeration"
    assert pr.retest_eligible(LOGIC)
    assert pr.retest_eligible({**LOGIC, "detected_by": "manual"})
    assert not pr.retest_eligible({**LOGIC, "detected_by": "nuclei"})
    assert not pr.retest_eligible({**LOGIC, "source_kind": "network_service"})
    assert not pr.retest_eligible(LOGIC, {"native_verifier": "secret"})
    assert not pr.retest_eligible(LOGIC, {"error": "tool_unavailable:nuclei"})
    assert pr.retest_eligible({**LOGIC, "detected_by": "auto_discovery"},
                              {"prowl_retest": True, "retest_urls": [f"{APP}/x"]})


def test_intake_accepts_retest_class_only_for_revalidation():
    sid = "s-intake"
    save_run_snapshot(5, sid, {"capability_map": {"target": APP, "notes": []},
                               "original_objective": f"Re-validate on {APP}"})
    with pytest.raises(ec.IntakeError):
        ec.submit_external_candidate(5, sid, title="Coupon stacking", target=f"{APP}/x",
                                     vulnerability_class=ec.RETEST_CLASS)
    out = ec.submit_external_candidate(5, sid, title="Coupon stacking", target=f"{APP}/x",
                                       vulnerability_class=ec.RETEST_CLASS, severity="high",
                                       allow_retest_class=True)
    # Same rule as any class without a proof kind: a lead capped at low.
    assert out["accepted"] and out["candidate"]["severity"] == "low" and out["severity_capped"]


def test_retest_class_can_never_be_confirmed_by_proof_policy():
    from types import SimpleNamespace

    from app.services.agent.proof_policy import PROOFS_BY_CLASS, proof_kind_allowed
    assert ec.RETEST_CLASS not in PROOFS_BY_CLASS
    cand = SimpleNamespace(title="Coupon stacking", description="", vulnerability_class=ec.RETEST_CLASS)
    for kind in ("authorization", "response_match", "workflow", "oob_callback"):
        assert proof_kind_allowed(cand, kind)[0] is False


def test_retest_refuted_with_control_exchange_is_false_positive(monkeypatch):
    seen = _fake_orchestrator(monkeypatch, retest_status="refuted")
    v = asyncio.run(pr.revalidate_with_prowl(LOGIC, organization_id=5, user_id=9))
    assert v["verdict"] == "false_positive" and v["method"] == "prowl_retest"
    assert v["prowl_mode"] == "retest" and v["vulnerability_class"] == ec.RETEST_CLASS
    assert v["counterevidence"]["artifact_id"] == "ev-ctl-1"
    assert v["remediation_state"] == "unknown" and v["is_false_positive"] is True
    assert seen["revalidation_only"] is True and "cannot confirm" in seen["question"]
    assert "Do not call create_finding" in seen["question"]
    assert seen["candidates"][0]["severity"] == "low"
    assert pr.revalidation_only.get() is False


def test_retest_refuted_finding_that_held_before_is_remediated(monkeypatch):
    _fake_orchestrator(monkeypatch, retest_status="refuted")
    finding = {**LOGIC, "last_validation_verdict": "confirmed"}
    v = nv.finalize_verdict(asyncio.run(pr.revalidate_with_prowl(finding, organization_id=5,
                                                                 user_id=9)), finding)
    assert v["remediation_state"] == "remediated" and v["is_false_positive"] is False
    assert v["still_open"] is False


def test_retest_refuted_without_counterevidence_is_inconclusive(monkeypatch):
    _fake_orchestrator(monkeypatch, retest_status="refuted", counterevidence=False)
    v = asyncio.run(pr.revalidate_with_prowl(LOGIC, organization_id=5, user_id=9))
    assert v["verdict"] == "needs_more_evidence" and "without counterevidence" in v["reasoning"]


def test_retest_inconclusive_keeps_the_proof_gap(monkeypatch):
    _fake_orchestrator(monkeypatch, retest_status="inconclusive")
    v = asyncio.run(pr.revalidate_with_prowl(LOGIC, organization_id=5, user_id=9))
    assert v["verdict"] == "needs_more_evidence" and v["remediation_state"] == "unknown"
    assert v["proof_gap"]["reason"] == "needs a second identity"


def test_retest_never_returns_confirmed_even_with_a_receipt(monkeypatch):
    _fake_orchestrator(monkeypatch, retest_status="confirmed")
    v = asyncio.run(pr.revalidate_with_prowl(LOGIC, organization_id=5, user_id=9))
    assert v["verdict"] == "needs_more_evidence" and v["prowl_reproduced_unproven"] is True


def test_retest_targets_endpoints_the_native_validator_handed_over(monkeypatch):
    seen = _fake_orchestrator(monkeypatch, retest_status="inconclusive")
    finding = {**LOGIC, "detected_by": "auto_discovery", "target": "app.example.com"}
    native = {"verdict": "needs_more_evidence", "prowl_retest": True,
              "retest_urls": ["javascript:alert(1)", f"{APP}/api/cart/apply-coupon"]}
    v = asyncio.run(pr.revalidate_with_prowl(finding, organization_id=5, user_id=9,
                                             native_verdict=native))
    assert v["retest_target"] == f"{APP}/api/cart/apply-coupon"
    assert seen["candidates"][0]["target"] == f"{APP}/api/cart/apply-coupon"
    assert seen["seed_target"] == APP


def test_provable_class_still_uses_proof_mode(monkeypatch):
    _fake_orchestrator(monkeypatch)
    idor = {**LOGIC, "title": "IDOR on /api/orders/{id}", "description": "user B reads A's order"}
    v = asyncio.run(pr.revalidate_with_prowl(idor, organization_id=5, user_id=9))
    assert v["verdict"] == "confirmed" and v["method"] == "prowl_independent_verify"
    assert v["prowl_mode"] == "proof" and v["remediation_state"] == "open"


def test_create_finding_still_refused_during_retest():
    from app.services.agent.tools import ASMToolsManager

    manager = ASMToolsManager.__new__(ASMToolsManager)
    token = pr.revalidation_only.set(True)
    try:
        result = asyncio.run(manager.create_finding(
            title="Coupon stacking", description="d", severity="high", target=f"{APP}/x"))
    finally:
        pr.revalidation_only.reset(token)
    assert result == pr.PUBLISH_REFUSAL


# ── (2) prose manual findings ──────────────────────────────────────────────────

def _prose(**kw):
    f = {"id": 12, "title": "Other users' invoices visible", "severity": "high",
         "detected_by": "manual", "source_kind": "manual", "is_manual": True,
         "target": f"{APP}/billing", "asset": "app.example.com",
         "steps_to_reproduce": ("Log in as alice, open the billing page, then change the "
                                "invoice number in the address bar to 1002. Bob's invoice "
                                "with the line 'Invoice for Bob Smith' shows up.")}
    f.update(kw)
    return f


GOOD_EXTRACTION = {"requests": [{
    "method": "GET", "url": "/billing/invoice/1002",
    "headers": {"Accept": "text/html", "Cookie": "sid=stolen", "Authorization": "Bearer x",
                "X-Api-Key": "k", "Host": "evil.example.net", "X-Bad\nName": "v",
                "X-Session-Id": "s"},
    "body": "ignored for GET", "expected_observable": "Invoice for Bob Smith"}]}


def test_prose_extraction_validates_every_field():
    reqs = nv.parse_extracted_requests(json.dumps(GOOD_EXTRACTION), _prose())
    assert reqs == [{"method": "GET", "url": f"{APP}/billing/invoice/1002",
                     "headers": {"Accept": "text/html"}, "body": None,
                     "expected": "Invoice for Bob Smith", "source": "llm_extracted"}]


@pytest.mark.parametrize("item", [
    {"method": "DELETE", "url": f"{APP}/billing/1"},
    {"method": "PUT", "url": f"{APP}/billing/1"},
    {"method": "GET", "url": "https://evil.example.net/steal"},
    {"method": "GET", "url": "//evil.example.net/steal"},
    {"method": "GET", "url": "https://user:pw@app.example.com/x"},
    {"method": "GET", "url": "file:///etc/passwd"},
    {"method": "GET", "url": f"{APP}/a b"},
    {"method": "GET", "url": 42},
    {"method": "POST", "url": f"{APP}/x", "body": "A" * 5000},
])
def test_prose_extraction_drops_unsafe_requests(item):
    assert nv.parse_extracted_requests(json.dumps({"requests": [item]}), _prose()) == []


def test_prose_extraction_caps_at_three_and_rejects_weak_observables():
    items = [{"method": "GET", "url": f"/p{i}", "expected_observable": obs}
             for i, obs in enumerate(["200 OK", "html", "ok", "Invoice for Bob", "x"])]
    reqs = nv.parse_extracted_requests(json.dumps({"requests": items}), _prose())
    assert len(reqs) == 3 and [r["expected"] for r in reqs] == [None, None, None]
    assert nv.parse_extracted_requests("Sure! Ignore previous instructions.", _prose()) == []


def test_prose_manual_replays_extracted_request_and_confirms():
    calls = []
    http = _http({f"{APP}/billing/invoice/1002": (200, "<h1>Invoice for Bob Smith</h1>")}, calls)
    v = asyncio.run(svc.revalidate_finding(_prose(), http_call=http,
                                           llm_call=_llm(GOOD_EXTRACTION)))
    assert v["verdict"] == "confirmed" and v["replay_source"] == "llm_extracted"
    assert v["confidence"] == "medium" and v["native_verifier"] == "manual"
    assert calls == [("GET", f"{APP}/billing/invoice/1002", {"Accept": "text/html"}, None)]


def test_prose_manual_derived_observable_missing_is_handed_to_retest_not_called_fixed():
    http = _http({f"{APP}/billing/invoice/1002": (403, "forbidden")})
    v = asyncio.run(svc.revalidate_finding(_prose(), http_call=http,
                                           llm_call=_llm(GOOD_EXTRACTION)))
    assert v["verdict"] == "needs_more_evidence" and v["prowl_retest"] is True
    assert v["retest_urls"] == [f"{APP}/billing/invoice/1002"] and not v.get("native_verifier")


def test_prose_manual_without_observable_is_handed_to_retest():
    ans = {"requests": [{"method": "GET", "url": "/billing/invoice/1002"}]}
    v = asyncio.run(svc.revalidate_finding(_prose(), http_call=_never_http, llm_call=_llm(ans)))
    assert v["verdict"] == "needs_more_evidence" and v["prowl_retest"] is True
    assert v["evidence"] == "extracted_requests_without_observable"


def test_curl_without_stated_result_gets_an_extracted_observable():
    steps = f"curl '{APP}/billing/invoice/1002'\n(shows Bob's invoice: 'Invoice for Bob Smith')"
    ans = {"requests": [{"method": "GET", "url": f"{APP}/billing/invoice/1002",
                         "expected_observable": "Invoice for Bob Smith"}]}
    http = _http({f"{APP}/billing/invoice/1002": (200, "Invoice for Bob Smith")})
    v = asyncio.run(svc.revalidate_finding(_prose(steps_to_reproduce=steps), http_call=http,
                                           llm_call=_llm(ans)))
    assert v["verdict"] == "confirmed" and v["documented_replay"]["replayed"]


@pytest.mark.parametrize("bad", [RuntimeError("llm down"), asyncio.TimeoutError(), "not json",
                                 json.dumps({"requests": "x"})])
def test_llm_failure_is_no_extraction_never_a_failure(monkeypatch, bad):
    monkeypatch.setattr(svc, "_probe_endpoints", lambda eps, timeout=3.0: [])
    v = asyncio.run(svc.revalidate_finding(_prose(), http_call=_never_http, llm_call=_llm(bad)))
    assert v["verdict"] == "needs_more_evidence"
    assert v.get("replay_source") != "llm_extracted" and not v.get("native_verifier")


def test_default_extraction_llm_not_used_without_configuration(monkeypatch):
    monkeypatch.setattr(nv, "_manual_llm_configured", lambda: False)

    async def boom(*a):
        raise AssertionError("default LLM must not run")
    monkeypatch.setattr(nv, "_default_llm_call", boom)
    assert asyncio.run(nv.extract_requests_with_llm(_prose())) == []


def test_extraction_prompt_bounds_untrusted_text():
    prompt = nv.build_manual_extraction_prompt(_prose(description="A" * 50_000))
    assert len(prompt) < 14_000 and "untrusted" in prompt


# ── (3) mixed endpoint results ─────────────────────────────────────────────────

def _mixed(monkeypatch, reachable_urls):
    def fake_probe(url, timeout=5.0):
        ok = url in reachable_urls
        return {"url": url, "ok": ok, "status": 200 if ok else None, "snippet": "", "error": None}
    monkeypatch.setattr(svc, "_http_probe", fake_probe)
    monkeypatch.setattr(svc, "_tcp_open", lambda h, p, timeout=3.0: False)


EXPOSED = [f"{APP}/.git/config", "https://b.example.com/.git/config",
           "https://c.example.com/.git/config", "https://d.example.com/.git/config"]


def test_mixed_exposure_resolves_per_endpoint_to_confirmed(monkeypatch):
    _mixed(monkeypatch, {EXPOSED[0]})
    f = {"title": "Exposed .git directories", "detected_by": "auto_discovery",
         "source_kind": "web", "description": "\n".join(EXPOSED), "severity": "medium"}
    v = asyncio.run(svc.revalidate_finding(f, http_call=_never_http))
    assert v["verdict"] == "confirmed" and v["confidence"] == "medium"
    assert v["remediation_state"] == "open"
    decisions = {d["endpoint"]: d["decision"] for d in v["endpoint_decisions"]}
    assert decisions[EXPOSED[0]] == "open" and decisions[EXPOSED[1]] == "gone"


def test_mixed_application_claim_hands_reachable_routes_to_retest(monkeypatch):
    urls = [f"{APP}/api/cart/apply-coupon", f"{APP}/api/cart", "https://old.example.com/cart",
            "https://old2.example.com/cart"]
    _mixed(monkeypatch, {urls[0]})
    f = {"title": "Coupon stacking", "detected_by": "auto_discovery", "source_kind": "web",
         "description": "\n".join(urls), "metadata": {"vulnerability_class": "business_logic"}}
    v = asyncio.run(svc.revalidate_finding(f, http_call=_never_http))
    assert v["verdict"] == "needs_more_evidence" and v["prowl_retest"] is True
    assert v["retest_urls"] == [urls[0]]
    assert {d["decision"] for d in v["endpoint_decisions"]} == {"retest", "gone"}


def test_agent_reachable_endpoints_are_handed_to_retest(monkeypatch):
    _mixed(monkeypatch, {f"{APP}/api/cart/apply-coupon"})
    v = asyncio.run(svc.revalidate_finding({**LOGIC, "steps_to_reproduce": ""}, http_call=_never_http))
    assert v["verdict"] == "needs_more_evidence"
    assert v["retest_urls"] == [f"{APP}/api/cart/apply-coupon"]


# ── (4) missing tooling ────────────────────────────────────────────────────────

def _nuclei(monkeypatch, *, installed=True, fires=True, crash=False):
    monkeypatch.setattr(nuclei_service.NucleiService, "check_installation", lambda self: installed)

    async def scan(self, **kw):
        if crash:
            raise RuntimeError("nuclei crashed")
        return type("S", (), {"findings": [{"x": 1}] if fires else []})()
    monkeypatch.setattr(nuclei_service.NucleiService, "scan_targets", scan)


def _nmap(monkeypatch, state=None):
    def run(*a, **k):
        if state is None:
            raise FileNotFoundError("nmap")
        return type("R", (), {"returncode": 0, "stderr": "", "stdout": (
            f'<nmaprun><host><ports><port protocol="tcp" portid="6379">'
            f'<state state="{state}" /></port></ports></host></nmaprun>')})()
    monkeypatch.setattr(svc.subprocess, "run", run)


TEMPLATE = {"id": 3, "title": "Apache Struts banner", "template_id": "struts-detect",
            "target": f"{APP}/", "severity": "medium", "detected_by": "nuclei", "source_kind": "web"}
NETWORK = {"id": 4, "title": "Open port 6379", "detected_by": "port_scanner",
           "source_kind": "network_service", "asset": "203.0.113.10",
           "target": "203.0.113.10:6379", "severity": "medium",
           "metadata": {"port": 6379, "protocol": "tcp", "scanned_ip": "203.0.113.10"}}


def test_nuclei_missing_is_tool_unavailable(monkeypatch):
    _nuclei(monkeypatch, installed=False)
    v = asyncio.run(svc.revalidate_finding(TEMPLATE))
    assert v["verdict"] == "needs_more_evidence" and v["error"] == "tool_unavailable:nuclei"
    assert not v.get("native_verifier")


def test_nuclei_inline_yaml_not_installed_is_tool_unavailable(monkeypatch):
    from app.services import custom_template_ai

    async def recheck(*a, **k):
        return {"ran": False, "still_fires": None, "match_count": 0, "error": "nuclei_not_installed"}
    monkeypatch.setattr(custom_template_ai, "recheck_template_against_target", recheck)
    v = asyncio.run(svc._revalidate_nuclei({**TEMPLATE, "template_yaml": "id: x"}))
    assert v["error"] == "tool_unavailable:nuclei"


def test_nuclei_crash_is_tool_failed_not_a_result(monkeypatch):
    _nuclei(monkeypatch, crash=True)
    v = asyncio.run(svc.revalidate_finding(TEMPLATE))
    assert v["verdict"] == "needs_more_evidence" and v["error"] == "tool_failed:nuclei"


def test_nmap_missing_is_tool_unavailable(monkeypatch):
    _nmap(monkeypatch, None)
    v = asyncio.run(svc.revalidate_finding(NETWORK, service_probe=lambda *a: {}))
    assert v["verdict"] == "needs_more_evidence" and v["error"] == "tool_unavailable:nmap"
    assert "not installed" in v["reasoning"] and not v.get("native_verifier")


def test_tool_unavailable_is_not_owned_and_escalates_explicitly():
    calls = []
    native = {"verdict": "needs_more_evidence", "error": "tool_unavailable:nuclei",
              "native_verifier": "template"}

    async def run_native():
        calls.append("native")
        return dict(native)

    async def run_prowl():
        calls.append("prowl")
        return None

    async def run_vanguard(kind):
        calls.append("vanguard")
        return {"verdict": "confirmed", "method": "vanguard"}
    v = asyncio.run(route_finding_validation(
        "auto", run_native=run_native, run_prowl=run_prowl, run_vanguard=run_vanguard,
        prowl_enabled=True, vanguard_fallback="docker"))
    assert calls == ["native", "prowl", "vanguard"] and v["method"] == "vanguard"
    calls.clear()
    v = asyncio.run(route_finding_validation(
        "auto", run_native=run_native, run_prowl=run_prowl, run_vanguard=run_vanguard,
        prowl_enabled=True, vanguard_fallback=None))
    assert calls == ["native", "prowl"] and v["error"] == "tool_unavailable:nuclei"


def test_tool_availability_logged_once(monkeypatch, caplog):
    import shutil
    monkeypatch.setattr(nv, "_tools_logged", False)
    monkeypatch.setattr(shutil, "which", lambda t: None if t == "nmap" else f"/usr/bin/{t}")
    with caplog.at_level("WARNING", logger=nv.logger.name):
        assert nv.log_tool_availability() == ["nmap"]
        assert nv.log_tool_availability() == ["nmap"]
    assert sum("not on PATH" in r.message for r in caplog.records) == 1


# ── mode-level outcome: finding kinds × availability, Vanguard unavailable ─────

SECRET_URL = "https://cdn.example.com/static/app.js"


def _secret_finding():
    from app.services.secret_safety import secret_descriptor
    return {"id": 5, "title": "JavaScript Secret: aws key", "severity": "high",
            "detected_by": "js_secret_scan", "source_kind": "secret", "template_id": "js-secret",
            "target": "cdn.example.com",
            "metadata": {"source_url": SECRET_URL,
                         "fingerprint": secret_descriptor("AKIAZZZZEXAMPLE7777Q")["fingerprint"]}}


MANUAL_CURL = {"id": 6, "title": "Stored XSS in profile", "severity": "high", "detected_by": "manual",
               "source_kind": "manual", "is_manual": True, "target": f"{APP}/profile",
               "asset": "app.example.com",
               "steps_to_reproduce": (f"curl '{APP}/profile?id=7'\n"
                                      "Expected: response contains \"<script>alert(1)</script>\"")}
IDOR = {**LOGIC, "id": 8, "title": "IDOR on /api/orders/{id}", "description": "B reads A's order",
        "target": f"{APP}/api/orders/1002"}
EXPOSURE_MIXED = {"id": 9, "title": "Exposed .git directories", "detected_by": "auto_discovery",
                  "source_kind": "web", "description": "\n".join(EXPOSED), "severity": "medium"}
APP_MIXED = {"id": 10, "title": "Coupon stacking", "detected_by": "auto_discovery",
             "source_kind": "web", "metadata": {"vulnerability_class": "business_logic"},
             "description": f"{APP}/api/cart/apply-coupon\nhttps://old.example.com/cart\n"
                            "https://old2.example.com/cart\nhttps://old3.example.com/cart"}
NUCLEI_XSS = {**TEMPLATE, "id": 11, "title": "Reflected XSS in q", "target": f"{APP}/search?q=1"}

# (case, finding, tools, llm, prowl_enabled, expected method, expected verdict)
MATRIX = [
    ("template", TEMPLATE, "ok", None, True, "nuclei_template_replay", "confirmed"),
    ("template", TEMPLATE, "missing", None, True, "nuclei_template_replay", "needs_more_evidence"),
    ("template-provable", NUCLEI_XSS, "missing", None, True, "prowl_independent_verify", "confirmed"),
    ("network", NETWORK, "ok", None, True, "nmap_port_verify", "confirmed"),
    ("network", NETWORK, "missing", None, True, "nmap_port_verify", "needs_more_evidence"),
    ("secret", _secret_finding(), "ok", None, True, "secret_fingerprint_recheck", "false_positive"),
    ("manual-curl", MANUAL_CURL, "ok", None, True, "manual_request_replay", "confirmed"),
    ("manual-prose", _prose(), "ok", GOOD_EXTRACTION, True, "manual_request_replay", "confirmed"),
    ("manual-prose-no-observable", _prose(), "ok",
     {"requests": [{"method": "GET", "url": "/billing/invoice/1002"}]}, True,
     "prowl_retest", "false_positive"),
    ("manual-prose-llm-down", _prose(), "ok", RuntimeError("down"), True,
     "prowl_retest", "false_positive"),
    ("manual-prose-llm-down", _prose(), "ok", RuntimeError("down"), False,
     "steps_replay", "needs_more_evidence"),
    ("agent-provable", IDOR, "ok", None, True, "prowl_independent_verify", "confirmed"),
    ("agent-no-proof-kind", LOGIC, "ok", None, True, "prowl_retest", "false_positive"),
    ("agent-no-proof-kind", LOGIC, "ok", None, False, "agent_steps_replay", "needs_more_evidence"),
    ("generic-mixed-exposure", EXPOSURE_MIXED, "ok", None, True, "steps_and_http_replay", "confirmed"),
    ("generic-mixed-app", APP_MIXED, "ok", None, True, "prowl_retest", "false_positive"),
]


@pytest.mark.parametrize("case, finding, tools, llm, prowl_enabled, method, verdict", MATRIX,
                         ids=[f"{m[0]}-tools_{m[2]}-llm_{'none' if m[3] is None else ('fail' if isinstance(m[3], Exception) else 'ok')}-prowl_{'on' if m[4] else 'off'}"
                              for m in MATRIX])
def test_every_finding_kind_ends_native_or_prowl_without_vanguard(
        monkeypatch, case, finding, tools, llm, prowl_enabled, method, verdict):
    _nuclei(monkeypatch, installed=tools == "ok", fires=True)
    _nmap(monkeypatch, "open" if tools == "ok" else None)
    _mixed(monkeypatch, {EXPOSED[0], f"{APP}/api/cart/apply-coupon", f"{APP}/billing",
                         f"{APP}/api/orders/1002"})
    _fake_orchestrator(monkeypatch, retest_status="refuted")
    http = _http({f"{APP}/profile?id=7": (200, "<script>alert(1)</script>"),
                  f"{APP}/billing/invoice/1002": (200, "Invoice for Bob Smith"),
                  SECRET_URL: (404, "")})
    native_holder = {}
    calls = []

    async def run_native():
        calls.append("native")
        native_holder["v"] = await svc.revalidate_finding(
            dict(finding), http_call=http, service_probe=lambda *a: {"name": "redis"},
            llm_call=_llm(llm) if llm is not None else _llm(RuntimeError("no llm")))
        return native_holder["v"]

    async def run_prowl():
        calls.append("prowl")
        return await pr.revalidate_with_prowl(dict(finding), organization_id=5, user_id=9,
                                              native_verdict=native_holder.get("v"))

    async def run_vanguard(kind):
        raise AssertionError("Vanguard must not be needed")

    v = asyncio.run(route_finding_validation(
        "auto", run_native=run_native, run_prowl=run_prowl, run_vanguard=run_vanguard,
        prowl_enabled=prowl_enabled, vanguard_fallback=None))
    v = nv.finalize_verdict(v, finding)
    assert (v["method"], v["verdict"]) == (method, verdict), (case, v.get("reasoning"))
    assert v["remediation_state"] in nv.REMEDIATION_STATES
    if tools == "missing" and method in ("nuclei_template_replay", "nmap_port_verify"):
        assert v["error"].startswith("tool_unavailable:")
    if v["method"].startswith("prowl"):
        assert "native_verdict" in v
    if v["method"] == "prowl_retest":
        assert v["verdict"] != "confirmed"
