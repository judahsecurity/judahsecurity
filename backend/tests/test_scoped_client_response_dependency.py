"""Assigned client, response, and dependency reviews keep evidence scoped."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlsplit

import httpx
import pytest

from app.services.agent.assessment_scope import register_scope
from app.services.agent.coverage_cells import (
    claim_coverage_cell_leases, seed_js_coverage_cells, seed_parameter_coverage_cells,
)
from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.evidence_store import evidence_store
from app.services.agent.independent_verify import run_independent_verifiers, submit_candidate
from app.services.agent.scoped_assessment.response_probe import probe_response
from app.services.agent.tools import ASMToolsManager
from app.services.retirejs_service import _fetch_url


TARGET = "https://app.example.test"


def _manager(brain):
    manager = ASMToolsManager()
    manager._fallback_target = TARGET
    manager._capability_map = {"target": TARGET, "scope": TARGET}
    manager._engagement_brain = brain.to_dict()
    register_scope(manager, "app.example.test")
    return manager


@pytest.mark.asyncio
async def test_client_template_probe_needs_observed_page_and_leased_source(monkeypatch):
    brain = EngagementBrain(target=TARGET)
    seed_js_coverage_cells(brain, {"target": TARGET,
        "js_sources": [{"url": TARGET + "/static/blog.js", "kind": "external",
            "page_paths": ["/blog"], "source_leads": [{"kind": "fragment", "line": 1}],
            "client_leads": [{"kind": "client_template_injection", "line": 2}]}]})
    lease = claim_coverage_cell_leases(
        brain, ["spa_client"],
        allowed_test_types=frozenset({"client_template_injection"}),
    )["spa_client"]
    manager = _manager(brain)
    calls = []

    async def browser(operation, url, **kwargs):
        calls.append((operation, url, kwargs))
        assert operation == "check_client"
        assert kwargs["client_test_type"] == "client_template_injection"
        proof = {"operation": operation, "behavior_observed": True,
                 "observations": {"template_evaluated": True}}
        evidence_id = evidence_store(manager).record(
            "scoped_browser_check_client", proof, target=TARGET + "/blog",
            identity="anonymous", success=True)
        return json.dumps({**proof, "evidence_id": evidence_id})

    monkeypatch.setattr(manager, "scoped_browser_assessment", browser)
    assert (await manager.scoped_client_probe_assigned(
        lease.coverage_cell_id, "wrong"))["error"] == "invalid_client_lease"
    result = await manager.scoped_client_probe_assigned(lease.coverage_cell_id, lease.id)
    assert result["behavior_observed"] is True
    assert result["proof_confirmed"] is False
    assert calls[0][1] == TARGET + "/blog#{{7*7}}__PROWL_NONCE__"


@pytest.mark.asyncio
async def test_response_probe_preserves_observed_query_and_checks_header(monkeypatch):
    brain = EngagementBrain(target=TARGET)
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "path": "/catalog", "host": "app.example.test",
        "name": "searchTerm", "location": "query", "source": "browser_link",
        "identity": "anonymous", "testable": True,
    }])
    lease = claim_coverage_cell_leases(
        brain, ["injection"], allowed_test_types=frozenset({"crlf"}),
    )["injection"]
    manager = _manager(brain)
    manager._scoped_link_baselines = {
        "anonymous": [TARGET + "/catalog?category=Gifts&searchTerm=seed"],
    }
    calls = []

    def fake_probe(control, probe, **kwargs):
        calls.append((control, probe, kwargs))
        return {"operation": "scoped_response_probe", "test_type": "crlf",
                "requests_sent": 2, "control": {"header_marker": False},
                "probe": {"header_marker": True}, "proof_confirmed": True,
                "finding": False}

    monkeypatch.setattr(
        "app.services.agent.scoped_assessment.response_probe.probe_response", fake_probe,
    )
    result = await manager.scoped_response_probe_assigned(lease.coverage_cell_id, lease.id)
    assert result["proof_confirmed"] is True
    assert len(calls) == 1
    assert "category=Gifts" in calls[0][0] and "category=Gifts" in calls[0][1]
    assert "%250D%250A" in calls[0][0] and "%0D%0A" in calls[0][1]
    assert calls[0][2]["test_type"] == "crlf"


def test_response_probe_requires_differential_marker(monkeypatch):
    from app.services.agent.scoped_assessment import response_probe as module

    def fake_headers(url, **_kwargs):
        return {"status": 302, "header_marker": False,
                "redirect_canary": "probe" in url, "location_present": True}

    monkeypatch.setattr(module, "_headers", fake_headers)
    proof = probe_response("https://app.test/control", "https://app.test/probe",
                           test_type="open_redirect", allowed_origin="https://app.test",
                           state=None, nonce="n1")
    assert proof["proof_confirmed"] is True and proof["requests_sent"] == 2


def test_response_transport_reads_only_header_and_does_not_follow_redirect():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            value = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
            if value.startswith("https://prowl.invalid/"):
                self.send_response(302)
                self.send_header("Location", value)
            else:
                self.send_response(200)
                if value.startswith("\r\nX-Prowl-Probe: "):
                    self.send_header("X-Prowl-Probe", value.split(": ", 1)[1])
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        nonce = "probe123"
        header = probe_response(
            base + "/search?q=" + quote("%0D%0AX-Prowl-Probe: " + nonce),
            base + "/search?q=" + quote("\r\nX-Prowl-Probe: " + nonce),
            test_type="crlf", allowed_origin=base, state=None, nonce=nonce,
        )
        assert header["proof_confirmed"] is True
        redirect = probe_response(
            base + "/search?q=" + quote(base + "/safe"),
            base + "/search?q=" + quote("https://prowl.invalid/" + nonce),
            test_type="open_redirect", allowed_origin=base, state=None, nonce=nonce,
        )
        assert redirect["proof_confirmed"] is True
        assert redirect["probe"]["status"] == 302
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_dependency_review_matches_captured_bytes_and_keeps_cve_a_lead(monkeypatch):
    brain = EngagementBrain(target=TARGET)
    script = TARGET + "/resources/js/angular_1-7-7.js"
    seed_js_coverage_cells(brain, {"target": TARGET, "js_files": [script],
        "js_sources": [{"url": script, "sha256": "abc", "artifact_id": "script-a"}]})
    lease = claim_coverage_cell_leases(
        brain, ["spa_client"], allowed_test_types=frozenset({"js_dependency_review"}),
    )["spa_client"]
    manager = _manager(brain)
    monkeypatch.setattr(
        "app.services.retirejs_service.scan_js_urls_for_vulns",
        lambda url, max_urls, *, same_origin_only: {
            "success": True, "downloads": [{"url": url, "ok": True, "sha256": "abc"}],
            "retire_error": None,
            "vulnerable_components": [{"source_url": url, "component": "angularjs",
                                       "version": "1.7.7", "severity": "high",
                                       "cve": "CVE-example"}],
        },
    )
    result = json.loads(await manager.scan_assigned_js_dependency(
        lease.coverage_cell_id, lease.id))
    assert result["summary"]["status"] == "in_focus"
    assert result["summary"]["source_matched"] is True
    assert result["summary"]["proof_confirmed"] is False
    assert result["summary"]["candidates"][0]["component"] == "angularjs"


def test_retire_download_does_not_follow_cross_origin_redirect():
    transport = httpx.MockTransport(lambda _request: httpx.Response(
        302, headers={"Location": "http://127.0.0.1/private"},
    ))
    with httpx.Client(transport=transport) as client:
        data, error = _fetch_url(client, "https://app.test/script.js", 1024, 3)
    assert data is None and error == "HTTP 302"


@pytest.mark.asyncio
async def test_client_candidate_needs_fresh_independent_browser_replay(monkeypatch):
    brain = EngagementBrain(target=TARGET)
    seed_js_coverage_cells(brain, {"target": TARGET, "js_sources": [{
        "url": TARGET + "/blog.js", "kind": "external", "page_paths": ["/blog"],
        "source_leads": [{"kind": "fragment", "line": 1}],
        "client_leads": [{"kind": "client_template_injection", "line": 2}],
    }]})
    lease = claim_coverage_cell_leases(
        brain, ["spa_client"], allowed_test_types=frozenset({"client_template_injection"}),
    )["spa_client"]
    manager = _manager(brain)
    store = evidence_store(manager)
    template = TARGET + "/blog#{{7*7}}__PROWL_NONCE__"

    async def hunter_browser(_operation, _url, **_kwargs):
        payload = {"operation": "check_client", "client_test_type": "client_template_injection",
                   "target_template": template, "nonce": "hunter-nonce",
                   "behavior_observed": True,
                   "observations": {"initial_document_ok": True,
                                    "template_evaluated": True,
                                    "server_body_checked": True,
                                    "server_template_evaluated": False}}
        artifact_id = store.record("scoped_browser_check_client", payload,
                                   target=TARGET + "/blog", identity="anonymous")
        return json.dumps({**payload, "evidence_id": artifact_id})

    monkeypatch.setattr(manager, "scoped_browser_assessment", hunter_browser)
    result = await manager.scoped_client_probe_assigned(lease.coverage_cell_id, lease.id)
    from app.services.agent.engagement_brain import engagement_brain_from_dict

    active = engagement_brain_from_dict(manager._engagement_brain)
    candidate = submit_candidate(
        active, title="Client-side template injection in blog",
        target=TARGET + "/blog", vulnerability_class="client_template_injection",
        identity="anonymous", coverage_cell_id=lease.coverage_cell_id,
        evidence_ids=[result["evidence_id"]],
    )
    manager._engagement_brain = active.to_dict()

    async def verifier_execute(name, args):
        assert name == "scoped_browser_assessment"
        assert args["url"] == template and args["client_test_type"] == "client_template_injection"
        payload = {"operation": "check_client", "client_test_type": "client_template_injection",
                   "target_template": template, "nonce": "verifier-nonce",
                   "behavior_observed": True,
                   "observations": {"initial_document_ok": True,
                                    "template_evaluated": True,
                                    "server_body_checked": True,
                                    "server_template_evaluated": False}}
        artifact_id = store.record("scoped_browser_check_client", payload,
                                   target=TARGET + "/blog", identity="anonymous")
        return {"success": True, "output": json.dumps({**payload, "evidence_id": artifact_id})}

    manager.execute = verifier_execute
    reports = await run_independent_verifiers([candidate], llm=None,
        tools_manager=manager, targets=[TARGET + "/blog"])
    assert reports[0]["status"] == "confirmed", reports[0]["verifier_summary"]


@pytest.mark.asyncio
async def test_response_candidate_needs_fresh_independent_control(monkeypatch):
    brain = EngagementBrain(target=TARGET)
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "path": "/catalog", "host": "app.example.test",
        "name": "searchTerm", "location": "query", "source": "browser_link",
        "identity": "anonymous", "testable": True,
    }])
    lease = claim_coverage_cell_leases(
        brain, ["injection"], allowed_test_types=frozenset({"crlf"}),
    )["injection"]
    manager = _manager(brain)
    manager._scoped_link_baselines = {
        "anonymous": [TARGET + "/catalog?searchTerm=seed"],
    }
    monkeypatch.setattr(
        "app.services.agent.scoped_assessment.response_probe.probe_response",
        lambda *_args, **_kwargs: {
            "operation": "scoped_response_probe", "test_type": "crlf",
            "requests_sent": 2, "control": {"header_marker": False},
            "probe": {"header_marker": True}, "proof_confirmed": True,
            "finding": False,
        },
    )
    hunter = await manager.scoped_response_probe_assigned(lease.coverage_cell_id, lease.id)
    from app.services.agent.engagement_brain import engagement_brain_from_dict

    active = engagement_brain_from_dict(manager._engagement_brain)
    candidate = submit_candidate(
        active, title="CRLF response header injection in catalog",
        target=TARGET + "/catalog", vulnerability_class="crlf",
        identity="anonymous", coverage_cell_id=lease.coverage_cell_id,
        evidence_ids=[hunter["evidence_id"]],
    )
    manager._engagement_brain = active.to_dict()
    reports = await run_independent_verifiers([candidate], llm=None,
        tools_manager=manager, targets=[TARGET + "/catalog"])
    assert reports[0]["status"] == "confirmed", reports[0]["verifier_summary"]
