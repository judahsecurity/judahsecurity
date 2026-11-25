"""CSP-blocked XSS: signal detection (unit) and a real Chromium check (opt-in)."""

import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from app.services.agent.evidence_store import EvidenceStore, VerificationRun, verification_run
from app.services.agent.finding_gate import cap_proof_kind_severity
from app.services.agent.proof_policy import validate_proof
from app.services.agent.scoped_assessment.browser import csp_blocked_signal

NONCE = "a1b2c3d4e5f60718"
INLINE = {"tag": "img", "attr": "onerror", "inline": True}
BLOCKED = [{"directive": "script-src-attr", "blocked": "inline", "sample": "", "disposition": "enforce"}]


def test_signal_needs_injection_and_a_new_block():
    assert csp_blocked_signal(nonce=NONCE, executed=False, injected=INLINE,
                              violations=BLOCKED, baseline_violations=[])["csp_blocked"] is True
    # Same inline violation already happens without the payload: not tied to it.
    assert csp_blocked_signal(nonce=NONCE, executed=False, injected=INLINE,
                              violations=BLOCKED, baseline_violations=BLOCKED)["csp_blocked"] is False
    # No injected element: a blocked script elsewhere on the page proves nothing.
    assert csp_blocked_signal(nonce=NONCE, executed=False, injected=None,
                              violations=BLOCKED, baseline_violations=[])["csp_blocked"] is False
    # Executed means it was not blocked.
    assert csp_blocked_signal(nonce=NONCE, executed=True, injected=INLINE,
                              violations=BLOCKED, baseline_violations=[])["csp_blocked"] is False
    # A report-only policy does not block.
    report_only = [{**BLOCKED[0], "disposition": "report"}]
    assert csp_blocked_signal(nonce=NONCE, executed=False, injected=INLINE,
                              violations=report_only, baseline_violations=[])["csp_blocked"] is False
    # An external script tied by its blocked URI works without the baseline delta.
    external = {"tag": "script", "attr": "src", "inline": False}
    named = [{"directive": "script-src-elem", "blocked": f"https://evil.test/{NONCE}.js",
              "sample": "", "disposition": "enforce"}]
    out = csp_blocked_signal(nonce=NONCE, executed=False, injected=external,
                             violations=named, baseline_violations=named)
    assert out["csp_blocked"] is True and out["csp_violation_names_nonce"] is True


def _receipt(store, nonce, *, csp_blocked=True, attr="onerror"):
    return store.record("scoped_browser_check_xss", {
        "operation": "check_xss", "target_template": "https://app.example.com/s?q=__PROWL_NONCE__",
        "nonce": nonce, "executed": False, "csp_blocked": csp_blocked,
        "csp_violation_names_nonce": False, "csp_inline_violation_delta": 1,
        "injected_element": {"tag": "img", "attr": attr, "inline": True},
    }, target="https://app.example.com/s", success=csp_blocked)


def _pair(**verifier_kwargs):
    store = EvidenceStore()
    hunter = _receipt(store, "1111111111111111")
    candidate = SimpleNamespace(id="c1", revision=1, nonce="n", title="Reflected XSS on search",
                                description="", vulnerability_class="xss",
                                target="https://app.example.com/s", evidence_ids=[hunter])
    token = verification_run.set(VerificationRun("v1", "c1", 1, "n"))
    try:
        verifier = _receipt(store, "2222222222222222", **verifier_kwargs)
    finally:
        verification_run.reset(token)
    proof = {"kind": "scoped_browser_xss_csp_blocked", "hunter_artifact_id": hunter, "artifact_id": verifier}
    return store, candidate, proof, verifier


def test_csp_blocked_proof_and_cap():
    store, candidate, proof, verifier = _pair()
    assert validate_proof(store, candidate, proof, [verifier]) == (True, "")
    ok, _ = store.validate([verifier], candidate_id="c1", revision=1, run_id="v1",
                           target="https://app.example.com/s")
    assert ok
    assert cap_proof_kind_severity("high", "scoped_browser_xss_csp_blocked") == ("medium", True)
    assert cap_proof_kind_severity("high", "scoped_browser_xss") == ("high", False)


def test_csp_blocked_proof_rejections():
    store, candidate, proof, verifier = _pair(csp_blocked=False)
    assert validate_proof(store, candidate, proof, [verifier])[0] is False
    store, candidate, proof, verifier = _pair(attr="onload")
    assert validate_proof(store, candidate, proof, [verifier])[0] is False
    # A CSP-blocked receipt cannot pass as a full browser execution.
    store, candidate, proof, verifier = _pair()
    assert validate_proof(store, candidate, {**proof, "kind": "scoped_browser_xss"}, [verifier])[0] is False


def _server(csp_header):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            q = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
            body = f"<html><body><h1>Results for {q}</h1></body></html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            if csp_header:
                self.send_header(*csp_header)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.mark.skipif(os.environ.get("RUN_ASSESSMENT_BROWSER_TESTS") != "1",
                    reason="Opt-in local Chromium fixture")
@pytest.mark.asyncio
@pytest.mark.parametrize("header,executed,blocked", [
    (("Content-Security-Policy", "script-src 'self'"), False, True),
    (("Content-Security-Policy-Report-Only", "script-src 'self'"), True, False),
    (None, True, False),
])
async def test_real_browser_csp_detection(header, executed, blocked):
    from app.services.agent.scoped_assessment.browser import check_browser

    server = _server(header)
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        result, _ = await check_browser(
            operation="check_xss",
            url=base + "/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(%27__PROWL_NONCE__%27)%3E",
            allowed_origins=[base],
        )
    finally:
        server.shutdown()
        server.server_close()
    assert result["executed"] is executed
    assert result["csp_blocked"] is blocked
    if blocked:
        assert result["injected_element"]["attr"] == "onerror"
        assert result["csp_inline_violation_delta"] >= 1
        assert result["csp_header_present"] is True


def test_baseline_url_drops_the_whole_payload():
    from app.services.agent.scoped_assessment.browser import csp_baseline_url

    url = "https://app.example.com/s?q=%3Cimg+onerror%3Dalert('__PROWL_NONCE__')%3E&page=2#x"
    assert csp_baseline_url(url) == "https://app.example.com/s?q=aegiscspbaseline&page=2#x"
    assert csp_baseline_url("https://a.test/p#<svg onload=__PROWL_NONCE__>") == \
        "https://a.test/p#aegiscspbaseline"
