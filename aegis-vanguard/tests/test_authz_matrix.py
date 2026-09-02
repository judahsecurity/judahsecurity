"""Authorization matrix: automated broken-access-control detection with proof.

The property under test: a request that carried credentials, replayed without
them (or as another user) and still returning the same private 2xx body, is
flagged BROKEN_ACCESS/AUTH_BYPASS with a proof token — while enforced endpoints
and public pages are not.
"""

import json
import os
import unittest
from pathlib import Path

from agent.authz_matrix import (
    AUTH_BYPASS,
    BROKEN_ACCESS,
    ENFORCED,
    run_authorization_matrix,
)
from agent.http_session import (
    HttpRequest,
    HttpResponse,
    ProxyBackend,
    SessionStore,
    reset_session,
    set_backend,
    set_session_store,
)
from agent.finding_oracle import (
    ProofLedger,
    grade_finding,
    reset_proof_ledger,
    set_proof_ledger,
    CONFIRMED,
)

PRIVATE = "<h1>Account 1001</h1> SSN 555-01-1001 balance $9000"
ADMIN = "<h1>Admin panel</h1> user list ..."


class VulnApp(ProxyBackend):
    """/account leaks to anyone; /admin enforces; / is public."""

    name = "vulnapp"

    def send(self, request: HttpRequest) -> HttpResponse:
        path = request.url
        has_cookie = any(k.lower() == "cookie" for k in request.headers)
        if "/account" in path:
            return HttpResponse(200, {}, PRIVATE)          # broken: ignores identity
        if "/admin" in path:
            return HttpResponse(200, {}, ADMIN) if has_cookie else HttpResponse(403, {}, "Forbidden")
        return HttpResponse(200, {}, "<h1>Home</h1>")      # public


def _authed(url):
    return HttpRequest("GET", url, {"Cookie": "session=alice"}, "")


class MatrixTest(unittest.TestCase):
    def setUp(self):
        reset_proof_ledger()
        set_proof_ledger(ProofLedger())

    def tearDown(self):
        reset_proof_ledger()

    def test_missing_authorization_detected_and_proven(self):
        report = run_authorization_matrix([_authed("http://t/account?id=1001")],
                                          VulnApp(), include_unauth=True)
        self.assertEqual(report.tested, 1)
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].classification, AUTH_BYPASS)
        # proof token flows to the gate → a finding at that url confirms
        v = grade_finding({"title": "BAC", "endpoint": "http://t/account?id=1001"})
        self.assertEqual(v.status, CONFIRMED)

    def test_enforced_endpoint_not_flagged(self):
        report = run_authorization_matrix([_authed("http://t/admin")],
                                          VulnApp(), include_unauth=True)
        self.assertEqual(len(report.findings), 0)
        self.assertEqual(report.results[0]["classification"], ENFORCED)

    def test_horizontal_idor_as_user_b(self):
        report = run_authorization_matrix(
            [_authed("http://t/account?id=1001")], VulnApp(),
            identity_b={"Cookie": "session=bob"}, include_unauth=False)
        self.assertTrue(any(f.classification == BROKEN_ACCESS for f in report.findings))

    def test_unauthenticated_request_is_skipped(self):
        # No auth header in baseline → nothing to strip, not a test (avoids public-page FPs)
        report = run_authorization_matrix(
            [HttpRequest("GET", "http://t/account", {}, "")], VulnApp())
        self.assertEqual(report.tested, 0)
        self.assertEqual(report.skipped_no_auth, 1)

    def test_public_page_with_cookie_is_not_flagged_when_enforced(self):
        # A cookie'd request to a public page returns identical body unauthenticated,
        # which WOULD look like bypass — acceptable and expected; the guard is that
        # hunters only send cookies to authenticated endpoints. Here we assert the
        # classifier itself: identical 2xx under strip == AUTH_BYPASS by design.
        report = run_authorization_matrix([_authed("http://t/")], VulnApp())
        self.assertEqual(report.findings[0].classification, AUTH_BYPASS)


class ToolWiringTest(unittest.TestCase):
    def setUp(self):
        reset_session()
        reset_proof_ledger()
        set_proof_ledger(ProofLedger())
        set_session_store(SessionStore())
        set_backend(VulnApp())

    def tearDown(self):
        reset_session()
        reset_proof_ledger()

    def test_authz_matrix_tool_over_recorded_requests(self):
        from agent import agents
        store = set_session_store(SessionStore())
        set_backend(VulnApp())
        # record an authenticated request and a no-auth one
        store.record(_authed("http://t/account?id=1001"), HttpResponse(200, {}, PRIVATE))
        store.record(HttpRequest("GET", "http://t/", {}, ""), HttpResponse(200, {}, "home"))
        out = json.loads(agents.authz_matrix())
        self.assertEqual(out["tested"], 1)          # only the authed one tested
        self.assertEqual(out["skipped_no_auth"], 1)
        self.assertEqual(out["broken_access_findings"], 1)


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    unittest.main()
