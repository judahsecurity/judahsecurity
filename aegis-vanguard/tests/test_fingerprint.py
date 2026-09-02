"""Passive HTTP fingerprinting → targeting. Infer stack from captured responses,
map to the vuln classes worth prioritising."""

import json
import os
import unittest
from pathlib import Path

from agent.fingerprint import fingerprint_response, fingerprint_transactions


class ResponseFingerprintTest(unittest.TestCase):
    def test_powered_by_header_with_version_is_high(self):
        sigs = fingerprint_response(200, {"X-Powered-By": "PHP/7.4.33"}, "")
        php = [s for s in sigs if "PHP" in s["tech"]]
        self.assertTrue(php and php[0]["confidence"] == "high")

    def test_cookie_reveals_framework(self):
        sigs = fingerprint_response(200, {"Set-Cookie": "JSESSIONID=abc; Path=/"}, "")
        self.assertTrue(any(s["tech"] == "Java servlet" for s in sigs))

    def test_server_banner(self):
        sigs = fingerprint_response(200, {"Server": "nginx/1.25.1"}, "")
        self.assertTrue(any(s["tech"] == "nginx" for s in sigs))

    def test_spring_boot_error_shape(self):
        body = '{"timestamp":"2026-01-01","status":500,"error":"Internal","path":"/api/x"}'
        sigs = fingerprint_response(500, {"Content-Type": "application/json"}, body)
        self.assertTrue(any("Spring Boot" in s["tech"] for s in sigs))

    def test_api_gateway_header(self):
        sigs = fingerprint_response(200, {"x-amzn-RequestId": "abc-123"}, "")
        self.assertTrue(any(s["category"] == "api_gateway" for s in sigs))


class TargetingTest(unittest.TestCase):
    class _T:
        def __init__(self, url, status, headers, body=""):
            self.request = type("R", (), {"url": url})()
            self.response = type("P", (), {"status": status, "headers": headers, "body": body})()

    def test_php_stack_recommends_injection_focus(self):
        txns = [self._T("http://app/x", 200, {"X-Powered-By": "PHP/8.1", "Set-Cookie": "PHPSESSID=1"})]
        rep = fingerprint_transactions(txns)
        self.assertIn("app", rep["hosts"])
        foci = {f["stack"] for f in rep["recommended_focus"]}
        self.assertIn("php", foci)
        php_focus = next(f for f in rep["recommended_focus"] if f["stack"] == "php")
        self.assertEqual(php_focus["hunter"], "injection")

    def test_spring_stack_recommends_ssrf_focus(self):
        body = '{"timestamp":"t","status":500,"error":"e","path":"/p"}'
        txns = [self._T("http://api/x", 500, {"Content-Type": "application/json"}, body)]
        rep = fingerprint_transactions(txns)
        self.assertTrue(any(f["hunter"] == "ssrf" for f in rep["recommended_focus"]))

    def test_no_signals_no_focus(self):
        txns = [self._T("http://x/", 200, {"Content-Type": "text/html"}, "<h1>hi</h1>")]
        rep = fingerprint_transactions(txns)
        self.assertEqual(rep["recommended_focus"], [])


class ToolWiringTest(unittest.TestCase):
    def setUp(self):
        from agent.http_session import reset_session, set_session_store, SessionStore, HttpRequest, HttpResponse
        reset_session()
        store = set_session_store(SessionStore())
        store.record(HttpRequest("GET", "http://app/", {}, ""),
                     HttpResponse(200, {"X-Powered-By": "Express"}, "Cannot GET /x"))

    def tearDown(self):
        from agent.http_session import reset_session
        reset_session()

    def test_fingerprint_stack_tool(self):
        from agent import agents
        out = json.loads(agents.fingerprint_stack())
        self.assertTrue(any(f["stack"] in ("express", "node") for f in out["recommended_focus"]))


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    unittest.main()
