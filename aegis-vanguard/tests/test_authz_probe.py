"""Authz probe — multi-identity IDOR/BOLA verdicts, compare primitive, tools."""

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_OBJECT = json.dumps({"id": 42, "owner": "alice", "ssn": "111-22-3333", "balance": 9000})


class AuthzVerdictTest(unittest.TestCase):
    def _r(self, status, body):
        return {"status": status, "body": body, "headers": {}}

    def test_idor_cross_identity(self):
        from agent.authz_probe import _authz_verdict
        v = _authz_verdict(self._r(200, _OBJECT), self._r(200, _OBJECT), None)
        self.assertEqual(v["finding"], "idor")

    def test_other_identity_denied_is_clean(self):
        from agent.authz_probe import _authz_verdict
        v = _authz_verdict(self._r(200, _OBJECT), self._r(403, "Forbidden"), None)
        self.assertIsNone(v["finding"])

    def test_other_identity_own_object_is_clean(self):
        from agent.authz_probe import _authz_verdict
        other = json.dumps({"id": 7, "owner": "bob", "ssn": "999-88-7777", "balance": 3})
        v = _authz_verdict(self._r(200, _OBJECT), self._r(200, other), None)
        self.assertIsNone(v["finding"])  # different body → their own object

    def test_unauthenticated_access(self):
        from agent.authz_probe import _authz_verdict
        v = _authz_verdict(self._r(200, _OBJECT), None, self._r(200, _OBJECT))
        self.assertEqual(v["finding"], "broken_access_control")

    def test_inconclusive_owner_baseline(self):
        from agent.authz_probe import _authz_verdict
        v = _authz_verdict(self._r(404, "nope"), self._r(200, _OBJECT), None)
        self.assertIsNone(v["finding"])  # no real owner object → inconclusive


class AuthzDriverTest(unittest.TestCase):
    def test_authz_diff_flags_idor(self):
        from agent.authz_probe import run_authz_diff
        def fetch(method, url, headers, body):
            # every identity gets the same object → BOLA
            return {"status": 200, "body": _OBJECT, "headers": {}}
        res = run_authz_diff("https://t/api/accounts/42",
                             owner_headers_json='{"Cookie":"s=alice"}',
                             other_headers_json='{"Cookie":"s=bob"}',
                             fetch=fetch)
        self.assertTrue(res["candidates"])
        self.assertIn(res["candidates"][0]["vuln_type"], ("idor", "broken_access_control"))

    def test_authz_diff_clean_when_protected(self):
        from agent.authz_probe import run_authz_diff
        def fetch(method, url, headers, body):
            if headers.get("Cookie") == "s=alice":
                return {"status": 200, "body": _OBJECT, "headers": {}}
            return {"status": 403, "body": "Forbidden", "headers": {}}
        res = run_authz_diff("https://t/api/accounts/42",
                             owner_headers_json='{"Cookie":"s=alice"}',
                             other_headers_json='{"Cookie":"s=bob"}',
                             fetch=fetch)
        self.assertEqual(res["candidates"], [])

    def test_compare_requests_detects_status_change(self):
        from agent.authz_probe import run_compare_requests
        def fetch(method, url, headers, body):
            if headers.get("X-Tenant-Id") == "b":
                return {"status": 200, "body": "tenant B data", "headers": {}}
            return {"status": 403, "body": "denied", "headers": {}}
        res = run_compare_requests("https://t/api/data",
                                   headers_a_json='{"X-Tenant-Id":"a"}',
                                   headers_b_json='{"X-Tenant-Id":"b"}',
                                   fetch=fetch)
        self.assertFalse(res["same_status"])
        self.assertIn("status changed", res["verdict_hint"])

    def test_tools_registered_and_in_authz_pack(self):
        import agent.agents  # noqa: F401
        from agent.tools import ToolRegistry
        from agent.owasp_hunters import AUTHZ_TOOLS
        reg = ToolRegistry()
        self.assertIsNotNone(reg.get("authz_diff"))
        self.assertIsNotNone(reg.get("compare_requests"))
        self.assertIn("authz_diff", AUTHZ_TOOLS)
        self.assertIn("compare_requests", AUTHZ_TOOLS)


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    unittest.main()
