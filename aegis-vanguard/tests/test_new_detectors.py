"""New detectors — NoSQL, prototype pollution, stored XSS, JWT, GraphQL,
request smuggling, and exposed-VCS dump."""

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class NoSQLTest(unittest.TestCase):
    def test_bool_diff_hit(self):
        from agent.probes import _bool_diff_hit
        base = {"status": 200, "body": "welcome alice " * 20}
        true_r = {"status": 200, "body": "welcome alice " * 20}
        false_r = {"status": 401, "body": "denied"}
        self.assertTrue(_bool_diff_hit(base, true_r, false_r))
        self.assertFalse(_bool_diff_hit(base, base, base))  # no divergence

    def test_nosql_driver(self):
        from agent.probes import run_probe_nosql
        def fetch(m, url, h, b):
            # $ne (true) → data; $eq nonexistent (false) → empty/denied
            if "%24ne" in url or "$ne" in url or "1%27%3D%3D%271" in url or "1'=='1" in url:
                return {"status": 200, "body": "RECORDS " * 40}
            if "%24eq" in url or "$eq" in url or "1'=='2" in url or "1%27%3D%3D%272" in url:
                return {"status": 200, "body": "no records"}
            return {"status": 200, "body": "RECORDS " * 40}  # baseline
        res = run_probe_nosql("https://t/api?user=x", fetch=fetch)
        self.assertTrue(res["candidates"])
        self.assertEqual(res["candidates"][0]["vuln_type"], "nosql")


class ProtoPollutionTest(unittest.TestCase):
    def test_pp_hit_reflect_and_error(self):
        from agent.probes import _pp_hit
        self.assertIsNotNone(_pp_hit({"status": 200, "body": "x"},
                                     {"status": 200, "body": "polluted1337"}, "polluted1337"))
        self.assertIsNotNone(_pp_hit({"status": 200, "body": "ok"},
                                     {"status": 500, "body": "err"}, "polluted1337"))
        self.assertIsNone(_pp_hit({"status": 200, "body": "polluted1337"},
                                  {"status": 200, "body": "polluted1337"}, "polluted1337"))

    def test_pp_driver(self):
        from agent.probes import run_probe_prototype_pollution
        def fetch(m, url, h, b):
            if b and "polluted1337" in b:
                return {"status": 200, "body": "echo: polluted1337"}
            return {"status": 200, "body": "clean"}
        res = run_probe_prototype_pollution("https://t/api", fetch=fetch)
        self.assertTrue(res["candidates"])


class StoredXSSTest(unittest.TestCase):
    def test_stored_hit(self):
        from agent.probes import _stored_xss_hit
        self.assertIsNotNone(_stored_xss_hit('<div><svg/onload=alert(1)>aegstored12345</div>',
                                             "aegstored12345"))
        self.assertIsNone(_stored_xss_hit("&lt;svg&gt;aegstored12345", "aegstored12345"))
        self.assertIsNone(_stored_xss_hit("no marker here", "aegstored12345"))

    def test_stored_driver_two_phase(self):
        from agent.probes import run_probe_stored_xss
        from urllib.parse import unquote
        store = {}
        def fetch(m, url, h, b):
            if m == "GET" and "comment" in url:            # phase 1: inject (query)
                store["p"] = url.split("comment=")[-1]
                return {"status": 200, "body": "saved"}
            if "profile" in url:                           # phase 2: observe reflects it raw
                return {"status": 200, "body": f"<div>{unquote(store.get('p', ''))}</div>"}
            return {"status": 200, "body": "ok"}
        res = run_probe_stored_xss("https://t/post?comment=x",
                                   observe_urls="https://t/profile", fetch=fetch)
        self.assertTrue(res["candidates"])
        self.assertEqual(res["candidates"][0]["vuln_type"], "stored_xss")


class JWTTest(unittest.TestCase):
    def _token(self):
        from agent.api_probes import _encode_jwt
        return _encode_jwt({"alg": "HS256", "typ": "JWT"}, {"user": "alice", "role": "user"},
                           "originalsig")

    def test_attack_tokens_generated(self):
        from agent.api_probes import jwt_attack_tokens
        toks = jwt_attack_tokens(self._token())
        attacks = [t["attack"] for t in toks]
        self.assertTrue(any(a.startswith("alg=none") for a in attacks))
        self.assertIn("tampered-signature", attacks)
        self.assertTrue(any(a.startswith("weak-secret:") for a in attacks))

    def test_probe_detects_alg_none_acceptance(self):
        from agent.api_probes import run_probe_jwt
        valid = self._token()
        def fetch(m, url, headers, b):
            auth = headers.get("Authorization", "")
            # server accepts ANY token (broken verification)
            return {"status": 200, "body": "ok"} if auth else {"status": 401, "body": "no"}
        res = run_probe_jwt("https://t/me", valid, fetch=fetch)
        self.assertTrue(res["candidates"])
        self.assertEqual(res["candidates"][0]["vuln_type"], "jwt")

    def test_probe_clean_when_verified(self):
        from agent.api_probes import run_probe_jwt
        valid = self._token()
        def fetch(m, url, headers, b):
            # only the exact valid token works
            return {"status": 200, "body": "ok"} if valid in headers.get("Authorization", "") \
                else {"status": 401, "body": "no"}
        res = run_probe_jwt("https://t/me", valid, fetch=fetch)
        self.assertEqual(res["candidates"], [])


class GraphQLTest(unittest.TestCase):
    def test_verdict_helpers(self):
        from agent.api_probes import _introspection_enabled, _batching_enabled, _suggestions_leak
        self.assertTrue(_introspection_enabled('{"data":{"__schema":{"types":[{"name":"Q"}]}}}'))
        self.assertFalse(_introspection_enabled('{"errors":["disabled"]}'))
        self.assertTrue(_batching_enabled('[{"data":{}},{"data":{}}]'))
        self.assertFalse(_batching_enabled('{"data":{}}'))
        self.assertTrue(_suggestions_leak('{"errors":[{"message":"Did you mean \\"user\\"?"}]}'))

    def test_graphql_driver(self):
        from agent.api_probes import run_probe_graphql
        def fetch(m, url, h, b):
            if "__schema" in (b or ""):
                return {"status": 200, "body": '{"data":{"__schema":{"types":[{"name":"Query"}]}}}'}
            if (b or "").startswith("["):
                return {"status": 200, "body": '[{"data":{}},{"data":{}}]'}
            return {"status": 200, "body": '{"errors":[{"message":"Did you mean \\"user\\"?"}]}'}
        res = run_probe_graphql("https://t/graphql", fetch=fetch)
        vts = {c["vuln_type"] for c in res["candidates"]}
        self.assertIn("graphql_introspection", vts)
        self.assertIn("graphql_batching", vts)
        self.assertIn("graphql_suggestions", vts)


class SmugglingTest(unittest.TestCase):
    def test_desync_verdict(self):
        from agent.smuggling_probe import _desync_verdict
        # CL.TE stalled (status None)
        self.assertIsNotNone(_desync_verdict(120, 8000, None, 130, 200))
        # big delay
        self.assertIsNotNone(_desync_verdict(120, 6000, 200, 130, 200))
        # all fast → clean
        self.assertIsNone(_desync_verdict(120, 140, 200, 130, 200))

    def test_build_requests(self):
        from agent.smuggling_probe import build_requests
        r = build_requests("https://t/path?a=1")
        self.assertIn("Transfer-Encoding: chunked", r["clte"])
        self.assertIn("/path?a=1", r["control"])

    def test_driver_with_injected_timing(self):
        from agent.smuggling_probe import run_probe_smuggling
        def send(url, req):
            if "Transfer-Encoding" in req and "6" in req:  # clte stalls
                return (8000.0, None)
            return (100.0, 200)
        res = run_probe_smuggling("https://t/", send=send)
        self.assertTrue(res["candidates"])
        self.assertEqual(res["candidates"][0]["vuln_type"], "http_smuggling")


class VCSDumpTest(unittest.TestCase):
    def test_extract_git_config(self):
        from agent.vcs_dump import extract_git_config
        cfg = "[remote \"origin\"]\n url = https://user:pass@github.com/acme/app.git\n"
        got = extract_git_config(cfg)
        self.assertIn("https://user:pass@github.com/acme/app.git", got["remotes"])
        self.assertTrue(got["credential_urls"])

    def test_confirms_signatures(self):
        from agent.vcs_dump import _confirms
        self.assertTrue(_confirms("/.git/HEAD", "ref: refs/heads/main\n"))
        self.assertFalse(_confirms("/.git/HEAD", "<html>404</html>"))

    def test_dump_driver_flags_critical_on_creds(self):
        from agent.vcs_dump import run_vcs_dump
        def fetch(m, url, h, b):
            if url.endswith("/.git/HEAD"):
                return {"status": 200, "body": "ref: refs/heads/main\n"}
            if url.endswith("/.git/config"):
                return {"status": 200, "body": "[core]\n[remote \"o\"]\n url = https://u:p@h/x.git\n"}
            return {"status": 404, "body": "nope"}
        res = run_vcs_dump("https://t", fetch=fetch)
        self.assertTrue(res["candidates"])
        self.assertEqual(res["candidates"][0]["severity"], "critical")


class ToolRegistrationTest(unittest.TestCase):
    def test_all_new_tools_registered(self):
        import agent.agents  # noqa: F401
        from agent.tools import ToolRegistry
        reg = ToolRegistry()
        for name in ("probe_nosql", "probe_prototype_pollution", "probe_stored_xss",
                     "probe_jwt", "probe_graphql", "probe_smuggling", "dump_exposed_vcs"):
            self.assertIsNotNone(reg.get(name), name)


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    unittest.main()
