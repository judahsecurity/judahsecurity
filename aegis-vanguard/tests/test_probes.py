"""Differential probes — SSTI / path-traversal / open-redirect / CRLF verdicts."""

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class ProbeVerdictTest(unittest.TestCase):
    def test_ssti_hit_requires_computed_product(self):
        from agent.probes import _ssti_hit
        self.assertTrue(_ssti_hit("result: 1022117 done", 1022117, "10091013"))
        self.assertFalse(_ssti_hit("echoed 1009*1013 literally", 1022117, "10091013"))
        self.assertFalse(_ssti_hit("nothing", 1022117, "10091013"))

    def test_traversal_hit_signatures(self):
        from agent.probes import _traversal_hit
        self.assertIsNotNone(_traversal_hit("root:x:0:0:root:/root:/bin/bash"))
        self.assertIsNotNone(_traversal_hit("; for 16-bit app support\n[fonts]"))
        self.assertIsNone(_traversal_hit("normal page body"))

    def test_open_redirect_hit_location_and_client_side(self):
        from agent.probes import _open_redirect_hit
        loc = {"status": 302, "headers": {"Location": "https://aeg-redir-canary.example/"}}
        self.assertIsNotNone(_open_redirect_hit(loc, "aeg-redir-canary.example"))
        body = {"status": 200, "headers": {},
                "body": "<script>location.href='https://aeg-redir-canary.example/'</script>"}
        self.assertIsNotNone(_open_redirect_hit(body, "aeg-redir-canary.example"))
        safe = {"status": 302, "headers": {"Location": "/dashboard"}}
        self.assertIsNone(_open_redirect_hit(safe, "aeg-redir-canary.example"))

    def test_crlf_hit(self):
        from agent.probes import _crlf_hit
        resp = {"headers": {"X-Aeg-Inj": "crlf1337", "Content-Type": "text/html"}}
        self.assertTrue(_crlf_hit(resp, "X-Aeg-Inj", "crlf1337"))
        self.assertFalse(_crlf_hit({"headers": {}}, "X-Aeg-Inj", "crlf1337"))


class ProbeDriverTest(unittest.TestCase):
    def test_ssti_driver_confirms(self):
        from agent.probes import run_probe_ssti
        import random

        def fetch(method, url, headers, body):
            # Simulate an engine that evaluates the injected expression.
            import re
            m = re.search(r"(\d{3,4})\*(\d{3,4})", url) or re.search(r"(\d{3,4})%2A(\d{3,4})", url)
            # our payloads urlencode '*'? _with_param uses urlencode -> '*' stays or %2A
            body_out = ""
            m2 = re.search(r"(\d{3,4})[*]?(\d{3,4})", url)
            return {"status": 200, "headers": {}, "body": body_out}

        # Deterministic operands, and a fetch that actually computes them:
        def smart_fetch(method, url, headers, body):
            import re
            from urllib.parse import unquote
            u = unquote(url)
            m = re.search(r"(\d{3,4})\*(\d{3,4})", u)
            if m:
                prod = int(m.group(1)) * int(m.group(2))
                return {"status": 200, "headers": {}, "body": f"<b>{prod}</b>"}
            return {"status": 200, "headers": {}, "body": "no eval"}

        res = run_probe_ssti("https://t/page?name=x", fetch=smart_fetch,
                             rng=random.Random(1))
        self.assertTrue(res["candidates"])
        self.assertEqual(res["candidates"][0]["vuln_type"], "ssti")

    def test_traversal_driver_confirms(self):
        from agent.probes import run_probe_path_traversal
        def fetch(method, url, headers, body):
            if "passwd" in url or "%2f" in url.lower():
                return {"status": 200, "headers": {}, "body": "root:x:0:0:root:/root:/bin/bash"}
            return {"status": 200, "headers": {}, "body": "ok"}
        res = run_probe_path_traversal("https://t/get?file=a", fetch=fetch)
        self.assertTrue(res["candidates"])
        self.assertEqual(res["candidates"][0]["vuln_type"], "path_traversal")

    def test_open_redirect_driver_confirms(self):
        from agent.probes import run_probe_open_redirect
        def fetch(method, url, headers, body):
            if "aeg-redir-canary.example" in url:
                return {"status": 302, "headers": {"Location": "https://aeg-redir-canary.example/"}}
            return {"status": 200, "headers": {}}
        res = run_probe_open_redirect("https://t/login?next=/home", fetch=fetch)
        self.assertTrue(res["candidates"])
        self.assertEqual(res["candidates"][0]["vuln_type"], "open_redirect")

    def test_crlf_driver_confirms(self):
        from agent.probes import run_probe_crlf
        def fetch(method, url, headers, body):
            if "X-Aeg-Inj" in url or "%0d%0a" in url.lower() or "crlf1337" in url:
                return {"status": 200, "headers": {"X-Aeg-Inj": "crlf1337"}}
            return {"status": 200, "headers": {}}
        res = run_probe_crlf("https://t/p?q=1", fetch=fetch)
        self.assertTrue(res["candidates"])
        self.assertEqual(res["candidates"][0]["vuln_type"], "crlf")

    def test_no_params_returns_note(self):
        from agent.probes import run_probe_ssti
        res = run_probe_ssti("https://t/page", fetch=lambda *a: {"status": 200})
        self.assertEqual(res["candidates"], [])
        self.assertIn("note", res)

    def test_tools_registered(self):
        import agent.agents  # noqa: F401
        from agent.tools import ToolRegistry
        reg = ToolRegistry()
        for name in ("probe_ssti", "probe_path_traversal", "probe_open_redirect", "probe_crlf"):
            self.assertIsNotNone(reg.get(name), name)


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    unittest.main()
