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

    def test_ssti_mutates_json_body_and_preserves_other_fields(self):
        from agent.probes import run_probe_ssti
        import random

        seen = []
        def fetch(method, url, headers, body):
            seen.append((method, headers, body))
            document = json.loads(body)
            self.assertEqual(document["csrf"], "keep-me")
            import re
            match = re.search(r"(\d+)\*(\d+)", document["profile"]["name"])
            output = str(int(match.group(1)) * int(match.group(2))) if match else "normal"
            return {"status": 200, "headers": {}, "body": output}

        result = run_probe_ssti(
            "https://t/profile", params="json:profile.name", method="POST",
            headers_json='{"Content-Type":"application/json"}',
            body='{"profile":{"name":"a"},"csrf":"keep-me"}',
            fetch=fetch, rng=random.Random(1),
        )
        self.assertTrue(result["candidates"])
        self.assertEqual(result["candidates"][0]["location"], "json")
        self.assertTrue(all(row[0] == "POST" for row in seen))

    def test_path_traversal_mutates_form_and_preserves_controls(self):
        from agent.probes import run_probe_path_traversal

        def fetch(method, url, headers, body):
            values = dict(__import__("urllib.parse", fromlist=["parse_qsl"]).parse_qsl(body))
            self.assertEqual(values["csrf"], "token")
            leaked = "passwd" in values.get("file", "")
            return {"status": 200, "headers": {}, "body":
                    "root:x:0:0:root:/root:/bin/bash" if leaked else "ok"}

        result = run_probe_path_traversal(
            "https://t/download", params="form:file", method="POST",
            headers_json='{"Content-Type":"application/x-www-form-urlencoded"}',
            body="file=readme.txt&csrf=token", fetch=fetch,
        )
        self.assertTrue(result["candidates"])
        self.assertEqual(result["candidates"][0]["method"], "POST")

    def test_command_injection_supports_header_location(self):
        from agent.probes import run_probe_command_injection
        import random

        def fetch(method, url, headers, body):
            value = headers.get("X-Diagnostic", "")
            marker = value.split("AEGCMD", 1)[1] if "AEGCMD" in value else ""
            return {"status": 200, "headers": {},
                    "body": "AEGCMD" + marker if marker else "normal"}

        result = run_probe_command_injection(
            "https://t/check", params="header:X-Diagnostic",
            headers_json='{"Accept":"text/plain"}', fetch=fetch,
            rng=random.Random(4),
        )
        self.assertTrue(result["candidates"])
        self.assertEqual(result["candidates"][0]["vuln_type"], "command_injection")

    def test_nosql_supports_json_operator_objects(self):
        from agent.probes import run_probe_nosql

        def fetch(method, url, headers, body):
            document = json.loads(body)
            self.assertEqual(document["csrf"], "keep")
            username = document["username"]
            if isinstance(username, dict) and "$eq" in username:
                return {"status": 403, "headers": {}, "body": "denied"}
            return {"status": 200, "headers": {}, "body": "allowed"}

        result = run_probe_nosql(
            "https://t/login", params="json:username", method="POST",
            headers_json='{"Content-Type":"application/json"}',
            body='{"username":"alice","csrf":"keep"}', fetch=fetch,
        )
        self.assertTrue(result["candidates"])
        self.assertIn('"$ne"', result["candidates"][0]["request_body"])

    def test_common_mutator_supports_cookie_location(self):
        from agent.probes import run_probe_command_injection
        import random

        def fetch(method, url, headers, body):
            cookie = headers.get("Cookie", "")
            marker = "AEGCMD" + cookie.split("AEGCMD", 1)[1].split(";", 1)[0] \
                if "AEGCMD" in cookie else ""
            return {"status": 200, "headers": {}, "body": marker or "normal"}

        result = run_probe_command_injection(
            "https://t/", params="cookie:diagnostic",
            headers_json='{"Cookie":"session=keep; diagnostic=off"}',
            fetch=fetch, rng=random.Random(9),
        )
        self.assertTrue(result["candidates"])
        self.assertEqual(result["candidates"][0]["location"], "cookie")

    def test_tools_registered(self):
        import agent.agents  # noqa: F401
        from agent.tools import ToolRegistry
        reg = ToolRegistry()
        for name in ("probe_ssti", "probe_path_traversal", "probe_open_redirect",
                     "probe_crlf", "probe_command_injection"):
            self.assertIsNotNone(reg.get(name), name)


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    unittest.main()
