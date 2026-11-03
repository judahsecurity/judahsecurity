"""Opt-in real Chromium smoke: RUN_ASSESSMENT_BROWSER_TESTS=1 pytest this file."""

import json
import base64
import hashlib
import os
import threading
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote

import pytest
from app.services.agent.assessment_scope import register_scope
from test_capture_to_proof import crud_app as crud_app, prepare


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["error", "blind", "patched"])
async def test_fresh_token_post_sqli_controls_keep_repeated_proof(mode):
    """Every control needs a new browser token; a patched endpoint stays negative."""
    from app.services.agent.scoped_assessment import body_probe
    from app.services.agent.scoped_assessment.browser_post_replay import replay_observed_post_controls

    class Handler(BaseHTTPRequestHandler):
        issued = 0
        used = set()
        seen = []

        def log_message(self, *args):
            pass

        def do_GET(self):
            Handler.issued += 1
            token = f"fresh-{Handler.issued}"
            body = ("<script>fetch('/api/filter',{method:'POST',headers:{'Content-Type':"
                    "'application/x-www-form-urlencoded'},body:new URLSearchParams({"
                    f"template:'botox',csrf_token:'{token}'"
                    "})})</script>").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            data = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
            token = data.get("csrf_token", [""])[0]
            value = data.get("template", [""])[0]
            Handler.seen.append((token, value))
            if token in Handler.used or not token.startswith("fresh-"):
                self.send_response(403)
                self.end_headers()
                return
            Handler.used.add(token)
            if mode == "error" and value.endswith("'") and not value.endswith("''"):
                body = b"SQLSTATE[42000]: Syntax error 1064 You have an error in your SQL syntax"
            elif mode == "blind" and " OR '" in value:
                import re
                match = re.search(r" OR '(\d{5})'='(\d{5})'-- $", value)
                body = b"A" * (700 if match and match.group(1) == match.group(2) else 100)
            else:
                body = b"A" * 100
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    private = json.dumps({
        "url": base + "/api/filter", "method": "POST", "resource_type": "fetch",
        "page_url": base + "/catalog", "request_content_type": "application/x-www-form-urlencoded",
        "request_body_base64": base64.b64encode(b"template=botox&csrf_token=captured-old").decode(),
    }).encode()
    try:
        url, mime, baseline, _, _ = body_probe.plan_sql_error_body(
            private, parameter="template", allowed_origins=[base],
        )
        if mode == "blind":
            _, _, variants, nonce = body_probe.plan_sql_boolean_body(
                private, parameter="template", allowed_origins=[base],
            )
            other = nonce[:-1] + str((int(nonce[-1]) + 1) % 10)
            checks = await replay_observed_post_controls(
                private, parameter="template", allowed_origins=[base], storage_state=None,
                payloads={
                    "baseline_first": "", "true_first": f"' OR '{nonce}'='{nonce}'-- ",
                    "false_first": f"' OR '{nonce}'='{other}'-- ",
                    "true_second": f"' OR '{nonce}'='{nonce}'-- ",
                    "false_second": f"' OR '{nonce}'='{other}'-- ",
                    "baseline_last": "",
                },
            )
            result = body_probe.build_sql_boolean_result(
                url, mime, variants, nonce, parameter="template", checks=checks,
            )
            assert result["proof_confirmed"] is True
        else:
            checks = await replay_observed_post_controls(
                private, parameter="template", allowed_origins=[base], storage_state=None,
                payloads={
                    "baseline_first": "", "quote_first": "'", "escaped_quote": "''",
                    "quote_second": "'", "baseline_last": "",
                },
            )
            result = body_probe.build_sql_error_result(
                url, mime, baseline, parameter="template", checks=checks,
            )
            assert result["proof_confirmed"] is (mode == "error")
        assert len(Handler.seen) == len(checks)
        assert len({token for token, _ in Handler.seen}) == len(checks)
        assert all(row["body_match_mode"] == "volatile_fields" for row in checks.values())
        assert all(row["status"] == 200 for row in checks.values())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_post_replay_uses_fresh_header_and_cookie_with_static_body():
    from app.services.agent.scoped_assessment import body_probe
    from app.services.agent.scoped_assessment.browser_post_replay import replay_observed_post_controls

    class Handler(BaseHTTPRequestHandler):
        issued = 0
        used = set()
        seen = []

        def log_message(self, *args):
            pass

        def do_GET(self):
            Handler.issued += 1
            token = f"page-{Handler.issued}"
            body = ("<script>fetch('/api/filter',{method:'POST',headers:{"
                    "'Content-Type':'application/x-www-form-urlencoded',"
                    f"'X-CSRF-Token':'{token}'"
                    "},body:'template=botox'})</script>").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", f"page_session={token}; Path=/; SameSite=Lax")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            token = self.headers.get("X-CSRF-Token", "")
            Handler.seen.append((token, self.headers.get("Cookie", ""), body))
            if (not token.startswith("page-") or token in Handler.used
                    or f"page_session={token}" not in self.headers.get("Cookie", "")):
                self.send_response(403)
                self.end_headers()
                return
            Handler.used.add(token)
            value = parse_qs(body.decode())["template"][0]
            response = (b"You have an error in your SQL syntax" if value.endswith("'")
                        and not value.endswith("''") else b"ordinary response")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    private = json.dumps({
        "url": base + "/api/filter", "method": "POST", "resource_type": "fetch",
        "action_ref": "navigate", "page_url": base + "/catalog",
        "request_content_type": "application/x-www-form-urlencoded",
        "request_body_base64": base64.b64encode(b"template=botox").decode(),
    }).encode()
    try:
        url, mime, baseline, _, _ = body_probe.plan_sql_error_body(
            private, parameter="template", allowed_origins=[base],
        )
        checks = await replay_observed_post_controls(
            private, parameter="template", allowed_origins=[base], storage_state=None,
            payloads={
                "baseline_first": "", "quote_first": "'", "escaped_quote": "''",
                "quote_second": "'", "baseline_last": "",
            },
        )
        result = body_probe.build_sql_error_result(
            url, mime, baseline, parameter="template", checks=checks,
        )
        assert result["proof_confirmed"] is True
        assert len({row[0] for row in Handler.seen}) == 5
        assert all(row["body_match_mode"] == "exact" for row in checks.values())
        assert all(row["browser_requests_seen"] <= 24 for row in checks.values())
        assert all(row["status"] == 200 for row in checks.values())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_post_replay_caps_incidental_page_requests():
    from app.services.agent.scoped_assessment.browser_post_replay import (
        MAX_HTTP_REQUESTS_PER_CONTROL, replay_observed_post_controls,
    )

    class Handler(BaseHTTPRequestHandler):
        seen = 0
        posts = 0

        def log_message(self, *args):
            pass

        def do_GET(self):
            Handler.seen += 1
            body = (b"<script>(async()=>{for(let i=0;i<35;i++){try{await fetch('/asset?i='+i)}"
                    b"catch(e){}}fetch('/api/filter',{method:'POST',headers:{'Content-Type':"
                    b"'application/x-www-form-urlencoded'},body:'template=botox'})})()</script>"
                    if self.path == "/catalog" else b"ok")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            Handler.posts += 1
            self.send_response(200)
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    private = json.dumps({
        "url": base + "/api/filter", "method": "POST", "resource_type": "fetch",
        "action_ref": "navigate", "page_url": base + "/catalog",
        "request_content_type": "application/x-www-form-urlencoded",
        "request_body_base64": base64.b64encode(b"template=botox").decode(),
    }).encode()
    try:
        with pytest.raises(ValueError, match="request cap exceeded"):
            await replay_observed_post_controls(
                private, parameter="template", allowed_origins=[base],
                storage_state=None, payloads={"baseline_first": ""},
            )
        assert Handler.seen <= MAX_HTTP_REQUESTS_PER_CONTROL
        assert Handler.posts == 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_get_replay_uses_fresh_header_and_cookie():
    from app.services.agent.scoped_assessment.browser_post_replay import replay_observed_get_controls
    from app.services.agent.scoped_assessment.query_probe import plan_observed_query

    class Handler(BaseHTTPRequestHandler):
        issued = 0
        used = set()
        seen = []

        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path == "/catalog":
                Handler.issued += 1
                token = f"page-{Handler.issued}"
                body = ("<script>fetch('/api/filter?template=botox',{headers:{"
                        f"'X-CSRF-Token':'{token}'"
                        "}})</script>").encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Set-Cookie", f"page_session={token}; Path=/; SameSite=Lax")
            elif self.path.startswith("/api/filter?"):
                token = self.headers.get("X-CSRF-Token", "")
                Handler.seen.append((token, self.headers.get("Cookie", ""), self.path))
                if (not token.startswith("page-") or token in Handler.used
                        or f"page_session={token}" not in self.headers.get("Cookie", "")):
                    self.send_response(403)
                    self.end_headers()
                    return
                Handler.used.add(token)
                value = parse_qs(self.path.split("?", 1)[1])["template"][0]
                body = (b"You have an error in your SQL syntax" if value.endswith("'")
                        else b"ordinary response")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
            else:
                body = b"missing"
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    private = json.dumps({
        "url": base + "/api/filter?template=botox", "method": "GET",
        "resource_type": "fetch", "action_ref": "navigate",
        "page_url": base + "/catalog", "request_body_base64": "",
    }).encode()
    try:
        baseline, mutated = plan_observed_query(
            private, parameter="template", allowed_origins=[base],
        )
        checks = await replay_observed_get_controls(
            private, parameter="template", allowed_origins=[base], storage_state=None,
            variants={"baseline": baseline, "probe": mutated},
        )
        assert len(Handler.seen) == 2
        assert len({token for token, _, _ in Handler.seen}) == 2
        assert all(row["status"] == 200 for row in checks.values())
        assert checks["probe"]["sql_error_family"] == "mysql"
        assert all(row["browser_requests_seen"] <= 24 for row in checks.values())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_browser_capture_retains_parameterized_request_with_large_response():
    from app.services.agent.scoped_assessment.browser import check_browser

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path == "/catalog":
                body = (b"<script>fetch('/api/ping');"
                        b"fetch('/api/search?term=seed')</script>")
                mime = "text/html"
            elif self.path == "/api/search?term=seed":
                body = b"A" * 300_000
                mime = "text/plain"
            else:
                body = b"ok"
                mime = "text/plain"
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        traffic = []
        result, _ = await check_browser(
            operation="map", url=base + "/catalog", allowed_origins=[base],
            traffic_exchanges=traffic,
        )
        assert [row["public"]["path"] for row in traffic] == ["/api/search"]
        capture = traffic[0]
        assert capture["public"]["query_fields"] == [{"name": "term", "value_type": "string"}]
        assert capture["public"]["response_body_truncated"] is True
        assert capture["public"]["response_bytes"] == 0
        assert capture["public"]["response_bytes_declared"] == 300_000
        assert json.loads(capture["private"])["response_body_base64"] == ""
        assert result["traffic_capture"]["input_responses_seen"] == 1
        assert result["traffic_capture"]["response_truncated"] == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_ASSESSMENT_BROWSER_TESTS") != "1",
    reason="Opt-in local Chromium fixture",
)


@pytest.mark.asyncio
@pytest.mark.parametrize("vulnerable", [True, False])
async def test_xss_lab_sweep_browser_controls_and_independent_repeat(vulnerable):
    """A reflected marker becomes a finding only after fresh browser execution."""
    from app.services.agent.coverage_cells import seed_parameter_coverage_cells
    from app.services.agent.engagement_brain import EngagementBrain
    from app.services.agent.independent_verify import (
        candidate_from_dict, run_independent_verifiers,
    )
    from app.services.agent.observed_input_batch import run_observed_input_batch
    from app.services.agent.tools import ASMToolsManager
    from harness.local_harness.benchmark.class_lab import handler_for

    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for("xss", vulnerable, ""))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        manager = ASMToolsManager()
        register_scope(manager, base)
        manager._fallback_target = base
        observed_url = base + "/search?q=public&view=full"
        manager._capability_map = {"target": base, "scope": base}
        manager._scoped_link_baselines = {"anonymous": [observed_url]}
        brain = EngagementBrain(target=base)
        seed_parameter_coverage_cells(brain, [{
            "method": "GET", "host": f"127.0.0.1:{server.server_port}",
            "path": "/search", "name": "q", "location": "query",
            "identity": "anonymous", "source": "browser_link", "testable": True,
        }])
        for row in brain.coverage_cells:
            if row["test_type"] != "xss":
                row["status"] = "skipped"
        manager._engagement_brain = brain.to_dict()
        batch = await run_observed_input_batch(manager, target=base, max_checks=2)
        assert batch["processed"] == 2
        assert batch["results"][0]["outcome"] == "inconclusive"
        assert batch["results"][0]["baseline_evidence_id"]
        assert batch["results"][0]["probe_evidence_id"]
        assert batch["results"][1]["outcome"] == (
            "proof_signal" if vulnerable else "inconclusive"
        )
        candidates = [candidate_from_dict(row)
                      for row in manager._engagement_brain["candidates"]]
        reports = await run_independent_verifiers(
            candidates, llm=None, tools_manager=manager, targets=[base],
        ) if candidates else []
        assert [report["status"] for report in reports] == (
            ["confirmed"] if vulnerable else []
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_browser_capture_flows_into_controlled_authorization_proof(crud_app, monkeypatch):
    from playwright.async_api import BrowserType
    from app.services.agent.tools import ASMToolsManager
    executable = os.environ.get("ASSESSMENT_TEST_CHROMIUM")
    if executable:
        original = BrowserType.launch
        async def launch(self, **kwargs):
            return await original(self, **dict(kwargs, executable_path=executable))
        monkeypatch.setattr(BrowserType, "launch", launch)
    base, state = crud_app
    manager = ASMToolsManager()
    register_scope(manager, base)
    await manager.register_test_identity("a", base, cookies={"sid": "a"})
    await manager._http_exchange("POST", base + "/objects", identity="a", body={"marker": "browser-seed"})
    result = json.loads(await manager.browse_as_identity("a", base, [dict(action="wait", ms=600)]))
    assert result["success"], result
    capture = next(c for c in result["captures"] if c["url"] == base + "/objects/1")
    assert capture["source"] == "browser"
    assert any(
        row["reference"] == "path:2"
        for row in capture["authorization_references"]
    )
    leads = json.loads(await manager.list_authorization_leads(capture["operation_id"]))
    assert any(
        row["capture_id"] == capture["id"] and row["status"] == "needs_policy"
        for row in leads["leads"]
    )
    assert result["authorization_handoff"]["candidates"] >= 1
    assert "browser-seed" not in json.dumps(result)
    manager, cell, _, _ = await prepare(base, "captured_read", m=manager, capture=capture)
    receipt = json.loads(await manager.run_authorization_proof(cell["hypothesis_id"]))["receipt"]
    assert receipt["verdict"] == "confirmed", receipt
    assert receipt["capture_id"] == capture["id"]
    assert set(state["objects"]) == {"1"}  # Only the pre-existing browser seed remains.


@pytest.mark.asyncio
async def test_real_browser_identity_capture_and_origin_block(monkeypatch):
    from playwright.async_api import BrowserType
    from app.services.agent.tools import ASMToolsManager

    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            requests.append((self.path, self.headers.get("Cookie", "")))
            self.send_response(200)
            self.send_header(
                "Content-Type", "text/html" if self.path == "/" else "application/json"
            )
            self.end_headers()
            if self.path == "/":
                port = self.server.server_port
                self.wfile.write(
                    f"""<html><script>
                fetch('/api/orders?id=7');
                fetch('/graphql', {{method:'POST', headers:{{'Content-Type':'application/json'}},
                body:JSON.stringify({{query:'query Orders {{ orders {{ id }} }}', variables:{{token:'sensitive-variable'}}}})}});
                fetch('http://localhost:{port}/out-of-origin').catch(()=>{{}});
                </script></html>""".encode()
                )
            else:
                self.wfile.write(b'{"ok":true}')

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.do_GET()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    executable = os.environ.get("ASSESSMENT_TEST_CHROMIUM")
    if executable:
        original = BrowserType.launch

        async def launch(self, **kwargs):
            return await original(self, **dict(kwargs, executable_path=executable))

        monkeypatch.setattr(BrowserType, "launch", launch)
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        manager = ASMToolsManager()
        register_scope(manager, base)
        for identity in ("a", "b"):
            await manager.register_test_identity(
                identity, base, cookies=[dict(name="sid", value=identity)]
            )
            result = json.loads(
                await manager.browse_as_identity(
                    identity, base, [dict(action="wait", ms=600)]
                )
            )
            assert result["success"], result
            assert any(
                o["protocol"] == "graphql" and o["identities"] == [identity]
                for o in result["operations"]
            )
            assert "sensitive-variable" not in json.dumps(result)
        assert any(cookie == "sid=a" for path, cookie in requests if path == "/graphql")
        assert any(cookie == "sid=b" for path, cookie in requests if path == "/graphql")
        assert all(path != "/out-of-origin" for path, cookie in requests)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_scoped_post_form_xss_needs_response_and_browser_execution():
    from app.services.agent.scoped_assessment.browser import check_browser

    posted = []

    class Handler(BaseHTTPRequestHandler):
        encode = False

        def log_message(self, *args):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b'<form method="POST" action="/submit">'
                             b'<input type="email" name="email">'
                             b'<button type="submit">Subscribe</button></form>')

        def do_POST(self):
            value = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode()).get(
                "email", [""])[0]
            posted.append(self.path)
            rendered = escape(value) if self.encode else value
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(("<html><body>" + rendered + "</body></html>").encode())

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        for encoded in (False, True):
            Handler.encode = encoded
            result, _ = await check_browser(
                operation="check_form_xss", url=base + "/page",
                allowed_origins=[base], form_action=base + "/submit",
                form_field="email",
                form_payload_template='<img src=x onerror=alert("__PROWL_NONCE__")>',
            )
            assert result["post_submitted"] is True
            assert result["post_response_seen"] is True
            assert result["executed"] is not encoded
        assert posted == ["/submit", "/submit"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_scoped_xhr_xss_replays_rendering_page_and_requires_execution(monkeypatch):
    from app.services.agent.scoped_assessment.browser import check_browser
    from playwright.async_api import BrowserType

    executable = os.environ.get("ASSESSMENT_TEST_CHROMIUM")
    if executable:
        original = BrowserType.launch

        async def launch(self, **kwargs):
            return await original(self, **dict(kwargs, executable_path=executable))

        monkeypatch.setattr(BrowserType, "launch", launch)

    seen_queries = []

    class Handler(BaseHTTPRequestHandler):
        encode = False

        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path.startswith("/api/search"):
                value = parse_qs(self.path.split("?", 1)[1]).get("term", [""])[0]
                seen_queries.append(value)
                rendered = escape(value) if self.encode else value
                body = rendered.encode()
                content_type = "text/html"
            else:
                body = (b'<div id="result"></div><script>'
                        b'fetch("/api/search?term=seed").then(r => r.text())'
                        b'.then(v => document.getElementById("result").innerHTML = v)'
                        b'</script>')
                content_type = "text/html"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        traffic = []
        mapped, _ = await check_browser(operation="map", url=base + "/catalog",
                                        allowed_origins=[base], traffic_exchanges=traffic)
        assert mapped["operation"] == "map"
        assert len(traffic) == 1
        assert json.loads(traffic[0]["private"])["page_url"] == base + "/catalog"
        payload = '<img src=x onerror=alert("__PROWL_NONCE__")>'
        for encoded in (False, True):
            Handler.encode = encoded
            result, _ = await check_browser(
                operation="check_xhr_xss", url=base + "/catalog",
                allowed_origins=[base], xhr_path="/api/search",
                xhr_parameter="term", xhr_query_keys=["term"],
                xhr_payload_template=payload,
            )
            assert result["xhr_mutated"] is True
            assert result["xhr_response_seen"] is True
            assert result["executed"] is not encoded
        assert seen_queries[0] == "seed"
        assert all("onerror" in value for value in seen_queries[1:])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_scoped_xhr_xss_replays_observed_tab_before_mutating_request(monkeypatch):
    from app.services.agent.scoped_assessment.browser import check_browser
    from playwright.async_api import BrowserType

    executable = os.environ.get("ASSESSMENT_TEST_CHROMIUM")
    if executable:
        original = BrowserType.launch

        async def launch(self, **kwargs):
            return await original(self, **dict(kwargs, executable_path=executable))

        monkeypatch.setattr(BrowserType, "launch", launch)

    class Handler(BaseHTTPRequestHandler):
        encode = False

        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path.startswith("/api/search"):
                value = parse_qs(self.path.split("?", 1)[1]).get("term", [""])[0]
                body = (escape(value) if self.encode else value).encode()
            else:
                body = (b'<button role="tab" aria-controls="results">Results</button>'
                        b'<div id="results"></div><script>'
                        b'document.querySelector("[role=tab]").addEventListener("click", () => {'
                        b'fetch("/api/search?term=seed").then(r => r.text())'
                        b'.then(v => document.getElementById("results").innerHTML = v)'
                        b'});</script>')
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        sources, traffic = [], []
        observed, _ = await check_browser(
            operation="inspect_js", url=base + "/catalog", allowed_origins=[base],
            javascript_sources=sources, traffic_exchanges=traffic,
            max_pages=1, max_actions=1,
        )
        ui_action = next(row for row in observed["actions"] if row["kind"] == "tab")
        assert ui_action["status"] == "completed"
        assert traffic[0]["public"]["action_ref"] == ui_action["ref"]
        actions = [{key: ui_action[key] for key in (
            "kind", "label", "aria_controls", "before_path",
        )}]
        payload = '<img src=x onerror=alert("__PROWL_NONCE__")>'
        for encoded in (False, True):
            Handler.encode = encoded
            result, _ = await check_browser(
                operation="check_xhr_xss", url=base + "/catalog",
                allowed_origins=[base], xhr_path="/api/search",
                xhr_parameter="term", xhr_query_keys=["term"],
                xhr_payload_template=payload, xhr_actions=actions,
            )
            assert result["xhr_actions_replayed"] == 1
            assert result["xhr_mutated"] is True
            assert result["xhr_response_seen"] is True
            assert result["executed"] is not encoded
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_scoped_post_xhr_xss_mutates_only_matching_capture_and_needs_execution(monkeypatch):
    from app.services.agent.scoped_assessment.browser import check_browser
    from playwright.async_api import BrowserType

    executable = os.environ.get("ASSESSMENT_TEST_CHROMIUM")
    if executable:
        original = BrowserType.launch

        async def launch(self, **kwargs):
            return await original(self, **dict(kwargs, executable_path=executable))

        monkeypatch.setattr(BrowserType, "launch", launch)

    seen_posts = []

    class Handler(BaseHTTPRequestHandler):
        encode = False

        def log_message(self, *args):
            pass

        def do_GET(self):
            body = (b'<div id="result"></div><script>'
                    b'fetch("/api/render", {method:"POST", headers:{"Content-Type":'
                    b'"application/x-www-form-urlencoded"}, body:"message=seed"})'
                    b'.then(r => r.text()).then(v => '
                    b'document.getElementById("result").innerHTML = v)'
                    b'</script>')
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            seen_posts.append(body)
            value = parse_qs(body.decode()).get("message", [""])[0]
            rendered = (escape(value) if self.encode else value).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(rendered)))
            self.end_headers()
            self.wfile.write(rendered)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    payload = '<img src=x onerror=alert("__PROWL_NONCE__")>'
    template = ("message=" + quote(payload, safe="")).encode()
    try:
        for encoded in (False, True):
            Handler.encode = encoded
            result, _ = await check_browser(
                operation="check_xhr_xss", url=base + "/catalog",
                allowed_origins=[base], xhr_path="/api/render",
                xhr_parameter="message", xhr_query_keys=[],
                xhr_payload_template=payload, xhr_post_baseline=b"message=seed",
                xhr_post_template=template,
                xhr_post_content_type="application/x-www-form-urlencoded",
                xhr_capture_id="fixture",
                xhr_body_location="body_form",
            )
            assert result["xhr_mutated"] is True
            assert result["xhr_response_seen"] is True
            assert result["executed"] is not encoded
        count = len(seen_posts)
        mismatch, _ = await check_browser(
            operation="check_xhr_xss", url=base + "/catalog",
            allowed_origins=[base], xhr_path="/api/render",
            xhr_parameter="message", xhr_query_keys=[],
            xhr_payload_template=payload, xhr_post_baseline=b"message=other",
            xhr_post_template=template,
            xhr_post_content_type="application/x-www-form-urlencoded",
            xhr_capture_id="fixture",
            xhr_body_location="body_form",
        )
        assert mismatch["xhr_mutated"] is False
        assert mismatch["executed"] is False
        assert len(seen_posts) == count
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_scoped_post_xhr_xss_replays_with_current_page_token(monkeypatch):
    from app.services.agent.scoped_assessment.body_probe import plan_observed_body
    from app.services.agent.scoped_assessment.browser import check_browser
    from playwright.async_api import BrowserType

    executable = os.environ.get("ASSESSMENT_TEST_CHROMIUM")
    if executable:
        original = BrowserType.launch

        async def launch(self, **kwargs):
            return await original(self, **dict(kwargs, executable_path=executable))

        monkeypatch.setattr(BrowserType, "launch", launch)

    class Handler(BaseHTTPRequestHandler):
        encode = False
        issued = 0
        valid_tokens = set()
        accepted_tokens = []

        def log_message(self, *args):
            pass

        def do_GET(self):
            Handler.issued += 1
            token = f"csrf-{Handler.issued:04d}"
            Handler.valid_tokens.add(token)
            body = ('<button role="tab" aria-controls="results">Preview</button>'
                    '<div id="results"></div><script>'
                    'document.querySelector("[role=tab]").onclick=async()=>{'
                    'const r=await fetch("/api/render",{method:"POST",'
                    'headers:{"Content-Type":"application/json"},'
                    'body:JSON.stringify({message:"hello",csrf_token:"' + token + '"})});'
                    'document.getElementById("results").innerHTML=await r.text()}'
                    '</script>').encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            token = data.get("csrf_token")
            if token not in Handler.valid_tokens:
                status, body = 403, b"invalid token"
            else:
                Handler.valid_tokens.remove(token)
                Handler.accepted_tokens.append(token)
                value = data.get("message", "")
                status, body = 200, (escape(value) if Handler.encode else value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    payload = '<img src=x onerror=alert("__PROWL_NONCE__")>'
    try:
        sources, traffic = [], []
        observed, _ = await check_browser(
            operation="inspect_js", url=base + "/", allowed_origins=[base],
            javascript_sources=sources, traffic_exchanges=traffic,
            max_pages=1, max_actions=1,
        )
        action = next(row for row in observed["actions"] if row["kind"] == "tab")
        captured = next(row for row in traffic if row["public"]["path"] == "/api/render")
        private = captured["private"]
        _, mime, baseline, template = plan_observed_body(
            private, parameter="/message", allowed_origins=[base], payload=payload,
        )
        captured_token = json.loads(base64.b64decode(
            json.loads(private)["request_body_base64"]
        ))["csrf_token"]
        actions = [{key: action[key] for key in (
            "kind", "label", "aria_controls", "before_path",
        )}]
        for encoded in (False, True):
            Handler.encode = encoded
            result, _ = await check_browser(
                operation="check_xhr_xss", url=base + "/", allowed_origins=[base],
                xhr_path="/api/render", xhr_parameter="/message",
                xhr_query_keys=[], xhr_payload_template=payload,
                xhr_actions=actions, xhr_post_baseline=baseline,
                xhr_post_template=template, xhr_post_content_type=mime,
                xhr_capture_id="fixture", xhr_body_location="body_json",
                xhr_baseline_request_sha256=hashlib.sha256(baseline).hexdigest(),
            )
            assert result["xhr_actions_replayed"] == 1
            assert result["xhr_mutated"] is True
            assert result["xhr_response_seen"] is True
            assert result["xhr_body_match_mode"] == "volatile_fields"
            assert result["xhr_volatile_fields"] == ["csrf_token"]
            assert result["executed"] is not encoded
        assert len(Handler.accepted_tokens) == 3
        assert captured_token == Handler.accepted_tokens[0]
        assert all(token != captured_token for token in Handler.accepted_tokens[1:])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_scoped_dom_fragment_executes_only_in_unsafe_sink(monkeypatch):
    from app.services.agent.scoped_assessment.browser import check_browser
    from playwright.async_api import BrowserType

    executable = os.environ.get("ASSESSMENT_TEST_CHROMIUM")
    if executable:
        original = BrowserType.launch

        async def launch(self, **kwargs):
            return await original(self, **dict(kwargs, executable_path=executable))

        monkeypatch.setattr(BrowserType, "launch", launch)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            sink = "innerHTML" if self.path == "/unsafe" else "textContent"
            body = (f'<div id="result"></div><script>'
                    f'document.getElementById("result").{sink} = '
                    f'decodeURIComponent(location.hash.slice(1));</script>').encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    payload = "%3Cimg%20src%3Dx%20onerror%3Dalert(%22__PROWL_NONCE__%22)%3E"
    try:
        for path, expected in (("/unsafe", True), ("/safe", False)):
            result, _ = await check_browser(
                operation="check_xss", url=base + path + "#" + payload,
                allowed_origins=[base],
            )
            assert result["executed"] is expected
            observations = result["reflection_observations"]
            if expected:
                assert {"context": "html_attribute",
                        "representation": "event_handler_attribute"} in observations
            else:
                assert {"context": "html_text",
                        "representation": "literal_markup_text"} in observations
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_scoped_client_parser_probe_observes_rendered_template_and_prototype():
    from app.services.agent.scoped_assessment.browser import check_browser

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path.startswith("/template"):
                body = (b'<div id="result"></div><script>'
                        b'const value=decodeURIComponent(location.hash.slice(1));'
                        b'document.getElementById("result").innerText='
                        b'value.replace("{{7*7}}","49");</script>')
            else:
                body = (b'<script>for(const [k,v] of new URLSearchParams(location.search))'
                        b'{const m=k.match(/^__proto__\\[(prowl_[a-f0-9]+)\\]$/);'
                        b'if(m)Object.prototype[m[1]]=v;}</script>')
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        template, _ = await check_browser(
            operation="check_client", url=base + "/template#{{7*7}}__PROWL_NONCE__",
            client_test_type="client_template_injection", allowed_origins=[base],
        )
        assert template["behavior_observed"] is True
        assert template["observations"]["server_template_evaluated"] is False
        polluted, _ = await check_browser(
            operation="check_client",
            url=base + "/prototype?__proto__%5Bprowl___PROWL_NONCE__%5D=1",
            client_test_type="client_prototype_pollution", allowed_origins=[base],
        )
        assert polluted["behavior_observed"] is True
        assert polluted["observations"]["prototype_polluted"] is True
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_scoped_stored_xss_reads_then_cleans_up(monkeypatch):
    from playwright.async_api import BrowserType
    from app.services.agent.scoped_assessment.browser import check_browser

    executable = os.environ.get("ASSESSMENT_TEST_CHROMIUM")
    if executable:
        original = BrowserType.launch

        async def launch(self, **kwargs):
            return await original(self, **dict(kwargs, executable_path=executable))

        monkeypatch.setattr(BrowserType, "launch", launch)

    values = []

    class Handler(BaseHTTPRequestHandler):
        encode = False

        def log_message(self, *args):
            pass

        def respond(self, status, body=b""):
            self.send_response(status)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/new":
                self.respond(200, b'<form method="POST" action="/comments">'
                             b'<textarea name="message"></textarea>'
                             b'<button type="submit">Save</button></form>')
            elif self.path == "/comments/view":
                body = "".join(escape(value) if self.encode else value for value in values)
                self.respond(200, ("<html><body>" + body + "</body></html>").encode())
            else:
                self.respond(404)

        def do_POST(self):
            if self.path != "/comments":
                self.respond(404)
                return
            body = self.rfile.read(int(self.headers["Content-Length"])).decode()
            values.append(parse_qs(body).get("message", [""])[0])
            self.respond(200, b"Saved")

        def do_DELETE(self):
            marker = parse_qs(self.path.split("?", 1)[1]).get("marker", [""])[0]
            values[:] = [value for value in values if marker not in value]
            self.respond(200)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        for encoded in (False, True):
            Handler.encode = encoded
            result, _ = await check_browser(
                operation="check_stored_xss", url=base + "/new",
                allowed_origins=[base], form_action=base + "/comments",
                form_field="message",
                form_payload_template='<img src=x onerror=alert("__PROWL_NONCE__")>',
                readback_url=base + "/comments/view",
                cleanup_url_template=base + "/comments/purge?marker=__PROWL_NONCE__",
            )
            assert result["post_submitted"] is True
            assert result["readback_status"] == 200
            assert result["readback_final_exact"] is True
            assert result["cleanup_success"] is True
            assert result["executed"] is not encoded
            assert values == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
