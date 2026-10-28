"""Opt-in real Chromium smoke: RUN_ASSESSMENT_BROWSER_TESTS=1 pytest this file."""

import json
import os
import threading
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import pytest
from app.services.agent.assessment_scope import register_scope
from test_capture_to_proof import crud_app as crud_app, prepare

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_ASSESSMENT_BROWSER_TESTS") != "1",
    reason="Opt-in local Chromium fixture",
)


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
