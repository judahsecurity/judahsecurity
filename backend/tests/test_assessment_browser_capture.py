"""Opt-in real Chromium smoke: RUN_ASSESSMENT_BROWSER_TESTS=1 pytest this file."""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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
