"""Intercepted-request XSS in a local Chromium (opt-in, like the other browser
fixtures): set RUN_ASSESSMENT_BROWSER_TESTS=1 (and ASSESSMENT_TEST_CHROMIUM to
a Chromium binary when Playwright's own is not installed). Loopback only."""

import html
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

import pytest

from app.services.agent.scoped_assessment import browser_intercept as bi

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_ASSESSMENT_BROWSER_TESTS") != "1",
    reason="Opt-in local Chromium fixture",
)

PAYLOAD = '<img src=x onerror=alert("__PROWL_NONCE__")>'
RENDER_FETCH = """<html><body><div id=out></div><script>
fetch(%s).then(r => r.text()).then(t => { document.getElementById('out').innerHTML = t; });
</script></body></html>"""


class Lab(BaseHTTPRequestHandler):
    seen: list = []

    def log_message(self, *args):
        pass

    def _send(self, body, status=200, headers=None):
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body.encode() if isinstance(body, str) else body)

    def _cookie(self, name):
        for pair in (self.headers.get("Cookie") or "").split(";"):
            key, _, value = pair.strip().partition("=")
            if key == name:
                return unquote(value)
        return ""

    def do_GET(self):
        path = urlsplit(self.path).path
        self.seen.append(("GET", self.path, dict(self.headers), b""))
        if path in ("/h", "/api/h"):
            return self._send(f"<p>{self.headers.get('X-Theme', '')}</p>")
        if path == "/h-safe":
            return self._send(f"<p>{html.escape(self.headers.get('X-Theme', ''))}</p>")
        if path == "/h-noisy":
            return self._send("<script>alert('hello')</script>"
                              f"<p>{html.escape(self.headers.get('X-Theme', ''))}</p>")
        if path == "/c":
            return self._send(f"<p>{self._cookie('lang')}</p>")
        if path.startswith("/u/"):
            return self._send(f"<p>{unquote(path.split('/')[2])}</p>")
        if path == "/redir":
            return self._send("", 302, {"Location": "/h"})
        if path == "/page-h":
            return self._send(RENDER_FETCH % "'/api/h', {headers: {'X-Theme': 'light'}}")
        if path == "/page-j":
            return self._send(RENDER_FETCH % (
                "'/api/j', {method: 'POST', headers: {'Content-Type': 'application/json'}, "
                "body: JSON.stringify({k: 1, a: {b: 'hi'}})}"))
        if path == "/page-none":
            return self._send("<p>no fetch here</p>")
        return self._send("ok")

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.seen.append(("POST", self.path, dict(self.headers), body))
        path = urlsplit(self.path).path
        if path == "/f":
            from urllib.parse import parse_qs

            return self._send(f"<p>{parse_qs(body.decode())['q'][0]}</p>")
        if path in ("/j", "/api/j"):
            return self._send(f"<p>{json.loads(body)['a']['b']}</p>")
        if path == "/x":
            import xml.etree.ElementTree as ET

            return self._send(f"<p>{ET.fromstring(body).find('n').text}</p>")
        return self._send("ok")


@pytest.fixture
def lab(monkeypatch):
    executable = os.environ.get("ASSESSMENT_TEST_CHROMIUM")
    if executable:
        monkeypatch.setenv("AEGIS_CHROMIUM_PATH", executable)
    Lab.seen = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Lab)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


async def _run(base, *, method="GET", path, location, parameter, page="", state=None,
               payload=PAYLOAD):
    spec = bi.plan_intercept(method=method, url=base + path, location=location,
                             parameter=parameter, payload_template=payload,
                             page_url=base + page if page else "", state=state)
    result, _ = await bi.check_intercept_xss(spec, allowed_origins=[base], storage_state=state)
    return result


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path,location,parameter,page", [
    ("GET", "/h", "header", "X-Theme", ""),
    ("GET", "/c", "cookie", "lang", ""),
    ("POST", "/f", "body_form", "q", ""),
    ("POST", "/j", "body_json", "/a/b", ""),
    ("POST", "/x", "body_xml", "/o/n", ""),
    ("GET", "/u/alice", "path", "alice", ""),
    ("GET", "/api/h", "header", "X-Theme", "/page-h"),
    ("POST", "/api/j", "body_json", "/a/b", "/page-j"),
])
async def test_each_location_executes_only_through_the_mutated_request(
        lab, method, path, location, parameter, page):
    result = await _run(lab, method=method, path=path, location=location,
                        parameter=parameter, page=page)
    assert result["executed"] is True, result
    assert result["intercept_mutated"] and result["mutated_response_seen"]
    assert result["intercept_mode"] == ("fetch" if page else "document")
    assert bi.receipt_valid({**result})
    mutated = [row for row in Lab.seen if result["nonce"] in (
        unquote(row[1]) + json.dumps(row[2]) + unquote(row[3].decode()))]
    assert len(mutated) == 1
    sent_method, url, headers, body = mutated[0]
    assert sent_method == method
    if location == "path":
        assert result["path_template"] == "/u/alice" and result["path_segment_index"] == 2
    if page == "/page-j":
        # Only the one field changed; the page's other field is untouched.
        assert json.loads(body) == {"k": 1, "a": {"b": PAYLOAD.replace(
            "__PROWL_NONCE__", result["nonce"])}}


@pytest.mark.asyncio
async def test_reflection_only_unrelated_dialog_and_never_sent_are_inconclusive(lab):
    safe = await _run(lab, path="/h-safe", location="header", parameter="X-Theme")
    assert safe["executed"] is False and safe["intercept_mutated"] is True
    assert "html_text" in safe["reflection_contexts"]
    noisy = await _run(lab, path="/h-noisy", location="header", parameter="X-Theme")
    assert noisy["executed"] is False and noisy["dialog_count"] >= 1
    never = await _run(lab, path="/api/h", location="header", parameter="X-Theme",
                       page="/page-none")
    assert never["executed"] is False and never["intercept_mutated"] is False
    assert not bi.receipt_valid(never)


@pytest.mark.asyncio
async def test_redirect_is_refused_not_followed(lab):
    result = await _run(lab, path="/redir", location="header", parameter="X-Theme")
    assert result["mutated_redirect_refused"] is True and result["executed"] is False
    assert not any(row[1] == "/h" for row in Lab.seen)


@pytest.mark.asyncio
async def test_httponly_cookie_in_live_jar_is_never_mutated(lab):
    host = urlsplit(lab).hostname
    state = {"cookies": [{"name": "lang", "value": "en", "domain": host, "path": "/",
                          "httpOnly": True, "secure": False, "sameSite": "Lax",
                          "expires": -1}], "origins": []}
    with pytest.raises(ValueError, match="protected_cookie"):
        await _run(lab, path="/c", location="cookie", parameter="lang", state=state)
