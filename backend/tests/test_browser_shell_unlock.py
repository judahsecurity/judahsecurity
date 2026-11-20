"""Credential-free rendering of a single-page app's signed-in shell."""

import base64
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.services.agent.scoped_assessment.browser_actions import allowed_discovery_path
from app.services.agent.scoped_assessment.browser_shell_unlock import (
    PLACEHOLDER_JWT,
    choose_routes,
    is_bootstrap_path,
    looks_unauthenticated,
    normalize_route,
    routes_from_sources,
    stub_body,
)


def test_placeholder_token_is_jwt_shaped_but_not_alg_none():
    header, payload, signature = PLACEHOLDER_JWT.split(".")
    decoded = json.loads(base64.urlsafe_b64decode(header + "=="))
    assert decoded["alg"] == "HS256"
    assert signature
    assert json.loads(base64.urlsafe_b64decode(payload + "=="))["exp"] > 4_000_000_000


@pytest.mark.parametrize("status,ctype,body,expected", [
    (401, "text/html", b"", True),
    (403, "application/json", b"{}", True),
    (200, "application/json", b'{"code":401,"msg":"token expired"}', True),
    (200, "application/json", b'{"code":1001,"message":"Please log in"}', True),
    (200, "application/json", b'{"code":0,"data":[]}', False),
    (200, "application/json", b'{"code":0,"msg":"login ok"}', False),
    (200, "application/json", b'[1,2]', False),
    (200, "text/html", b"please log in", False),
    (404, "application/json", b'{"error":"not found"}', False),
])
def test_unauthenticated_detection(status, ctype, body, expected):
    assert looks_unauthenticated(status, ctype, body) is expected


def test_stub_bodies():
    assert is_bootstrap_path("/api/user/info")
    assert is_bootstrap_path("/api/v1/me")
    assert not is_bootstrap_path("/api/orders")
    user = json.loads(stub_body("/api/getInfo"))
    assert user["code"] == 0 and user["data"]["roles"] == ["admin"]
    plain = json.loads(stub_body("/api/orders"))
    assert plain["data"] == {} and "roles" not in plain


def test_route_normalization_and_choice():
    assert normalize_route("/users/:id/edit") == "/users/1/edit"
    assert normalize_route("/files/[slug]") == "/files/1"
    assert normalize_route("#/settings/") == "#/settings"
    assert normalize_route("//evil.example/x") == ""
    assert normalize_route("/a?b=1") == ""
    assert normalize_route("javascript:alert(1)") == ""
    chosen = choose_routes(
        ["/dashboard", "/login", "/users/:id", "/dashboard", "/logout", "#/reports", 5],
        allowed_path=allowed_discovery_path,
    )
    assert chosen == ["/dashboard", "/users/1", "#/reports"]


def test_routes_from_router_tables():
    sources = [{"data": b"const r=[{path:'/admin/users',component:A},{path: \"/billing/:id\"}]"}]
    assert routes_from_sources(sources) == ["/admin/users", "/billing/1"]


# ---------------------------------------------------------------------------
# Real Chromium against a small app with a client-side login gate
# ---------------------------------------------------------------------------

_APP = """<!doctype html><html><body><div id="app">loading</div><script>
const token = localStorage.getItem('token');
async function render() {
  if (!token) { history.replaceState({}, '', '/login'); app.textContent = 'login'; return; }
  const me = await (await fetch('/api/user/info', {headers: {Authorization: 'Bearer ' + token}})).json();
  if (me.code !== 0) { history.replaceState({}, '', '/login'); app.textContent = 'login'; return; }
  const route = location.pathname;
  if (route === '/' || route === '/dashboard') {
    await fetch('/api/orders?page=1&size=20');
    app.innerHTML = '<a href="/reports">Reports</a>';
  }
  if (route === '/reports') {
    await fetch('/api/reports/summary?range=7d');
    await fetch('/api/reports/export', {method: 'POST', body: JSON.stringify({fmt: 'csv'}),
                                       headers: {'Content-Type': 'application/json'}});
  }
}
window.addEventListener('popstate', render);
render();
</script></body></html>"""


@pytest.mark.skipif(os.environ.get("RUN_ASSESSMENT_BROWSER_TESTS") != "1",
                    reason="real Chromium smoke is opt-in")
@pytest.mark.asyncio
async def test_shell_unlock_reaches_apis_behind_the_login_gate():
    from app.services.agent.scoped_assessment.browser import check_browser

    seen = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, status, ctype, body):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            seen.append(("GET", self.path, self.headers.get("Authorization", "")))
            if self.path.startswith("/api/"):
                self._send(401, "application/json", b'{"error":"unauthorized"}')
            else:
                self._send(200, "text/html", _APP.encode())

        def do_POST(self):
            seen.append(("POST", self.path, ""))
            self._send(500, "text/plain", b"must not be reached")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        anonymous, _ = await check_browser(
            operation="map", url=base + "/", allowed_origins=[base],
        )
        unlocked, _ = await check_browser(
            operation="map", url=base + "/", allowed_origins=[base],
            unlock_shell=True, shell_routes=["/reports"],
        )
    finally:
        server.shutdown()

    anonymous_paths = {row["path"] for row in anonymous["requests"]}
    assert "/api/orders" not in anonymous_paths

    shell = unlocked["shell_unlock"]
    gated = {(row["method"], row["path"]) for row in shell["auth_gated"]}
    assert ("GET", "/api/user/info") in gated
    assert ("GET", "/api/orders") in gated
    assert ("GET", "/api/reports/summary") in gated
    # The state-changing request is recorded but never reaches the server.
    export = next(row for row in unlocked["requests"] if row["path"] == "/api/reports/export")
    assert export["method"] == "POST" and export["not_sent"] is True
    assert not any(method == "POST" for method, _, _ in seen)
    # Real statuses are reported, not the page's placeholder.
    orders = next(row for row in unlocked["requests"] if row["path"] == "/api/orders")
    assert orders["status"] == 401 and orders["auth_gated"] is True
    assert shell["routes"][0]["route"] == "/reports"
    assert shell["routes"][0]["login_redirect"] is False
    # The placeholder token reached the server only as an unauthenticated header.
    assert any(auth.startswith("Bearer " + PLACEHOLDER_JWT[:10]) for _, _, auth in seen)
