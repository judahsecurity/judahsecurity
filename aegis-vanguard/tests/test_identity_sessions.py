import json


from agent.identity_sessions import IdentitySessionManager


LOGIN_PAGE = """
<html><form method="post" action="/session">
  <input type="hidden" name="csrf_token" value="login-csrf">
  <input type="email" name="email">
  <input type="password" name="password">
</form></html>
"""


def _credential_identity():
    return {
        "label": "owner",
        "username": "alice@example.test",
        "password": "secret-password",
        "role": "member",
        "tenant": "a",
        "headers": {},
        "login": {},
    }


def _login_surface():
    return {
        "forms": [{
            "source_url": "https://example.test/login",
            "action_url": "https://example.test/session",
            "method": "POST",
            "content_type": "application/x-www-form-urlencoded",
            "controls": [
                {"name": "email", "type": "email"},
                {"name": "password", "type": "password"},
            ],
            "eligible_parameters": ["email", "password"],
        }],
    }


def test_login_discovers_form_preserves_cookie_and_hides_secrets():
    calls = []

    def transport(method, url, headers, body, follow_redirects):
        calls.append((method, url, dict(headers), body, follow_redirects))
        if url.endswith("/login"):
            return {"status": 200, "body": LOGIN_PAGE, "headers": {"Set-Cookie": "pre=one"}}
        if url.endswith("/session"):
            assert "pre=one" in headers.get("Cookie", "")
            assert "email=alice%40example.test" in body
            assert "password=secret-password" in body
            assert "csrf_token=login-csrf" in body
            return {
                "status": 302,
                "body": "",
                "raw_headers": (
                    "HTTP/1.1 302 Found\r\n"
                    "Location: /dashboard\r\n"
                    "Set-Cookie: session=private-cookie; HttpOnly\r\n\r\n"
                ),
            }
        assert url.endswith("/dashboard")
        assert "session=private-cookie" in headers.get("Cookie", "")
        return {"status": 200, "body": "Welcome Alice", "headers": {}}

    manager = IdentitySessionManager(transport=transport)
    manager.configure([_credential_identity()], "https://example.test", _login_surface())

    status = manager.establish("owner")

    assert status["state"] == "authenticated"
    assert status["evidence"] == "session_cookie+redirect"
    assert status["cookie_names"] == ["pre", "session"]
    public = json.dumps(status)
    assert "secret-password" not in public
    assert "private-cookie" not in public
    assert len(calls) == 3





def test_failed_login_cookie_does_not_create_false_authenticated_state():
    def transport(method, url, headers, body, follow_redirects):
        if url.endswith("/login"):
            return {"status": 200, "body": LOGIN_PAGE, "headers": {}}
        return {
            "status": 500,
            "body": "login failed",
            "headers": {"Set-Cookie": "session=failed-login-cookie"},
        }

    manager = IdentitySessionManager(transport=transport)
    manager.configure([_credential_identity()], "https://example.test", _login_surface())

    status = manager.establish("owner")

    assert status["state"] == "rejected"
    assert "failure" in status["error"]


def test_default_transport_does_not_follow_redirects_and_keeps_set_cookie():
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from agent.identity_sessions import _default_transport, _set_cookie_values

    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            seen.append(self.path)
            self.send_response(302)
            self.send_header("Location", "/after")
            self.send_header("Set-Cookie", "sid=abc; HttpOnly")
            self.send_header("Set-Cookie", "pref=1")
            self.end_headers()

        do_GET = do_POST

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/session"
        response = _default_transport("POST", url, {"Content-Type": "text/plain"}, "x=1", False)
    finally:
        server.shutdown()
    assert response["status"] == 302 and seen == ["/session"]
    assert sorted(_set_cookie_values(response)) == ["pref=1", "sid=abc; HttpOnly"]

