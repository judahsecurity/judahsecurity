import json

import pytest

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


def test_identity_request_injects_fresh_csrf_without_exposing_session():
    def transport(method, url, headers, body, follow_redirects):
        if url.endswith("/verify"):
            return {"status": 200, "body": "private account", "headers": {}}
        if url.endswith("/settings"):
            return {
                "status": 200,
                "body": '<form><input type="hidden" name="_csrf" value="fresh-token"></form>',
                "headers": {},
            }
        assert url.endswith("/change-email")
        assert headers["Authorization"] == "Bearer internal-token"
        assert body == "email=new%40example.test&_csrf=fresh-token"
        return {
            "status": 200,
            "body": "updated fresh-token",
            "headers": {"Set-Cookie": "session=rotated-secret", "X-Test": "ok"},
        }

    manager = IdentitySessionManager(transport=transport)
    manager.configure([{
        "label": "member",
        "username": "",
        "password": "",
        "role": "member",
        "tenant": "a",
        "headers": {"Authorization": "Bearer internal-token"},
        "login": {"verify_url": "https://example.test/verify"},
    }], "https://example.test")
    assert manager.establish("member")["state"] == "ready_unverified"

    result = manager.request(
        "member",
        "POST",
        "https://example.test/change-email",
        body="email=new%40example.test&_csrf={{csrf}}",
        csrf_url="https://example.test/settings",
    )

    assert result["status"] == 200
    assert result["headers"]["set-cookie"] == "[REDACTED]"
    rendered = json.dumps(result)
    assert "internal-token" not in rendered
    assert "rotated-secret" not in rendered
    assert "fresh-token" not in rendered


def test_identity_authz_diff_uses_labels_and_emits_per_identity_coverage():
    object_body = json.dumps({"id": 42, "owner": "alice", "private": "x" * 80})

    def transport(method, url, headers, body, follow_redirects):
        auth = headers.get("Authorization", "")
        if url.endswith("/private/42"):
            if auth in {"Bearer owner-token", "Bearer other-token"}:
                return {"status": 200, "body": object_body, "headers": {}}
            return {"status": 403, "body": "denied", "headers": {}}
        return {"status": 200, "body": "public", "headers": {}}

    manager = IdentitySessionManager(transport=transport)
    manager.configure([
        {"label": "owner", "headers": {"Authorization": "Bearer owner-token"},
         "username": "", "password": "", "role": "member", "tenant": "a", "login": {}},
        {"label": "other", "headers": {"Authorization": "Bearer other-token"},
         "username": "", "password": "", "role": "member", "tenant": "b", "login": {}},
    ], "https://example.test")
    manager.establish("owner")
    manager.establish("other")

    result = manager.authz_diff(
        "owner", "other", "https://example.test/private/42"
    )

    assert result["verdict"]["finding"] == "idor"
    assert result["candidates"][0]["other_identity"] == "other"
    states = {item["identity"]: item["status"] for item in result["coverage"]}
    assert states == {
        "owner": "tested_negative",
        "other": "candidate",
        "anonymous": "tested_negative",
    }


def test_identity_request_rejects_cross_origin_and_session_header_override():
    manager = IdentitySessionManager(
        transport=lambda method, url, headers, body, follow: {
            "status": 200, "body": "ok", "headers": {}
        }
    )
    manager.configure([{
        "label": "member", "headers": {"Authorization": "Bearer token"},
        "username": "", "password": "", "role": "member", "tenant": "a", "login": {},
    }], "https://example.test")
    manager.establish("member")

    override = manager.request(
        "member", "GET", "https://example.test/private",
        headers={"Authorization": "Bearer replacement"},
    )
    assert "cannot override" in override["error"]

    with pytest.raises(ValueError, match="target origin"):
        manager.request("member", "GET", "https://evil.test/private")


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


def test_identity_tools_reach_validation_and_exploit_phases():
    from agent.agents import (
        create_exploit_agent,
        create_exploit_chain_agent,
        create_validator_agent,
    )

    required = {
        "identity_session_status", "identity_request", "identity_authz_diff",
    }
    for agent in (
        create_validator_agent(), create_exploit_chain_agent(), create_exploit_agent()
    ):
        assert required <= set(agent.tool_names or [])
