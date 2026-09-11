from app.services.browser_automation_service import (
    BrowserSessionResult,
    _format_session_output,
)


def test_browser_output_redacts_password_totp_and_cookies():
    session = BrowserSessionResult(success=True, actions_executed=2)
    session.results = [
        {
            "action": "fill",
            "success": True,
            "data": {"selector": "input[type='password']", "value": "password-value"},
        },
        {
            "action": "fill",
            "success": True,
            "data": {"selector": "input[name='totp']", "value": "123456"},
        },
    ]
    session.final_cookies = [
        {"name": "session", "value": "cookie-value", "domain": "app.test"}
    ]

    output = _format_session_output(session)
    assert "password-value" not in output
    assert "123456" not in output
    assert "cookie-value" not in output
    assert output.count("[redacted]") == 3
