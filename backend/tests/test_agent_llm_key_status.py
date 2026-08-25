"""LLM provider key failures must not look like a user session 401."""

from fastapi import HTTPException

from app.api.routes.agent import _handle_agent_error


def test_invalid_cloud_llm_key_is_not_session_unauthorized():
    try:
        _handle_agent_error("Error code: 401 - authentication_error: API key is invalid")
    except HTTPException as exc:
        assert exc.status_code == 502
        assert "API key is invalid" in str(exc.detail)
    else:
        raise AssertionError("expected HTTPException")
