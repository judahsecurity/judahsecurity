"""Tests for cloud credit/quota → Ollama fallback helpers."""

from app.services.agent.model_router import is_llm_credit_or_quota_error


class _FakeStatusError(Exception):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.message = message


def test_detects_anthropic_credit_balance_error():
    exc = Exception(
        "Error code: 400 - {'type': 'error', 'error': {"
        "'type': 'invalid_request_error', "
        "'message': 'Your credit balance is too low to access the Anthropic API. "
        "Please go to Plans & Billing to upgrade or purchase credits.'}}"
    )
    assert is_llm_credit_or_quota_error(exc) is True


def test_detects_openai_insufficient_quota():
    exc = _FakeStatusError(
        "Error code: 429 - insufficient_quota: You exceeded your current quota",
        status_code=429,
    )
    assert is_llm_credit_or_quota_error(exc) is True


def test_detects_http_402():
    assert is_llm_credit_or_quota_error(_FakeStatusError("payment failed", 402)) is True


def test_detects_anthropic_invalid_api_key():
    exc = Exception(
        "Error code: 401 - {'type': 'error', 'error': {"
        "'type': 'authentication_error', 'message': 'API key is invalid.'}, "
        "'request_id': None}"
    )
    assert is_llm_credit_or_quota_error(exc) is True


def test_detects_http_401():
    assert is_llm_credit_or_quota_error(
        _FakeStatusError("API key is invalid.", 401)
    ) is True


def test_ignores_overloaded_and_generic_errors():
    assert is_llm_credit_or_quota_error(Exception("529 overloaded_error")) is False
    assert is_llm_credit_or_quota_error(Exception("connection reset by peer")) is False
    assert is_llm_credit_or_quota_error(ValueError("invalid tool args")) is False
