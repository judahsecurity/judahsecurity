"""Self-hosted OpenAI-protocol endpoints and LiteLLM model strings."""

import sys
import types

import pytest

from app.core.config import settings
from app.services.agent import llm_factory, model_router
from app.services.agent.llm_factory import (
    UnsupportedProviderError,
    build_chat_model,
    parse_model_spec,
    validate_model_base_url,
)


def test_parse_recognizes_new_provider_prefixes():
    assert parse_model_spec("openai_compatible:qwen3-coder") == ("openai_compatible", "qwen3-coder")
    assert parse_model_spec("litellm:bedrock/anthropic.claude-x:0") == (
        "litellm", "bedrock/anthropic.claude-x:0")


@pytest.mark.parametrize("url", [
    "ftp://models.local/v1", "http://user:pw@models.local/v1",
    "http://169.254.169.254/latest", "http://metadata.google.internal/v1",
    "http://[fe80::1]/v1", "http://models.local/v1?x=1",
])
def test_unsafe_base_urls_are_rejected(url):
    with pytest.raises(UnsupportedProviderError):
        validate_model_base_url(url)


def test_private_and_loopback_endpoints_are_allowed():
    assert validate_model_base_url("http://10.0.0.5:8000/v1/") == "http://10.0.0.5:8000/v1"
    assert validate_model_base_url("http://localhost:1234/v1") == "http://localhost:1234/v1"


def test_openai_compatible_uses_override_then_setting(monkeypatch):
    monkeypatch.setattr(settings, "OPENAI_COMPATIBLE_BASE_URL", "http://vllm.internal:8000/v1")
    llm = build_chat_model("openai_compatible", "qwen3", None, use_cache=False)
    assert llm.openai_api_base == "http://vllm.internal:8000/v1"
    assert llm.openai_api_key.get_secret_value() == "not-needed"
    llm = build_chat_model("openai_compatible", "qwen3", "k", use_cache=False,
                           base_url="http://lmstudio.local:1234/v1")
    assert llm.openai_api_base == "http://lmstudio.local:1234/v1"


def test_openai_compatible_requires_endpoint_and_model(monkeypatch):
    monkeypatch.setattr(settings, "OPENAI_COMPATIBLE_BASE_URL", None)
    with pytest.raises(UnsupportedProviderError):
        build_chat_model("openai_compatible", "qwen3", None, use_cache=False)
    with pytest.raises(UnsupportedProviderError):
        build_chat_model("openai_compatible", "", None, use_cache=False,
                         base_url="http://vllm.internal/v1")


def test_litellm_builds_through_optional_package(monkeypatch):
    captured = {}

    class FakeChatLiteLLM:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    module = types.ModuleType("langchain_litellm")
    module.ChatLiteLLM = FakeChatLiteLLM
    monkeypatch.setitem(sys.modules, "langchain_litellm", module)
    build_chat_model("litellm", "bedrock/anthropic.claude-x", None, use_cache=False,
                     base_url="http://litellm-proxy:4000")
    assert captured["model"] == "bedrock/anthropic.claude-x"
    assert captured["api_base"] == "http://litellm-proxy:4000"
    assert "api_key" not in captured


def test_litellm_without_package_is_a_clear_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "langchain_litellm", None)
    monkeypatch.setitem(sys.modules, "langchain_community.chat_models", None)
    with pytest.raises(UnsupportedProviderError, match="langchain-litellm"):
        build_chat_model("litellm", "vertex_ai/gemini-x", None, use_cache=False)


def test_router_passes_org_base_url_and_no_placeholder_key(monkeypatch):
    seen = {}

    def fake_build(provider, model, api_key, **kwargs):
        seen.update(provider=provider, model=model, api_key=api_key, base_url=kwargs.get("base_url"))
        return object()

    monkeypatch.setattr(model_router, "build_chat_model", fake_build)
    monkeypatch.setattr(model_router, "resolve_llm_key", lambda *_a, **_k: None)
    monkeypatch.setattr(model_router, "_attach_credit_fallback", lambda primary, *_a, **_k: primary)
    model_router.get_llm_for_task(None, 1, "reasoning", agent_config={
        "task_models": {"default": "openai_compatible:qwen3"},
        "llm_base_url": "http://vllm.internal:8000/v1",
    })
    assert seen == {"provider": "openai_compatible", "model": "qwen3", "api_key": None,
                    "base_url": "http://vllm.internal:8000/v1"}


def test_global_runtime_selects_configured_endpoint(monkeypatch):
    monkeypatch.setattr(settings, "AI_PROVIDER", "openai_compatible")
    monkeypatch.setattr(settings, "OPENAI_COMPATIBLE_MODEL", "qwen3")
    monkeypatch.setattr(settings, "OPENAI_COMPATIBLE_BASE_URL", "http://vllm.internal:8000/v1")
    assert model_router.global_runtime_model_spec() == ("openai_compatible", "qwen3")
    monkeypatch.setattr(settings, "OPENAI_COMPATIBLE_BASE_URL", None)
    assert model_router.global_runtime_model_spec() != ("openai_compatible", "qwen3")


def test_factory_module_exports_defaults_for_new_providers():
    assert llm_factory.DEFAULT_MODEL_BY_PROVIDER["openai_compatible"] == ""
    assert llm_factory.DEFAULT_MODEL_BY_PROVIDER["litellm"] == ""
