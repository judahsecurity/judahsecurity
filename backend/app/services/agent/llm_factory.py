"""
Provider-agnostic LLM factory.

Builds a LangChain chat model for any supported provider from a single
``provider:model`` spec, so the rest of the codebase never has to branch on
``ChatAnthropic`` vs ``ChatOpenAI`` vs a DeepSeek endpoint.

Security invariant
------------------
API keys handled here are ONLY ever passed to the SDK client constructor. They
are never logged, never returned, and must never be placed into an LLM prompt,
tool output, or agent state. Logging in this module deliberately records the
provider and model only.

Adding a provider is a registry change, not new call-site code.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Optional

from langchain_core.language_models.chat_models import BaseChatModel

from app.models.api_config import ExternalService

logger = logging.getLogger(__name__)


# OpenAI-compatible providers only differ by base_url + which key they read.
# Ollama's URL is resolved at construct time from settings (host vs Docker).
_OPENAI_COMPATIBLE_BASE_URLS = {
    ExternalService.DEEPSEEK: "https://api.deepseek.com/v1",
    ExternalService.OPENROUTER: "https://openrouter.ai/api/v1",
    # International Moonshot endpoint. China mainland: https://api.moonshot.cn/v1
    ExternalService.KIMI: "https://api.moonshot.ai/v1",
    ExternalService.GROQ: "https://api.groq.com/openai/v1",
}

# Fallback default model per provider, used when a spec omits the model half.
DEFAULT_MODEL_BY_PROVIDER = {
    ExternalService.ANTHROPIC: "claude-sonnet-4-6",
    ExternalService.OPENAI: "gpt-4o",
    ExternalService.DEEPSEEK: "deepseek-chat",
    ExternalService.KIMI: "kimi-k3",
    ExternalService.GROQ: "llama-3.3-70b-versatile",
    ExternalService.OLLAMA: "qwen2.5:14b",
    ExternalService.GEMINI: "gemini-2.5-pro",
    ExternalService.OPENROUTER: "openai/gpt-4o",
}


class UnsupportedProviderError(ValueError):
    """Raised when a provider has no factory mapping."""


def parse_model_spec(spec: str, default_provider: str = ExternalService.ANTHROPIC) -> tuple[str, str]:
    """Split a ``"provider:model"`` spec into ``(provider, model)``.

    Accepts a bare model string too (falls back to ``default_provider``). Only
    the first ``:`` is treated as the provider separator so model IDs that
    themselves contain ``:`` (e.g. Bedrock-style) survive intact.
    """
    spec = (spec or "").strip()
    if not spec:
        return default_provider, DEFAULT_MODEL_BY_PROVIDER.get(default_provider, "")

    if ":" in spec:
        provider, model = spec.split(":", 1)
        provider = provider.strip().lower()
        model = model.strip()
        if provider in DEFAULT_MODEL_BY_PROVIDER:
            return provider, (model or DEFAULT_MODEL_BY_PROVIDER[provider])

    # No recognized provider prefix -> treat the whole string as a model name.
    return default_provider, spec


def _key_fingerprint(api_key: Optional[str]) -> str:
    if not api_key:
        return "none"
    return hashlib.sha256(api_key.encode()).hexdigest()[:8]


def _ollama_base_url() -> str:
    from app.core.config import settings
    return (getattr(settings, "OLLAMA_BASE_URL", None) or "http://127.0.0.1:11434/v1").rstrip("/")


def _base_url_for_provider(provider: str) -> Optional[str]:
    if provider == ExternalService.OLLAMA:
        return _ollama_base_url()
    return _OPENAI_COMPATIBLE_BASE_URLS.get(provider)


# Cache constructed models. Keyed by everything that affects construction,
# including a NON-reversible fingerprint of the key (never the key itself).
_MODEL_CACHE: dict[tuple, BaseChatModel] = {}


def build_chat_model(
    provider: str,
    model: str,
    api_key: Optional[str],
    *,
    temperature: Optional[float] = 0,
    max_tokens: Optional[int] = None,
    timeout: Optional[float] = 120,
    max_retries: int = 2,
    use_cache: bool = True,
) -> BaseChatModel:
    """Construct (or return a cached) LangChain chat model for ``provider``.

    ``provider`` must be one of the LLM ``ExternalService`` names. ``api_key``
    is passed straight to the SDK client and is otherwise never retained in a
    loggable form.
    """
    provider = (provider or "").strip().lower()

    cache_key = (
        provider, model, _key_fingerprint(api_key),
        temperature, max_tokens, timeout, max_retries,
        _base_url_for_provider(provider) if provider == ExternalService.OLLAMA else None,
    )
    if use_cache and cache_key in _MODEL_CACHE:
        return _MODEL_CACHE[cache_key]

    logger.info("Building chat model provider=%s model=%s (key=%s)",
                provider, model, "set" if api_key else "MISSING")

    llm = _construct(
        provider, model, api_key,
        temperature=temperature, max_tokens=max_tokens,
        timeout=timeout, max_retries=max_retries,
    )

    if use_cache:
        _MODEL_CACHE[cache_key] = llm
    return llm


def _construct(
    provider: str,
    model: str,
    api_key: Optional[str],
    *,
    temperature: Optional[float],
    max_tokens: Optional[int],
    timeout: Optional[float],
    max_retries: int,
) -> BaseChatModel:
    # Common kwargs; drop None so provider defaults apply (e.g. reasoning models
    # that reject an explicit temperature).
    common: dict = {"timeout": timeout, "max_retries": max_retries}
    if temperature is not None:
        common["temperature"] = temperature
    if max_tokens is not None:
        common["max_tokens"] = max_tokens

    if provider == ExternalService.ANTHROPIC:
        from langchain_anthropic import ChatAnthropic
        kwargs = dict(common)
        if api_key:
            kwargs["api_key"] = api_key
        return ChatAnthropic(model=model, **kwargs)

    if provider == ExternalService.OPENAI:
        from langchain_openai import ChatOpenAI
        kwargs = dict(common)
        if api_key:
            kwargs["api_key"] = api_key
        return ChatOpenAI(model=model, **kwargs)

    base_url = _base_url_for_provider(provider)
    if base_url:
        # DeepSeek / Groq / Kimi / Ollama / OpenRouter speak the OpenAI wire protocol.
        from langchain_openai import ChatOpenAI
        kwargs = dict(common)
        # Ollama accepts any non-empty key; SDKs often require one to be set.
        if api_key:
            kwargs["api_key"] = api_key
        elif provider == ExternalService.OLLAMA:
            kwargs["api_key"] = "ollama"
        kwargs["base_url"] = base_url
        return ChatOpenAI(model=model, **kwargs)

    if provider == ExternalService.GEMINI:
        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
        except ImportError as exc:
            raise UnsupportedProviderError(
                "Gemini support requires the 'langchain-google-genai' package"
            ) from exc
        kwargs = dict(common)
        if api_key:
            kwargs["google_api_key"] = api_key
        return ChatGoogleGenerativeAI(model=model, **kwargs)

    raise UnsupportedProviderError(f"Unsupported LLM provider: {provider!r}")
