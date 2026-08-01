"""
Task -> model routing.

Maps a *task category* (reasoning, offensive, report) to a concrete
``provider:model`` for a given organization, then builds the chat model via the
provider-agnostic factory using the org's own key (bring-your-own-key).

Resolution precedence for a task, most specific first:

1. Per-org agent config ``task_models[<task>]``      (e.g. "anthropic:claude-sonnet-4-6")
2. Per-org agent config legacy ``llm_provider`` + ``llm_model``
3. Global defaults from ``settings`` (AI_PROVIDER + that provider's model)

If the preferred cloud provider has no API key and ``OLLAMA_FALLBACK_ENABLED``
is on, the router falls back to a reachable local Ollama instance.

Keys are resolved separately per provider and passed only to the SDK client.
"""

from __future__ import annotations

import logging
import time
from typing import Optional
from urllib.parse import urlparse
from urllib.request import urlopen

from langchain_core.language_models.chat_models import BaseChatModel

from app.core.config import settings
from app.models.api_config import (
    KEYLESS_LLM_PROVIDERS,
    ExternalService,
    resolve_llm_key,
)
from app.services.agent.llm_factory import (
    DEFAULT_MODEL_BY_PROVIDER,
    build_chat_model,
    parse_model_spec,
)

logger = logging.getLogger(__name__)


# ── Task categories ───────────────────────────────────────────────────────
class LLMTask:
    REASONING = "reasoning"   # agent planning / analysis / orchestration
    OFFENSIVE = "offensive"   # exploit agents, pentest, red-team (Claude-leaning)
    REPORT = "report"         # findings write-up / summarization


ALL_TASKS = (LLMTask.REASONING, LLMTask.OFFENSIVE, LLMTask.REPORT)

# Cache Ollama reachability briefly so we don't probe on every LLM call.
_OLLAMA_REACHABLE_CACHE: dict[str, tuple[bool, float]] = {}
_OLLAMA_REACHABLE_TTL_SECONDS = 30.0


def _settings_key_for_provider(provider: str) -> Optional[str]:
    """Final key fallback from global settings (covers local .env where keys are
    loaded into ``settings`` but not necessarily ``os.environ``)."""
    if provider == ExternalService.ANTHROPIC:
        return getattr(settings, "ANTHROPIC_API_KEY", None)
    if provider == ExternalService.OPENAI:
        return getattr(settings, "OPENAI_API_KEY", None)
    if provider == ExternalService.DEEPSEEK:
        return getattr(settings, "DEEPSEEK_API_KEY", None)
    if provider == ExternalService.KIMI:
        return getattr(settings, "MOONSHOT_API_KEY", None)
    if provider == ExternalService.GROQ:
        return getattr(settings, "GROQ_API_KEY", None)
    if provider == ExternalService.OPENROUTER:
        return getattr(settings, "OPENROUTER_API_KEY", None)
    return None


def _global_default_spec() -> str:
    """Build a ``provider:model`` spec from global settings."""
    provider = (getattr(settings, "AI_PROVIDER", "") or "").strip().lower()
    if provider == ExternalService.OPENAI:
        model = getattr(settings, "OPENAI_MODEL", "") or DEFAULT_MODEL_BY_PROVIDER[ExternalService.OPENAI]
        return f"{ExternalService.OPENAI}:{model}"
    if provider == ExternalService.DEEPSEEK:
        model = getattr(settings, "DEEPSEEK_MODEL", "") or DEFAULT_MODEL_BY_PROVIDER[ExternalService.DEEPSEEK]
        return f"{ExternalService.DEEPSEEK}:{model}"
    if provider == ExternalService.KIMI:
        model = getattr(settings, "KIMI_MODEL", "") or DEFAULT_MODEL_BY_PROVIDER[ExternalService.KIMI]
        return f"{ExternalService.KIMI}:{model}"
    if provider == ExternalService.GROQ:
        model = getattr(settings, "GROQ_MODEL", "") or DEFAULT_MODEL_BY_PROVIDER[ExternalService.GROQ]
        return f"{ExternalService.GROQ}:{model}"
    if provider == ExternalService.OLLAMA:
        model = getattr(settings, "OLLAMA_MODEL", "") or DEFAULT_MODEL_BY_PROVIDER[ExternalService.OLLAMA]
        return f"{ExternalService.OLLAMA}:{model}"
    # Default/anthropic.
    model = getattr(settings, "ANTHROPIC_MODEL", "") or DEFAULT_MODEL_BY_PROVIDER[ExternalService.ANTHROPIC]
    return f"{ExternalService.ANTHROPIC}:{model}"


def resolve_model_spec_for_task(agent_config: Optional[dict], task: str) -> str:
    """Return the ``provider:model`` spec for ``task`` given an org agent config.

    ``agent_config`` is the merged per-org ``MODULE_AGENT`` config (or None).
    """
    cfg = agent_config or {}

    task_models = cfg.get("task_models") or {}
    if isinstance(task_models, dict):
        spec = task_models.get(task) or task_models.get("default")
        if spec:
            return str(spec)

    # Legacy single-model fields.
    provider = (cfg.get("llm_provider") or "").strip().lower()
    model = (cfg.get("llm_model") or "").strip()
    if provider and model:
        return f"{provider}:{model}"
    if model:  # model without provider -> let the factory infer default provider
        return model

    return _global_default_spec()


def _ollama_probe_url() -> str:
    base = (getattr(settings, "OLLAMA_BASE_URL", None) or "http://127.0.0.1:11434/v1").rstrip("/")
    # ChatOpenAI uses .../v1; Ollama native health is on the host root /api/tags.
    if base.endswith("/v1"):
        root = base[:-3]
    else:
        parsed = urlparse(base)
        root = f"{parsed.scheme}://{parsed.netloc}"
    return f"{root}/api/tags"


def ollama_is_reachable(timeout: float = 0.75) -> bool:
    """Return True if a local Ollama daemon responds (cached briefly)."""
    url = _ollama_probe_url()
    now = time.monotonic()
    cached = _OLLAMA_REACHABLE_CACHE.get(url)
    if cached and (now - cached[1]) < _OLLAMA_REACHABLE_TTL_SECONDS:
        return cached[0]

    ok = False
    try:
        with urlopen(url, timeout=timeout) as resp:  # nosec B310 — fixed local admin URL
            ok = 200 <= getattr(resp, "status", 200) < 300
    except Exception:
        ok = False

    _OLLAMA_REACHABLE_CACHE[url] = (ok, now)
    return ok


def _maybe_fallback_to_ollama(
    provider: str,
    model: str,
    api_key: Optional[str],
) -> tuple[str, str, Optional[str]]:
    """If cloud key is missing, optionally fall back to local Ollama."""
    if provider in KEYLESS_LLM_PROVIDERS:
        return provider, model, api_key or "ollama"

    if api_key:
        return provider, model, api_key

    if not getattr(settings, "OLLAMA_FALLBACK_ENABLED", True):
        return provider, model, api_key

    if not ollama_is_reachable():
        logger.warning(
            "No API key for provider=%s and Ollama is not reachable at %s",
            provider, getattr(settings, "OLLAMA_BASE_URL", ""),
        )
        return provider, model, api_key

    fallback_model = (
        getattr(settings, "OLLAMA_MODEL", None)
        or DEFAULT_MODEL_BY_PROVIDER[ExternalService.OLLAMA]
    )
    logger.warning(
        "No API key for provider=%s; falling back to local Ollama model=%s",
        provider, fallback_model,
    )
    return ExternalService.OLLAMA, fallback_model, "ollama"


def get_llm_for_task(
    db,
    organization_id: Optional[int],
    task: str,
    *,
    agent_config: Optional[dict] = None,
    temperature: Optional[float] = 0,
    max_tokens: Optional[int] = None,
    timeout: Optional[float] = 120,
    max_retries: int = 2,
) -> BaseChatModel:
    """Resolve the model + key for ``task``/``organization_id`` and build it.

    Pass ``agent_config`` if already loaded to avoid a second DB read; otherwise
    it is fetched from ``MODULE_AGENT`` project settings.
    """
    if agent_config is None:
        agent_config = _load_agent_config(db, organization_id)

    spec = resolve_model_spec_for_task(agent_config, task)
    provider, model = parse_model_spec(spec)

    api_key = resolve_llm_key(db, provider, organization_id) or _settings_key_for_provider(provider)
    provider, model, api_key = _maybe_fallback_to_ollama(provider, model, api_key)

    logger.info(
        "Resolved LLM task=%s org=%s -> provider=%s model=%s",
        task, organization_id, provider, model,
    )

    return build_chat_model(
        provider, model, api_key,
        temperature=temperature, max_tokens=max_tokens,
        timeout=timeout, max_retries=max_retries,
    )


def _load_agent_config(db, organization_id: Optional[int]) -> dict:
    """Best-effort load of the per-org MODULE_AGENT config."""
    if db is None or organization_id is None:
        return {}
    try:
        from app.models.project_settings import MODULE_AGENT, ProjectSettings
        return ProjectSettings.get_config(db, organization_id, MODULE_AGENT) or {}
    except Exception:  # pragma: no cover - defensive; fall back to global defaults
        logger.debug("Could not load agent config for org=%s", organization_id, exc_info=True)
        return {}
