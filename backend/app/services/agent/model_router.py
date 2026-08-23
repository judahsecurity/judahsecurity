"""
Task -> model routing.

Maps a *task category* (reasoning, offensive, report) to a concrete
``provider:model`` for a given organization, then builds the chat model via the
provider-agnostic factory using the org's own key (bring-your-own-key).

Resolution precedence for a task, most specific first:

1. Per-org agent config ``task_models[<task>]``      (e.g. "anthropic:claude-sonnet-4-6")
2. Per-org agent config legacy ``llm_provider`` + ``llm_model``
3. Global defaults from ``settings`` (AI_PROVIDER + that provider's model)

Resilience (keep the product usable when a customer's preferred LLM is down):

- Preferred cloud provider has no API key → try other configured cloud keys, then Ollama
- Cloud call fails with credit/quota/billing/auth errors → retry remaining cloud
  providers that have keys, then Ollama
- Soft degrade notice is recorded (ContextVar) so the API can warn without failing

Keys are resolved separately per provider and passed only to the SDK client.
"""

from __future__ import annotations

import logging
import time
from contextvars import ContextVar
from typing import Any, List, Optional
from urllib.parse import urlparse
from urllib.request import urlopen

from langchain_core.callbacks import (
    AsyncCallbackManagerForLLMRun,
    CallbackManagerForLLMRun,
)
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import BaseMessage
from langchain_core.outputs import ChatResult
from pydantic import ConfigDict, Field

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


# Soft notice when a call degraded to a fallback provider (request-scoped).
_llm_degrade_notice: ContextVar[Optional[str]] = ContextVar(
    "llm_degrade_notice", default=None
)


def note_llm_degraded(message: str) -> None:
    """Record a customer-visible soft warning for the current request."""
    _llm_degrade_notice.set(message)


def consume_llm_degrade_notice() -> Optional[str]:
    """Return and clear any degrade notice for this request."""
    notice = _llm_degrade_notice.get()
    _llm_degrade_notice.set(None)
    return notice


# ── Task categories ───────────────────────────────────────────────────────
class LLMTask:
    REASONING = "reasoning"   # agent planning / analysis / orchestration
    OFFENSIVE = "offensive"   # exploit agents, pentest, red-team (Claude-leaning)
    REPORT = "report"         # findings write-up / summarization
    RECON = "recon"           # fireteam recon/coverage — cheaper model

ALL_TASKS = (LLMTask.REASONING, LLMTask.OFFENSIVE, LLMTask.REPORT, LLMTask.RECON)

# Prefer these clouds (in order) when the primary is unavailable / out of credits.
_CLOUD_FALLBACK_ORDER = (
    ExternalService.OPENAI,
    ExternalService.GROQ,
    ExternalService.DEEPSEEK,
    ExternalService.KIMI,
    ExternalService.OPENROUTER,
    ExternalService.ANTHROPIC,
)

# Cache Ollama reachability briefly so we don't probe on every LLM call.
_OLLAMA_REACHABLE_CACHE: dict[str, tuple[bool, float]] = {}
_OLLAMA_REACHABLE_TTL_SECONDS = 30.0

# Substrings that indicate the cloud provider rejected the call for billing /
# quota / auth reasons (not transient overload). Matched case-insensitively
# against the exception message + type name. These trigger provider cascade.
_CREDIT_QUOTA_MARKERS = (
    "credit balance is too low",
    "credit balance",
    "plans & billing",
    "plans and billing",
    "purchase credits",
    "insufficient_quota",
    "insufficient quota",
    "exceeded your current quota",
    "exceeded your quota",
    "billing hard limit",
    "billing_not_active",
    "payment required",
    "usage limit",
    "quota exceeded",
    "out of credits",
    "no credits",
    # Invalid / revoked / missing cloud keys — keep serving via another provider
    "authentication_error",
    "api key is invalid",
    "invalid api key",
    "invalid x-api-key",
    "incorrect api key",
    "invalid_api_key",
    "unauthorized",
)


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
        if not spec and task == LLMTask.RECON:
            spec = task_models.get(LLMTask.REPORT)
        if spec:
            return str(spec)

    # Recon defaults to Haiku when the org has not set a per-task model and the
    # global provider is Anthropic — flagship stays on offensive/reasoning.
    if task == LLMTask.RECON:
        provider = (cfg.get("llm_provider") or "").strip().lower() or (
            (getattr(settings, "AI_PROVIDER", "") or "").strip().lower()
        )
        if provider in ("", ExternalService.ANTHROPIC, "anthropic"):
            return "anthropic:claude-haiku-4-5"

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


def clear_ollama_reachability_cache() -> None:
    """Force the next Ollama probe to hit the network."""
    _OLLAMA_REACHABLE_CACHE.clear()


def is_llm_credit_or_quota_error(exc: BaseException) -> bool:
    """True when a provider rejected the call for billing / quota / bad API key.

    Auth failures are included so a revoked or invalid Anthropic/OpenAI key
    still falls through to local Ollama when fallback is enabled.
    """
    parts = [str(exc), type(exc).__name__]
    cause = getattr(exc, "__cause__", None)
    if cause is not None:
        parts.append(str(cause))
        parts.append(type(cause).__name__)
    # Anthropic / OpenAI SDK errors often stash the body on `.body` or `.message`
    for attr in ("message", "body", "response"):
        val = getattr(exc, attr, None)
        if val is not None:
            parts.append(str(val))
    for arg in getattr(exc, "args", ()) or ():
        parts.append(str(arg))
    haystack = " ".join(parts).lower()
    if any(marker in haystack for marker in _CREDIT_QUOTA_MARKERS):
        return True
    # HTTP 402 Payment Required, 401 Unauthorized (invalid key)
    status = getattr(exc, "status_code", None) or getattr(exc, "status", None)
    if status in (401, 402):
        return True
    name = type(exc).__name__.lower()
    if "authentication" in name or "permissiondenied" in name:
        return True
    return False


def _default_model_for_provider(provider: str) -> str:
    if provider == ExternalService.ANTHROPIC:
        return getattr(settings, "ANTHROPIC_MODEL", None) or DEFAULT_MODEL_BY_PROVIDER[provider]
    if provider == ExternalService.OPENAI:
        return getattr(settings, "OPENAI_MODEL", None) or DEFAULT_MODEL_BY_PROVIDER[provider]
    if provider == ExternalService.DEEPSEEK:
        return getattr(settings, "DEEPSEEK_MODEL", None) or DEFAULT_MODEL_BY_PROVIDER[provider]
    if provider == ExternalService.KIMI:
        return getattr(settings, "KIMI_MODEL", None) or DEFAULT_MODEL_BY_PROVIDER[provider]
    if provider == ExternalService.GROQ:
        return getattr(settings, "GROQ_MODEL", None) or DEFAULT_MODEL_BY_PROVIDER[provider]
    if provider == ExternalService.OLLAMA:
        return _ollama_fallback_model_name()
    return DEFAULT_MODEL_BY_PROVIDER.get(provider, "")


def _ollama_fallback_model_name() -> str:
    return (
        getattr(settings, "OLLAMA_MODEL", None)
        or DEFAULT_MODEL_BY_PROVIDER[ExternalService.OLLAMA]
    )


def ollama_fallback_available() -> bool:
    """True when credit/key fallback to Ollama is enabled and the daemon responds."""
    if not getattr(settings, "OLLAMA_FALLBACK_ENABLED", True):
        return False
    return ollama_is_reachable()


def build_ollama_chat_model(
    *,
    temperature: Optional[float] = 0,
    max_tokens: Optional[int] = None,
    timeout: Optional[float] = 120,
    max_retries: int = 2,
) -> BaseChatModel:
    """Construct the configured local Ollama chat model."""
    return build_chat_model(
        ExternalService.OLLAMA,
        _ollama_fallback_model_name(),
        "ollama",
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
        max_retries=max_retries,
    )


def _customer_friendly_degrade_message(failed_provider: str, next_label: str) -> str:
    return (
        f"Your preferred AI provider ({failed_provider}) is unavailable "
        f"(credits exhausted or invalid API key). Continuing with {next_label} "
        f"so the product keeps working — top up or update the key when you can."
    )


class ResilientFallbackChatModel(BaseChatModel):
    """Try ``primary``, then each ``fallbacks`` entry on credit/quota/auth errors.

    Product rule: tell the customer their preferred LLM is out of credits, but
    keep the agent functional via another configured cloud key or local Ollama.

    If no fallbacks were attached at construction time (Ollama was still starting),
    we re-probe and lazily attach Ollama on the first credit/auth failure.
    """

    primary: Any = Field(exclude=True)
    fallbacks: List[Any] = Field(default_factory=list, exclude=True)
    fallback_labels: List[str] = Field(default_factory=list, exclude=True)
    primary_label: str = "cloud"

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def model_post_init(self, __context: Any) -> None:
        object.__setattr__(self, "_lazy_ollama_attempted", False)

    @property
    def _llm_type(self) -> str:
        return "resilient-fallback"

    def _ensure_lazy_ollama(self) -> None:
        """On demand: if chain has no Ollama yet, probe and append it."""
        if getattr(self, "_lazy_ollama_attempted", False):
            return
        object.__setattr__(self, "_lazy_ollama_attempted", True)
        labels = list(self.fallback_labels or [])
        if any(str(l).startswith("ollama:") for l in labels) or (
            self.primary_label or ""
        ).startswith("ollama:"):
            return
        clear_ollama_reachability_cache()
        if not ollama_fallback_available():
            logger.warning(
                "Cloud LLM failed and Ollama is not reachable at %s — cannot degrade",
                getattr(settings, "OLLAMA_BASE_URL", ""),
            )
            return
        try:
            ollama = build_ollama_chat_model()
            label = f"ollama:{_ollama_fallback_model_name()}"
            object.__setattr__(self, "fallbacks", list(self.fallbacks or []) + [ollama])
            object.__setattr__(self, "fallback_labels", labels + [label])
            logger.info("Lazily attached Ollama fallback %s after cloud failure", label)
        except Exception:
            logger.warning("Failed to lazily build Ollama fallback", exc_info=True)

    def _chain(self) -> List[Any]:
        return [self.primary, *list(self.fallbacks or [])]

    def _labels(self) -> List[str]:
        labels = [self.primary_label, *list(self.fallback_labels or [])]
        while len(labels) < len(self._chain()):
            labels.append("fallback")
        return labels

    def _run_chain_sync(
        self,
        messages: List[BaseMessage],
        stop: Optional[List[str]],
        run_manager: Optional[CallbackManagerForLLMRun],
        **kwargs: Any,
    ) -> ChatResult:
        last_exc: Optional[BaseException] = None
        attempted_lazy = False
        while True:
            chain = self._chain()
            labels = self._labels()
            for i, llm in enumerate(chain):
                try:
                    return llm._generate(
                        messages, stop=stop, run_manager=run_manager, **kwargs
                    )
                except Exception as exc:
                    last_exc = exc
                    if not is_llm_credit_or_quota_error(exc):
                        raise
                    # Last pre-built option failed — try lazy Ollama once.
                    if i >= len(chain) - 1:
                        if not attempted_lazy:
                            attempted_lazy = True
                            self._ensure_lazy_ollama()
                            if len(self._chain()) > len(chain):
                                note_llm_degraded(
                                    _customer_friendly_degrade_message(
                                        labels[i], self._labels()[-1]
                                    )
                                )
                                break  # restart while-loop with extended chain
                        raise
                    next_label = labels[i + 1]
                    logger.warning(
                        "LLM provider %s failed (%s); continuing with %s",
                        labels[i], exc, next_label,
                    )
                    note_llm_degraded(
                        _customer_friendly_degrade_message(labels[i], next_label)
                    )
            else:
                break
        assert last_exc is not None
        raise last_exc

    async def _run_chain_async(
        self,
        messages: List[BaseMessage],
        stop: Optional[List[str]],
        run_manager: Optional[AsyncCallbackManagerForLLMRun],
        **kwargs: Any,
    ) -> ChatResult:
        last_exc: Optional[BaseException] = None
        attempted_lazy = False
        while True:
            chain = self._chain()
            labels = self._labels()
            for i, llm in enumerate(chain):
                try:
                    return await llm._agenerate(
                        messages, stop=stop, run_manager=run_manager, **kwargs
                    )
                except Exception as exc:
                    last_exc = exc
                    if not is_llm_credit_or_quota_error(exc):
                        raise
                    if i >= len(chain) - 1:
                        if not attempted_lazy:
                            attempted_lazy = True
                            self._ensure_lazy_ollama()
                            if len(self._chain()) > len(chain):
                                note_llm_degraded(
                                    _customer_friendly_degrade_message(
                                        labels[i], self._labels()[-1]
                                    )
                                )
                                break
                        raise
                    next_label = labels[i + 1]
                    logger.warning(
                        "LLM provider %s failed (%s); continuing with %s",
                        labels[i], exc, next_label,
                    )
                    note_llm_degraded(
                        _customer_friendly_degrade_message(labels[i], next_label)
                    )
            else:
                break
        assert last_exc is not None
        raise last_exc

    def _generate(
        self,
        messages: List[BaseMessage],
        stop: Optional[List[str]] = None,
        run_manager: Optional[CallbackManagerForLLMRun] = None,
        **kwargs: Any,
    ) -> ChatResult:
        return self._run_chain_sync(messages, stop, run_manager, **kwargs)

    async def _agenerate(
        self,
        messages: List[BaseMessage],
        stop: Optional[List[str]] = None,
        run_manager: Optional[AsyncCallbackManagerForLLMRun] = None,
        **kwargs: Any,
    ) -> ChatResult:
        return await self._run_chain_async(messages, stop, run_manager, **kwargs)


# Back-compat alias for earlier import sites.
CreditFallbackChatModel = ResilientFallbackChatModel


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

    fallback_model = _ollama_fallback_model_name()
    logger.warning(
        "No API key for provider=%s; falling back to local Ollama model=%s",
        provider, fallback_model,
    )
    note_llm_degraded(
        _customer_friendly_degrade_message(provider, f"ollama:{fallback_model}")
    )
    return ExternalService.OLLAMA, fallback_model, "ollama"


def _build_runtime_fallback_models(
    *,
    skip_provider: str,
    db=None,
    organization_id: Optional[int] = None,
    temperature: Optional[float],
    max_tokens: Optional[int],
    timeout: Optional[float],
    max_retries: int,
) -> tuple[List[BaseChatModel], List[str]]:
    """Build ordered alternate models: other cloud keys, then Ollama."""
    models: List[BaseChatModel] = []
    labels: List[str] = []
    seen = {skip_provider}

    for provider in _CLOUD_FALLBACK_ORDER:
        if provider in seen:
            continue
        api_key = None
        if db is not None:
            api_key = resolve_llm_key(db, provider, organization_id)
        api_key = api_key or _settings_key_for_provider(provider)
        if not api_key:
            continue
        model_name = _default_model_for_provider(provider)
        try:
            models.append(
                build_chat_model(
                    provider, model_name, api_key,
                    temperature=temperature, max_tokens=max_tokens,
                    timeout=timeout, max_retries=max_retries,
                )
            )
            labels.append(f"{provider}:{model_name}")
            seen.add(provider)
        except Exception:
            logger.debug("Could not build fallback model for %s", provider, exc_info=True)

    if ExternalService.OLLAMA not in seen and ollama_fallback_available():
        models.append(
            build_ollama_chat_model(
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=timeout,
                max_retries=max_retries,
            )
        )
        labels.append(f"ollama:{_ollama_fallback_model_name()}")

    return models, labels


def _attach_credit_fallback(
    primary: BaseChatModel,
    provider: str,
    *,
    temperature: Optional[float],
    max_tokens: Optional[int],
    timeout: Optional[float],
    max_retries: int,
    db=None,
    organization_id: Optional[int] = None,
    model: Optional[str] = None,
) -> BaseChatModel:
    """Wrap ``primary`` so credit/auth failures cascade to other providers / Ollama.

    Always wraps non-Ollama primaries — even when no fallbacks are pre-built —
    so a later lazy Ollama probe can still rescue an invalid/out-of-credit key.
    """
    if provider == ExternalService.OLLAMA:
        return primary
    if isinstance(primary, ResilientFallbackChatModel):
        return primary

    fallbacks, labels = _build_runtime_fallback_models(
        skip_provider=provider,
        db=db,
        organization_id=organization_id,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
        max_retries=max_retries,
    )

    primary_label = f"{provider}:{model}" if model else provider
    logger.info(
        "Attached resilient LLM wrapper behind %s (prebuilt fallbacks=%s)",
        primary_label, labels or ["(lazy ollama on failure)"],
    )
    return ResilientFallbackChatModel(
        primary=primary,
        fallbacks=fallbacks,
        fallback_labels=labels,
        primary_label=primary_label,
    )


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

    Cloud models are wrapped so credit/quota/auth failure cascades to other
    configured providers and then local Ollama — the product keeps working.
    """
    if agent_config is None:
        agent_config = _load_agent_config(db, organization_id)

    spec = resolve_model_spec_for_task(agent_config, task)
    provider, model = parse_model_spec(spec)

    api_key = resolve_llm_key(db, provider, organization_id) or _settings_key_for_provider(provider)

    # If preferred has no key, jump to another cloud with a key before Ollama.
    if not api_key and provider not in KEYLESS_LLM_PROVIDERS:
        for alt in _CLOUD_FALLBACK_ORDER:
            if alt == provider:
                continue
            alt_key = resolve_llm_key(db, alt, organization_id) or _settings_key_for_provider(alt)
            if alt_key:
                provider, model, api_key = alt, _default_model_for_provider(alt), alt_key
                note_llm_degraded(
                    _customer_friendly_degrade_message(spec, f"{provider}:{model}")
                )
                break

    provider, model, api_key = _maybe_fallback_to_ollama(provider, model, api_key)

    logger.info(
        "Resolved LLM task=%s org=%s -> provider=%s model=%s",
        task, organization_id, provider, model,
    )

    primary = build_chat_model(
        provider, model, api_key,
        temperature=temperature, max_tokens=max_tokens,
        timeout=timeout, max_retries=max_retries,
    )
    return _attach_credit_fallback(
        primary,
        provider,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
        max_retries=max_retries,
        db=db,
        organization_id=organization_id,
        model=model,
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
