"""Provider prompt caching for the agent's stable system prompt.

The planner and fireteam specialists resend a large, mostly fixed system
prompt on every step. Two things make that prompt cacheable:

1. Ordering. Text that is fixed for a session (role, rules, proof guidance,
   per-phase tool list) comes first, and per-step state (iteration, trace,
   brain, recommendations) goes in the human turn after it. OpenAI-format
   providers cache a stable prefix automatically once it is long enough.
2. Explicit breakpoints. Anthropic caches only up to a ``cache_control``
   marker, so a :class:`CacheableSystemMessage` remembers its segments and
   :func:`prepare_for_model` turns them into marked text blocks, but only when
   the receiving model is ``ChatAnthropic``. Every other provider gets an
   ordinary string system message, so an OpenAI-compatible relay, Ollama or a
   fallback provider never sees an unknown field.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from langchain_core.messages import BaseMessage, SystemMessage

# Anthropic allows at most four cache breakpoints per request.
_MAX_BREAKPOINTS = 4
_EPHEMERAL = {"type": "ephemeral"}


class CacheableSystemMessage(SystemMessage):
    """A string system message that also records its cacheable segments.

    ``content`` is the plain concatenation, so any code or provider that treats
    it as an ordinary ``SystemMessage`` sees the same text as before.
    """

    cache_segments: list[str] = []
    # Also mark the newest message, for a multi-turn loop that resends a
    # growing history. Off for single-turn calls, where the user turn is new
    # every step and a cache write would only add cost.
    cache_history: bool = False

    def __init__(self, segments: Sequence[str] | None = None, **kwargs: Any) -> None:
        if segments is None:  # copy / deserialization path
            super().__init__(**kwargs)
            return
        parts = [s for s in segments if s]
        super().__init__(content="".join(parts), cache_segments=parts, **kwargs)


def cacheable_system(*segments: str, cache_history: bool = False) -> CacheableSystemMessage:
    """Build a system message whose segments end in cache breakpoints.

    Order the segments from most to least stable (for example the fixed
    guidance, then the per-phase tool list), so a phase change only misses the
    last segment's cache. ``cache_history`` adds a rolling breakpoint on the
    newest message so each turn of a loop reads the previous turns from cache.
    """
    return CacheableSystemMessage(segments, cache_history=cache_history)


def _is_anthropic(llm: Any) -> bool:
    try:
        from langchain_anthropic import ChatAnthropic
    except ImportError:  # pragma: no cover - optional dependency
        return False
    return isinstance(llm, ChatAnthropic)


def _anthropic_blocks(segments: Sequence[str], limit: int) -> list[dict]:
    blocks: list[dict] = [{"type": "text", "text": s} for s in segments if s]
    # Mark the last segments, within the breakpoint budget.
    for block in blocks[-limit:] if limit > 0 else []:
        block["cache_control"] = dict(_EPHEMERAL)
    return blocks


def _with_breakpoint(message: BaseMessage) -> BaseMessage:
    """Copy ``message`` with a cache breakpoint on its last text block."""
    content = message.content
    if isinstance(content, str):
        if not content:
            return message
        blocks: list = [{"type": "text", "text": content}]
    elif isinstance(content, list) and content:
        blocks = [dict(b) if isinstance(b, dict) else {"type": "text", "text": b} for b in content]
        if blocks[-1].get("type") != "text":
            return message
    else:
        return message
    blocks[-1]["cache_control"] = dict(_EPHEMERAL)
    return message.model_copy(update={"content": blocks})


def prepare_for_model(llm: Any, messages: Sequence[BaseMessage]) -> list[BaseMessage]:
    """Return ``messages`` shaped for ``llm``.

    Only a ``ChatAnthropic`` model gets cache breakpoints. A wrapper such as
    the resilient fallback chain calls this again for each concrete model it
    tries, so the alternate provider receives plain messages.
    """
    if not _is_anthropic(llm):
        return list(messages)
    out: list[BaseMessage] = []
    rolling = False
    for message in messages:
        if isinstance(message, CacheableSystemMessage) and message.cache_segments:
            rolling = rolling or message.cache_history
            limit = _MAX_BREAKPOINTS - (1 if message.cache_history else 0)
            out.append(SystemMessage(content=_anthropic_blocks(message.cache_segments, limit)))
        else:
            out.append(message)
    if rolling and out and out[-1].type != "system":
        out[-1] = _with_breakpoint(out[-1])
    return out
