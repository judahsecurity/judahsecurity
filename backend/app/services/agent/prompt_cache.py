"""Cache-friendly system messages for the agent's planning calls.

The planner's system prompt is ~22k tokens, almost all of it the same on
every step of a run (instructions and the phase's tool docs). We send it as
ordered blocks — static instructions, tool docs, then per-step state — so:

* Anthropic models get ``cache_control`` breakpoints on the first two blocks
  and bill repeated prefixes as cache reads (about a tenth of input price).
* Other providers get one plain string with the same stable prefix, which
  providers with automatic prefix caching (OpenAI, DeepSeek) can reuse.

``adapt_messages`` converts block messages for whichever concrete model a
fallback wrapper ends up calling, so cache markers never reach a provider
that would reject them.
"""

from __future__ import annotations

from typing import Any, List, Sequence

from langchain_core.messages import BaseMessage, SystemMessage

CACHE_MARKER = {"type": "ephemeral"}


def is_anthropic(llm: Any) -> bool:
    try:
        from langchain_anthropic import ChatAnthropic
    except ImportError:  # pragma: no cover - dependency guard
        return False
    return isinstance(llm, ChatAnthropic)


def build_system_message(static: str, tools: str, dynamic: str) -> SystemMessage:
    """Ordered text blocks; the first two are marked as cache breakpoints."""
    blocks = []
    for text, cache in ((static, True), (tools, True), (dynamic, False)):
        if not text:
            continue
        block = {"type": "text", "text": text}
        if cache:
            block["cache_control"] = dict(CACHE_MARKER)
        blocks.append(block)
    return SystemMessage(content=blocks)


def _flatten(content: Any) -> Any:
    if not isinstance(content, list):
        return content
    if not all(isinstance(part, dict) and part.get("type") == "text" for part in content):
        return content  # images or tool blocks: leave for the provider adapter
    return "\n\n".join(str(part.get("text") or "") for part in content)


def adapt_messages(llm: Any, messages: Sequence[BaseMessage]) -> List[BaseMessage]:
    """Keep cache blocks for Anthropic; flatten text blocks for anything else."""
    if is_anthropic(llm):
        return list(messages)
    adapted = []
    for message in messages:
        flat = _flatten(message.content)
        adapted.append(message if flat is message.content
                       else message.model_copy(update={"content": flat}))
    return adapted


def system_message_for(llm: Any, static: str, tools: str, dynamic: str) -> SystemMessage:
    """Blocks for Anthropic or a fallback wrapper (which adapts per model), else a string."""
    from app.services.agent.model_router import ResilientFallbackChatModel

    message = build_system_message(static, tools, dynamic)
    if is_anthropic(llm) or isinstance(llm, ResilientFallbackChatModel):
        return message
    return adapt_messages(llm, [message])[0]
