"""Prompt caching: stable prompt prefix and Anthropic-only cache breakpoints."""

import asyncio

from langchain_anthropic import ChatAnthropic
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_openai import ChatOpenAI
from pydantic import ConfigDict

from app.services.agent.model_router import ResilientFallbackChatModel
from app.services.agent.prompt_cache import (
    CacheableSystemMessage,
    cacheable_system,
    prepare_for_model,
)
from app.services.agent.prompts import render_prompt_parts

FIELDS = (
    "current_phase", "available_tools", "iteration", "max_iterations",
    "objective", "objective_history_summary", "execution_trace", "todo_list",
    "target_info", "capability_map", "engagement_brain", "session_notes",
    "knowledge_context", "qa_history", "tool_recommendations",
)


def _context(step: int) -> dict:
    ctx = {name: f"sample-{name}-{step}" for name in FIELDS}
    ctx.update(current_phase="informational", available_tools="tool-list",
               max_iterations=40, iteration=step)
    return ctx


def _anthropic() -> ChatAnthropic:
    return ChatAnthropic(model="claude-test", api_key="sk-ant-test")


def _breakpoints(payload: dict) -> int:
    count = sum(1 for b in payload["system"] if "cache_control" in b)
    for message in payload["messages"]:
        content = message["content"]
        if isinstance(content, list):
            count += sum(1 for b in content if "cache_control" in b)
    return count


def test_system_prefix_is_identical_across_steps() -> None:
    first = render_prompt_parts(mode="agent", **_context(1))
    later = render_prompt_parts(mode="agent", **_context(7))

    assert first.static == later.static
    assert first.tools == later.tools
    assert "sample-execution_trace-7" in later.state
    assert "7/40" in later.state
    for leaked in ("sample-execution_trace", "sample-engagement_brain", "sample-objective"):
        assert leaked not in first.static + first.tools


def test_pilot_prompts_split_the_same_way() -> None:
    for web in (False, True):
        a = render_prompt_parts(mode="pilot", pilot_web_only=web, **_context(1))
        b = render_prompt_parts(mode="pilot", pilot_web_only=web, **_context(2))
        assert a.static == b.static
        assert "sample-objective-2" in b.state
        assert "Output exactly one JSON object" in a.static


def test_anthropic_payload_marks_static_and_tool_segments() -> None:
    llm = _anthropic()
    messages = [cacheable_system("static guidance", "tool list"), HumanMessage(content="state")]

    payload = llm._get_request_payload(prepare_for_model(llm, messages))

    assert payload["system"] == [
        {"type": "text", "text": "static guidance", "cache_control": {"type": "ephemeral"}},
        {"type": "text", "text": "tool list", "cache_control": {"type": "ephemeral"}},
    ]
    # Single-turn planner: the per-step user turn is not marked.
    assert payload["messages"][-1]["content"] == "state"


def test_rolling_breakpoint_marks_newest_message_within_limit() -> None:
    llm = _anthropic()
    messages = [
        cacheable_system("a", "b", "c", "d", cache_history=True),
        HumanMessage(content="Begin."),
        AIMessage(content='{"tool_calls": []}'),
        HumanMessage(content='{"tool_results": []}'),
    ]

    payload = llm._get_request_payload(prepare_for_model(llm, messages))

    last = payload["messages"][-1]["content"]
    assert last[-1]["cache_control"] == {"type": "ephemeral"}
    assert _breakpoints(payload) == 4  # Anthropic's per-request maximum
    # The caller's history is not mutated.
    assert messages[-1].content == '{"tool_results": []}'


def test_other_providers_get_plain_string_system_message() -> None:
    llm = ChatOpenAI(model="gpt-test", api_key="sk-test")
    messages = [cacheable_system("static", "tools", cache_history=True), HumanMessage(content="s")]

    prepared = prepare_for_model(llm, messages)
    payload = llm._get_request_payload(prepared)

    assert payload["messages"][0] == {"role": "system", "content": "statictools"}
    assert payload["messages"][1]["content"] == "s"


def test_cacheable_message_reads_as_plain_system_message() -> None:
    message = cacheable_system("one", "", "two")
    assert isinstance(message, SystemMessage)
    assert message.content == "onetwo"
    assert message.cache_segments == ["one", "two"]
    assert CacheableSystemMessage(content="copied").content == "copied"


class _Recorder(BaseChatModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    seen: list = []
    fail: bool = False

    @property
    def _llm_type(self) -> str:
        return "recorder"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        raise NotImplementedError

    async def _agenerate(self, messages, stop=None, run_manager=None, **kwargs):
        self.seen.append(list(messages))
        if self.fail:
            raise Exception("Your credit balance is too low to access the Anthropic API")
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content="ok"))])


class _RecordingAnthropic(ChatAnthropic):
    seen: list = []

    async def _agenerate(self, messages, stop=None, run_manager=None, **kwargs):
        self.seen.append(list(messages))
        raise Exception("Your credit balance is too low to access the Anthropic API")


def test_fallback_chain_shapes_messages_per_provider() -> None:
    primary = _RecordingAnthropic(model="claude-test", api_key="sk-ant-test", seen=[])
    fallback = _Recorder(seen=[])
    wrapped = ResilientFallbackChatModel(
        primary=primary, fallbacks=[fallback],
        fallback_labels=["openai:gpt"], primary_label="anthropic:claude",
    )
    messages = [cacheable_system("static", "tools"), HumanMessage(content="state")]

    out = asyncio.run(wrapped.ainvoke(messages))

    assert out.content == "ok"
    anthropic_system = primary.seen[0][0]
    assert isinstance(anthropic_system.content, list)
    assert anthropic_system.content[0]["cache_control"] == {"type": "ephemeral"}
    fallback_system = fallback.seen[0][0]
    assert fallback_system.content == "statictools"
