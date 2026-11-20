"""Cache-friendly planner prompt: same content, stable prefix, provider-safe blocks."""

import collections
import string

import pytest
from langchain_core.messages import HumanMessage, SystemMessage

from app.services.agent.prompt_cache import adapt_messages, build_system_message, system_message_for
from app.services.agent.prompts import (
    REACT_SYSTEM_PROMPT, all_tool_docs, get_phase_tools, render_system_prompt,
    render_system_prompt_parts, tool_doc_entries, tool_index,
)

KEYS = [f for _, f, _, _ in string.Formatter().parse(REACT_SYSTEM_PROMPT) if f]


def _ctx(**over):
    ctx = {k: f"<{k}>" for k in KEYS}
    ctx["available_tools"] = get_phase_tools("exploitation")
    ctx.update(over)
    return ctx


def test_parts_have_identical_content_and_static_prefix_has_no_step_state():
    ctx = _ctx()
    full = render_system_prompt(mode="agent", **ctx)
    static, tools, dynamic = render_system_prompt_parts(mode="agent", **ctx)
    assert collections.Counter(full.split()) == collections.Counter(
        (static + "\n" + tools + "\n" + dynamic).split())
    for key in KEYS:
        if key not in ("max_iterations", "available_tools"):
            assert f"<{key}>" not in static and f"<{key}>" not in tools


def test_static_prefix_is_byte_stable_across_steps():
    a = render_system_prompt_parts(mode="agent", **_ctx(iteration=1, execution_trace="x"))
    b = render_system_prompt_parts(mode="agent", **_ctx(iteration=9, execution_trace="y"))
    assert a[0] == b[0] and a[1] == b[1] and a[2] != b[2]


def test_pilot_stays_single_block():
    from app.services.agent.prompts import PILOT_SYSTEM_PROMPT

    keys = [f for _, f, _, _ in string.Formatter().parse(PILOT_SYSTEM_PROMPT) if f]
    static, tools, dynamic = render_system_prompt_parts(mode="pilot", **{k: "v" for k in keys})
    assert static == "" and tools == "" and dynamic


def test_anthropic_gets_cache_breakpoints_others_get_plain_string():
    from langchain_anthropic import ChatAnthropic
    from langchain_openai import ChatOpenAI

    message = build_system_message("S" * 10, "T" * 10, "D")
    assert [b.get("cache_control") for b in message.content] == [
        {"type": "ephemeral"}, {"type": "ephemeral"}, None]

    claude = ChatAnthropic(model="claude-sonnet-4-5", api_key="test-key")
    gpt = ChatOpenAI(model="gpt-4o", api_key="test-key")
    msgs = [message, HumanMessage(content="next?")]
    assert adapt_messages(claude, msgs)[0].content == message.content
    flat = adapt_messages(gpt, msgs)
    assert flat[0].content == "SSSSSSSSSS\n\nTTTTTTTTTT\n\nD"
    assert flat[1].content == "next?"
    assert isinstance(system_message_for(gpt, "S", "T", "D").content, str)
    assert isinstance(system_message_for(claude, "S", "T", "D").content, list)


def test_image_blocks_are_not_flattened():
    from langchain_openai import ChatOpenAI

    image = HumanMessage(content=[{"type": "text", "text": "x"},
                                  {"type": "image_url", "image_url": {"url": "data:,"}}])
    assert adapt_messages(ChatOpenAI(model="gpt-4o", api_key="k"), [image])[0] is image


def test_fallback_wrapper_adapts_per_underlying_model():
    from langchain_core.language_models.fake_chat_models import FakeListChatModel

    from app.services.agent.model_router import ResilientFallbackChatModel

    seen = []

    class Recording(FakeListChatModel):
        def _generate(self, messages, stop=None, run_manager=None, **kwargs):
            seen.append(messages[0].content)
            return super()._generate(messages, stop=stop, run_manager=run_manager, **kwargs)

    wrapper = ResilientFallbackChatModel(primary=Recording(responses=["ok"]), fallbacks=[],
                                         fallback_labels=[], primary_label="fake")
    assert isinstance(system_message_for(wrapper, "S", "T", "D").content, list)
    wrapper.invoke([build_system_message("S", "T", "D"), HumanMessage(content="go")])
    assert seen == ["S\n\nT\n\nD"]


def test_cache_aware_cost():
    from types import SimpleNamespace

    from app.services.agent.observability import estimate_cost_usd, record_llm_usage

    assert estimate_cost_usd("claude-sonnet-4-5", 1_000_000, 0) == 3.0
    assert estimate_cost_usd("claude-sonnet-4-5", 1_000_000, 0, cache_read_tokens=1_000_000) == 0.3
    assert estimate_cost_usd("claude-sonnet-4-5", 1_000_000, 0, cache_write_tokens=1_000_000) == 3.75
    bucket = {}
    response = SimpleNamespace(usage_metadata={
        "input_tokens": 22000, "output_tokens": 300,
        "input_token_details": {"cache_read": 21000}})
    usage = record_llm_usage(bucket, response, model="claude-sonnet-4-5")
    assert usage["cache_read_tokens"] == 21000
    assert bucket["token_usage"]["cache_read_tokens"] == 21000
    assert usage["cost_usd"] < estimate_cost_usd("claude-sonnet-4-5", 22000, 300) / 3


def test_tool_index_covers_every_tool_and_describe_returns_full_docs():
    docs = get_phase_tools("exploitation")
    index = tool_index(docs)
    entries = tool_doc_entries(docs)
    assert len(index) < len(docs) / 3
    for name in entries:
        assert f"**{name}**" in index
    assert "describe_tools" in index.splitlines()[0]
    assert "**CRITICAL" in index


@pytest.mark.asyncio
async def test_describe_tools():
    from app.services.agent.tools import ASMToolsManager

    manager = ASMToolsManager()
    out = await manager.describe_tools(["execute_httpx", "nope_tool"])
    assert out.startswith("- **execute_httpx**: HTTP prober. Example:")
    assert "Unknown tools: nope_tool" in out
    assert "query_assets" in await manager.describe_tools("query_assets, query_ports")
    assert set(all_tool_docs()) <= set(manager.tools) | {"web_search", "vulnx_query", "search_vulnx"}
