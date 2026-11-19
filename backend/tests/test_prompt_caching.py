"""The planner prompt keeps a stable, cacheable prefix across steps."""

from langchain_core.messages import HumanMessage, SystemMessage

from app.services.agent.llm_factory import (
    _caching_chat_anthropic_class,
    add_system_cache_breakpoint,
)
from app.services.agent.observability import record_llm_usage
from app.services.agent.prompts import render_prompt_parts

FIELDS = (
    "current_phase", "available_tools", "iteration", "max_iterations",
    "objective", "objective_history_summary", "execution_trace", "todo_list",
    "target_info", "capability_map", "engagement_brain", "session_notes",
    "knowledge_context", "qa_history", "tool_recommendations",
)
PER_STEP = [f for f in FIELDS if f not in ("available_tools", "max_iterations")]


def _context(step: int) -> dict:
    ctx = {name: f"<{name}-{step}>" for name in FIELDS}
    ctx["available_tools"] = "<tools>"
    ctx["max_iterations"] = 40
    return ctx


def _modes():
    return [("agent", {}), ("pilot", {}), ("pilot", {"pilot_web_only": True})]


def test_system_part_is_identical_across_steps() -> None:
    for mode, extra in _modes():
        first = render_prompt_parts(mode=mode, **_context(1), **extra)
        second = render_prompt_parts(mode=mode, **_context(2), **extra)
        assert first.system == second.system, mode
        assert first.state != second.state, mode


def test_per_step_fields_render_only_in_state() -> None:
    for mode, extra in _modes():
        parts = render_prompt_parts(mode=mode, **_context(7), **extra)
        for name in PER_STEP:
            marker = f"<{name}-7>"
            assert marker not in parts.system, (mode, name)
        assert "<tools>" in parts.system
        assert "<tools>" not in parts.state
        assert "<objective-7>" in parts.state


def test_tool_list_closes_the_system_prompt() -> None:
    parts = render_prompt_parts(mode="agent", **_context(1))
    assert parts.system.rstrip().endswith("<tools>")
    assert "## Your Task" in parts.system
    assert "## Current State" in parts.state


def test_breakpoint_marks_end_of_long_system_prompt() -> None:
    payload = add_system_cache_breakpoint({"system": "x" * 5000, "messages": []})
    assert payload["system"][-1]["cache_control"] == {"type": "ephemeral"}
    assert payload["system"][-1]["text"] == "x" * 5000


def test_breakpoint_skips_short_or_already_marked_prompts() -> None:
    short = {"system": "short", "messages": []}
    assert add_system_cache_breakpoint(dict(short)) == short

    marked = {"system": [{"type": "text", "text": "y" * 5000,
                          "cache_control": {"type": "ephemeral", "ttl": "1h"}}]}
    assert add_system_cache_breakpoint(marked)["system"][0]["cache_control"]["ttl"] == "1h"

    top_level = {"system": "z" * 5000, "cache_control": {"type": "ephemeral"}}
    assert add_system_cache_breakpoint(dict(top_level))["system"] == "z" * 5000


def test_anthropic_payload_carries_breakpoint_on_system_only() -> None:
    model = _caching_chat_anthropic_class()(
        model="claude-opus-4-8", api_key="test-key", max_tokens=64,
    )
    payload = model._get_request_payload([
        SystemMessage(content="rules " * 1000),
        HumanMessage(content="state for this step"),
    ])
    assert payload["system"][-1]["cache_control"] == {"type": "ephemeral"}
    assert "cache_control" not in str(payload["messages"])


class _Response:
    def __init__(self, meta):
        self.usage_metadata = meta


def test_usage_records_cache_reads_and_discounts_cost() -> None:
    cold, warm = {}, {}
    record_llm_usage(cold, _Response({"input_tokens": 10_000, "output_tokens": 100}),
                     model="claude-sonnet-4-6")
    usage = record_llm_usage(
        warm,
        _Response({"input_tokens": 10_000, "output_tokens": 100,
                   "input_token_details": {"cache_read": 9_000}}),
        model="claude-sonnet-4-6",
    )
    assert usage["cache_read_tokens"] == 9_000
    assert warm["token_usage"]["cache_read_tokens"] == 9_000
    assert warm["token_usage"]["cost_usd"] < cold["token_usage"]["cost_usd"] / 3


def test_multi_turn_conversation_caches_its_newest_message() -> None:
    from langchain_core.messages import AIMessage

    model = _caching_chat_anthropic_class()(
        model="claude-opus-4-8", api_key="test-key", max_tokens=64,
    )
    payload = model._get_request_payload([
        SystemMessage(content="rules " * 1000),
        HumanMessage(content="mission"),
        AIMessage(content="ran a probe"),
        HumanMessage(content="probe output"),
    ])
    assert payload["messages"][-1]["content"][-1]["cache_control"] == {"type": "ephemeral"}
    assert "cache_control" not in str(payload["messages"][:-1])
