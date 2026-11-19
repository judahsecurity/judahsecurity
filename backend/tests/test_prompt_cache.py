"""Anthropic prompt caching: request shape and cache-aware cost accounting."""

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from app.services.agent import fireteam_service
from app.services.agent.llm_factory import (
    PROMPT_CACHE_BOUNDARY,
    _construct,
    split_system_at_cache_boundary,
)
from app.services.agent.observability import (
    cost_from_usage,
    estimate_cost_usd,
    record_llm_usage,
    usage_from_llm_response,
)


def _anthropic():
    return _construct(
        "anthropic", "claude-sonnet-4-6", "sk-test",
        temperature=0, max_tokens=1024, timeout=10, max_retries=0,
    )


def test_anthropic_requests_enable_automatic_caching():
    payload = _anthropic()._get_request_payload(
        [SystemMessage(content="fixed"), HumanMessage(content="hi")]
    )
    assert payload["cache_control"] == {"type": "ephemeral"}


def test_system_prompt_split_at_boundary_gets_its_own_breakpoint():
    system = f"fixed rules\n\n{PROMPT_CACHE_BOUNDARY}\n\nlease 7 details"
    payload = _anthropic()._get_request_payload(
        [SystemMessage(content=system), HumanMessage(content="Begin.")]
    )
    blocks = payload["system"]
    assert blocks[0]["text"] == "fixed rules"
    assert blocks[0]["cache_control"] == {"type": "ephemeral"}
    assert blocks[1]["text"].startswith(PROMPT_CACHE_BOUNDARY)
    assert "lease 7 details" in blocks[1]["text"]
    assert "cache_control" not in blocks[1]


def test_prompt_without_boundary_is_unchanged():
    assert split_system_at_cache_boundary("plain") == "plain"
    assert split_system_at_cache_boundary(None) is None


def test_caching_can_be_switched_off(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "AGENT_PROMPT_CACHE", False, raising=False)
    system = f"fixed\n{PROMPT_CACHE_BOUNDARY}\nvaries"
    llm = _construct(
        "anthropic", "claude-sonnet-4-6", "sk-test",
        temperature=0, max_tokens=1024, timeout=10, max_retries=0,
    )
    payload = llm._get_request_payload([SystemMessage(content=system), HumanMessage(content="x")])
    assert "cache_control" not in payload
    assert payload["system"] == system


def test_specialist_prompt_keeps_assignment_below_the_boundary():
    prompt = fireteam_service._SPECIALIST_SYSTEM_PROMPT.format(
        epithet="E", role="R", directive="DIRECTIVE-X", mission="MISSION-X",
        targets="https://t.example", tool_list="- tool", memory="MEM-X",
        max_iter=9, suffix="SUFFIX", cache_boundary=PROMPT_CACHE_BOUNDARY,
    )
    head, tail = prompt.split(PROMPT_CACHE_BOUNDARY, 1)
    for varying in ("DIRECTIVE-X", "MISSION-X", "https://t.example", "MEM-X", "9 iterations"):
        assert varying not in head
        assert varying in tail
    assert "SUFFIX" in head


def _response(total_in, out, read, created):
    return AIMessage(
        content="ok",
        usage_metadata={
            "input_tokens": total_in,
            "output_tokens": out,
            "total_tokens": total_in + out,
            "input_token_details": {"cache_read": read, "cache_creation": created},
        },
    )


def test_cached_tokens_are_priced_at_cache_rates():
    usage = usage_from_llm_response(_response(10_000, 0, 9_000, 0))
    assert usage["cache_read_tokens"] == 9_000
    full = estimate_cost_usd("claude-sonnet-4-6", 10_000, 0)
    cached = cost_from_usage("claude-sonnet-4-6", usage)
    # 1,000 uncached + 9,000 at a tenth of the rate = 1,900 token-equivalents.
    assert abs(cached - full * 0.19) < 1e-6


def test_record_llm_usage_tracks_cache_reads():
    bucket = {}
    record_llm_usage(bucket, _response(5_000, 100, 4_000, 0), model="claude-sonnet-4-6")
    record_llm_usage(bucket, _response(5_000, 100, 0, 5_000), model="claude-sonnet-4-6")
    totals = bucket["token_usage"]
    assert totals["cache_read_tokens"] == 4_000
    assert totals["cache_creation_tokens"] == 5_000
    assert totals["input_tokens"] == 10_000
