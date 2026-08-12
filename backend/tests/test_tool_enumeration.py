"""Tests for AI agent tool-enumeration red-team category."""

from app.services.llm_red_team.payloads import (
    ALL_PAYLOAD_CATEGORIES,
    get_category_metadata,
    get_payloads_by_category,
)


def test_tool_enumeration_category_registered():
    assert "tool_enumeration" in ALL_PAYLOAD_CATEGORIES
    payloads = get_payloads_by_category(["tool_enumeration"])
    assert len(payloads) >= 5
    ids = {p.id for p in payloads}
    assert "te-001" in ids
    assert all(p.category == "tool_enumeration" for p in payloads)


def test_tool_enumeration_metadata():
    meta = get_category_metadata()
    assert "tool_enumeration" in meta
    assert meta["tool_enumeration"]["count"] == len(ALL_PAYLOAD_CATEGORIES["tool_enumeration"])
    assert "Tool Enumeration" in meta["tool_enumeration"]["name"]


def test_tool_enumeration_covers_attack_vectors():
    prompts = " ".join(p.prompt.lower() for p in get_payloads_by_category(["tool_enumeration"]))
    assert "tool" in prompts
    assert "user_id" in prompts
    assert "refund" in prompts or "payment" in prompts
    assert "email" in prompts
    assert "send_now" in prompts
