"""Redaction, cost, and engagement replay — no secrets in exported traces."""

from app.services.agent.observability import (
    estimate_cost_usd,
    redact_value,
    replay_from_execution_trace,
    usage_from_llm_response,
)


def test_redact_secret_keys_and_bearer():
    raw = {
        "Authorization": "Bearer super-secret-token",
        "cookie": "session=abc",
        "url": "https://app.example.com/login",
        "body": "Cookie: sessionid=xyz; Path=/",
    }
    out = redact_value(raw)
    assert out["Authorization"] == "[redacted]"
    assert out["cookie"] == "[redacted]"
    assert "example.com" in out["url"]
    assert "[redacted]" in out["body"]
    assert "xyz" not in out["body"]


def test_replay_drops_raw_tool_output():
    replay = replay_from_execution_trace(
        [
            {
                "iteration": 1,
                "thought": "Probe login",
                "tool_name": "execute_httpx",
                "tool_output": "Set-Cookie: session=stealme; Authorization: Bearer aabbcc",
                "success": True,
                "actionable_findings": ["Open /login"],
            }
        ],
        token_usage={"input_tokens": 1000, "output_tokens": 50, "cost_usd": 0.0038},
    )
    step = replay["steps"][0]
    assert step["tool_name"] == "execute_httpx"
    assert step["evidence"] == ["Open /login"]
    assert "stealme" not in (step["output_preview"] or "")
    assert "aabbcc" not in (step["output_preview"] or "")
    assert replay["cost_usd"] == 0.0038


def test_usage_from_langchain_style_message():
    class Msg:
        usage_metadata = {"input_tokens": 10, "output_tokens": 4}

    assert usage_from_llm_response(Msg()) == {"input_tokens": 10, "output_tokens": 4}


def test_sonnet_cost_matches_vanguard_table():
    # 1M in + 1M out at $3 / $15
    assert estimate_cost_usd("claude-sonnet-4-6", 1_000_000, 1_000_000) == 18.0
