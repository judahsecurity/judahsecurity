"""CAI-style compact, prior-hunt brief, and spend-cap helpers."""

from app.services.agent.session_ops import (
    compact_execution_trace,
    format_prior_hunt_brief,
    over_budget,
    price_limit_usd,
    should_auto_compact,
)


def test_compact_keeps_recent_and_summarizes_older():
    trace = [
        {
            "iteration": i,
            "phase": "reconnaissance",
            "tool_name": "execute_httpx" if i % 2 == 0 else "execute_nuclei",
            "thought": f"step {i}",
            "actionable_findings": [f"note-{i}"] if i == 1 else [],
        }
        for i in range(20)
    ]
    compacted, brief = compact_execution_trace(trace, keep_recent=8)
    assert compacted[0]["tool_name"] == "compact_context"
    assert len(compacted) == 9  # 1 summary + 8 recent
    assert "execute_httpx" in brief
    assert "note-1" in brief
    assert compacted[-1]["iteration"] == 19


def test_auto_compact_threshold():
    assert should_auto_compact([{"a": 1}] * 24, threshold=24)
    assert not should_auto_compact([{"a": 1}] * 10, threshold=24)
    assert not should_auto_compact([], threshold=0)


def test_spend_cap():
    assert over_budget({"cost_usd": 5.0}, 5.0)
    assert not over_budget({"cost_usd": 4.99}, 5.0)
    assert not over_budget({"cost_usd": 99.0}, 0)
    assert price_limit_usd(2.5) == 2.5
    assert price_limit_usd(-1) == 0.0


def test_prior_hunt_brief_includes_replay_and_last_prompt():
    brief = format_prior_hunt_brief(
        source_session_id="abc123456789",
        title="GraphQL hunt",
        execution_summary="Found introspection open",
        engagement_replay=[
            {"tool_name": "execute_httpx", "thought": "Probe /graphql", "evidence": ["200 OK"]},
        ],
        messages=[{"role": "user", "content": "Focus on GraphQL, skip /admin"}],
    )
    assert "abc123456789"[:12] in brief
    assert "GraphQL hunt" in brief
    assert "execute_httpx" in brief
    assert "Focus on GraphQL" in brief
    assert "Do not re-run" in brief
