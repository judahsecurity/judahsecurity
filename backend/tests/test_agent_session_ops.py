"""CAI-style compact, prior-hunt brief, and spend-cap helpers."""

import json

from app.services.agent.session_ops import (
    compact_execution_trace,
    format_prior_hunt_brief,
    over_budget,
    prior_identical_browser_action,
    price_limit_usd,
    should_auto_compact,
)
from app.services.agent.tester_loop import (
    _dispatched_input_signature,
    _full_fireteam_completed,
    normalized_tools_run,
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


def test_compaction_keeps_control_progress_and_exact_evidence_handles():
    artifact = "a" * 32
    trace = [
        {"tool_name": "assessment_kickoff", "success": True,
         "tool_args": {"root_status": 200}},
        {"tool_name": "execute_deep_crawl", "success": True,
         "artifact_id": artifact},
        {"tool_name": "scoped_browser_assessment", "success": True,
         "tool_args": {"operation": "inspect_js"}},
        {"tool_name": "spawn_recon_workers", "success": True,
         "tool_args": {"pack": "enrich"}},
        {"tool_name": "wait_recon_workers", "success": True},
        {"tool_name": "wait_recon_workers", "success": True},
        {"tool_name": "fingerprint_api", "success": True},
        {"tool_name": "fetch_lazy_chunks", "success": True},
        {"tool_name": "extract_js_endpoints", "success": True},
        {"tool_name": "sync_engagement_brain", "success": True},
        {"tool_name": "fireteam_dispatch", "success": True,
         "tool_args": {"mode": "observed_inputs", "surface_signature": "sig-1",
                       "pending_input_count": 5}},
        {"tool_name": "fireteam_dispatch", "success": True,
         "tool_args": {"specialists": "auto"}},
        *({"tool_name": "other", "success": True} for _ in range(12)),
    ]
    compacted, brief = compact_execution_trace(trace)
    assert "artifact_id=" + artifact in brief
    assert compacted[0]["evidence_cards"][0]["artifact_id"] == artifact
    assert "execute_deep_crawl" in normalized_tools_run(compacted)
    assert "scoped_browser_crawl" in normalized_tools_run(compacted)
    assert _dispatched_input_signature(compacted, "sig-1")
    assert _full_fireteam_completed(compacted)
    assert sum(s.get("tool_name") == "wait_recon_workers" for s in compacted) == 2
    assert not should_auto_compact(compacted, threshold=24)

    twice, second_brief = compact_execution_trace([
        *compacted, *({"tool_name": "other", "success": True} for _ in range(15))
    ])
    assert "execute_deep_crawl" in normalized_tools_run(twice)
    assert _dispatched_input_signature(twice, "sig-1")
    assert "artifact_id=" + artifact in second_brief


def test_subtask_boundary_compacts_only_when_there_is_context_to_save():
    trace = [{"tool_name": "other", "tool_output": "x" * 1600}
             for _ in range(13)]
    trace[-1] = {"tool_name": "fireteam_dispatch", "success": True}
    assert should_auto_compact(trace)
    assert not should_auto_compact(trace, threshold=24)
    trace[0]["tool_output"] = "x"
    trace[1]["tool_output"] = "x"
    trace[2]["tool_output"] = "x"
    trace[3]["tool_output"] = "x"
    trace[4]["tool_output"] = "x"
    assert not should_auto_compact(trace)


def test_spend_cap():
    assert over_budget({"cost_usd": 5.0}, 5.0)
    assert not over_budget({"cost_usd": 4.99}, 5.0)
    assert not over_budget({"cost_usd": 99.0}, 0)
    assert price_limit_usd(2.5) == 2.5
    assert price_limit_usd(-1) == 0.0


def test_identical_successful_browser_action_is_detected_before_resending_post():
    actions = [
        {"action": "navigate", "url": "https://ginandjuice.shop/catalog"},
        {"action": "execute_js", "script": "fetch('/catalog/subscribe',{method:'POST'})"},
    ]
    args = {"args": json.dumps({"actions": actions})}
    prior = {"tool_name": "execute_browser", "tool_args": args,
             "success": True, "tool_output": "HTTP 200"}
    assert prior_identical_browser_action([prior], args) is prior
    assert prior_identical_browser_action([prior], {
        "args": json.dumps({"actions": [actions[0]]}),
    }) is None
    assert prior_identical_browser_action([{**prior, "success": False}], args) is None


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
