"""Persisted trace keeps the capped tool output the model saw."""

from app.services.agent.orchestrator import _cap_persisted_tool_output
from app.services.agent.state import cap_trace_step


def test_cap_keeps_short_output_unchanged():
    step = {"tool_output": "ok", "artifact_id": "ev1"}
    assert cap_trace_step(step, 10) is step


def test_cap_truncates_with_evidence_pointer_and_lengths():
    step = {"tool_output": "x" * 50, "artifact_id": "ev1"}
    capped = cap_trace_step(step, 10)
    assert capped is not step and step["tool_output"] == "x" * 50
    assert capped["tool_output"].startswith("x" * 10 + "\n...[truncated 40 of 50 chars.")
    assert "read_evidence('ev1')" in capped["tool_output"]
    assert capped["tool_output_chars"] == 50 and capped["tool_output_truncated"] is True


def test_node_updates_are_capped(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "AGENT_TOOL_OUTPUT_MAX_CHARS", 5, raising=False)
    big = {"tool_name": "execute_nuclei", "tool_output": "y" * 100}
    updates = _cap_persisted_tool_output({
        "_current_step": big,
        "execution_trace": [{"tool_output": "short"}, big],
        "other": 1,
    })
    assert updates["_current_step"]["tool_output_chars"] == 100
    assert updates["execution_trace"][0] == {"tool_output": "short"}
    assert updates["execution_trace"][1]["tool_output"].startswith("yyyyy\n...[truncated")
    assert updates["other"] == 1
