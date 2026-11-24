"""Model refusals are recorded per role and summarized for benchmarks."""

import pytest
from langchain_core.messages import AIMessage

from app.services.agent import action_ledger
from app.services.agent.refusals import is_refusal


@pytest.mark.parametrize("message,expected", [
    (AIMessage(content="I can't help with attacking this system."), True),
    (AIMessage(content="", response_metadata={"stop_reason": "refusal"}), True),
    (AIMessage(content='{"tool_calls": [], "reasoning": "I will not repeat that probe"}'), False),
    (AIMessage(content="Next I will test the id parameter."), False),
])
def test_refusal_detection(message, expected):
    assert is_refusal(message) is expected


@pytest.mark.asyncio
async def test_ledger_call_records_a_refusal_for_its_role(monkeypatch):
    from app.services.agent.orchestrator import _ledger_llm_call

    calls = []
    monkeypatch.setattr(action_ledger, "append_action",
                        lambda run_id, action_id, event, name, **kw: calls.append((name, event, kw)))

    class LLM:
        async def ainvoke(self, messages):
            return AIMessage(content="I must decline to help with that.")

    await _ledger_llm_call(LLM(), [], kind="agent_specialist_model", phase="injection")
    names = [(name, kw.get("phase")) for name, event, kw in calls if event == "completed"]
    assert ("agent_specialist_model", "injection") in names
    assert ("model_refusal", "injection") in names


def test_harness_reports_refusal_rates_by_role():
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "harness"))
    from local_harness.agent_eval import summarize_run_ledgers

    actions = [
        {"tool_name": "agent_specialist_model", "phase": "injection", "status": "completed"},
        {"tool_name": "agent_specialist_model", "phase": "injection", "status": "completed"},
        {"tool_name": "model_refusal", "phase": "injection", "status": "completed"},
        {"tool_name": "agent_specialist_model", "phase": "xss", "status": "completed"},
        {"tool_name": "specialist:xss", "phase": "", "status": "completed"},
    ]
    summary = summarize_run_ledgers([{"run_id": "r", "status": "completed", "actions": actions,
                                      "coverage": {"actions": len(actions)}}])
    assert summary["model_refusals"] == 1
    assert summary["refusals_by_role"]["injection"] == {"calls": 2, "refusals": 1, "refusal_rate": 0.5}
    assert summary["refusals_by_role"]["xss"]["refusal_rate"] == 0.0
