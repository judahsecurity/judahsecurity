"""Guard against Agent page: TypeError: 'NoneType' object is not subscriptable.

dict.get("k", "")[:n] still crashes when the key exists and the value is None.
That is what killed the first think turn after assessment_kickoff wrote
output_analysis=None into the execution trace.
"""

from app.services.agent.orchestrator import llm_text, AgentOrchestrator
from app.services.agent.state import (
    LLMDecision,
    OutputAnalysis,
    clip_text,
    format_execution_trace,
    format_objective_history,
    format_qa_history,
    format_todo_list,
    summarize_trace_for_response,
)


def test_clip_text_none_and_non_str():
    assert clip_text(None, 10) == ""
    assert clip_text("abcdef", 3) == "abc"
    assert clip_text(12, 10) == "12"


def test_format_execution_trace_kickoff_null_fields():
    """Kickoff step dumps output_analysis=None — this used to crash think."""
    trace = [
        {
            "iteration": 0,
            "phase": None,
            "thought": None,
            "tool_name": "assessment_kickoff",
            "success": True,
            "output_analysis": None,
        },
        None,
    ]
    text = format_execution_trace(trace)
    assert "assessment_kickoff" in text
    assert "Step 0" in text


def test_format_qa_and_objective_history_null_fields():
    qa = format_qa_history(
        [{"question": {"question": None}, "answer": {"answer": None}}]
    )
    assert "Q1:" in qa
    hist = format_objective_history(
        [{"objective": {"content": None}, "success": True}, {"objective": None}]
    )
    assert "Unknown objective" in hist


def test_format_todo_list_skips_none_items():
    text = format_todo_list([None, {"description": None, "status": None}])
    assert "[" in text


def test_summarize_trace_null_findings_and_steps():
    summary = summarize_trace_for_response(
        [
            None,
            {"tool_name": "execute_httpx", "actionable_findings": None},
        ]
    )
    assert "execute_httpx" in summary


def test_llm_decision_null_thought():
    d = LLMDecision.model_validate(
        {"thought": None, "reasoning": None, "action": "complete"}
    )
    assert d.thought == ""
    assert d.reasoning == ""
    assert d.thought[:300] == ""


def test_output_analysis_null_interpretation():
    a = OutputAnalysis.model_validate({"interpretation": None})
    assert a.interpretation == ""


def test_llm_text_none_str_and_blocks():
    assert llm_text(None) == ""
    assert llm_text("hello") == "hello"
    assert "hi" in llm_text([{"type": "text", "text": "hi"}])


def test_parse_helpers_tolerate_none_and_list_content():
    orch = AgentOrchestrator.__new__(AgentOrchestrator)
    decision = orch._parse_llm_decision(None)
    assert decision.action in ("complete", "use_tool", "ask_user", "transition_phase")
    analysis = orch._parse_analysis_response(None)
    assert isinstance(analysis.interpretation, str)
    analysis2 = orch._parse_analysis_response([{"text": '{"interpretation": "ok"}'}])
    assert "ok" in analysis2.interpretation or analysis2.interpretation
