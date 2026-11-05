"""Regression coverage for literal JSON in the main agent prompt."""

from app.services.agent.prompts import (
    render_system_prompt,
)


CONTEXT = {
    name: f"sample-{name}"
    for name in (
        "current_phase", "available_tools", "iteration", "max_iterations",
        "objective", "objective_history_summary", "execution_trace", "todo_list",
        "target_info", "capability_map", "engagement_brain", "session_notes",
        "knowledge_context", "qa_history", "tool_recommendations",
    )
}


def test_agent_prompt_renders_literal_proof_json_after_template_fields() -> None:
    rendered = render_system_prompt(mode="agent", **CONTEXT)

    assert "sample-objective" in rendered
    assert 'proof={"kind":"workflow","run_id":"<fresh proof run>"}' in rendered
    assert "Use {{nonce}} and {{object_id}}" in rendered


def test_pilot_prompt_uses_only_its_own_template() -> None:
    rendered = render_system_prompt(mode="pilot", **CONTEXT)

    assert "sample-objective" in rendered
    assert "scoped_numeric_sqli" not in rendered


def test_web_only_pilot_prompt_excludes_port_probe_guidance() -> None:
    rendered = render_system_prompt(mode="pilot", pilot_web_only=True, **CONTEXT)
    assert "GET and HEAD requests only" in rendered
    assert "Do not probe ports" in rendered
    assert "probe_pilot_ports" not in rendered
