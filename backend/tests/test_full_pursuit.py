"""Full Pursuit: exhaustive, full-impact guidance and a browser-render gate."""

from app.services.agent.full_pursuit import (
    FULL_PURSUIT_GUIDANCE,
    full_pursuit_enabled,
    rendered_client_side,
)
from app.services.agent.prompts import render_system_prompt
from app.services.agent.tester_loop import tester_loop_progress

TARGET = "https://app.test"


def _state(trace, **extra):
    return {
        "mode": "agent",
        "target_info": {"primary_target": TARGET},
        "capability_map": {"target": TARGET, "scope": TARGET},
        "execution_trace": trace,
        **extra,
    }


def _missing_ids(state):
    return {row["id"] for row in tester_loop_progress(state)["missing"]}


def test_http_only_crawl_requires_a_browser_render():
    katana = {"tool_name": "execute_katana", "tool_args": {"args": f"-u {TARGET}"}, "success": True}
    assert "render" in _missing_ids(_state([katana]))


def test_browser_or_headless_crawl_satisfies_render():
    headless = {"tool_name": "execute_katana", "tool_args": {"args": f"-u {TARGET} -headless"},
                "success": True}
    browser = {"tool_name": "execute_interceptor", "tool_args": {"args": "{}"}, "success": True}
    assert rendered_client_side([headless])
    assert "render" not in _missing_ids(_state([headless]))
    assert "render" not in _missing_ids(_state([browser]))


def test_failed_browser_run_does_not_count():
    failed = {"tool_name": "execute_deep_crawl", "tool_args": {}, "success": False}
    assert not rendered_client_side([failed])


def test_render_gate_follows_org_switch():
    katana = {"tool_name": "execute_katana", "tool_args": {"args": f"-u {TARGET}"}, "success": True}
    assert "render" not in _missing_ids(_state([katana], full_pursuit_enabled=False))
    assert full_pursuit_enabled(None) and not full_pursuit_enabled({"full_pursuit_enabled": False})


def _render(**overrides):
    fields = dict(
        current_phase="informational", available_tools="", iteration=1, max_iterations=10,
        objective="test", objective_history_summary="", execution_trace="", todo_list="",
        target_info="", capability_map="", engagement_brain="", session_notes="",
        knowledge_context="", qa_history="", tool_recommendations="", pilot_web_only=False,
    )
    fields.update(overrides)
    return render_system_prompt(**fields)


def test_guidance_is_in_autonomous_prompt_and_can_be_switched_off():
    assert FULL_PURSUIT_GUIDANCE in _render(mode="agent")
    assert FULL_PURSUIT_GUIDANCE not in _render(mode="agent", full_pursuit=False)
    assert FULL_PURSUIT_GUIDANCE not in _render(mode="pilot")
