"""Scenario guidance loads from skill packs only when the evidence shows it."""

from app.services.agent.prompts import get_phase_tools, render_prompt_parts
from app.services.agent.skill_md import list_skill_packs, triggered_skill_packs
from app.services.agent.wordpress_surface import wordpress_hunt_note

SCENARIO_PACKS = {
    "elasticsearch_exposure", "unauth_account_lookup", "unauth_settings_write",
    "container_registry_exposure", "email_change_ato", "socketio_idor",
    "ml_pipeline_rbac",
}
# Strings that only make sense for one past engagement or one product shape.
# (Tool descriptions may still name their own inputs, e.g. probe_registry_anonymous
# takes an *.azurecr.io host and compare_requests documents its forced unauth paths.)
TARGET_SPECIFIC = (
    "emulate3d", "SaveSettings 200", "Elasticsearch :9200", "/api/auth/account",
    "users/reset_email/", "get_stream", "celery-task", "wp-admin/admin-ajax",
    "ACR anonymous pull",
)


def _context() -> dict:
    fields = (
        "current_phase", "iteration", "max_iterations", "objective",
        "objective_history_summary", "execution_trace", "todo_list", "target_info",
        "capability_map", "engagement_brain", "session_notes", "knowledge_context",
        "qa_history", "tool_recommendations",
    )
    ctx = {name: "-" for name in fields}
    ctx["available_tools"] = get_phase_tools("informational")
    return ctx


def test_scenario_packs_exist_with_triggers() -> None:
    assert SCENARIO_PACKS <= set(list_skill_packs())


def test_cached_planner_prompt_carries_no_target_specific_scenarios() -> None:
    system = render_prompt_parts(mode="agent", **_context()).system
    for marker in TARGET_SPECIFIC:
        assert marker not in system, marker
    assert "Scenario playbooks" in system


def test_packs_load_only_on_matching_evidence() -> None:
    assert triggered_skill_packs("") == []
    assert triggered_skill_packs("GET https://shop.test/ 200 nginx") == []

    names = [name for name, _ in triggered_skill_packs(
        'httpx: http://10.0.0.5:9200 200 {"tagline":"You Know, for Search"}'
    )]
    assert names == ["elasticsearch_exposure"]

    hits = dict(triggered_skill_packs("openapi path POST /api/Settings/SaveSettings"))
    assert "unauth_settings_write" in hits
    assert 'compare_requests(use_auth_session=false' in hits["unauth_settings_write"]
    assert "{{" not in hits["unauth_settings_write"]

    registry = dict(triggered_skill_packs("asset acme.azurecr.io"))
    assert "probe_registry_anonymous" in registry["container_registry_exposure"]


def test_pack_count_is_bounded() -> None:
    evidence = ("elasticsearch /api/auth/account /api/Settings/SaveSettings "
                "x.azurecr.io reset_email socket.io /api/v1/train")
    assert len(triggered_skill_packs(evidence)) == 3


def test_wordpress_timing_signal_goes_through_verification() -> None:
    state = {"target_info": {"primary_target": "https://blog.test",
                             "technologies": ["WordPress"]}}
    note = wordpress_hunt_note(state)
    assert "submit_finding_candidate" in note
    assert "only a timing lead" in note
