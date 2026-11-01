"""New tester schedules default to durable work on the approved target only."""

from app.api.routes.scan_schedules import config_for_new_schedule
from app.services.agent.assessment_scope import observation_scope_hosts
from app.services.agent.autonomy_limits import AutonomyLimits, current_autonomy_limits


def test_new_tester_schedule_defaults_on_and_respects_explicit_off():
    enabled = config_for_new_schedule("tester_process", {"max_turns": 4})
    assert enabled["autonomous_followup"] is True
    assert enabled["max_turns"] == 4
    assert config_for_new_schedule(
        "tester_process", {"autonomous_followup": False},
    )["autonomous_followup"] is False
    assert "autonomous_followup" not in config_for_new_schedule("nuclei", {})
    assert config_for_new_schedule("nuclei", {"custom": 1}) == {"custom": 1}


def test_autonomous_observations_use_only_saved_target_scope():
    token = current_autonomy_limits.set(AutonomyLimits(allowed_hosts=("shop.example.test",)))
    try:
        assert observation_scope_hosts(object()) == {"shop.example.test"}
    finally:
        current_autonomy_limits.reset(token)
