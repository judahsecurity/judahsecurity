from __future__ import annotations

import pytest
from aegis_runtime import AgentEvent, RiskClass, SkillManifest, SkillPolicyError
from aegis_runtime.events import normalize_event_type


def test_legacy_stream_events_normalize_to_canonical_contract() -> None:
    assert normalize_event_type("tool_start") == "tool.started"
    assert normalize_event_type("approval_required") == "run.waiting"
    assert normalize_event_type("unknown_widget") == "run.progress"

    event = AgentEvent.from_stream_message(
        run_id="run-1",
        organization_id=7,
        user_id="42",
        message={"type": "tool_complete", "tool": "http_probe", "iteration": 3},
    )
    assert event.event_type == "tool.completed"
    assert event.step_id == "3"
    assert event.payload["tool"] == "http_probe"
    assert event.to_dict()["run_id"] == "run-1"


def test_high_impact_skill_requires_approval() -> None:
    with pytest.raises(SkillPolicyError, match="must require approval"):
        SkillManifest(id="credential_spray", risk=RiskClass.HIGH_IMPACT)


def test_skill_authorization_and_digest_are_deterministic() -> None:
    manifest = SkillManifest(
        id="surface_map",
        version="1.2.3",
        allowed_tools=("dnsx", "httpx"),
        required_inputs=("target",),
    )
    assert manifest.digest() == manifest.digest()
    manifest.authorize_tool("dnsx")
    with pytest.raises(SkillPolicyError, match="not authorized"):
        manifest.authorize_tool("shell")
