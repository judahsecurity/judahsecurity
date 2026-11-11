"""Per-run credential testing must not be inferred from a full assessment."""

from app.services.agent.run_permissions import (
    credential_testing_allowed,
    exploit_dev_allowed,
    oob_callbacks_allowed,
    permitted_specialists,
    post_exploit_allowed,
)


def test_full_assessment_does_not_authorize_credential_testing():
    assert not credential_testing_allowed("Run a full Agent-mode black-box assessment")
    assert not credential_testing_allowed(
        "Run a full assessment. Avoid credential guessing.",
        {"credential_testing_allowed": True},
    )
    assert not credential_testing_allowed("Test credential guessing is not allowed")


def test_explicit_credential_testing_grant_is_required():
    assert credential_testing_allowed("I authorize credential testing of the login form")
    assert credential_testing_allowed("Run a full assessment", {"credential_testing_allowed": True})
    assert not credential_testing_allowed("Test the login form for SQL injection")


def test_auto_wave_removes_credential_assault_without_grant():
    names = ["xss", "credential_assault", "sqli"]
    assert permitted_specialists(names, allow_credential_testing=False) == ["xss", "sqli"]
    assert permitted_specialists(names, allow_credential_testing=True) == names


def test_oob_callbacks_require_a_separate_operator_grant():
    assert not oob_callbacks_allowed("Run a full assessment")
    assert not oob_callbacks_allowed(
        "Avoid third-party callbacks without approval",
        {"oob_callbacks_allowed": True},
    )
    assert oob_callbacks_allowed("I authorize out-of-band callbacks")
    assert oob_callbacks_allowed("Run a full assessment", {"oob_callbacks_allowed": True})


def test_agent_policy_model_exposes_structured_grants():
    """The /agent policy object can carry the grants without objective wording."""
    from app.api.routes.agent import AgentAssessmentPolicy

    default = AgentAssessmentPolicy().model_dump()
    assert default["oob_callbacks_allowed"] is False
    assert default["credential_testing_allowed"] is False
    assert not oob_callbacks_allowed("Assess https://app.test", default)
    assert not credential_testing_allowed("Assess https://app.test", default)

    granted = AgentAssessmentPolicy(
        oob_callbacks_allowed=True, credential_testing_allowed=True,
    ).model_dump()
    assert oob_callbacks_allowed("Assess https://app.test", granted)
    assert credential_testing_allowed("Assess https://app.test", granted)

    # An explicit objective veto still wins over the structured grant.
    assert not oob_callbacks_allowed("Assess https://app.test. Do not use callbacks.", granted)


def test_exploit_dev_tier_requires_a_structured_grant_only():
    # Never inferred from objective wording, however emphatic.
    assert not exploit_dev_allowed("Run exploit development in a sandbox workspace")
    assert not exploit_dev_allowed("Run a full assessment")
    # Structured grant opens it; a negative objective vetoes it.
    assert exploit_dev_allowed("Assess https://app.test", {"exploit_dev_allowed": True})
    assert not exploit_dev_allowed(
        "Assess https://app.test but do not use the exploit sandbox",
        {"exploit_dev_allowed": True},
    )


def test_post_exploit_requires_both_grants():
    # post_exploit presumes a sandbox foothold, so exploit_dev must be on too.
    assert not post_exploit_allowed("Assess", {"post_exploit_allowed": True})
    assert not post_exploit_allowed("Assess", {"exploit_dev_allowed": True})
    assert post_exploit_allowed(
        "Assess", {"exploit_dev_allowed": True, "post_exploit_allowed": True},
    )
    # Vetoing either lane turns post-exploitation off.
    assert not post_exploit_allowed(
        "Assess. No post-exploitation.",
        {"exploit_dev_allowed": True, "post_exploit_allowed": True},
    )
    assert not post_exploit_allowed(
        "Assess but avoid the exploit sandbox",
        {"exploit_dev_allowed": True, "post_exploit_allowed": True},
    )


def test_agent_policy_exposes_exploit_tier_grants():
    from app.api.routes.agent import AgentAssessmentPolicy

    default = AgentAssessmentPolicy().model_dump()
    assert default["exploit_dev_allowed"] is False
    assert default["post_exploit_allowed"] is False
    assert not exploit_dev_allowed("Assess https://app.test", default)
    assert not post_exploit_allowed("Assess https://app.test", default)

    granted = AgentAssessmentPolicy(
        exploit_dev_allowed=True, post_exploit_allowed=True,
    ).model_dump()
    assert exploit_dev_allowed("Assess https://app.test", granted)
    assert post_exploit_allowed("Assess https://app.test", granted)
