"""Per-run credential testing must not be inferred from a full assessment."""

from app.services.agent.run_permissions import (
    credential_testing_allowed,
    oob_callbacks_allowed,
    permitted_specialists,
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
