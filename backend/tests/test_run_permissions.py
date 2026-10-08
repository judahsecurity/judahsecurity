"""Per-run credential testing must not be inferred from a full assessment."""

from app.services.agent.run_permissions import (
    credential_testing_allowed,
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
