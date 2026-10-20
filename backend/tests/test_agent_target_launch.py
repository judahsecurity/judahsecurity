"""Normal Prowl runs use the built-in Aegis agent and keep the selected target."""

import pytest

from app.api.routes.agent import _agent_question_with_target, _preset_question_with_note
from app.services.agent.tools import extract_seed_target


def test_selected_target_is_available_to_the_agent_without_a_separate_executor():
    question = _agent_question_with_target("Assess the application", "ginandjuice.shop")

    assert "Assessment target: https://ginandjuice.shop" in question
    assert extract_seed_target(question) == "https://ginandjuice.shop"


def test_selected_target_rejects_non_http_urls():
    with pytest.raises(ValueError, match=r"HTTP\(S\) host"):
        _agent_question_with_target("Assess the application", "file:///etc/passwd")


def test_unselected_target_keeps_the_question():
    assert _agent_question_with_target("Assess https://ginandjuice.shop", None) == (
        "Assess https://ginandjuice.shop"
    )


def test_selected_target_takes_priority_over_reference_urls():
    question = _agent_question_with_target(
        "Assess the site and compare with https://example.org/docs",
        "ginandjuice.shop",
    )
    assert extract_seed_target(question) == "https://ginandjuice.shop"


def test_preset_keeps_initial_manual_testing_note():
    objective = "Run the web assessment.\n\nTarget: https://ginandjuice.shop"
    question = _preset_question_with_note(
        objective,
        "Web App Assessment — https://ginandjuice.shop\nOperator note: "
        "Avoid automated scanners and directory brute forcing; use manual checks.",
    )
    assert question == (
        objective + "\n\nOperator note: "
        "Avoid automated scanners and directory brute forcing; use manual checks."
    )
