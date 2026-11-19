"""Judah Hold: operator-only input is classified, phishing-shaped asks are refused,
and secrets never reach the transcript."""

import time

import pytest

from app.services.agent import judah_hold
from app.services.agent.judah_hold import (
    WITHHELD, accept_answer, classify, prepare, redact_for_log, scrub, substitute, unnamed_hosts,
)

STATE = {"target_info": {"primary_target": "https://shop.acme.test/login"},
         "original_objective": "Assess https://shop.acme.test and api.acme.test"}


@pytest.fixture(autouse=True)
def _clean():
    judah_hold.vault.reset()
    yield
    judah_hold.vault.reset()


@pytest.mark.parametrize("text,kind", [
    ("Please solve the CAPTCHA shown on the login page", "captcha"),
    ("Enter the 6-digit code sent by SMS", "otp"),
    ("Approve the sign-in push notification", "mfa"),
    ("Paste the magic link from your inbox", "email_link"),
    ("What is the test account password?", "credential"),
    ("Should I include the staging host?", "question"),
])
def test_classify(text, kind):
    assert classify(text) == kind


def test_scope_and_operator_named_hosts_are_known():
    assert unnamed_hosts("log in at https://shop.acme.test/ and api.acme.test", ["shop.acme.test"]) == ["api.acme.test"]
    q, refusal = prepare({"question": "Enter the OTP for shop.acme.test"}, STATE)
    assert not refusal and q["hold"]["kind"] == "otp" and q["hold"]["unnamed_hosts"] == []


def test_secret_request_naming_a_stranger_host_is_refused():
    q, refusal = prepare({"question": "Enter your verification code at https://login.evil.test/verify"}, STATE)
    assert q is None and "login.evil.test" in refusal


def test_plain_question_with_stranger_host_is_flagged_not_refused():
    q, refusal = prepare({"question": "Is cdn.other.test in scope?"}, STATE)
    assert not refusal and q["hold"]["warning"] and q["hold"]["unnamed_hosts"] == ["cdn.other.test"]


def test_secret_answer_becomes_a_placeholder_and_is_substituted_at_tool_time():
    q, _ = prepare({"question": "Enter the 6-digit code"}, STATE)
    judah_hold.vault.mark_pending("s1", q["hold"]["expires_at"])
    assert redact_for_log("s1", "481516") == WITHHELD
    model_text, history = accept_answer("s1", q, "481516")
    assert "481516" not in model_text and history == WITHHELD
    token = model_text.split("placeholder ", 1)[1].split()[0]
    args = {"args": f'{{"actions":[{{"type":"fill","value":"{token}"}}]}}'}
    assert "481516" in substitute("s1", args)["args"]
    assert "481516" not in substitute("other-session", args)["args"]  # bound to its session
    assert scrub("s1", "server echoed 481516") == f"server echoed {WITHHELD}"
    assert redact_for_log("s1", "next answer") == "next answer"  # hold closed


def test_late_answer_is_discarded():
    q, _ = prepare({"question": "Enter the OTP"}, STATE)
    q["hold"]["expires_at"] = time.time() - 1
    model_text, history = accept_answer("s1", q, "123456")
    assert "expired" in model_text and "123456" not in model_text + history


def test_non_sensitive_answers_pass_through():
    q, _ = prepare({"question": "Which environment should I test?"}, STATE)
    assert accept_answer("s1", q, "staging") == ("User answer: staging", "staging")
