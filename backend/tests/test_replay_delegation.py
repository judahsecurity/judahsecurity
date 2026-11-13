"""Operator-delegated approval of write paths the agent observed."""

import json

import pytest

from app.services.agent.assessment_scope import assert_method_allowed
from app.services.agent.autonomy_limits import limits_from_config
from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.replay_delegation import (
    evaluate, normalize_delegation, sensitive_reason,
)
from app.services.agent.tools import (
    ASMToolsManager, current_organization_id, current_session_id,
)

ORIGIN = "https://app.test"


def _op(method, path, *, captured=True, host="app.test"):
    return {
        "id": f"op-{method}-{path}", "url": f"https://{host}{path}", "host": host,
        "path": path, "method": method,
        "capture_ids": ["cap-1"] if captured else [],
    }


@pytest.fixture
def manager():
    org = current_organization_id.set(4242)
    session = current_session_id.set("replay-delegation-test")
    instance = ASMToolsManager()
    instance._assessment_scope.update({"app.test"})
    instance._engagement_brain = EngagementBrain(
        target=ORIGIN,
        application_operations=[
            _op("POST", "/comments"),
            _op("POST", "/guestbook/entry"),
            _op("POST", "/search", captured=False),        # JS lead only
            _op("POST", "/account/email"),
            _op("DELETE", "/comments/remove-test"),
            _op("POST", "/feedback", host="other.test"),
            _op("POST", "/contact"),
            _op("POST", "/newsletter"),
        ],
    ).to_dict()
    yield instance
    current_session_id.reset(session)
    current_organization_id.reset(org)


async def _propose(manager, path, kind="body_replay"):
    return json.loads(await manager.propose_replay_path(path, kind=kind, reason="observed form"))


def test_delegation_is_off_unless_explicitly_enabled():
    assert normalize_delegation(None)["enabled"] is False
    assert normalize_delegation({"enabled": "yes"})["enabled"] is False
    on = normalize_delegation({"enabled": True, "max_paths": 50})
    assert on == {"enabled": True, "max_paths": 8, "allow_cleanup": False}


@pytest.mark.parametrize("path,sensitive", [
    ("/comments", False), ("/display", False), ("/border", False),
    ("/account/email", True), ("/api/v1/resetPassword", True), ("/api/orders", True),
    ("/admin/posts", True), ("/user-settings", True),
])
def test_sensitive_paths_are_matched_by_word(path, sensitive):
    assert bool(sensitive_reason(path)) is sensitive


@pytest.mark.asyncio
async def test_without_delegation_the_agent_cannot_unlock_a_path(manager):
    manager.set_scoped_assessment_policy({})
    result = await _propose(manager, "/comments")
    assert result["approved"] is False
    assert result["reason"].startswith("operator_approval_required")
    with pytest.raises(ValueError):
        assert_method_allowed(manager, f"{ORIGIN}/comments", "POST")


@pytest.mark.asyncio
async def test_observed_in_scope_path_is_approved_and_unlocks_post(manager):
    manager.set_scoped_assessment_policy({"delegated_replay_approval": {"enabled": True}})
    result = await _propose(manager, "/comments")
    assert result["approved"] is True and result["operation_id"] == "op-POST-/comments"
    assert_method_allowed(manager, f"{ORIGIN}/comments", "POST")
    record = manager._engagement_brain["replay_approvals"][-1]
    assert record["decision"] == "approved" and record["capture_id"] == "cap-1"
    assert record["note"] == "observed form"
    # Still exact: a sibling path stays locked.
    with pytest.raises(ValueError):
        assert_method_allowed(manager, f"{ORIGIN}/comments/2", "POST")


@pytest.mark.asyncio
@pytest.mark.parametrize("path,expected", [
    ("/search", "not observed"),                       # JS lead without a capture
    ("/never-seen", "not observed"),
    ("/account/email", "operator_approval_required"),  # sensitive
    ("/feedback", "out of scope"),                     # captured on another host
    ("/comments?x=1", "invalid path"),
    ("/../etc", "invalid path"),
])
async def test_unsafe_or_unobserved_proposals_are_denied(manager, path, expected):
    manager.set_scoped_assessment_policy({"delegated_replay_approval": {"enabled": True}})
    result = await _propose(manager, path)
    assert result["approved"] is False
    assert result["reason"].startswith(expected), result["reason"]
    assert manager._engagement_brain["replay_approvals"][-1]["decision"] == "denied"


@pytest.mark.asyncio
async def test_cleanup_needs_its_own_opt_in(manager):
    manager.set_scoped_assessment_policy({"delegated_replay_approval": {"enabled": True}})
    denied = await _propose(manager, "/comments/remove-test", kind="stored_xss_cleanup")
    assert denied["approved"] is False and "cleanup" in denied["reason"]
    manager.set_scoped_assessment_policy({
        "delegated_replay_approval": {"enabled": True, "allow_cleanup": True},
    })
    approved = await _propose(manager, "/comments/remove-test", kind="stored_xss_cleanup")
    assert approved["approved"] is True
    assert_method_allowed(manager, f"{ORIGIN}/comments/remove-test", "DELETE")


@pytest.mark.asyncio
async def test_delegated_limit_counts_only_agent_approvals(manager):
    manager.set_scoped_assessment_policy({
        "body_replay_paths": ["/newsletter"],
        "delegated_replay_approval": {"enabled": True, "max_paths": 2},
    })
    assert (await _propose(manager, "/newsletter"))["approved"] is True  # operator path
    assert (await _propose(manager, "/comments"))["approved"] is True
    assert (await _propose(manager, "/guestbook/entry"))["approved"] is True
    capped = await _propose(manager, "/contact")
    assert capped["approved"] is False and "limit of 2" in capped["reason"]
    assert (await _propose(manager, "/comments"))["reason"] == "already approved"


@pytest.mark.asyncio
async def test_approvals_survive_the_per_turn_policy_reset_only_while_delegated(manager):
    policy = {"delegated_replay_approval": {"enabled": True}}
    manager.set_scoped_assessment_policy(policy)
    await _propose(manager, "/comments")
    # The next turn resets the session policy; approvals come back from the brain.
    manager.set_scoped_assessment_policy(policy)
    assert_method_allowed(manager, f"{ORIGIN}/comments", "POST")
    # If the operator withdraws delegation, the agent's approvals no longer apply.
    manager.set_scoped_assessment_policy({})
    with pytest.raises(ValueError):
        assert_method_allowed(manager, f"{ORIGIN}/comments", "POST")


def test_cleanup_may_say_delete_but_not_other_sensitive_words():
    assert sensitive_reason("/comments/remove-test", allowed=frozenset({"delete", "remove"})) == ""
    assert sensitive_reason("/users/delete", allowed=frozenset({"delete", "remove"}))
    assert sensitive_reason("/comments/remove-test")  # still sensitive for a POST


def test_evaluate_is_pure_and_rejects_unknown_kinds():
    approved, reason, _ = evaluate(
        path="/x", kind="race", delegation={"enabled": True, "max_paths": 4},
        operations=[], approved_paths=set(), in_scope=lambda url: None,
    )
    assert approved is False and "unsupported kind" in reason


def test_schedule_delegation_requires_state_change():
    assert limits_from_config({"delegate_replay_approval": True}).delegate_replay_approval is False
    on = limits_from_config({
        "delegate_replay_approval": True, "allowed_actions": ["read", "probe", "state_change"],
    })
    assert on.delegate_replay_approval is True
    assert limits_from_config(on.__dict__).delegate_replay_approval is True


def test_api_policy_accepts_delegation():
    from app.api.routes.agent import AgentAssessmentPolicy

    policy = AgentAssessmentPolicy.model_validate({
        "delegated_replay_approval": {"enabled": True, "max_paths": 3},
    }).model_dump()
    assert normalize_delegation(policy["delegated_replay_approval"])["max_paths"] == 3
    with pytest.raises(Exception):
        AgentAssessmentPolicy.model_validate({"delegated_replay_approval": {"max_paths": 99}})
