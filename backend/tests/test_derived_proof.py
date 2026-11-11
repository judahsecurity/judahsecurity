"""Open-tier leads become fixed probe types only after explicit review."""

import pytest

from app.services.agent.proof_engine import (
    PROOF_STRATEGIES, DerivedProofRegistry,
)


def _reg():
    return DerivedProofRegistry()


def test_unapproved_proposal_never_resolves():
    reg = _reg()
    reg.propose(
        name="derived_tenantleak1", base_strategy="authorization_read",
        source_lead_id="abc123", source_kind="exploit_workspace_lead",
        target="https://app.test", notes="observed cross-tenant read",
    )
    assert reg.resolve("derived_tenantleak1") is None
    assert [p.name for p in reg.pending()] == ["derived_tenantleak1"]


def test_approved_proposal_reuses_trusted_evaluator():
    reg = _reg()
    reg.propose(
        name="derived_tenantleak1", base_strategy="authorization_read",
        source_lead_id="abc123", source_kind="exploit_workspace_lead",
        target="https://app.test",
    )
    reg.approve("derived_tenantleak1", reviewer="operator@judah")
    strat = reg.resolve("derived_tenantleak1")
    assert strat is not None
    base = PROOF_STRATEGIES["authorization_read"]
    # Same trusted code, new name — no model-supplied evaluator.
    assert strat.evaluate is base.evaluate
    assert strat.attack_methods == base.attack_methods
    assert not reg.pending()


def test_approval_requires_a_named_reviewer():
    reg = _reg()
    reg.propose(
        name="derived_x1", base_strategy="authorization_mutation",
        source_lead_id="id", source_kind="post_exploit_lead", target="https://app.test",
    )
    with pytest.raises(ValueError):
        reg.approve("derived_x1", reviewer="")
    assert reg.resolve("derived_x1") is None


def test_rejects_untrusted_base_and_non_lead_source():
    reg = _reg()
    with pytest.raises(ValueError):
        reg.propose(
            name="derived_bad", base_strategy="model_supplied_eval",
            source_lead_id="id", source_kind="exploit_workspace_lead",
            target="https://app.test",
        )
    with pytest.raises(ValueError):
        reg.propose(
            name="derived_bad2", base_strategy="authorization_read",
            source_lead_id="id", source_kind="http_exchange",  # not an open-tier lead
            target="https://app.test",
        )


def test_cannot_shadow_a_builtin_or_use_a_bad_name():
    reg = _reg()
    with pytest.raises(ValueError):
        reg.propose(
            name="authorization_read", base_strategy="authorization_read",
            source_lead_id="id", source_kind="exploit_workspace_lead",
            target="https://app.test",
        )
    with pytest.raises(ValueError):
        reg.propose(
            name="no_prefix", base_strategy="authorization_read",
            source_lead_id="id", source_kind="exploit_workspace_lead",
            target="https://app.test",
        )
