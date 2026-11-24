"""Unverified findings tier: inconclusive candidates with hunter evidence become
reviewable findings instead of disappearing, and every verdict is logged."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.db.database as database
from app.core.config import settings
from app.db.database import Base
import app.models  # noqa: F401 - registers model metadata for foreign keys
from app.models.agent_verdict_log import AgentVerdictLog
from app.models.asset import Asset
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus
from app.services.agent import tools as tools_module
from app.services.agent.engagement_brain import EngagementBrain, engagement_brain_from_dict
from app.services.agent.evidence_store import VerificationRun, verification_run
from app.services.agent.independent_verify import (
    apply_verdict,
    candidate_from_dict,
    submit_candidate,
)
from app.services.agent.tools import ASMToolsManager
from app.services.agent.unverified_findings import (
    ANALYST_VERIFIED,
    SUPERSEDED,
    UNVERIFIED,
    cap_unverified_severity,
    close_unverified_finding,
    dismiss_finding,
    exclude_hidden_levels,
    promote_finding,
    verdict_summary,
)

ORG_ID = 41
TARGET = "https://app.example.com/api/orders/1002"


@pytest.fixture
def db_factory(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=[
        Asset.__table__, Vulnerability.__table__, AgentVerdictLog.__table__,
    ])
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(database, "SessionLocal", factory)
    tools_module.set_tenant_context(user_id=7, organization_id=ORG_ID, session_id="session-1")
    yield factory
    tools_module.set_tenant_context(user_id=None, organization_id=None)


def _manager():
    manager = ASMToolsManager.__new__(ASMToolsManager)
    manager._engagement_brain = EngagementBrain().to_dict()
    manager._require_independent_verify = False
    return manager


def _candidate(manager, **kwargs):
    brain = engagement_brain_from_dict(manager._engagement_brain)
    args = dict(title="IDOR on order detail", target=TARGET, severity="high",
                description="Cross-user order read", vulnerability_class="authorization",
                evidence_ids=["hunter-evidence-1"])
    args.update(kwargs)
    cand = submit_candidate(brain, **args)
    manager._engagement_brain = brain.to_dict()
    return cand


def _verdict(manager, cand, verdict, **kwargs):
    run = VerificationRun("verifier-1", cand.id, cand.revision, cand.nonce)
    token = verification_run.set(run)
    try:
        return apply_verdict(manager, candidate_id=cand.id, verdict=verdict, **kwargs)
    finally:
        verification_run.reset(token)


def _stored(manager, cand_id):
    brain = engagement_brain_from_dict(manager._engagement_brain)
    return next(candidate_from_dict(c) for c in brain.candidates
                if (c.get("id") if isinstance(c, dict) else c.id) == cand_id)


def test_severity_cap():
    assert cap_unverified_severity("critical") == "medium"
    assert cap_unverified_severity("high") == "medium"
    assert cap_unverified_severity("low") == "low"
    assert cap_unverified_severity("bogus") == "info"


def test_inconclusive_with_hunter_evidence_publishes_unverified_finding(db_factory):
    manager = _manager()
    cand = _candidate(manager)
    result = _verdict(manager, cand, "inconclusive", summary="Second identity unavailable",
                      proof={"next_step": "Register identity B and replay"})
    assert result.review_status == "needs_analyst_review"

    stored = _stored(manager, cand.id)
    assert stored.unverified_finding_id
    with db_factory() as db:
        vuln = db.query(Vulnerability).one()
        assert vuln.id == stored.unverified_finding_id
        assert vuln.verification_level == UNVERIFIED
        assert vuln.severity == Severity.MEDIUM  # requested high, capped
        assert vuln.metadata_["unverified_lead"]["requested_severity"] == "high"
        assert "Second identity unavailable" in vuln.description
        log = db.query(AgentVerdictLog).one()
        assert (log.verdict, log.vulnerability_class, log.finding_id) == (
            "inconclusive", "authorization", vuln.id)
        assert log.hunter_evidence_count == 1

    # A second inconclusive verdict refreshes the same row, not a duplicate.
    _verdict(manager, _stored(manager, cand.id), "inconclusive", summary="Still no identity")
    with db_factory() as db:
        assert db.query(Vulnerability).count() == 1
        assert db.query(AgentVerdictLog).count() == 2


def test_inconclusive_without_hunter_evidence_is_only_logged(db_factory):
    manager = _manager()
    cand = _candidate(manager, evidence_ids=None, title="Weak lead",
                      target="https://app.example.com/y")
    _verdict(manager, cand, "inconclusive", summary="No evidence")
    with db_factory() as db:
        assert db.query(Vulnerability).count() == 0
        assert db.query(AgentVerdictLog).count() == 1


def test_tier_can_be_disabled(db_factory, monkeypatch):
    monkeypatch.setattr(settings, "AGENT_UNVERIFIED_FINDINGS", False)
    manager = _manager()
    _verdict(manager, _candidate(manager), "inconclusive", summary="gap")
    with db_factory() as db:
        assert db.query(Vulnerability).count() == 0
        assert db.query(AgentVerdictLog).count() == 1


def test_self_challenge_setting_still_requires_challenge(db_factory, monkeypatch):
    monkeypatch.setattr(settings, "AGENT_SELF_CHALLENGE", True)
    manager = _manager()
    result = _verdict(manager, _candidate(manager), "inconclusive", summary="gap")
    assert result.review_status == ""
    with db_factory() as db:
        assert db.query(Vulnerability).count() == 0


def test_superseded_and_refuted_findings_close(db_factory):
    manager = _manager()
    cand = _candidate(manager)
    _verdict(manager, cand, "inconclusive", summary="gap")
    first = _stored(manager, cand.id).unverified_finding_id
    close_unverified_finding(first, superseded_by=999)
    with db_factory() as db:
        vuln = db.get(Vulnerability, first)
        assert vuln.verification_level == SUPERSEDED
        assert vuln.status == VulnerabilityStatus.RESOLVED
        assert vuln.metadata_["superseded_by"] == 999

    other = _candidate(manager, title="Order export IDOR", target="https://app.example.com/api/export/7")
    _verdict(manager, other, "inconclusive", summary="gap")
    second = _stored(manager, other.id).unverified_finding_id
    close_unverified_finding(second, refuted_reason="Owner check held")
    with db_factory() as db:
        vuln = db.get(Vulnerability, second)
        assert vuln.status == VulnerabilityStatus.FALSE_POSITIVE
        assert vuln.metadata_["refuted"]["reason"] == "Owner check held"


def test_promote_restores_severity_and_dismiss_closes(db_factory):
    manager = _manager()
    _verdict(manager, _candidate(manager), "inconclusive", summary="gap")
    user = type("U", (), {"email": "analyst@example.test", "id": 3})()
    with db_factory() as db:
        vuln = db.query(Vulnerability).one()
        promote_finding(vuln, user, note="Reproduced by hand")
        assert vuln.verification_level == ANALYST_VERIFIED
        assert vuln.severity == Severity.HIGH
        assert "unverified" not in (vuln.tags or [])
        with pytest.raises(ValueError):
            promote_finding(vuln, user)
        with pytest.raises(ValueError):
            dismiss_finding(vuln, user)
        db.commit()

    other = _manager()
    _verdict(other, _candidate(other, title="Another", target="https://app.example.com/z"),
             "inconclusive", summary="gap")
    with db_factory() as db:
        vuln = db.query(Vulnerability).filter(Vulnerability.verification_level == UNVERIFIED).one()
        dismiss_finding(vuln, user, note="Public demo data")
        assert vuln.status == VulnerabilityStatus.FALSE_POSITIVE


def test_default_queries_hide_unverified(db_factory):
    manager = _manager()
    _verdict(manager, _candidate(manager), "inconclusive", summary="gap")
    with db_factory() as db:
        asset = db.query(Asset).one()
        db.add(Vulnerability(title="Confirmed", severity=Severity.HIGH, asset_id=asset.id,
                             verification_level="exploit_verified"))
        db.add(Vulnerability(title="Scanner", severity=Severity.LOW, asset_id=asset.id))
        db.commit()
        titles = {v.title for v in exclude_hidden_levels(db.query(Vulnerability), Vulnerability)}
        assert titles == {"Confirmed", "Scanner"}


def test_verdict_summary_groups_by_class(db_factory):
    manager = _manager()
    _verdict(manager, _candidate(manager), "inconclusive", summary="Second identity unavailable")
    _verdict(manager, _candidate(manager, title="SSRF via webhook", vulnerability_class="ssrf",
                                 target="https://app.example.com/hook"),
             "inconclusive", summary="No callback")
    with db_factory() as db:
        db.add(AgentVerdictLog(organization_id=ORG_ID, vulnerability_class="ssrf",
                               verdict="confirmed"))
        db.add(AgentVerdictLog(organization_id=ORG_ID + 1, vulnerability_class="ssrf",
                               verdict="inconclusive"))
        db.commit()
        out = verdict_summary(db, ORG_ID)
    by_class = {row["vulnerability_class"]: row for row in out["classes"]}
    assert by_class["ssrf"]["total"] == 2  # other org's row excluded
    assert by_class["ssrf"]["rejection_rate"] == 0.5
    assert by_class["authorization"]["top_inconclusive_reasons"][0]["reason"] == \
        "Second identity unavailable"
    assert out["totals"]["inconclusive"] == 2
