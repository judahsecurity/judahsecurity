"""Prowl re-test of existing platform findings (scanner worker escalation)."""

import asyncio

import pytest

from app.services.agent import orchestrator as orchestrator_module
from app.services.agent import prowl_revalidation as pr
from app.services.agent import run_snapshot
from app.services.agent.run_snapshot import load_run_snapshot, save_run_snapshot

IDOR = {
    "id": 42, "title": "IDOR on /api/orders/{id} exposes other customers' orders",
    "description": "User B can read user A's order by changing the id.", "severity": "high",
    "target": "https://app.example.com/api/orders/1002", "detected_by": "agent",
    "source_kind": "web", "steps_to_reproduce": "GET /api/orders/1002 as user B",
    "metadata": {},
}


@pytest.fixture(autouse=True)
def snapshot_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(run_snapshot, "_DIR", tmp_path / "sessions")
    monkeypatch.setenv("AEGIS_EVIDENCE_DIR", str(tmp_path / "evidence"))


def test_proof_class_and_origin():
    assert pr.proof_class_for(IDOR) == "authorization"
    assert pr.proof_class_for({"title": "Reflected XSS in q"}) == "xss"
    assert pr.proof_class_for({"title": "Outdated jQuery CVE-2020-11022"}) == ""  # no proof kind
    assert pr.proof_class_for({"title": "Weird thing"}) == ""
    assert pr.proof_class_for({"title": "x", "metadata": {"vulnerability_class": "ssrf"}}) == "ssrf"
    assert pr.finding_origin(IDOR) == "https://app.example.com"
    assert pr.finding_origin({"target": "app.example.com:8443"}) == "https://app.example.com:8443"
    assert pr.finding_origin({"target": "ldap://dc.example.com"}) == ""


@pytest.mark.parametrize("status, verdict, still_open", [
    ("confirmed", "confirmed", True),
    ("refuted", "false_positive", False),
    ("inconclusive", "needs_more_evidence", None),
    ("pending", "needs_more_evidence", None),
])
def test_verdict_mapping(status, verdict, still_open):
    out = pr.verdict_from_candidate({"id": "c1", "status": status, "verifier_summary": "why"},
                                    session_id="s", cls="xss", severity="high")
    assert out["verdict"] == verdict and out["still_open"] is still_open
    assert out["method"] == "prowl_independent_verify" and out["prowl_session_id"] == "s"
    assert pr.verdict_from_candidate(None, session_id="s", cls="xss",
                                     severity="high")["verdict"] == "needs_more_evidence"


def _fake_orchestrator(monkeypatch, *, status, seen, receipt=True):
    class Fake:
        async def invoke(self, *, question, user_id, organization_id, session_id, mode,
                         max_iterations, **_kw):
            seen.update(question=question, session_id=session_id, mode=mode,
                        revalidation_only=pr.revalidation_only.get(), max_iterations=max_iterations)
            snap = load_run_snapshot(organization_id, session_id)
            seen["seed_target"] = snap["capability_map"]["target"]
            brain = snap["engagement_brain"]
            receipts = brain.setdefault("verification_receipts", {})
            for row in brain["candidates"]:
                row.update(status=status, verifier_summary=f"verifier says {status}",
                           verifier_run_id="vr1", nonce="n1")
                if receipt:
                    # What the real verifier records alongside a confirmed verdict.
                    receipts[row["id"]] = {
                        "candidate_id": row["id"], "verdict": status, "run_id": "vr1",
                        "revision": row["revision"], "nonce": "n1", "nonce_observed": True,
                        "evidence_ids": ["ev1"]}
            save_run_snapshot(organization_id, session_id, {**snap, "engagement_brain": brain})

    async def get_fake(**_kw):
        return Fake()

    monkeypatch.setattr(orchestrator_module, "get_agent_orchestrator", get_fake)


def test_confirmed_retest_maps_back_without_publishing(monkeypatch):
    seen = {}
    _fake_orchestrator(monkeypatch, status="confirmed", seen=seen)
    verdict = asyncio.run(pr.revalidate_with_prowl(IDOR, organization_id=5, user_id=9))
    assert verdict["verdict"] == "confirmed" and verdict["vulnerability_class"] == "authorization"
    assert verdict["reasoning"] == "verifier says confirmed"
    assert seen["revalidation_only"] is True and seen["mode"] == "agent"
    assert seen["seed_target"] == "https://app.example.com"
    assert seen["session_id"].startswith("reval-42-") and "Do not call create_finding" in seen["question"]
    assert pr.revalidation_only.get() is False


def test_confirmed_without_durable_receipt_is_never_trusted(monkeypatch):
    # Snapshot recovery demotes it to pending, so there is no verdict to report.
    _fake_orchestrator(monkeypatch, status="confirmed", seen={}, receipt=False)
    assert asyncio.run(pr.revalidate_with_prowl(IDOR, organization_id=5, user_id=9)) is None


def test_verifier_that_never_ran_lets_the_caller_fall_back(monkeypatch):
    _fake_orchestrator(monkeypatch, status="pending", seen={})
    assert asyncio.run(pr.revalidate_with_prowl(IDOR, organization_id=5, user_id=9)) is None


def test_inconclusive_verifier_is_a_final_answer(monkeypatch):
    _fake_orchestrator(monkeypatch, status="inconclusive", seen={})
    verdict = asyncio.run(pr.revalidate_with_prowl(IDOR, organization_id=5, user_id=9))
    assert verdict["verdict"] == "needs_more_evidence" and verdict["prowl_status"] == "inconclusive"


def test_refuted_retest_is_a_false_positive(monkeypatch):
    _fake_orchestrator(monkeypatch, status="refuted", seen={})
    verdict = asyncio.run(pr.revalidate_with_prowl(IDOR, organization_id=5, user_id=9))
    assert verdict["verdict"] == "false_positive" and verdict["still_open"] is False


@pytest.mark.parametrize("finding, user_id", [
    # No provable class and not an application claim (template exposure):
    # application claims without a class get a retest instead (test_validation_gaps).
    ({**IDOR, "title": "Outdated jQuery", "description": "", "detected_by": "nuclei"}, 9),
    (IDOR, None),                                                      # no requesting user
    ({**IDOR, "target": "ldap://dc.example.com"}, 9),                 # not HTTP
])
def test_findings_prowl_cannot_take_return_none(monkeypatch, finding, user_id):
    async def must_not_run(**_kw):
        raise AssertionError("orchestrator should not start")

    monkeypatch.setattr(orchestrator_module, "get_agent_orchestrator", must_not_run)
    assert asyncio.run(pr.revalidate_with_prowl(finding, organization_id=5, user_id=user_id)) is None


def test_create_finding_refuses_during_revalidation():
    from app.services.agent.tools import ASMToolsManager

    manager = ASMToolsManager.__new__(ASMToolsManager)
    token = pr.revalidation_only.set(True)
    try:
        result = asyncio.run(manager.create_finding(
            title="IDOR", description="d", severity="high", target="https://app.example.com/x"))
    finally:
        pr.revalidation_only.reset(token)
    assert result == pr.PUBLISH_REFUSAL
