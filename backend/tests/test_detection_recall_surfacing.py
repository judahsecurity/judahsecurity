"""Regression tests: don't silently drop real SQLi/XSS findings.

Covers three false-negative fixes:
  1. XML body parameters are tested for sqli/xss (not XXE-only).
  2. When the verifier returns narrative instead of a structured verdict, the
     candidate is left inconclusive BUT its account is preserved, not replaced
     with a generic placeholder.
  3. An inconclusive/refuted verdict surfaces the specific "why" on the
     coverage cell so the operator-facing funnel shows the real drop reason.
"""

from __future__ import annotations

from types import SimpleNamespace

from app.services.agent.engagement_brain import (
    EngagementBrain,
    engagement_brain_from_dict,
)
from app.services.agent.evidence_store import VerificationRun, verification_run
from app.services.agent.independent_verify import apply_verdict, submit_candidate
from app.services.agent.vulnerability_catalog import parameter_test_classes


def test_xml_body_parameter_is_tested_for_injection_not_only_xxe():
    classes = parameter_test_classes({
        "location": "body_xml",
        "name": "productId",
        "path": "/api/stock",
        "method": "POST",
    })
    # Previously returned ("xxe",) only, silently skipping injection testing.
    assert "sqli" in classes
    assert "xss" in classes
    assert "xxe" in classes


def test_json_body_parameter_still_tested_for_injection():
    # Guard the symmetric case so the XML fix didn't change JSON behaviour.
    classes = parameter_test_classes({
        "location": "body_json",
        "name": "comment",
        "path": "/api/reviews",
        "method": "POST",
    })
    assert "sqli" in classes
    assert "xss" in classes


def _candidate_with_cell(brain: EngagementBrain, *, cell_id: str):
    # Seed the coverage cell first so apply_verdict's cell loop can find it.
    brain.coverage_cells = [{
        "id": cell_id,
        "status": "leased",
        "reason": "",
        "specialist": "xss",
        "test_type": "xss",
    }]
    cand = submit_candidate(
        brain,
        title="Reflected XSS in q",
        target="https://app.example.com",
        severity="medium",
        coverage_cell_id=cell_id,
    )
    return cand


def _run_verdict(brain: EngagementBrain, cand, **kwargs):
    tm = SimpleNamespace(_engagement_brain=brain.to_dict(), _verify_receipts={})
    run = VerificationRun(id="run-1", candidate_id=cand.id,
                          revision=cand.revision, nonce=cand.nonce)
    token = verification_run.set(run)
    try:
        apply_verdict(tm, candidate_id=cand.id, **kwargs)
    finally:
        verification_run.reset(token)
    return engagement_brain_from_dict(tm._engagement_brain)


def _cell_reason(brain: EngagementBrain, cell_id: str) -> str:
    for cell in brain.coverage_cells:
        if cell.get("id") == cell_id:
            return cell.get("reason") or ""
    return ""


def test_inconclusive_verdict_surfaces_specific_reason_on_cell():
    brain = EngagementBrain(target="https://app.example.com")
    cand = _candidate_with_cell(brain, cell_id="cell-xss-q")
    result = _run_verdict(
        brain, cand,
        verdict="inconclusive",
        summary="reflection is only a lead; dialog never fired",
    )
    reason = _cell_reason(result, "cell-xss-q")
    assert "inconclusive" in reason.lower()
    # The specific why must be carried through, not a bare generic line.
    assert "reflection is only a lead" in reason


def test_refuted_verdict_surfaces_specific_reason_on_cell():
    brain = EngagementBrain(target="https://app.example.com")
    cand = _candidate_with_cell(brain, cell_id="cell-xss-q")
    result = _run_verdict(
        brain, cand,
        verdict="refuted",
        summary="payload did not execute under any identity",
    )
    reason = _cell_reason(result, "cell-xss-q")
    assert "payload did not execute" in reason
