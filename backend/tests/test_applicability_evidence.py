from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.services.applicability_evidence import (
    evidence_view, finding_observations, oracle_asset_with_observations,
)
from app.services.agent.cve_applicability import match_cve_to_stack, format_applicability_report
from app.services.risk_model import FACTOR_RATINGS, merged_risk_model
from app.services.severity_evaluation import FindingContext, Precond, evaluate_context, _preconditions


@pytest.mark.parametrize("products, verdict", [
    ([], "unknown"),
    ([{"name": "uvicorn", "version": "0.30.0"}], "unknown"),
    ([{"name": "streamlit", "version": "1.2.2"}], "unknown"),
    ([{"name": "mesop", "version": "1.2.2"}], "version_match"),
    ([{"name": "mesop", "version": "1.2.3"}], "version_outside_range"),
    ([{"name": "mesop", "version": "1.2.3"}, {"name": "mesop"}], "product_present_version_unknown"),
])
def test_mesop_fingerprint_is_candidate_evidence(products, verdict):
    match = match_cve_to_stack(cve_id="CVE-2026-33057", intel_text="Mesop AI sandbox affected <=1.2.2",
                              affected_products=[{"product": "mesop"}], products=products)
    assert match["verdict"] == verdict
    report = format_applicability_report(url="https://example.test", products=products, match=match)
    assert "VERDICT: applicable" not in report
    assert "VERDICT: not_applicable" not in report


def test_partial_prerequisite_set_cannot_be_likely_even_with_endpoint_or_kev():
    result = evaluate_context(FindingContext(
        cve_id="CVE-2026-33057", detection_confidence="endpoint_confirmed",
        exploitation={"in_kev_sources": ["cisa_kev"], "metasploit_available": True},
        preconditions=[Precond("installed", "sandbox installed", True, "satisfied"),
                       Precond("enabled", "sandbox handler enabled", True, "unknown")],
    ))
    assert result["exploit_realism"]["tier"] == "unverified"
    view = merged_risk_model(result, {})
    assert "exploit_realism" in view["needs_analyst"]
    assert view["score"] > 0


@pytest.mark.parametrize("state, tier, zero", [
    ("conditions_met", "likely", False),
    ("needs_evidence", "unverified", False),
    ("documented_path_blocked", "blocked", True),
])
def test_path_assessment_controls_realism_without_changing_factor_scale(state, tier, zero):
    result = evaluate_context(FindingContext(
        cve_id="CVE-2026-33057", published_cvss=9.8,
        contextual_assessment={"state": state},
        # A blocked alternative must not override the combined path assessment.
        preconditions=[Precond("http", "HTTP disabled", True, "unsatisfied")],
    ))
    view = merged_risk_model(result, {})
    assert view["exploit_realism"]["tier"] == tier
    assert (view["score"] == 0) is zero
    assert all(f["score"] in FACTOR_RATINGS[key] for key, f in view["factors"].items())


def test_exploit_proof_conflicting_with_block_requires_review():
    result = evaluate_context(FindingContext(cve_id="CVE-2026-33057", detection_confidence="exploit_confirmed",
                                            contextual_assessment={"state": "documented_path_blocked"}))
    assert result["exploit_realism"]["tier"] == "conditional"
    assert result["exploit_realism"]["needs_analyst"] is True


def test_missing_evaluated_prerequisite_is_preserved_as_unknown():
    oracle = {"preconditions": [{"id": "enabled", "severity": "blocker"}],
              "preconditions_evaluated": [{"precondition": {"id": "installed", "severity": "blocker"}, "status": "satisfied"}]}
    assert [(p.id, p.status) for p in _preconditions(oracle)] == [("installed", "satisfied"), ("enabled", "")]


def test_observations_do_not_transfer_to_other_assets_or_cves():
    vuln = SimpleNamespace(asset_id=1, cve_id="CVE-2026-33057", metadata_={"applicability_evidence": {
        "asset_id": 1, "cve_id": "CVE-2026-33057", "signals": {"components.sandbox.enabled": {"value": "false"}},
    }})
    payload = oracle_asset_with_observations(vuln, {"signals": {}})
    assert payload["signals"]["observed_signals"]["components.sandbox.enabled"]["value"] == "false"
    vuln.asset_id = 2
    assert finding_observations(vuln) == {}
    vuln.asset_id, vuln.cve_id = 1, "CVE-2026-33058"
    assert finding_observations(vuln) == {}


def test_expired_evidence_is_shown_as_unknown():
    expired = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    vuln = SimpleNamespace(id=1, asset_id=1, cve_id="CVE-2026-33057", metadata_={"oracle": {
        "contextual_assessment": {"state": "documented_path_blocked", "preconditions": [{
            "precondition": {"id": "sandbox", "verification_signal": "components.sandbox.installed"},
            "status": "unsatisfied", "evidence": [{"valid_until": expired}],
        }]},
    }})
    view = evidence_view(vuln)
    assert view["state"] == "needs_evidence"
    assert view["checks"][0]["status"] == "unknown"
