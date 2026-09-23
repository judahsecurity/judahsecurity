"""Severity evaluation rules (Likelihood × Impact, factors 0–4)."""

import pytest

from app.services.risk_model import score_factors
from app.services.severity_evaluation import (
    FindingContext,
    Precond,
    evaluate_context,
)

UNAUTH_RCE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def _score(result):
    scores = {k: f["score"] for k, f in result["factors"].items()}
    return score_factors(scores, result["exploit_realism"]["tier"])


def kev_metasploit(**kw):
    base = dict(
        cve_id="CVE-2099-0002", published_cvss=9.8, cvss_vector=UNAUTH_RCE,
        detected_by="nuclei", template_id="cves/2099/CVE-2099-0002",
        exploitation={"in_kev_sources": ["cisa_kev"], "metasploit_available": True},
        asset_criticality="critical", exposure="internet", hosting_type="owned",
        hosting_basis="145.97.10.10 is in Acme's IP inventory", organization_name="Acme",
    )
    base.update(kw)
    return FindingContext(**base)


def test_kev_metasploit_org_hosted_is_critical():
    r = evaluate_context(kev_metasploit())
    f = {k: v["score"] for k, v in r["factors"].items()}
    assert f == {
        "business_impact": 4, "network_location": 4, "vulnerability_severity": 4,
        "skill_level": 4, "ease_of_discovery": 4, "ease_of_exploit": 3, "awareness": 4,
    }
    assert r["factors"]["network_location"]["rating"] == "Acme Hosted"
    assert r["exploit_realism"]["tier"] == "unverified"  # version match only → Metasploit held at 3
    assert r["needs_analyst"] == []
    assert _score(r)["level"] == "critical"


@pytest.mark.parametrize(
    "overrides, tier, ease, max_likelihood",
    [
        ({"detection_confidence": "exploit_confirmed"}, "confirmed", 4, 4),
        ({"validation_verdict": "confirmed"}, "confirmed", 4, 4),
        ({"detection_confidence": "endpoint_confirmed"}, "likely", 4, 4),
        ({"attack_path": "lateral_movement_required"}, "conditional", 2, 2),
        ({"preconditions": [Precond("mod", "module enabled", True, "unsatisfied")]}, "blocked", 0, 0),
    ],
)
def test_exploit_realism_tiers(overrides, tier, ease, max_likelihood):
    r = evaluate_context(kev_metasploit(**overrides))
    assert r["exploit_realism"]["tier"] == tier
    assert r["factors"]["ease_of_exploit"]["score"] == ease
    assert _score(r)["likelihood"] <= max_likelihood


def test_cve_2025_55130_uses_reconciled_cvss_and_is_conditional():
    ctx = FindingContext(
        cve_id="CVE-2025-55130", cwe_id="CWE-22", published_cvss=9.1, reconciled_cvss=7.1,
        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        attacker_capability="code_execution_required", remote_triggerability="no", exploit_complexity="medium",
        exploitation={"public_poc_found": True},
        preconditions=[Precond("perm", "permissions on", True, "unknown"), Precond("js", "runs user code", True, "unknown")],
        asset_criticality="high", exposure="internet",
    )
    r = evaluate_context(ctx)
    sev = r["factors"]["vulnerability_severity"]
    assert (sev["score"], sev["reason"]) == (3, "CVSS 7.1 (reconciled; published 9.1)")
    assert r["factors"]["skill_level"]["score"] == 2
    assert r["exploit_realism"]["tier"] == "conditional"
    assert _score(r)["score"] == pytest.approx(39.29, abs=0.01)
    assert "network_location" in r["needs_analyst"]


def test_skill_level_difficulty_then_tooling():
    hard = "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H"
    base = dict(cve_id="CVE-2099-0004", published_cvss=8.0, cvss_vector=hard, detection_confidence="endpoint_confirmed")
    assert evaluate_context(FindingContext(**base))["factors"]["skill_level"]["score"] == 1
    armed = evaluate_context(FindingContext(**base, exploitation={"metasploit_available": True}))
    assert armed["factors"]["skill_level"]["score"] == 4
    assert "Metasploit module automates exploitation (difficulty alone: 1)" in armed["factors"]["skill_level"]["reason"]
    sqli = evaluate_context(FindingContext(**{**base, "cwe_id": "CWE-89"}))
    assert sqli["factors"]["skill_level"]["score"] == 2


def test_discovery_ordering():
    def disc(**kw):
        return evaluate_context(FindingContext(cve_id="CVE-2099-1", **kw))["factors"]["ease_of_discovery"]

    assert disc(detected_by="nuclei", template_id="t")["score"] == 4
    assert disc(exploitation={"attacker_discoverability_tier": "version_detectable"})["score"] == 4
    assert disc(is_manual=True)["score"] == 3
    assert disc(detected_by="wiz")["score"] == 2
    assert disc()["source"] == "assumed"


def test_non_cve_scanner_finding_is_scored_without_oracle():
    # An exposed admin panel found by nuclei, never analysed by Oracle.
    ctx = FindingContext(
        title="Exposed admin panel", scanner_severity="high", detected_by="nuclei",
        template_id="exposed-panels/admin", asset_criticality="medium", exposure="internet",
        hosting_type="third_party", hosting_basis="20.1.2.3 is in azure cloud address space",
    )
    r = evaluate_context(ctx)
    f = r["factors"]
    assert f["vulnerability_severity"]["score"] == 3
    assert f["vulnerability_severity"]["reason"] == "No CVSS; rated high by nuclei"
    assert f["ease_of_discovery"]["score"] == 4
    assert f["awareness"]["rating"] == "Obvious"
    assert r["exploit_realism"]["tier"] == "likely"
    # Default "medium" asset criticality and no vector/exploit analysis.
    assert r["needs_analyst"] == ["business_impact", "skill_level"]


def test_business_app_criticality_drives_business_impact():
    ctx = kev_metasploit(asset_criticality="low", business_app_name="Payments (APM0001234)", business_app_criticality=1)
    f = evaluate_context(ctx)["factors"]["business_impact"]
    assert f["score"] == 4
    assert "Payments (APM0001234)" in f["reason"]


def test_nothing_known_is_all_flagged():
    r = evaluate_context(FindingContext(title="Something"))
    assert set(r["needs_analyst"]) >= {"business_impact", "network_location", "vulnerability_severity", "skill_level"}
