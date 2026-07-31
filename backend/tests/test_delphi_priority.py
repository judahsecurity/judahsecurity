"""Unit tests for Delphi's exploitation-likelihood scoring.

These exercise `DelphiEnrichmentService._assess_exploitation_likelihood`
directly so no network fetch (KEV/EPSS) is triggered — the KEV entry is passed
in explicitly and CVSS/exposure/detection-confidence are supplied as args.
"""

import pytest

from app.services.delphi_enrichment_service import DelphiEnrichmentService, TIER_RANK


CVSS_UNAUTH_NET_RCE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS_LOCAL = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"


@pytest.fixture()
def svc() -> DelphiEnrichmentService:
    return DelphiEnrichmentService()


def assess(svc, **kwargs):
    """Call the scorer with sensible defaults; returns (tier, score, reason, signals, factors)."""
    params = {
        "cve_id": "CVE-2024-0001",
        "kev": None,
        "vulncheck_kev": None,
        "shadowserver": False,
        "kevintel": None,
        "cvss_score": None,
        "cvss_vector": None,
        "detection_confidence": None,
        "exposure": None,
    }
    params.update(kwargs)
    return svc._assess_exploitation_likelihood(**params)


def test_kev_is_critical(svc):
    tier, score, reason, signals, _ = assess(svc, kev={"known_ransomware_use": "Unknown"})
    assert tier == "critical"
    assert score >= 92
    assert "cisa_kev" in signals
    assert "KEV" in reason


def test_kev_ransomware_ranks_highest(svc):
    tier, score, _, signals, _ = assess(svc, kev={"known_ransomware_use": "Known"})
    assert tier == "critical"
    assert score >= 98
    assert "ransomware_campaign" in signals


def test_breach_intel_is_high(svc):
    # CVE-2023-34362 (MOVEit) is in the Mandiant M-Trends set.
    tier, score, _, signals, _ = assess(svc, cve_id="CVE-2023-34362")
    assert tier == "high"
    assert score >= 79
    assert "mandiant_mtrends" in signals


def test_vulncheck_kev_is_critical(svc):
    # VulnCheck is the broadest exploitation catalog — same floor as CISA.
    tier, score, reason, signals, _ = assess(
        svc,
        kev=None,
        vulncheck_kev={"known_ransomware_use": "Unknown"},
    )
    assert tier == "critical"
    assert score >= 92
    assert "vulncheck_kev" in signals
    assert "VulnCheck" in reason


def test_vulncheck_parity_with_cisa(svc):
    _, cisa_score, _, _, _ = assess(svc, kev={"known_ransomware_use": "Unknown"})
    _, vkev_score, _, _, _ = assess(svc, vulncheck_kev={"known_ransomware_use": "Unknown"})
    assert cisa_score == vkev_score >= 92


def test_vulncheck_and_cisa_both_signaled(svc):
    tier, score, reason, signals, _ = assess(
        svc,
        kev={"known_ransomware_use": "Unknown"},
        vulncheck_kev={"known_ransomware_use": "Unknown"},
    )
    assert tier == "critical"
    assert score >= 92
    assert "cisa_kev" in signals
    assert "vulncheck_kev" in signals
    assert "VulnCheck" in reason


def test_shadowserver_or_kevintel_is_critical(svc):
    tier, score, reason, signals, _ = assess(
        svc, shadowserver=True, kevintel={"cve_id": "CVE-2024-9999"}
    )
    assert tier == "critical"
    assert score >= 85
    assert "shadowserver_exploited" in signals
    assert "kevintel" in signals
    assert "Shadowserver" in reason or "KEVIntel" in reason


def test_extended_kev_below_vulncheck(svc):
    _, vkev_score, _, _, _ = assess(svc, vulncheck_kev={"known_ransomware_use": "Unknown"})
    _, ext_score, _, _, _ = assess(svc, shadowserver=True)
    assert vkev_score > ext_score


def test_unauth_network_rce_internet_facing_is_critical(svc):
    tier, score, _, signals, factors = assess(
        svc,
        cvss_score=9.8,
        cvss_vector=CVSS_UNAUTH_NET_RCE,
        detection_confidence="endpoint_confirmed",
        exposure={"internet_facing": True, "is_live": True},
    )
    assert tier == "critical"
    assert score >= 80
    assert "internet_facing_live" in signals
    assert factors["exploitability"] == pytest.approx(1.0)
    assert factors["reachability"] == pytest.approx(1.0)


def test_same_cve_internal_ranks_lower(svc):
    _, external, _, _, _ = assess(
        svc, cvss_score=9.8, cvss_vector=CVSS_UNAUTH_NET_RCE,
        detection_confidence="endpoint_confirmed",
        exposure={"internet_facing": True, "is_live": True},
    )
    tier, internal, _, signals, _ = assess(
        svc, cvss_score=9.8, cvss_vector=CVSS_UNAUTH_NET_RCE,
        detection_confidence="endpoint_confirmed",
        exposure={"internet_facing": False, "is_live": True},
    )
    assert internal < external
    assert "internal_only" in signals


def test_version_only_downgrades_confidence(svc):
    _, confirmed, _, _, _ = assess(
        svc, cvss_score=9.8, cvss_vector=CVSS_UNAUTH_NET_RCE,
        detection_confidence="exploit_confirmed",
        exposure={"internet_facing": True, "is_live": True},
    )
    _, version_only, _, signals, _ = assess(
        svc, cvss_score=9.8, cvss_vector=CVSS_UNAUTH_NET_RCE,
        detection_confidence="version_only",
        exposure={"internet_facing": True, "is_live": True},
    )
    assert version_only < confirmed
    assert "detection_version_only" in signals


def test_local_vector_not_gated_by_exposure(svc):
    # Local AV should ignore internet exposure (reachability factor stays 1.0).
    _, internal, _, _, factors_int = assess(
        svc, cvss_score=7.8, cvss_vector=CVSS_LOCAL,
        exposure={"internet_facing": False, "is_live": False},
    )
    _, external, _, _, factors_ext = assess(
        svc, cvss_score=7.8, cvss_vector=CVSS_LOCAL,
        exposure={"internet_facing": True, "is_live": True},
    )
    assert internal == external
    assert factors_int["reachability"] == pytest.approx(1.0)
    assert factors_ext["reachability"] == pytest.approx(1.0)


def test_no_asset_context_flags_reachability_unknown(svc):
    _, _, _, signals, _ = assess(
        svc, cvss_score=9.8, cvss_vector=CVSS_UNAUTH_NET_RCE,
    )
    assert "reachability_unknown" in signals


def test_no_data_is_none(svc):
    tier, score, reason, _, _ = assess(svc)
    assert tier == "none"
    assert score == 0
    assert "No CVE scoring data" in reason


def test_tier_rank_is_monotonic_with_score(svc):
    # A more-exploitable finding must never rank worse than a less-exploitable one.
    high_tier, high_score, *_ = assess(
        svc, cvss_score=9.8, cvss_vector=CVSS_UNAUTH_NET_RCE,
        detection_confidence="exploit_confirmed",
        exposure={"internet_facing": True, "is_live": True},
    )
    low_tier, low_score, *_ = assess(
        svc, cvss_score=4.0, cvss_vector=CVSS_LOCAL,
        detection_confidence="version_only",
        exposure={"internet_facing": False, "is_live": False},
    )
    assert high_score > low_score
    assert TIER_RANK[high_tier] <= TIER_RANK[low_tier]
