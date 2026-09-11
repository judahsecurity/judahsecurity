from datetime import datetime, timedelta

import pytest

from app.services.posture_score_service import (
    FindingScoreInput,
    _is_demonstrated,
    age_multiplier,
    calculate_posture_score,
)
from app.models.vulnerability import Vulnerability


NOW = datetime(2026, 9, 10, 12, 0, 0)


def finding(
    finding_id: int,
    severity: str,
    *,
    age_days: float = 0,
    status: str = "open",
) -> FindingScoreInput:
    return FindingScoreInput(
        finding_id=finding_id,
        title=f"Finding {finding_id}",
        severity=severity,
        status=status,
        opened_at=NOW - timedelta(days=age_days),
        asset_id=finding_id,
        asset_name=f"asset-{finding_id}.example",
    )


def test_age_multiplier_is_exact_at_key_boundaries():
    assert age_multiplier(0, 7) == 1.0
    assert age_multiplier(7, 7) == 2.0
    assert age_multiplier(700, 7) == pytest.approx(3.0)


def test_one_new_critical_is_capped_at_b():
    result = calculate_posture_score([finding(1, "critical")], 100, calculated_at=NOW)

    assert result["raw_score"] == pytest.approx(92.7503, abs=0.0001)
    assert result["score"] == 89
    assert result["grade"] == "B"
    assert result["cap_reason"] == "CRITICAL_CAP"


def test_critical_at_sla_matches_worked_example():
    result = calculate_posture_score([finding(1, "critical", age_days=7)], 100, calculated_at=NOW)

    assert result["raw_score"] == pytest.approx(86.3300, abs=0.0001)
    assert result["score"] == 86
    assert result["grade"] == "B"
    assert result["top_drivers"][0]["age_multiplier"] == 2.0


def test_three_high_findings_cap_the_grade():
    result = calculate_posture_score(
        [finding(1, "high"), finding(2, "high"), finding(3, "high")],
        100,
        calculated_at=NOW,
    )

    assert result["score"] == 89
    assert result["grade"] == "B"
    assert result["cap_reason"] == "HIGH_COUNT_CAP"


def test_multiple_critical_caps_choose_most_restrictive():
    findings = [finding(i, "critical") for i in range(1, 6)]
    result = calculate_posture_score(findings, 1000, calculated_at=NOW)

    assert result["score"] == 69
    assert result["grade"] == "D"
    assert result["cap_reason"] == "SEVERE_CRITICAL_CAP"


def test_resolving_a_finding_cannot_reduce_score():
    before = calculate_posture_score(
        [finding(1, "high"), finding(2, "medium")], 50, calculated_at=NOW
    )
    after = calculate_posture_score([finding(2, "medium")], 50, calculated_at=NOW)

    assert after["score"] >= before["score"]


def test_accepted_finding_has_the_same_technical_deduction():
    open_result = calculate_posture_score([finding(1, "critical")], 100, calculated_at=NOW)
    accepted_result = calculate_posture_score(
        [finding(1, "critical", status="accepted")], 100, calculated_at=NOW
    )

    assert accepted_result["score"] == open_result["score"]
    assert accepted_result["total_deduction"] == open_result["total_deduction"]


def test_no_findings_is_a_score_of_100_when_measurement_is_eligible():
    result = calculate_posture_score([], 12, calculated_at=NOW)

    assert result["score"] == 100
    assert result["grade"] == "A"
    assert result["top_drivers"] == []


def test_informational_findings_do_not_appear_as_score_drivers():
    result = calculate_posture_score([finding(1, "info")], 12, calculated_at=NOW)

    assert result["score"] == 100
    assert result["eligible_finding_count"] == 1
    assert result["top_drivers"] == []


def test_latest_validation_verdict_overrides_older_proof_chain():
    vulnerability = Vulnerability(
        title="Old demonstrated finding",
        severity="high",
        asset_id=1,
        last_validation_verdict="false_positive",
        detection_confidence="exploit_confirmed",
        metadata_={"agent_detection": {"chain": [{"outcome": "old proof"}]}},
    )

    assert _is_demonstrated(vulnerability) is False


def test_live_agent_proof_chain_is_demonstrated_without_validator_run():
    vulnerability = Vulnerability(
        title="Agent finding",
        severity="high",
        asset_id=1,
        metadata_={"agent_detection": {"chain": [{"outcome": "confirmed"}]}},
    )

    assert _is_demonstrated(vulnerability) is True
