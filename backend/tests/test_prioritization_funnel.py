"""Prioritization value funnel: unscored is not noise; proof is counted honestly."""

from app.api.routes.vulnerabilities import _bucket_delphi, build_prioritization_funnel


def _row(sev, *, delphi=None, opes_cat=None, opes_score=None, agent_chain=False,
         level=None, verdict=None, vid=1):
    meta = {}
    if delphi is not None:
        meta["delphi"] = delphi
    if agent_chain:
        meta["agent_detection"] = {"chain": [{"tool": "curl"}]}
    return (sev, opes_cat, opes_score, meta, level, verdict, vid)


def test_delphi_none_or_missing_is_unscored_not_filtered():
    assert _bucket_delphi(None) == "unscored"
    assert _bucket_delphi("none") == "unscored"
    assert _bucket_delphi("low") == "filtered"
    assert _bucket_delphi("critical") == "critical"


def test_findings_without_cve_are_kept_not_counted_as_noise():
    rows = [
        # No CVE, so no Delphi data: a confirmed agent SQLi must not be "noise".
        _row("critical", agent_chain=True, level="exploit_verified", vid=10),
        # Delphi explicitly had no data.
        _row("critical", delphi={"priority": "none"}, vid=11),
        # Delphi scored it low: genuinely deprioritized.
        _row("high", delphi={"priority": "low"}, vid=12),
    ]
    out = build_prioritization_funnel(rows)
    vf = out["value_funnel"]
    assert vf["open_critical_high"] == 3
    assert vf["not_scored"] == 2
    assert vf["likely_exploitable"] == 2
    assert out["columns"][1]["filtered"] == 1  # only the scored-low one
    assert vf["prioritized"] == 2
    assert vf["proven"] == 1 and vf["proven_finding_ids"] == [10]
    assert vf["agent_tested"] == 1


def test_stages_are_nested_and_proof_outside_priority_is_surfaced():
    rows = [
        _row("critical", delphi={"priority": "critical"}, opes_cat="critical", level="exploit_verified", vid=1),
        _row("critical", delphi={"priority": "critical"}, opes_cat="critical", agent_chain=True, vid=2),
        _row("high", delphi={"priority": "high", "kev": True}, opes_cat="high", vid=3),
        # Proven, but Delphi scored it moderate: counted separately, never hidden.
        _row("high", delphi={"priority": "moderate"}, verdict="confirmed", vid=4),
        # False positive never counts as proven.
        _row("critical", delphi={"priority": "critical"}, opes_cat="critical",
             level="exploit_verified", verdict="false_positive", vid=5),
    ]
    vf = build_prioritization_funnel(rows)["value_funnel"]
    order = ["open_critical_high", "likely_exploitable", "prioritized", "agent_tested", "proven"]
    values = [vf[k] for k in order]
    assert values == sorted(values, reverse=True), values
    assert vf["proven"] == 1 and vf["proven_finding_ids"] == [1]
    assert vf["proven_outside_priority"] == 1
    assert vf["agent_tested"] == 3  # 1 verified, 2 chain, 5 has a verdict


def test_reduction_never_rounds_to_100_when_something_survives():
    rows = [_row("high", delphi={"priority": "low"}, vid=i) for i in range(5664)]
    rows += [_row("critical", delphi={"priority": "critical"}, opes_cat="critical", vid=9000 + i) for i in range(2)]
    summary = build_prioritization_funnel(rows)["summary"]
    assert summary["reduction_pct"] == 99.9
    assert summary["deprioritized_total"] == 5664


def test_empty_rows():
    out = build_prioritization_funnel([])
    assert out["value_funnel"]["open_critical_high"] == 0
    assert out["summary"]["reduction_pct"] == 0
