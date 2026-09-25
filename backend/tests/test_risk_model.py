"""Risk model triage layer: arithmetic, weights, analyst overrides.

Worked examples use the sheet's 70/20/10 impact baseline with Standard (2)
selectors; likelihood factors also start at Standard (2).
"""

import pytest

from app.services.risk_model import (
    FACTOR_KEYS,
    org_hosted_rating,
    apply_overrides,
    merged_risk_model,
    score_factors,
)


def _f(bi, nl, vs, skill, disc, exploit, aware):
    return dict(zip(FACTOR_KEYS, (bi, nl, vs, skill, disc, exploit, aware)))


@pytest.mark.parametrize(
    "scores, risk, level",
    [
        (_f(4, 4, 3, 2, 4, 4, 4), 72.19, "critical"),
        (_f(4, 0, 4, 4, 4, 4, 4), 90.0, "critical"),
        (_f(3, 2, 2, 3, 4, 3, 4), 48.13, "high"),
        (_f(1, 1, 2, 2, 3, 3, 2), 26.56, "medium"),
        (_f(1, 2, 1, 1, 2, 1, 4), 13.75, "low"),
        (_f(1, 0, 1, 1, 1, 0, 0), 2.81, "informational"),
        (_f(4, 4, 4, 0, 0, 0, 0), 0.0, "informational"),
    ],
)
def test_worked_examples(scores, risk, level):
    got = score_factors(scores)
    assert got["score"] == pytest.approx(risk, abs=0.011)
    assert got["level"] == level


def test_realism_caps_likelihood():
    maxed = _f(4, 4, 4, 4, 4, 4, 4)
    assert score_factors(maxed, "blocked")["score"] == 0
    assert score_factors(_f(0, 0, 0, 4, 4, 4, 4))["score"] == 0
    assert score_factors(maxed, "conditional")["likelihood"] == 2.0
    assert score_factors(maxed, "conditional")["likelihood_uncapped"] == 4.0


def test_default_impact_split_matches_sheet():
    scores = _f(0, 0, 0, 4, 4, 4, 4)
    for key, expected in (("business_impact", 0.2), ("network_location", 0.1),
                          ("vulnerability_severity", 0.7)):
        scores[key] = 4
        assert score_factors(scores)["impact"] == pytest.approx(4 * expected)
        scores[key] = 0


def _auto(**overrides):
    factors = {
        "business_impact": {"score": 2, "rating": "Medium", "reason": "Asset criticality not set; assumed medium", "source": "assumed"},
        "network_location": {"score": 4, "rating": "Company Hosted", "reason": "hosting not classified", "source": "assumed"},
        "vulnerability_severity": {"score": 4, "rating": "Critical", "reason": "CVSS 9.8", "source": "auto"},
        "skill_level": {"score": 4, "rating": "No Technical Skills", "reason": "PR:N", "source": "auto"},
        "ease_of_discovery": {"score": 4, "rating": "Automated Tools Available", "reason": "Nuclei", "source": "auto"},
        "ease_of_exploit": {"score": 3, "rating": "Easy", "reason": "PoC", "source": "auto"},
        "awareness": {"score": 4, "rating": "Public Knowledge", "reason": "CVE", "source": "auto"},
    }
    factors.update(overrides)
    return {
        "factors": factors,
        "needs_analyst": ["business_impact", "network_location"],
        "exploit_realism": {"score": 3, "tier": "unverified", "reasons": ["version match only"]},
        "version": "risk/v6",
    }


def test_assumed_factors_need_analyst_until_set():
    view = merged_risk_model(_auto(), None)
    assert view["status"] == "needs_analyst"
    assert view["needs_analyst"] == ["business_impact", "network_location"]
    assert view["level"]  # still scored from the assumptions meanwhile

    overrides = apply_overrides(
        {},
        {
            "business_impact": {"score": 1, "note": "Marketing microsite, no customer data"},
            "network_location": {"score": 2, "note": "Hosted by vendor on AWS"},
        },
        None,
        analyst="analyst@example.com",
    )
    view = merged_risk_model(_auto(), overrides)
    assert view["status"] == "triaged"
    assert view["needs_analyst"] == []
    bi = view["factors"]["business_impact"]
    assert bi["source"] == "analyst" and bi["score"] == 1 and bi["rating"] == "Low"
    assert bi["reason"] == "Marketing microsite, no customer data"
    assert bi["auto"]["score"] == 2  # automatic value kept for comparison
    # Impact 0.2·1 + 0.1·2 + 0.7·4 = 3.2; likelihood 3.75 → 75 critical.
    assert view["score"] == pytest.approx(75.0)


def test_clearing_an_override_restores_auto():
    overrides = apply_overrides({}, {"awareness": {"score": 2, "note": "private report"}}, None, analyst="a")
    assert merged_risk_model(_auto(), overrides)["factors"]["awareness"]["score"] == 2
    overrides = apply_overrides(overrides, {"awareness": None}, None, analyst="a")
    assert merged_risk_model(_auto(), overrides)["factors"]["awareness"]["source"] == "auto"


def test_analyst_realism_verification():
    overrides = apply_overrides({}, {}, {"tier": "blocked", "note": "Module disabled, checked httpd -M"}, analyst="a")
    view = merged_risk_model(_auto(), overrides)
    assert view["exploit_realism"]["source"] == "analyst"
    assert view["score"] == 0 and view["level"] == "informational"


def test_realism_override_recomputes_auto_exploit_factor():
    auto = _auto(ease_of_exploit={"score": 0, "rating": "Not Exploitable Here",
                                  "reason": "PoC, but blocked on this asset", "source": "auto",
                                  "uncapped": {"score": 3, "rating": "Easy", "reason": "PoC", "source": "auto"}})
    auto["exploit_realism"] = {"score": 0, "tier": "blocked", "reasons": ["module disabled"]}
    confirmed = apply_overrides({}, {}, {"tier": "confirmed", "note": "module enabled"}, analyst="a")
    view = merged_risk_model(auto, confirmed)
    assert view["factors"]["ease_of_exploit"]["score"] == 3
    assert view["factors"]["ease_of_exploit"]["rating"] == "Easy"
    assert view["score"] > 0

    manual = apply_overrides(confirmed, {"ease_of_exploit": {"score": 1, "note": "manual test"}}, None, analyst="a")
    assert merged_risk_model(auto, manual)["factors"]["ease_of_exploit"]["score"] == 1


def test_missing_oracle_output_is_incomplete():
    view = merged_risk_model(None, None)
    assert view["status"] == "incomplete"
    assert view["needs_analyst"] == list(FACTOR_KEYS)
    overrides = apply_overrides({}, {k: {"score": 2} for k in FACTOR_KEYS}, None, analyst="a")
    assert merged_risk_model(None, overrides)["status"] == "triaged"


def test_invalid_scores_rejected():
    with pytest.raises(ValueError):
        apply_overrides({}, {"network_location": {"score": 3}}, None, analyst="a")  # sheet has 4/2/1/0
    with pytest.raises(ValueError):
        apply_overrides({}, {"awareness": {"score": 5}}, None, analyst="a")
    with pytest.raises(ValueError):
        apply_overrides({}, {"nope": {"score": 1}}, None, analyst="a")
    with pytest.raises(ValueError):
        apply_overrides({}, {}, {"tier": "maybe"}, analyst="a")


def test_network_location_rating_uses_org_name():
    assert org_hosted_rating("Acme") == "Acme Hosted"
    assert org_hosted_rating("") == "Organization Hosted"
    overrides = apply_overrides({}, {"network_location": {"score": 4, "note": "in our /24"}}, None, analyst="a")
    view = merged_risk_model(_auto(), overrides, "Acme")
    assert view["ratings"]["network_location"]["4"] == "Acme Hosted"
    assert view["factors"]["network_location"]["rating"] == "Acme Hosted"


def test_weights_change_the_score():
    scores = _f(1, 4, 4, 4, 4, 1, 1)
    base = score_factors(scores)
    # Business Impact counts most on this finding; Ease of Exploit too.
    weighted = score_factors(scores, weights={"business_impact": 4, "vulnerability_severity": 1, "ease_of_exploit": 4})
    assert weighted["impact"] < base["impact"]  # low business impact now dominates
    assert weighted["likelihood"] < base["likelihood"]
    # Equal selectors preserve the impact baseline and equalize likelihood.
    equal = score_factors(scores, weights={k: 3 for k in FACTOR_KEYS})
    assert equal["impact"] == pytest.approx(3.4) and equal["likelihood"] == pytest.approx(2.5)


def test_analyst_weights_are_stored_and_reset():
    overrides = apply_overrides({}, {}, None, analyst="a", weights={"business_impact": 4, "awareness": 1})
    view = merged_risk_model(_auto(), overrides)
    assert view["weights"]["business_impact"] == {
        "weight": 4, "source": "analyst", "by": "a", "at": overrides["weights"]["business_impact"]["at"], "default": 2}
    assert view["weights"]["network_location"]["source"] == "default"
    expected = score_factors({k: f["score"] for k, f in _auto()["factors"].items()}, "unverified",
                             {"business_impact": 4, "awareness": 1})
    assert view["score"] == pytest.approx(expected["score"])
    overrides = apply_overrides(overrides, {}, None, analyst="a", weights={"business_impact": None})
    assert merged_risk_model(_auto(), overrides)["weights"]["business_impact"]["source"] == "default"


def test_invalid_weights_rejected():
    for bad in (0, 5):
        with pytest.raises(ValueError):
            apply_overrides({}, {}, None, analyst="a", weights={"awareness": bad})
    with pytest.raises(ValueError):
        apply_overrides({}, {}, None, analyst="a", weights={"nope": 2})


def test_org_default_weights_apply_unless_analyst_overrides():
    auto = _auto()
    view = merged_risk_model(auto, None, "Acme", {"business_impact": 4, "awareness": 9})  # 9 is ignored
    assert view["weights"]["business_impact"] == {"weight": 4, "source": "organization", "default": 4}
    assert view["weights"]["awareness"]["source"] == "default"
    overrides = apply_overrides({}, {}, None, analyst="a", weights={"business_impact": 1})
    view = merged_risk_model(auto, overrides, "Acme", {"business_impact": 4})
    assert (view["weights"]["business_impact"]["weight"], view["weights"]["business_impact"]["source"]) == (1, "analyst")
    assert view["weights"]["business_impact"]["default"] == 4  # reset goes back to the org default
