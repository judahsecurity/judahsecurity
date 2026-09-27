"""Risk model triage layer: arithmetic, weights, analyst overrides.

Worked examples use the default weights (Severity 4, Business Impact 2,
Network Location 1; likelihood factors 2 each).
"""

import pytest

from app.services.risk_model import (
    FACTOR_KEYS,
    FACTOR_RATINGS,
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
        (_f(4, 4, 3, 2, 4, 4, 4), 75.0, "critical"),
        (_f(4, 2, 4, 4, 4, 4, 4), 92.86, "critical"),
        (_f(3, 2, 2, 3, 4, 3, 4), 50.0, "high"),
        (_f(1, 2, 2, 2, 3, 3, 2), 26.79, "medium"),
        (_f(1, 2, 1, 1, 2, 1, 4), 14.29, "low"),
        (_f(1, 2, 1, 1, 1, 1, 1), 7.14, "low"),
        (_f(4, 4, 4, 1, 1, 1, 1), 25.0, "medium"),
    ],
)
def test_worked_examples(scores, risk, level):
    got = score_factors(scores)
    assert got["score"] == pytest.approx(risk, abs=0.011)
    assert got["level"] == level


def test_realism_caps_likelihood():
    maxed = _f(4, 4, 4, 4, 4, 4, 4)
    assert score_factors(maxed, "blocked")["score"] == 0
    assert score_factors(maxed, "conditional")["likelihood"] == 2.0
    assert score_factors(maxed, "conditional")["likelihood_uncapped"] == 4.0


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
    # Impact (2·1 + 1·2 + 4·4)/7 = 2.857; likelihood 3.75 → 66.96 critical
    assert view["score"] == pytest.approx(66.96)


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


def test_missing_oracle_output_is_incomplete():
    view = merged_risk_model(None, None)
    assert view["status"] == "incomplete"
    assert view["needs_analyst"] == list(FACTOR_KEYS)
    overrides = apply_overrides({}, {k: {"score": 2} for k in FACTOR_KEYS}, None, analyst="a")
    assert merged_risk_model(None, overrides)["status"] == "triaged"


def test_invalid_scores_rejected():
    with pytest.raises(ValueError):
        apply_overrides({}, {"network_location": {"score": 3}}, None, analyst="a")  # sheet has 4/2
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


def test_rating_choices_match_the_scoring_sheet():
    for key, ratings in FACTOR_RATINGS.items():
        assert set(ratings) == ({2, 4} if key == "network_location" else {1, 2, 3, 4})


@pytest.mark.parametrize("bad", [0, -1, 5, 2.5, 2.0, True, False, "2", None])
def test_factor_ratings_are_strict_integers(bad):
    for key in FACTOR_KEYS:
        with pytest.raises(ValueError):
            apply_overrides({}, {key: {"score": bad}}, None, analyst="a")
        with pytest.raises(ValueError):
            score_factors({**_f(2, 2, 2, 2, 2, 2, 2), key: bad})


def test_invalid_saved_analyst_rating_requires_review_without_losing_audit():
    stored = {"factors": {"business_impact": {"score": 0, "note": "old scale", "by": "a"}}}
    view = merged_risk_model(_auto(business_impact={"score": 4, "source": "auto", "reason": "Critical asset"}), stored)
    factor = view["factors"]["business_impact"]
    assert (factor["score"], factor["rating"], factor["source"]) == (4, "Critical", "assumed")
    assert "Saved analyst rating" in factor["reason"]
    assert "business_impact" in view["needs_analyst"]
    assert stored["factors"]["business_impact"]["score"] == 0
    updated = apply_overrides(stored, {"business_impact": {"score": 1}}, None, analyst="a")
    assert "business_impact" not in merged_risk_model(_auto(), updated)["needs_analyst"]


def test_invalid_cached_auto_rating_is_not_returned_or_scored():
    view = merged_risk_model(_auto(ease_of_exploit={"score": 0, "rating": "Not Exploitable Here"}), None)
    assert view["status"] == "incomplete"
    assert "ease_of_exploit" not in view["factors"]
    assert "ease_of_exploit" in view["needs_analyst"]
    assert "score" not in view


def test_weights_change_the_score():
    scores = _f(1, 4, 4, 4, 4, 1, 1)
    base = score_factors(scores)
    # Business Impact counts most on this finding; Ease of Exploit too.
    weighted = score_factors(scores, weights={"business_impact": 4, "vulnerability_severity": 1, "ease_of_exploit": 4})
    assert weighted["impact"] < base["impact"]  # low business impact now dominates
    assert weighted["likelihood"] < base["likelihood"]
    # Equal weights reduce to plain means.
    equal = score_factors(scores, weights={k: 3 for k in FACTOR_KEYS})
    assert equal["impact"] == pytest.approx(3.0) and equal["likelihood"] == pytest.approx(2.5)


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
