"""
Likelihood × Impact risk model — analyst triage layer.

Aegis Oracle scores the seven risk factors automatically and stores them in
``metadata_["oracle"]["opes_risk_model"]``. Some factors cannot be measured
from scan data (how important a system is to the business, who hosts it,
whether a condition was verified by hand); Oracle marks those ``assumed``
and lists them in ``needs_analyst``.

Analysts set those factors — or override any other — during triage. Their
input lives in ``metadata_["risk_overrides"]`` so an Oracle re-enrichment
never wipes it, and the final score is recomputed here on read.

The arithmetic mirrors ``aegis-oracle/internal/modules/reasoners/priority/
opes/riskmodel.go`` (scoreRiskFactors); the worked examples in
tests/test_risk_model.py pin both to the same numbers.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Factor keys, grouped as the scoring sheet groups them.
IMPACT_FACTORS = ("business_impact", "network_location", "vulnerability_severity")
LIKELIHOOD_FACTORS = ("skill_level", "ease_of_discovery", "ease_of_exploit", "awareness")
FACTOR_KEYS = IMPACT_FACTORS + LIKELIHOOD_FACTORS

# Ratings per factor, 0–4, as on the scoring sheet (0 = none).
FACTOR_RATINGS: Dict[str, Dict[int, str]] = {
    "business_impact": {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "None"},
    # 4 is shown as "<Org> Hosted" for the organization being assessed.
    "network_location": {4: "Organization Hosted", 2: "Third Party Hosted", 1: "Internal Only", 0: "Segmented Network"},
    "vulnerability_severity": {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Informational"},
    "skill_level": {
        4: "No Technical Skills",
        3: "Some Technical Skills",
        2: "Advanced Computer User",
        1: "Security Penetration Skills",
        0: "Not Feasible",
    },
    "ease_of_discovery": {4: "Automated Tools Available", 3: "Easy", 2: "Difficult", 1: "Practically Impossible"},
    "ease_of_exploit": {
        4: "Automated Tools Available",
        3: "Easy",
        2: "Difficult",
        1: "Practically Impossible",
        0: "Not Exploitable Here",
    },
    "awareness": {4: "Public Knowledge", 3: "Obvious", 2: "Hidden", 1: "Unknown"},
}

REALISM_TIERS = ("confirmed", "likely", "unverified", "conditional", "blocked")

# Defaults match opes.DefaultConfig().RiskModel.
WEIGHTS = {"business_impact": 0.20, "network_location": 0.10, "vulnerability_severity": 0.70}
LEVELS = ((64.0, "critical"), (36.0, "high"), (16.0, "medium"), (4.0, "low"))
BLOCKED_LIKELIHOOD_CAP = 0.0
CONDITIONAL_LIKELIHOOD_CAP = 2.0


def org_hosted_rating(org_name: Optional[str]) -> str:
    """Network Location 4 label, e.g. "Acme Hosted" (mirrors OrgHostedRating in Go)."""
    return f"{(org_name or '').strip() or 'Organization'} Hosted"


def factor_ratings(org_name: Optional[str] = None) -> Dict[str, Dict[int, str]]:
    ratings = {k: dict(v) for k, v in FACTOR_RATINGS.items()}
    ratings["network_location"][4] = org_hosted_rating(org_name)
    return ratings


def score_factors(scores: Dict[str, int], realism_tier: Optional[str] = None) -> Dict[str, Any]:
    """Risk = (Impact/4)·(Likelihood/4)·100 from seven 0–4 factor scores."""
    impact = sum(scores[k] * WEIGHTS[k] for k in IMPACT_FACTORS)
    uncapped = sum(scores[k] for k in LIKELIHOOD_FACTORS) / 4
    likelihood = uncapped
    if realism_tier == "blocked":
        likelihood = min(likelihood, BLOCKED_LIKELIHOOD_CAP)
    elif realism_tier == "conditional":
        likelihood = min(likelihood, CONDITIONAL_LIKELIHOOD_CAP)
    risk = (impact / 4) * (likelihood / 4) * 100
    level = "informational"
    for threshold, name in LEVELS:
        if risk >= threshold:
            level = name
            break
    return {
        "score": round(risk, 2),
        "level": level,
        "impact": round(impact, 2),
        "likelihood": round(likelihood, 2),
        "likelihood_uncapped": round(uncapped, 2),
    }


def validate_override(key: str, score: int) -> None:
    if key not in FACTOR_KEYS:
        raise ValueError(f"unknown risk factor {key!r}")
    if score not in FACTOR_RATINGS[key]:
        allowed = ", ".join(f"{s} ({r})" for s, r in sorted(FACTOR_RATINGS[key].items(), reverse=True))
        raise ValueError(f"{key}: score {score} not allowed; use one of {allowed}")


def apply_overrides(
    overrides: Dict[str, Any],
    factors: Dict[str, Optional[Dict[str, Any]]],
    realism: Optional[Dict[str, Any]],
    *,
    analyst: str,
) -> Dict[str, Any]:
    """Merge a triage submission into the stored overrides.

    ``factors`` maps factor key → ``{"score": int, "note": str}``, or None to
    clear the analyst value and fall back to the automatic score.
    ``realism`` is ``{"tier": str, "note": str}`` or None to clear.
    """
    out = dict(overrides or {})
    stored = dict(out.get("factors") or {})
    now = datetime.now(timezone.utc).isoformat()
    for key, value in (factors or {}).items():
        if value is None:
            stored.pop(key, None)
            continue
        score = int(value["score"])
        validate_override(key, score)
        stored[key] = {"score": score, "note": (value.get("note") or "").strip(), "by": analyst, "at": now}
    out["factors"] = stored
    if realism is not None:
        if realism.get("tier") is None:
            out.pop("exploit_realism", None)
        else:
            tier = realism["tier"]
            if tier not in REALISM_TIERS:
                raise ValueError(f"exploit realism tier must be one of {', '.join(REALISM_TIERS)}")
            out["exploit_realism"] = {"tier": tier, "note": (realism.get("note") or "").strip(), "by": analyst, "at": now}
    return out


def merged_risk_model(
    auto: Optional[Dict[str, Any]],
    overrides: Optional[Dict[str, Any]],
    org_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Combine Oracle's automatic factors with analyst overrides.

    Returns every factor with its effective score and source, the factors
    still waiting on an analyst, and the recomputed score — or
    ``status: "incomplete"`` when a factor has neither an automatic nor an
    analyst value.
    """
    auto = auto or {}
    overrides = overrides or {}
    auto_factors: Dict[str, Any] = auto.get("factors") or {}
    analyst_factors: Dict[str, Any] = overrides.get("factors") or {}
    needs_auto = set(auto.get("needs_analyst") or [])
    ratings = factor_ratings(org_name)

    factors: Dict[str, Dict[str, Any]] = {}
    missing: List[str] = []
    for key in FACTOR_KEYS:
        a = auto_factors.get(key)
        o = analyst_factors.get(key)
        if o is not None:
            factors[key] = {
                "score": o["score"],
                "rating": ratings[key].get(o["score"], ""),
                "reason": o.get("note") or "Set by analyst",
                "source": "analyst",
                "by": o.get("by"),
                "at": o.get("at"),
                "auto": a,
            }
        elif a is not None:
            factors[key] = {**a, "source": a.get("source") or ("assumed" if key in needs_auto else "auto")}
        else:
            missing.append(key)

    realism = auto.get("exploit_realism")
    realism_override = overrides.get("exploit_realism")
    if realism_override:
        realism = {
            "tier": realism_override["tier"],
            "reasons": [realism_override.get("note") or "Set by analyst"],
            "source": "analyst",
            "by": realism_override.get("by"),
            "at": realism_override.get("at"),
            "auto": auto.get("exploit_realism"),
        }

    needs_analyst = [k for k in FACTOR_KEYS if k in missing or factors.get(k, {}).get("source") == "assumed"]
    result: Dict[str, Any] = {
        "factors": factors,
        "exploit_realism": realism,
        "needs_analyst": needs_analyst,
        "ratings": {k: {str(s): r for s, r in v.items()} for k, v in ratings.items()},
        "auto_version": auto.get("version"),
    }
    if missing:
        result["status"] = "incomplete"
        return result

    # Oracle already applies realism caps to Ease of Exploit and the Skill
    # Level tooling floor; an analyst realism override only moves the
    # likelihood cap, since analyst factor scores are taken as given.
    result.update(score_factors({k: int(v["score"]) for k, v in factors.items()}, (realism or {}).get("tier")))
    result["status"] = "triaged" if not needs_analyst else "needs_analyst"
    return result
