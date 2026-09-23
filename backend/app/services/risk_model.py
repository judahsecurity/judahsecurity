"""
Likelihood × Impact risk model — analyst triage layer.

The severity evaluator (app/services/severity_evaluation.py) scores the
seven risk factors automatically and stores them in
``metadata_["severity_eval"]``. Some factors cannot be measured from the
evidence (how important a system is to the business, who hosts it, whether a
condition was verified by hand); those are ``assumed`` or proposed by the
gap agent (``agent``) and listed in ``needs_analyst``.

Analysts set those factors — or override any other — during triage. Their
input lives in ``metadata_["risk_overrides"]`` so an Oracle re-enrichment
never wipes it, and the final score is recomputed here on read.

tests/test_risk_model.py pins the arithmetic with worked examples.
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

# Per-factor weights, 1–4, chosen by the analyst per finding during triage.
# Impact and Likelihood are weighted averages, so they stay on the 0–4 scale.
# Defaults approximate the scoring sheet's 70/20/10 impact split with whole
# numbers (Severity 4 : Business 2 : Network 1 ≈ 57/29/14) and weight the
# likelihood factors equally.
WEIGHT_LABELS: Dict[int, str] = {1: "Low", 2: "Standard", 3: "High", 4: "Highest"}
DEFAULT_WEIGHTS: Dict[str, int] = {
    "business_impact": 2,
    "network_location": 1,
    "vulnerability_severity": 4,
    "skill_level": 2,
    "ease_of_discovery": 2,
    "ease_of_exploit": 2,
    "awareness": 2,
}
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


def _weighted_mean(scores: Dict[str, int], weights: Dict[str, int], keys) -> float:
    total = sum(weights[k] for k in keys)
    return sum(scores[k] * weights[k] for k in keys) / total


def score_factors(
    scores: Dict[str, int],
    realism_tier: Optional[str] = None,
    weights: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """Risk = (Impact/4)·(Likelihood/4)·100 from seven 0–4 factor scores,
    each side a weighted average using 1–4 weights."""
    w = {**DEFAULT_WEIGHTS, **(weights or {})}
    impact = _weighted_mean(scores, w, IMPACT_FACTORS)
    uncapped = _weighted_mean(scores, w, LIKELIHOOD_FACTORS)
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


def validate_weight(key: str, weight: int) -> None:
    if key not in FACTOR_KEYS:
        raise ValueError(f"unknown risk factor {key!r}")
    if weight not in WEIGHT_LABELS:
        raise ValueError(f"{key}: weight {weight} not allowed; use 1–4")


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
    weights: Optional[Dict[str, Optional[int]]] = None,
) -> Dict[str, Any]:
    """Merge a triage submission into the stored overrides.

    ``factors`` maps factor key → ``{"score": int, "note": str}``, or None to
    clear the analyst value and fall back to the automatic score.
    ``realism`` is ``{"tier": str, "note": str}`` or None to clear.
    ``weights`` maps factor key → 1–4, or None to go back to the default.
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
    stored_weights = dict(out.get("weights") or {})
    for key, weight in (weights or {}).items():
        if weight is None:
            stored_weights.pop(key, None)
            continue
        weight = int(weight)
        validate_weight(key, weight)
        stored_weights[key] = {"weight": weight, "by": analyst, "at": now}
    out["weights"] = stored_weights
    if realism is not None:
        if realism.get("tier") is None:
            out.pop("exploit_realism", None)
        else:
            tier = realism["tier"]
            if tier not in REALISM_TIERS:
                raise ValueError(f"exploit realism tier must be one of {', '.join(REALISM_TIERS)}")
            out["exploit_realism"] = {"tier": tier, "note": (realism.get("note") or "").strip(), "by": analyst, "at": now}
    return out


def valid_org_weights(org_weights: Optional[Dict[str, Any]]) -> Dict[str, int]:
    """The organization's valid 1–4 weight overrides (invalid entries ignored)."""
    out: Dict[str, int] = {}
    for key, value in (org_weights or {}).items():
        try:
            value = int(value)
            validate_weight(key, value)
        except (TypeError, ValueError):
            continue
        out[key] = value
    return out


def org_default_weights(org_weights: Optional[Dict[str, Any]]) -> Dict[str, int]:
    """Platform defaults with the organization's overrides applied."""
    return {**DEFAULT_WEIGHTS, **valid_org_weights(org_weights)}


def merged_risk_model(
    auto: Optional[Dict[str, Any]],
    overrides: Optional[Dict[str, Any]],
    org_name: Optional[str] = None,
    org_weights: Optional[Dict[str, Any]] = None,
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

    # Finding weight = analyst's choice, else the organization's default,
    # else the platform default.
    analyst_weights: Dict[str, Any] = overrides.get("weights") or {}
    org_set = valid_org_weights(org_weights)
    defaults = {**DEFAULT_WEIGHTS, **org_set}
    weights_view = {
        k: (
            {"weight": analyst_weights[k]["weight"], "source": "analyst",
             "by": analyst_weights[k].get("by"), "at": analyst_weights[k].get("at"), "default": defaults[k]}
            if k in analyst_weights
            else {"weight": defaults[k], "source": "organization" if k in org_set else "default", "default": defaults[k]}
        )
        for k in FACTOR_KEYS
    }

    # Assumed defaults and gap-agent proposals both wait on an analyst.
    needs_analyst = [k for k in FACTOR_KEYS if k in missing or factors.get(k, {}).get("source") in ("assumed", "agent")]
    result: Dict[str, Any] = {
        "factors": factors,
        "exploit_realism": realism,
        "needs_analyst": needs_analyst,
        "ratings": {k: {str(s): r for s, r in v.items()} for k, v in ratings.items()},
        "weights": weights_view,
        "weight_labels": {str(k): v for k, v in WEIGHT_LABELS.items()},
        "auto_version": auto.get("version"),
    }
    if missing:
        result["status"] = "incomplete"
        return result

    # Oracle already applies realism caps to Ease of Exploit and the Skill
    # Level tooling floor; an analyst realism override only moves the
    # likelihood cap, since analyst factor scores are taken as given.
    result.update(score_factors(
        {k: int(v["score"]) for k, v in factors.items()},
        (realism or {}).get("tier"),
        {k: v["weight"] for k, v in weights_view.items()},
    ))
    result["status"] = "triaged" if not needs_analyst else "needs_analyst"
    return result
