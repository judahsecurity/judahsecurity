"""Offline eval of the in-product swarm's *observe* step.

Does not invoke an LLM. Scores whether page assessment + specialist selection
match a ground-truth "how a human would start" list — the missing harness
target for Joshua / fireteam (not Vanguard CLI).
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Sequence


def score_start_here(
    predicted: Sequence[str],
    expected: Sequence[str],
    *,
    forbidden: Iterable[str] = ("coverage",),
) -> Dict[str, Any]:
    """Recall of expected specialists in the predicted auto-dispatch list."""
    pred = [str(x) for x in predicted if x]
    exp = [str(x) for x in expected if x]
    hit = [e for e in exp if e in pred]
    bad = [f for f in forbidden if pred and pred[0] == f]
    recall = (len(hit) / len(exp)) if exp else 1.0
    return {
        "recall": round(recall, 3),
        "hit": hit,
        "missed": [e for e in exp if e not in pred],
        "predicted": pred,
        "nuclei_first": bool(bad),
        "pass": recall >= 0.6 and not bad,
    }


def eval_capability_map(cmap: Any, expected: Dict[str, Any]) -> Dict[str, Any]:
    from app.services.agent.capability_map import select_specialists_for_map

    assessment = getattr(cmap, "assessment", None) or (
        cmap.get("assessment") if isinstance(cmap, dict) else {}
    ) or {}
    predicted = select_specialists_for_map(cmap)
    start = [r.get("specialist") for r in (assessment.get("start_here") or [])]
    return {
        "app_kind": assessment.get("app_kind"),
        "start_here": start,
        "dispatch": predicted,
        "start_score": score_start_here(start, expected.get("start_here") or []),
        "dispatch_score": score_start_here(predicted, expected.get("dispatch") or expected.get("start_here") or []),
    }
