"""Offline eval of the in-product swarm's *observe* step.

Does not invoke an LLM. Scores whether page assessment + specialist selection
match a ground-truth "how a human would start" list — the missing harness
target for Joshua / fireteam (not Vanguard CLI).
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Sequence

TERMINAL_RUN_STATES = {"completed", "partial", "timeout", "cancelled", "error", "interrupted"}


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


def summarize_run_ledgers(runs: Sequence[dict]) -> Dict[str, Any]:
    """Summarize work and telemetry quality across all turns of one assessment."""
    valid = [run for run in runs if isinstance(run, dict) and run.get("run_id")]
    actions = [action for run in valid for action in (run.get("actions") or [])]
    coverage = [run.get("coverage") or {} for run in valid]
    terminal = all(run.get("status") in TERMINAL_RUN_STATES for run in valid)
    no_open_actions = all(action.get("status") != "running" for action in actions)
    action_count_matches = all(
        (run.get("coverage") or {}).get("actions") == len(run.get("actions") or [])
        for run in valid
    )
    return {
        "runs": len(valid),
        "actions": len(actions),
        "completed_actions": sum(action.get("status") == "completed" for action in actions),
        "failed_actions": sum(action.get("status") == "failed" for action in actions),
        "interrupted_actions": sum(action.get("status") == "interrupted" for action in actions),
        "skipped_actions": sum(action.get("status") == "skipped" for action in actions),
        "model_calls": sum(int(row.get("model_calls") or 0) for row in coverage),
        "test_actions": sum(int(row.get("test_actions") or 0) for row in coverage),
        "repeated_tool_target_actions": sum(
            int(row.get("repeated_tool_target_actions") or 0) for row in coverage
        ),
        "published_findings": sum(int(row.get("published_findings") or 0) for row in coverage),
        "duration_seconds": round(sum(float(row.get("duration_seconds") or 0) for row in coverage), 1),
        "timeout_runs": sum(run.get("status") in {"timeout", "interrupted", "stalled"} for run in valid),
        "receipt_complete": bool(valid and actions and terminal and no_open_actions and action_count_matches),
    }


def compare_ledger_assessments(baseline: dict, candidate: dict) -> Dict[str, Any]:
    """Compare equal-budget product assessments; finding quality needs a judge."""
    keys = ("target", "scope", "max_turns", "max_iterations", "price_limit_usd")
    mismatched = [key for key in keys if baseline.get(key) != candidate.get(key)]
    if mismatched:
        raise ValueError("Assessments differ on: " + ", ".join(mismatched))
    old = baseline.get("ledger_metrics") or {}
    new = candidate.get("ledger_metrics") or {}
    if not old.get("receipt_complete") or not new.get("receipt_complete"):
        raise ValueError("Both assessments need complete run receipts")
    metrics = (
        "actions", "test_actions", "repeated_tool_target_actions",
        "timeout_runs", "published_findings", "duration_seconds",
    )
    return {
        "target": baseline.get("target"),
        "baseline": {key: old.get(key) for key in metrics},
        "candidate": {key: new.get(key) for key in metrics},
        "delta": {key: round(float(new.get(key) or 0) - float(old.get(key) or 0), 2)
                  for key in metrics},
    }
