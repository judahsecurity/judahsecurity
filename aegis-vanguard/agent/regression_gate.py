"""Blind-regression acceptance gate.

Before another long live assessment is worth running, a short regression on test
apps must clear hard, machine-checkable gates rather than a human eyeballing a
report. This evaluates a completed run's own artifacts against the criteria:

1. **First-pass breadth** — every eligible (planned) input cell received a
   recorded first pass; none is left ``pending``/``in_progress``.
2. **Clean tool I/O** — zero malformed tool calls and zero coverage-lease
   errors during the run.
3. **Independent reproduction** — the target's known SQLi and reflected XSS were
   each independently reproduced (not merely asserted by a hunter).

The gate is deterministic and takes only structured inputs, so it is unit-tested
and can run in CI against a fixed benchmark corpus.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from agent.coverage import _normalize_class


def _reproduced_classes(findings: Iterable[Dict[str, Any]]) -> set:
    """Classes with at least one independently reproduced, validated finding."""
    reproduced = set()
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        verdict = finding.get("independent_reproduction") or {}
        if (
            finding.get("lifecycle_state") == "validated"
            and isinstance(verdict, dict)
            and verdict.get("reproduced") is True
        ):
            reproduced.add(_normalize_class(
                verdict.get("class")
                or finding.get("vuln_type") or finding.get("type")
            ))
    return reproduced


def evaluate_regression_gate(
    coverage_summary: Dict[str, Any],
    findings: Iterable[Dict[str, Any]],
    *,
    require_reproduced: Iterable[str] = ("sqli", "xss"),
    tool_errors: int = 0,
    lease_errors: int = 0,
    max_tool_errors: int = 0,
    max_lease_errors: int = 0,
    budget: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return ``{"passed": bool, "checks": [...]}`` for a completed run."""
    checks: List[Dict[str, Any]] = []
    summary = coverage_summary or {}
    states = summary.get("states") or {}
    planned_total = int(summary.get("planned_total") or 0)
    planned_tested = int(summary.get("planned_tested") or 0)
    untested = max(0, planned_total - planned_tested)

    # 1. First-pass breadth across every eligible input.
    checks.append({
        "name": "first_pass_breadth",
        "passed": planned_total > 0 and untested == 0,
        "detail": (
            f"{planned_tested}/{planned_total} planned cells received a first pass; "
            f"{untested} still untested "
            f"(pending={states.get('pending', 0)}, in_progress={states.get('in_progress', 0)})"
        ),
    })

    # 2. Clean tool I/O — no malformed tool calls, no lease errors.
    checks.append({
        "name": "no_tool_format_errors",
        "passed": tool_errors <= max_tool_errors,
        "detail": f"{tool_errors} malformed tool calls (max {max_tool_errors})",
    })
    checks.append({
        "name": "no_lease_errors",
        "passed": lease_errors <= max_lease_errors,
        "detail": f"{lease_errors} coverage-lease errors (max {max_lease_errors})",
    })

    # 3. Independent reproduction of each required class.
    reproduced = _reproduced_classes(findings)
    required = {_normalize_class(c) for c in require_reproduced}
    missing = sorted(required - reproduced)
    checks.append({
        "name": "independent_reproduction",
        "passed": not missing,
        "detail": (
            "independently reproduced: "
            f"{sorted(reproduced) or '—'}; missing required: {missing or '—'}"
        ),
    })

    result = {
        "passed": all(c["passed"] for c in checks),
        "checks": checks,
    }
    if budget is not None:
        result["budget"] = budget
    return result


def format_gate(result: Dict[str, Any]) -> str:
    """Human-readable one-block summary of a gate result."""
    lines = [f"Regression gate: {'PASS' if result.get('passed') else 'FAIL'}"]
    for check in result.get("checks", []):
        mark = "✓" if check["passed"] else "✗"
        lines.append(f"  {mark} {check['name']}: {check['detail']}")
    return "\n".join(lines)


__all__ = ["evaluate_regression_gate", "format_gate"]
