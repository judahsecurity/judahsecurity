"""Severity gating for CI/CD — turn a findings list into a build pass/fail.

Pure, dependency-free helpers so a CI wrapper (or the platform) can decide
whether a scan should block a pipeline. `severity_gate` returns the exit code
a CI step should use plus a human-readable summary.
"""
from __future__ import annotations

from typing import Any, Dict, List

# Ordered low → high. Anything at or above the chosen threshold blocks.
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# Common aliases seen across nuclei / semgrep / our pipeline.
_ALIASES = {
    "informational": "info",
    "information": "info",
    "warning": "medium",
    "moderate": "medium",
    "error": "high",
    "important": "high",
    "severe": "critical",
    "crit": "critical",
    "none": "info",
    "unknown": "info",
}


def normalize_severity(sev: Any) -> str:
    """Map any severity string to one of SEVERITY_ORDER (defaults to 'info')."""
    if not sev:
        return "info"
    s = str(sev).strip().lower()
    s = _ALIASES.get(s, s)
    return s if s in _RANK else "info"


def _finding_severity(f: Dict[str, Any]) -> str:
    # Prefer an escalated severity when the pipeline set one.
    for key in ("escalated_severity", "severity", "current_severity", "original_severity"):
        if f.get(key):
            return normalize_severity(f.get(key))
    return "info"


def severity_gate(findings: List[Dict[str, Any]], fail_on: str = "high") -> Dict[str, Any]:
    """Decide whether a scan should fail the build.

    Args:
        findings: list of finding dicts (any of our finding shapes).
        fail_on: minimum severity that blocks — one of SEVERITY_ORDER, or
                 "never" to never fail (report-only mode).

    Returns dict: {exit_code, threshold, counts, blocking, total}.
      exit_code is 0 (pass) or 1 (blocked); 2 for a bad threshold argument.
    """
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings or []:
        counts[_finding_severity(f)] += 1

    total = sum(counts.values())
    threshold = str(fail_on or "high").strip().lower()

    if threshold in ("never", "none-fail", "off"):
        return {"exit_code": 0, "threshold": "never", "counts": counts,
                "blocking": 0, "total": total}

    if threshold not in _RANK:
        return {"exit_code": 2, "threshold": threshold, "counts": counts,
                "blocking": 0, "total": total,
                "error": f"invalid --fail-on '{threshold}'; use one of {SEVERITY_ORDER} or 'never'"}

    cutoff = _RANK[threshold]
    blocking = sum(n for s, n in counts.items() if _RANK[s] >= cutoff)
    return {
        "exit_code": 1 if blocking > 0 else 0,
        "threshold": threshold,
        "counts": counts,
        "blocking": blocking,
        "total": total,
    }


def summary_line(gate: Dict[str, Any]) -> str:
    c = gate["counts"]
    dist = " ".join(f"{s}={c[s]}" for s in reversed(SEVERITY_ORDER) if c[s])
    if gate.get("error"):
        return f"gate error: {gate['error']}"
    verdict = "BLOCKED" if gate["exit_code"] == 1 else "PASS"
    return (f"[{verdict}] {gate['total']} finding(s) [{dist or 'none'}] — "
            f"{gate['blocking']} at/above '{gate['threshold']}'")
