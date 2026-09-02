"""
Performance scorecard — turn run artifacts into a number you can track.

You cannot improve what you cannot measure, and an agent's self-reported
success is exactly what this whole verification stack exists to distrust. This
module scores the artifacts a run actually emits — the flag grade and the
proof-gated findings document — into objective metrics, aggregates them across
a suite, and diffs against a baseline so a change that makes the agent *worse*
fails loudly instead of shipping.

Key metrics:
  flag_pass_rate        — of benchmarks with an expected flag, how many captured it
  overall_confirmed_rate — confirmed / total findings: the precision of "confirmed"
  needs_evidence        — findings that could not earn a proof token (the
                          false-positive pressure the gate absorbs)
  proof_tokens by kind  — where the evidence came from (flag/response_diff/
                          browser_exec/oob) → coverage across vuln classes

Pure functions here; `scorecard.py` at the repo root is the CLI.
"""

import json
import logging
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("agent.scorecard")


def score_run(findings_doc: dict, flag_grade: Optional[dict] = None) -> dict:
    """Score one run from its findings document (+ optional flag grade)."""
    total = int(findings_doc.get("total", 0) or 0)
    confirmed = int(findings_doc.get("confirmed", 0) or 0)
    needs = int(findings_doc.get("needs_evidence", max(0, total - confirmed)) or 0)
    tokens = findings_doc.get("verified_proof_tokens", []) or []
    kinds = Counter(t.get("kind", "?") for t in tokens if isinstance(t, dict))
    return {
        "target": findings_doc.get("target"),
        "findings_total": total,
        "confirmed": confirmed,
        "needs_evidence": needs,
        "confirmed_rate": round(confirmed / total, 4) if total else None,
        "proof_tokens": dict(kinds),
        "flag": (flag_grade or {}).get("status"),  # PASS | FAIL | NO_EXPECTED_FLAG | None
    }


def aggregate(run_scores: List[dict]) -> dict:
    """Aggregate per-run scores into a suite scorecard."""
    graded = [s for s in run_scores if s.get("flag") in ("PASS", "FAIL")]
    flag_pass = sum(1 for s in graded if s["flag"] == "PASS")
    tot_findings = sum(s["findings_total"] for s in run_scores)
    tot_conf = sum(s["confirmed"] for s in run_scores)
    tot_needs = sum(s["needs_evidence"] for s in run_scores)
    rates = [s["confirmed_rate"] for s in run_scores if s["confirmed_rate"] is not None]
    kinds: Counter = Counter()
    for s in run_scores:
        kinds.update(s.get("proof_tokens") or {})
    return {
        "runs": len(run_scores),
        "flag_graded": len(graded),
        "flag_pass": flag_pass,
        "flag_pass_rate": round(flag_pass / len(graded), 4) if graded else None,
        "findings_total": tot_findings,
        "confirmed": tot_conf,
        "needs_evidence": tot_needs,
        "overall_confirmed_rate": round(tot_conf / tot_findings, 4) if tot_findings else None,
        "mean_confirmed_rate": round(sum(rates) / len(rates), 4) if rates else None,
        "proof_tokens": dict(kinds),
        "runs_detail": run_scores,
    }


# Metrics where higher is better; needs_evidence is handled inversely.
_HIGHER_BETTER = ("flag_pass_rate", "overall_confirmed_rate",
                  "mean_confirmed_rate", "confirmed")


def compare(current: dict, baseline: dict, tolerance: float = 0.0) -> dict:
    """Diff a scorecard against a baseline; flag regressions.

    A regression is a higher-is-better metric that dropped by more than
    `tolerance`, or needs_evidence rising by more than tolerance (as a rate of
    findings). Returns deltas, the regressions list, and the improvements list.
    """
    deltas, regressions, improvements = {}, [], []
    for key in _HIGHER_BETTER:
        cur, base = current.get(key), baseline.get(key)
        if cur is None or base is None:
            continue
        d = round(cur - base, 4)
        deltas[key] = d
        if d < -tolerance:
            regressions.append(f"{key} dropped {base} → {cur} ({d:+})")
        elif d > tolerance:
            improvements.append(f"{key} improved {base} → {cur} ({d:+})")

    # needs_evidence share (lower is better)
    def _share(sc):
        t = sc.get("findings_total") or 0
        return (sc.get("needs_evidence", 0) / t) if t else None
    cur_share, base_share = _share(current), _share(baseline)
    if cur_share is not None and base_share is not None:
        d = round(cur_share - base_share, 4)
        deltas["needs_evidence_share"] = d
        if d > tolerance:
            regressions.append(
                f"needs_evidence share rose {base_share:.2f} → {cur_share:.2f} ({d:+})")
        elif d < -tolerance:
            improvements.append(
                f"needs_evidence share fell {base_share:.2f} → {cur_share:.2f} ({d:+})")

    return {"deltas": deltas, "regressions": regressions, "improvements": improvements,
            "regressed": bool(regressions)}


def _pct(rate) -> str:
    return "—" if rate is None else f"{rate * 100:.0f}%"


def render_markdown(agg: dict) -> str:
    tokens = ", ".join(f"{k}={v}" for k, v in sorted(agg["proof_tokens"].items())) or "none"
    lines = [
        "# Agent performance scorecard",
        "",
        f"- **Runs:** {agg['runs']}",
    ]
    if agg["flag_graded"]:
        lines.append(f"- **Flag capture:** {agg['flag_pass']}/{agg['flag_graded']} "
                     f"({_pct(agg['flag_pass_rate'])})")
    lines += [
        f"- **Findings:** {agg['findings_total']} "
        f"({agg['confirmed']} confirmed, {agg['needs_evidence']} needs-evidence)",
        f"- **Confirmed rate:** {_pct(agg['overall_confirmed_rate'])} overall",
        f"- **Proof tokens:** {tokens}",
        "",
        "| Target | Findings | Confirmed | Rate | Flag |",
        "|---|---|---|---|---|",
    ]
    for s in agg["runs_detail"]:
        rate = "—" if s["confirmed_rate"] is None else f"{s['confirmed_rate']*100:.0f}%"
        lines.append(f"| {s.get('target') or '—'} | {s['findings_total']} | "
                     f"{s['confirmed']} | {rate} | {s.get('flag') or '—'} |")
    return "\n".join(lines) + "\n"


def load_runs(runs_dir: str) -> List[dict]:
    """Load per-run scores from a directory of run artifacts.

    Pairs each `findings_<sid>.json` with its `grade_<sid>.json` (flag verdict)
    when present.
    """
    d = Path(runs_dir)
    scores = []
    for fdoc_path in sorted(d.glob("findings_*.json")):
        try:
            fdoc = json.loads(fdoc_path.read_text())
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("skipping %s: %s", fdoc_path, e)
            continue
        sid = fdoc_path.stem[len("findings_"):]
        grade = None
        grade_path = d / f"grade_{sid}.json"
        if grade_path.exists():
            try:
                grade = json.loads(grade_path.read_text())
            except (json.JSONDecodeError, OSError):
                grade = None
        scores.append(score_run(fdoc, grade))
    return scores
