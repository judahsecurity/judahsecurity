"""
Detection judge.

Given the scanner's produced findings and a target's ground-truth
``expected_findings``, decide which expected defects were detected (recall) and
which produced findings correspond to nothing expected (candidate false
positives → precision).

Two backends:

* ``heuristic`` — deterministic, offline. Matches on vulnerability category and
  (when available) endpoint overlap. Needs no API key; used in CI/tests.
* ``anthropic`` / ``openai`` — an LLM maps produced findings to expected ones,
  which is more tolerant of naming/phrasing differences. Requires an API key.

Both return the same :class:`JudgeResult` shape so the tally code is agnostic.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ..findings import NormalizedFinding, categorize, vulnerabilities

# An LLM call: (system_prompt, user_prompt) -> raw text response.
LLMCall = Callable[[str, str], str]


@dataclass
class JudgeResult:
    detected: List[str] = field(default_factory=list)          # expected ids found
    missed: List[str] = field(default_factory=list)            # expected ids not found
    matches: List[Dict[str, Any]] = field(default_factory=list)  # expected_id -> finding
    false_positives: List[Dict[str, Any]] = field(default_factory=list)
    true_positive_count: int = 0
    false_positive_count: int = 0
    false_negative_count: int = 0

    def metrics(self) -> Dict[str, float]:
        tp, fp, fn = (
            self.true_positive_count,
            self.false_positive_count,
            self.false_negative_count,
        )
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall)
            else 0.0
        )
        return {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }


def _endpoint_overlap(expected_endpoint: str, finding: NormalizedFinding) -> bool:
    if not expected_endpoint:
        return True  # no endpoint constraint → category match is enough
    hay = " ".join(
        str(x) for x in [finding.endpoint or "", finding.url or "", finding.title]
    ).lower()
    needle = expected_endpoint.lower().strip("/")
    # Match on the last path segment or the full path fragment.
    tail = needle.split("/")[-1]
    return needle in hay or (len(tail) >= 3 and tail in hay)


def judge_heuristic(
    findings: List[NormalizedFinding], expected: List[Dict[str, Any]]
) -> JudgeResult:
    vulns = vulnerabilities(findings)
    result = JudgeResult()
    matched_finding_idx = set()

    for exp in expected:
        exp_id = exp.get("id", "")
        exp_cat = (exp.get("category") or categorize(exp.get("description", ""))).lower()
        exp_endpoint = exp.get("endpoint", "")

        hit = None
        for i, f in enumerate(vulns):
            if f.category == exp_cat and _endpoint_overlap(exp_endpoint, f):
                hit = (i, f)
                break

        if hit is not None:
            i, f = hit
            matched_finding_idx.add(i)
            result.detected.append(exp_id)
            result.matches.append(
                {"expected_id": exp_id, "finding_title": f.title, "category": f.category}
            )
        else:
            result.missed.append(exp_id)

    # Findings that mapped to no expected defect are candidate false positives.
    for i, f in enumerate(vulns):
        if i not in matched_finding_idx:
            result.false_positives.append(
                {"title": f.title, "category": f.category, "severity": f.severity}
            )

    result.true_positive_count = len(result.detected)
    result.false_negative_count = len(result.missed)
    result.false_positive_count = len(result.false_positives)
    return result


_JUDGE_SYSTEM = (
    "You are a precise security-assessment judge. You are given a list of "
    "EXPECTED vulnerabilities (ground truth) for a target application and a list "
    "of FINDINGS produced by an automated scanner. Map each expected "
    "vulnerability to a finding that clearly reports the same defect (same class "
    "and location). Be strict: a vague or unrelated finding does NOT count as a "
    "match. Respond ONLY with JSON."
)


def _build_judge_prompt(
    findings: List[NormalizedFinding], expected: List[Dict[str, Any]]
) -> str:
    findings_payload = [
        {
            "index": i,
            "title": f.title,
            "category": f.category,
            "severity": f.severity,
            "endpoint": f.endpoint or f.url,
            "confirmed": f.is_confirmed,
        }
        for i, f in enumerate(vulnerabilities(findings))
    ]
    expected_payload = [
        {
            "id": e.get("id"),
            "category": e.get("category"),
            "endpoint": e.get("endpoint"),
            "description": e.get("description"),
        }
        for e in expected
    ]
    return (
        "EXPECTED (ground truth):\n"
        + json.dumps(expected_payload, indent=2)
        + "\n\nFINDINGS (scanner output):\n"
        + json.dumps(findings_payload, indent=2)
        + "\n\nReturn JSON of exactly this shape:\n"
        '{\n'
        '  "matches": [{"expected_id": "<id>", "finding_index": <int>}],\n'
        '  "missed": ["<expected_id>", ...],\n'
        '  "false_positives": [<finding_index>, ...]\n'
        "}\n"
        "Every expected id must appear in either matches or missed exactly once."
    )


def _parse_judge_json(text: str) -> Dict[str, Any]:
    text = text.strip()
    # Tolerate ```json fences and leading prose.
    if "```" in text:
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1:
        text = text[start : end + 1]
    return json.loads(text)


def judge_llm(
    findings: List[NormalizedFinding],
    expected: List[Dict[str, Any]],
    llm_call: LLMCall,
) -> JudgeResult:
    vulns = vulnerabilities(findings)
    raw = llm_call(_JUDGE_SYSTEM, _build_judge_prompt(findings, expected))
    parsed = _parse_judge_json(raw)

    result = JudgeResult()
    matched_idx = set()
    for m in parsed.get("matches", []):
        exp_id = m.get("expected_id")
        idx = m.get("finding_index")
        result.detected.append(exp_id)
        if isinstance(idx, int) and 0 <= idx < len(vulns):
            matched_idx.add(idx)
            result.matches.append(
                {"expected_id": exp_id, "finding_title": vulns[idx].title}
            )
        else:
            result.matches.append({"expected_id": exp_id, "finding_title": None})

    result.missed = list(parsed.get("missed", []))
    for idx in parsed.get("false_positives", []):
        if isinstance(idx, int) and 0 <= idx < len(vulns):
            f = vulns[idx]
            result.false_positives.append(
                {"title": f.title, "category": f.category, "severity": f.severity}
            )

    result.true_positive_count = len(result.detected)
    result.false_negative_count = len(result.missed)
    result.false_positive_count = len(result.false_positives)
    return result


# =========================================================================
# Flag-capture mode (CTF-style, mirrors the XBOW/XBEN methodology)
# =========================================================================


@dataclass
class FlagResult:
    """Outcome of a CTF-style flag-capture challenge."""

    solved: bool
    flag: Optional[str] = None            # expected flag (exact) if provided
    flag_regex: Optional[str] = None      # expected flag pattern if provided
    matched_text: Optional[str] = None    # where the flag was seen (truncated)

    def metrics(self) -> Dict[str, Any]:
        return {"solved": self.solved}


def _finding_blob(f: NormalizedFinding) -> str:
    """Flatten a finding into searchable text (title, desc, PoC evidence, raw)."""
    raw = f.raw or {}
    poc = (raw.get("raw_data") or {}).get("poc") or {}
    parts = [
        f.title,
        raw.get("description", ""),
        poc.get("response_snippet", ""),
        poc.get("execution_evidence", ""),
        poc.get("payload", ""),
        # Fallback: the entire raw record, so a flag anywhere is caught.
        json.dumps(raw, default=str),
    ]
    return "\n".join(str(p) for p in parts if p)


def judge_flag_capture(
    findings: List[NormalizedFinding],
    flag: Optional[str] = None,
    flag_regex: Optional[str] = None,
) -> FlagResult:
    """Decide whether the scanner captured the challenge flag.

    A challenge is *solved* when the expected flag (exact substring) or a match
    for ``flag_regex`` appears anywhere in the produced findings — the same
    unambiguous, false-positive-free success signal XBEN uses.
    """
    haystack = "\n".join(_finding_blob(f) for f in findings)

    if flag:
        idx = haystack.find(flag)
        if idx != -1:
            return FlagResult(
                solved=True, flag=flag,
                matched_text=haystack[max(0, idx - 20): idx + len(flag) + 20],
            )

    if flag_regex:
        m = re.search(flag_regex, haystack)
        if m:
            return FlagResult(
                solved=True, flag_regex=flag_regex, matched_text=m.group(0)[:120]
            )

    return FlagResult(solved=False, flag=flag, flag_regex=flag_regex)


def judge(
    findings: List[NormalizedFinding],
    expected: List[Dict[str, Any]],
    backend: str = "heuristic",
    llm_call: Optional[LLMCall] = None,
) -> JudgeResult:
    """Dispatch to the configured judge backend.

    Falls back to the heuristic judge when no LLM call is available so the
    harness always produces a result, even offline.
    """
    if backend in ("anthropic", "openai") and llm_call is not None:
        try:
            return judge_llm(findings, expected, llm_call)
        except Exception:
            # A malformed LLM response should not abort the whole benchmark.
            return judge_heuristic(findings, expected)
    return judge_heuristic(findings, expected)
