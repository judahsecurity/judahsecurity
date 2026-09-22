"""Structured candidate validation and terminal finding lifecycle helpers."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Iterable, List

_DECISIONS = {"pass", "kill", "downgrade", "needs_more_evidence"}


def finding_id(finding: Dict[str, Any]) -> str:
    existing = finding.get("finding_id")
    if existing:
        return str(existing)
    material = "|".join(str(finding.get(key) or "") for key in (
        "vuln_type", "type", "title", "name", "endpoint", "url", "matched_at",
    ))
    return "F-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]


def initialize_candidates(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    initialized = []
    for finding in findings:
        item = dict(finding)
        item["finding_id"] = finding_id(item)
        item["lifecycle_state"] = "candidate"
        initialized.append(item)
    return initialized


def _json_values(text: str) -> Iterable[Any]:
    for match in re.finditer(r"```(?:json)?\s*(.*?)```", text or "", re.I | re.S):
        try:
            yield json.loads(match.group(1).strip())
        except (TypeError, json.JSONDecodeError):
            pass
    decoder = json.JSONDecoder()
    for index, char in enumerate(text or ""):
        if char not in "[{":
            continue
        try:
            value, _ = decoder.raw_decode(text[index:])
            yield value
        except json.JSONDecodeError:
            continue


def parse_validation_decisions(text: str) -> Dict[str, Dict[str, Any]]:
    """Extract the validator's required JSON decisions; ignore ambiguous prose."""
    decisions: Dict[str, Dict[str, Any]] = {}
    for value in _json_values(text):
        rows = value.get("decisions", []) if isinstance(value, dict) else value
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict) or not row.get("finding_id"):
                continue
            decision = str(row.get("decision") or "").strip().lower().replace(" ", "_")
            if decision not in _DECISIONS:
                continue
            decisions[str(row["finding_id"])] = {
                "decision": decision,
                "reason": str(row.get("reason") or ""),
                "severity": str(row.get("severity") or ""),
            }
    return decisions


def apply_validation_decisions(
    findings: Iterable[Dict[str, Any]], decisions: Dict[str, Dict[str, Any]]
) -> List[Dict[str, Any]]:
    annotated = []
    for finding in findings:
        item = dict(finding)
        fid = finding_id(item)
        item["finding_id"] = fid
        verdict = decisions.get(fid)
        if verdict is None:
            item["validation_status"] = "needs_more_evidence"
            item["validation_reason"] = "validator returned no structured decision"
            item["lifecycle_state"] = "candidate"
        else:
            status = verdict["decision"]
            item["validation_status"] = status
            item["validation_reason"] = verdict.get("reason", "")
            if verdict.get("severity"):
                item["severity"] = verdict["severity"]
            item["lifecycle_state"] = {
                "pass": "validated",
                "kill": "rejected",
                "downgrade": "validated",
                "needs_more_evidence": "candidate",
            }[status]
        annotated.append(item)
    return annotated


def reportable_findings(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        dict(item) for item in findings
        if item.get("lifecycle_state") == "validated"
        and item.get("validation_status") in {"pass", "downgrade"}
    ]


__all__ = [
    "apply_validation_decisions", "finding_id", "initialize_candidates",
    "parse_validation_decisions", "reportable_findings",
]
