"""
Unified SARIF export — one interoperable findings file for the whole run.

SARIF 2.1.0 is the lingua franca for static/dynamic security results (GitHub
code scanning, IDEs, dashboards ingest it). The harness produced per-target
JSONL and a report but no unified, standard artifact. ``findings_to_sarif``
converts all findings across all targets into a single SARIF run: one rule per
vulnerability class, one result per finding, severity mapped to SARIF levels,
and the target URL captured as the result location.

Pure and dependency-free so it is deterministic and unit-tested.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

_SARIF_VERSION = "2.1.0"
_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

# vuln severity → SARIF result level.
_LEVEL = {
    "critical": "error", "high": "error",
    "medium": "warning", "low": "note", "info": "note", "informational": "note",
}


def _rule_id(finding: Dict[str, Any]) -> str:
    return str(
        finding.get("vuln_type") or finding.get("type") or finding.get("category")
        or finding.get("template_id") or finding.get("template-id") or "finding"
    ).strip().lower().replace(" ", "-") or "finding"


def _uri(finding: Dict[str, Any]) -> str:
    return str(
        finding.get("url") or finding.get("endpoint") or finding.get("matched_at")
        or finding.get("matched-at") or finding.get("target") or ""
    )


def _text(finding: Dict[str, Any]) -> str:
    title = finding.get("title") or finding.get("name") or _rule_id(finding)
    ev = finding.get("evidence")
    return f"{title}" + (f" — {ev}" if ev else "")


def findings_to_sarif(
    findings: List[Dict[str, Any]],
    tool_name: str = "Aegis Vanguard",
    version: str = "",
    information_uri: str = "https://github.com/judahsecurity/judahsecurity",
) -> Dict[str, Any]:
    """Convert a flat list of finding dicts into a SARIF 2.1.0 document."""
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for f in findings or []:
        if not isinstance(f, dict):
            continue
        rid = _rule_id(f)
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": rid,
                "shortDescription": {"text": (f.get("title") or rid)[:120]},
            }
        result: Dict[str, Any] = {
            "ruleId": rid,
            "level": _LEVEL.get(str(f.get("severity") or "").lower(), "warning"),
            "message": {"text": _text(f)},
        }
        uri = _uri(f)
        if uri:
            result["locations"] = [{
                "physicalLocation": {"artifactLocation": {"uri": uri}}
            }]
        props = {k: f[k] for k in ("severity", "param", "payload", "confirmed", "source")
                 if k in f}
        if props:
            result["properties"] = props
        results.append(result)

    return {
        "version": _SARIF_VERSION,
        "$schema": _SCHEMA,
        "runs": [{
            "tool": {"driver": {
                "name": tool_name,
                "version": version or "0.0.0",
                "informationUri": information_uri,
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


__all__ = ["findings_to_sarif"]
