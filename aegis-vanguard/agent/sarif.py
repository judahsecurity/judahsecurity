"""SARIF 2.1.0 output for Aegis Vanguard findings.

Converts our findings (any of the pipeline's shapes) into a SARIF log so scan
results drop straight into GitHub code scanning, IDEs, and CI dashboards. Pure
functions, no third-party deps.

SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""
from __future__ import annotations

import hashlib
import os
from typing import Any, Dict, List, Optional

from agent.ci_gate import normalize_severity

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFO_URI = "https://github.com/judahsecurity"

# SARIF result.level is one of: none | note | warning | error.
_SEV_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}
# SARIF security-severity is a 0.0-10.0 string (GitHub uses it to bucket).
_SEV_TO_SCORE = {
    "critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0",
}


def _first(f: Dict[str, Any], *keys: str, default: str = "") -> str:
    for k in keys:
        v = f.get(k)
        if v:
            return str(v)
    return default


def _severity(f: Dict[str, Any]) -> str:
    return normalize_severity(
        _first(f, "escalated_severity", "severity", "current_severity", default="info")
    )


def finding_uri(f: Dict[str, Any], source_root: str = "") -> Optional[str]:
    """Repo-relative file path for a SAST finding, or None for a URL/DAST finding."""
    meta = f.get("metadata") or {}
    loc = f.get("location") or {}
    path = _first(f, "file", "file_path", "path") or _first(loc, "path", "file") or \
        _first(meta, "file", "file_path", "path")
    if not path:
        return None
    if source_root and os.path.isabs(path):
        try:
            path = os.path.relpath(path, source_root)
        except ValueError:
            pass
    return path.replace("\\", "/").lstrip("./") or None


def _line(f: Dict[str, Any]) -> int:
    meta = f.get("metadata") or {}
    loc = f.get("location") or {}
    for src in (f, loc, meta):
        v = src.get("line") or src.get("start_line") or src.get("startLine")
        if v:
            try:
                return max(1, int(v))
            except (TypeError, ValueError):
                pass
    return 1


def _rule_id(f: Dict[str, Any]) -> str:
    cwe = _first(f, "cwe_id", "cwe")
    if cwe:
        cwe = cwe.upper().replace(" ", "")
        return cwe if cwe.startswith("CWE") else f"CWE-{cwe}"
    return _first(f, "vuln_type", "category", "type", default="aegis.finding")


def _fingerprint(rule_id: str, uri: Optional[str], line: int, title: str) -> str:
    h = hashlib.sha256(f"{rule_id}|{uri or ''}|{line}|{title}".encode()).hexdigest()
    return h[:32]


def _result(f: Dict[str, Any], source_root: str) -> Dict[str, Any]:
    sev = _severity(f)
    title = _first(f, "title", "finding_title", "name", "finding", default="Security finding")
    desc = _first(f, "description", "evidence", "exploit_scenario", "impact", default=title)
    rule_id = _rule_id(f)
    uri = finding_uri(f, source_root)
    line = _line(f)

    result: Dict[str, Any] = {
        "ruleId": rule_id,
        "level": _SEV_TO_LEVEL.get(sev, "warning"),
        "message": {"text": desc[:2000]},
        "partialFingerprints": {"aegis/v1": _fingerprint(rule_id, uri, line, title)},
        "properties": {
            "severity": sev,
            "security-severity": _SEV_TO_SCORE.get(sev, "0.0"),
            "vuln_type": _first(f, "vuln_type"),
            "cwe": _first(f, "cwe_id", "cwe"),
            "cve": _first(f, "cve_id", "cve"),
        },
    }

    if uri:
        result["locations"] = [{
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": line},
            }
        }]
    else:
        # DAST / URL finding: no file — record the endpoint as a logical location.
        endpoint = _first(f, "endpoint", "url", "poc_endpoint", "target", "host")
        if endpoint:
            result["locations"] = [{
                "logicalLocations": [{"fullyQualifiedName": endpoint, "kind": "member"}]
            }]
            result["properties"]["endpoint"] = endpoint
    return result


def findings_to_sarif(
    findings: List[Dict[str, Any]],
    tool_name: str = "Aegis Vanguard",
    tool_version: str = "1.0.0",
    source_root: str = "",
) -> Dict[str, Any]:
    """Build a SARIF 2.1.0 log dict from a list of finding dicts."""
    results: List[Dict[str, Any]] = []
    rules: Dict[str, Dict[str, Any]] = {}

    for f in findings or []:
        res = _result(f, source_root)
        results.append(res)
        rid = res["ruleId"]
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": rid.replace("-", "_"),
                "shortDescription": {"text": rid},
                "helpUri": _INFO_URI,
                "properties": {"security-severity": res["properties"]["security-severity"]},
            }

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "informationUri": _INFO_URI,
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }
