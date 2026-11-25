"""WPScan parser (``--format json``, with a console-output fallback).

Ported from Vanguard ``run_wpscan``. Fixes: Vanguard read only
``interesting_findings`` (all as ``medium``) and never looked at the
WordPress core, main theme, theme or plugin ``vulnerabilities`` arrays. Exit
code 5 means "vulnerabilities found" and is a completed scan, not an error.
A ``scan_aborted`` document is inconclusive rather than "nothing found".
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from asm_scanner_core.parsers.base import Observation, ParsedResult, extract_json, run_status, strip_ansi

TOOL = "wpscan"
SUCCESS_EXIT_CODES = (0, 5)

_INTERESTING_SEVERITY = {
    "backup_db": "high", "db_exports": "high", "config_backup": "high",
    "debug_log": "medium", "full_path_disclosure": "low", "upload_directory_listing": "low",
    "registration": "low", "tmm_db_migrate": "medium", "emergency_pwd_reset_script": "medium",
    "duplicator_installer_log": "medium", "upload_sql_dump": "high",
}


def _cvss_severity(vuln: Dict[str, Any]) -> str:
    cvss = vuln.get("cvss")
    score = None
    if isinstance(cvss, dict):
        score = cvss.get("score")
    try:
        score = float(score) if score is not None else None
    except (TypeError, ValueError):
        score = None
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low" if score > 0 else "info"


def _vuln_rows(component: str, name: str, version: str, vulns: Any) -> List[Observation]:
    rows = []
    for vuln in vulns or []:
        if not isinstance(vuln, dict):
            continue
        refs = vuln.get("references") or {}
        cves = refs.get("cve") if isinstance(refs, dict) else None
        rows.append(Observation(
            kind="vulnerability", title=str(vuln.get("title") or f"{component} vulnerability"),
            severity=_cvss_severity(vuln),
            attributes={"component": component, "name": name, "version": version,
                        "fixed_in": vuln.get("fixed_in") or "",
                        "cve": [f"CVE-{c}" if not str(c).upper().startswith("CVE") else str(c)
                                for c in (cves or [])],
                        "vuln_type": vuln.get("vuln_type") or ""},
        ))
    return rows


def _version_of(entry: Any) -> str:
    if isinstance(entry, dict):
        version = entry.get("version")
        if isinstance(version, dict):
            return str(version.get("number") or "")
        return str(entry.get("number") or "")
    return ""


def _parse_json(data: Dict[str, Any], counts: Dict[str, int]) -> List[Observation]:
    observations: List[Observation] = []
    target = str(data.get("target_url") or "")
    for item in data.get("interesting_findings") or []:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("type") or "interesting")
        observations.append(Observation(
            kind="interesting_finding", title=str(item.get("to_s") or kind),
            severity=_INTERESTING_SEVERITY.get(kind, "info"), target=str(item.get("url") or target),
            attributes={"type": kind, "found_by": item.get("found_by") or "",
                        "confidence": item.get("confidence")},
        ))
    counts["interesting_findings"] = len(data.get("interesting_findings") or [])
    core = data.get("version")
    if isinstance(core, dict) and core.get("number"):
        number = str(core.get("number"))
        observations.append(Observation(
            kind="technology", title=f"WordPress {number}", target=target,
            severity="low" if core.get("status") == "insecure" else "info",
            attributes={"component": "wordpress", "version": number, "release_status": core.get("status") or ""},
        ))
        observations.extend(_vuln_rows("wordpress", "wordpress", number, core.get("vulnerabilities")))
    main_theme = data.get("main_theme")
    themes: Dict[str, Any] = dict(data.get("themes") or {})
    if isinstance(main_theme, dict) and main_theme.get("slug"):
        themes.setdefault(str(main_theme["slug"]), main_theme)
    plugins: Dict[str, Any] = dict(data.get("plugins") or {})
    for component, entries in (("theme", themes), ("plugin", plugins)):
        for slug, entry in entries.items():
            if not isinstance(entry, dict):
                continue
            version = _version_of(entry)
            observations.append(Observation(
                kind="technology", title=f"WordPress {component} {slug}" + (f" {version}" if version else ""),
                target=target, severity="info",
                attributes={"component": component, "name": slug, "version": version,
                            "outdated": bool(entry.get("outdated"))},
            ))
            observations.extend(_vuln_rows(component, slug, version, entry.get("vulnerabilities")))
    counts["plugins"] = len(plugins)
    counts["themes"] = len(themes)
    counts["users"] = len(data.get("users") or {})
    counts["vulnerabilities"] = sum(1 for o in observations if o.kind == "vulnerability")
    return observations


_TEXT_TITLE = re.compile(r"\[!\]\s*Title:\s*(.+)")
_TEXT_VERSION = re.compile(r"WordPress version\s+([\d.]+)\s+identified", re.I)


def _parse_text(text: str, counts: Dict[str, int]) -> List[Observation]:
    observations: List[Observation] = []
    version = _TEXT_VERSION.search(text)
    if version:
        observations.append(Observation(kind="technology", title=f"WordPress {version.group(1)}",
                                        attributes={"component": "wordpress", "version": version.group(1)}))
    for match in _TEXT_TITLE.finditer(text):
        observations.append(Observation(kind="vulnerability", title=match.group(1), severity="medium"))
    counts["vulnerabilities"] = sum(1 for o in observations if o.kind == "vulnerability")
    return observations


def parse_wpscan(output: str, exit_code: Optional[int] = None, *, timed_out: bool = False,
                 **_context: Any) -> ParsedResult:
    text = strip_ansi(output or "")
    counts: Dict[str, int] = {}
    data = extract_json(text)
    if isinstance(data, dict) and data.get("scan_aborted"):
        return ParsedResult(tool=TOOL, status="inconclusive",
                            reason=f"scan aborted: {data.get('scan_aborted')}")
    if isinstance(data, dict) and ("target_url" in data or "interesting_findings" in data):
        observations = _parse_json(data, counts)
        understood = True
    else:
        observations = _parse_text(text, counts)
        understood = bool(observations) or "Interesting Finding" in text or "[+] Finished" in text
    status, reason = run_status(exit_code=exit_code, timed_out=timed_out, have_data=bool(observations),
                                success_exit_codes=SUCCESS_EXIT_CODES)
    if status == "ok" and "Scan Aborted" in text:
        status, reason = ("partial" if observations else "inconclusive"), "scan aborted"
    elif status == "ok" and not understood:
        status, reason = "inconclusive", "no recognizable wpscan output"
    if exit_code == 5 and status == "ok":
        reason = "exit 5: vulnerabilities reported"
    return ParsedResult(tool=TOOL, status=status, observations=observations, counts=counts, reason=reason)
