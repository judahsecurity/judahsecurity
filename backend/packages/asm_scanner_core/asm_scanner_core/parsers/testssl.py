"""testssl.sh JSON parser (flat ``--json``/``--jsonfile`` or ``--json-pretty``).

The JSON may come from stdout or from the file testssl wrote; the caller reads
the file and passes its text as ``json_text`` (parsers do no I/O).

Ported from Vanguard ``run_testssl``. Fixes: for pretty JSON Vanguard iterated
``scanResult`` host blocks, which carry no ``severity``, so it never reported
anything; the per-section items (protocols, ciphers, vulnerabilities, ...) are
now flattened. ``WARN`` is testssl's "scan problem" level, not a vulnerability:
it is kept as a ``scan_warning`` observation instead of being raised to medium.
``LOW`` items are kept as low.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from asm_scanner_core.parsers.base import Observation, ParsedResult, extract_json, run_status, strip_ansi

TOOL = "testssl"

_LEVELS = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def _flatten(data: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and "severity" in item:
                yield item
            elif isinstance(item, dict):
                yield from _flatten(item)
        return
    if not isinstance(data, dict):
        return
    if "scanResult" in data:
        yield from _flatten(data.get("scanResult"))
        return
    host = data.get("targetHost") or data.get("ip") or ""
    port = data.get("port") or ""
    for value in data.values():
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and "severity" in item:
                    yield {"ip": host, "port": port, **item}


def parse_testssl(output: str, exit_code: Optional[int] = None, *, timed_out: bool = False,
                  json_text: str = "", **_context: Any) -> ParsedResult:
    data = extract_json(json_text) if json_text else None
    if data is None:
        data = extract_json(strip_ansi(output or ""))
    if data is None:
        failed = exit_code if exit_code is not None and exit_code >= 242 else None
        status, reason = run_status(exit_code=failed, timed_out=timed_out, have_data=False)
        if status == "ok":
            status, reason = "inconclusive", "no testssl JSON (pass --json/--jsonfile)"
        return ParsedResult(tool=TOOL, status=status, reason=reason)

    observations: List[Observation] = []
    counts = {"items": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "warn": 0}
    for item in _flatten(data):
        counts["items"] += 1
        level = str(item.get("severity") or "").upper()
        endpoint = ":".join(p for p in (str(item.get("ip") or "").split("/")[0], str(item.get("port") or "")) if p)
        attrs = {"id": item.get("id") or "", "cve": item.get("cve") or "", "cwe": item.get("cwe") or ""}
        if level in _LEVELS:
            counts[_LEVELS[level]] += 1
            observations.append(Observation(
                kind="tls_issue", title=str(item.get("id") or "TLS issue"), severity=_LEVELS[level],
                target=endpoint, detail=str(item.get("finding") or ""), attributes=attrs,
            ))
        elif level == "WARN":
            counts["warn"] += 1
            observations.append(Observation(
                kind="scan_warning", title=str(item.get("id") or "testssl warning"), severity="info",
                target=endpoint, detail=str(item.get("finding") or ""), attributes=attrs,
            ))
    # testssl's low exit codes count findings; only 242+ (ERR_*) mean the run failed.
    failed = exit_code if exit_code is not None and exit_code >= 242 else None
    status, reason = run_status(exit_code=failed, timed_out=timed_out, have_data=bool(observations))
    if status == "ok" and counts["items"] == 0:
        status, reason = "inconclusive", "testssl JSON had no result items"
    elif status == "ok" and any(o.kind == "scan_warning" and o.title == "scanProblem" for o in observations):
        status, reason = "partial", "testssl reported a scan problem"
    return ParsedResult(tool=TOOL, status=status, observations=observations, counts=counts, reason=reason)
