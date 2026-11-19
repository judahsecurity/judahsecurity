"""Code-side analysis of tool output that does not need a model call.

Every planner step used to send the tool output to a second LLM call to
interpret it and pull out ports, services, technologies and vulnerabilities.
For two kinds of output that call adds latency and cost without adding
information:

* bookkeeping tools (coverage, notes, brain, finding workflow, CLI help),
  whose JSON result states its own outcome and never carries new target
  facts, and
* scanners run in JSON-lines mode (httpx, nuclei, naabu), whose fields map
  directly onto the target model.

``analyze_without_model`` returns an ``OutputAnalysis`` for those and ``None``
for everything else, which still goes to the model. Scanner text from the
target (titles, template names) is kept short and only placed in data fields,
never treated as instructions.
"""

from __future__ import annotations

import json
from typing import Any, Iterable, Optional

from app.services.agent.state import ExtractedTargetInfo, OutputAnalysis

# Tools whose output records or reports platform state, never new facts about
# the target. Their JSON says whether the call worked and what changed.
BOOKKEEPING_TOOLS = frozenset({
    "add_asset", "add_engagement_credential", "assess_finding_risk",
    "build_threat_model", "compact_context", "create_finding", "create_scan",
    "get_assessment_coverage", "get_coverage", "get_engagement_brain",
    "get_finding_candidate", "get_methodology_progress", "get_notes",
    "get_threat_model", "list_recon_workers", "list_test_identities",
    "log_engagement_approach", "lookup_methodology_procedure",
    "queue_finding_followups", "record_recon_inventory",
    "record_surface_coverage", "record_verify_verdict",
    "register_test_identity", "sanitize_evidence", "save_note",
    "scoped_assessment_status", "spawn_recon_workers", "store_memory",
    "submit_finding_candidate", "sync_engagement_brain",
    "update_hypothesis", "update_threat_model",
})

# Keys that, when present at the top level of a bookkeeping result, best say
# what happened. Shown first, in this order.
_OUTCOME_KEYS = (
    "error", "success", "status", "verdict", "summary", "message", "note",
    "id", "finding_id", "candidate_id", "coverage_cell_id", "evidence_id",
)
_MAX_INTERPRETATION = 600
_MAX_ROWS = 200
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def analyze_without_model(tool_name: str, output: str, success: bool) -> Optional[OutputAnalysis]:
    """Analyse ``output`` in code when that loses nothing; else ``None``."""
    if not output:
        return None
    if tool_name.endswith("_help"):
        lines = output.count("\n") + 1
        return OutputAnalysis(
            interpretation=(
                f"{tool_name} returned CLI usage ({lines} lines). Use the documented "
                "flags in the next call; this is reference text, not a result."
            ),
        )
    if tool_name in BOOKKEEPING_TOOLS:
        return _bookkeeping(tool_name, output, success)
    if not success:
        return None
    parser = _SCANNER_PARSERS.get(tool_name)
    if parser is None:
        return None
    rows = _json_lines(output)
    if not rows:
        return None
    return parser(rows)


def _bookkeeping(tool_name: str, output: str, success: bool) -> Optional[OutputAnalysis]:
    try:
        data = json.loads(output)
    except (TypeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    parts = []
    for key in _OUTCOME_KEYS:
        if key in data and _scalar(data[key]) is not None:
            parts.append(f"{key}={_scalar(data[key])}")
    for key, value in data.items():
        if key in _OUTCOME_KEYS:
            continue
        if isinstance(value, list):
            parts.append(f"{key}: {len(value)} items")
        elif isinstance(value, dict):
            nested = [f"{k}={_scalar(v)}" for k, v in value.items() if _scalar(v) is not None][:6]
            if nested:
                parts.append(f"{key}({', '.join(nested)})")
        elif _scalar(value) is not None:
            parts.append(f"{key}={_scalar(value)}")
    failed = "error" in data or data.get("success") is False or not success
    head = f"{tool_name} {'FAILED' if failed else 'ok'}"
    text = head + (": " + "; ".join(parts) if parts else "")
    return OutputAnalysis(interpretation=_clip(text, _MAX_INTERPRETATION))


def _scalar(value: Any) -> Optional[str]:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str) and value.strip():
        return _clip(" ".join(value.split()), 160)
    return None


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _json_lines(output: str) -> list[dict[str, Any]]:
    """Parse JSON-lines scanner output; empty unless most lines are JSON objects."""
    rows: list[dict[str, Any]] = []
    candidates = 0
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("... (truncated"):
            continue
        candidates += 1
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append(row)
        if len(rows) >= _MAX_ROWS:
            break
    # Mixed banners are fine; mostly-text output is not JSON mode.
    if not rows or len(rows) * 2 < min(candidates, _MAX_ROWS):
        return []
    return rows


def _port(value: Any) -> Optional[int]:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 < port < 65536 else None


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(v for v in values if v))


def _httpx(rows: list[dict[str, Any]]) -> Optional[OutputAnalysis]:
    rows = [r for r in rows if r.get("url") or r.get("input")]
    if not rows:
        return None
    ports, techs, services, lines = [], [], [], []
    for row in rows:
        port = _port(row.get("port"))
        if port:
            ports.append(port)
        techs.extend(_clip(str(t), 60) for t in (row.get("tech") or row.get("technologies") or []))
        server = row.get("webserver")
        if server:
            services.append(_clip(str(server), 60))
        scheme = row.get("scheme")
        if scheme:
            services.append(str(scheme))
        title = _scalar(row.get("title")) or ""
        lines.append(
            f"{row.get('url') or row.get('input')} {row.get('status_code') or row.get('status-code') or '?'}"
            + (f" '{_clip(title, 60)}'" if title else "")
        )
    first = rows[0]
    info = ExtractedTargetInfo(
        primary_target=str(first.get("url") or first.get("input") or "") or None,
        ports=sorted(set(ports)),
        services=_unique(services),
        technologies=_unique(techs),
    )
    tech_note = f"; tech: {', '.join(info.technologies[:12])}" if info.technologies else ""
    return OutputAnalysis(
        interpretation=_clip(
            f"httpx: {len(rows)} live endpoint(s): " + "; ".join(lines[:8]) + tech_note,
            _MAX_INTERPRETATION,
        ),
        extracted_info=info,
    )


def _nuclei(rows: list[dict[str, Any]]) -> Optional[OutputAnalysis]:
    hits = []
    for row in rows:
        template = row.get("template-id") or row.get("template_id") or row.get("templateID")
        info = row.get("info") if isinstance(row.get("info"), dict) else {}
        if not template and not info:
            continue
        severity = str(info.get("severity") or row.get("severity") or "unknown").lower()
        name = _clip(str(info.get("name") or template or "nuclei match"), 80)
        where = row.get("matched-at") or row.get("matched_at") or row.get("host") or ""
        cves = (info.get("classification") or {}).get("cve-id") if isinstance(
            info.get("classification"), dict) else None
        cve = ", ".join(cves) if isinstance(cves, list) else (cves or "")
        hits.append((severity, name, str(template or ""), str(where), str(cve)))
    if not hits:
        return None
    hits.sort(key=lambda h: _SEVERITY_ORDER.get(h[0], 5))
    vulns = _unique(
        f"[{sev}] {name}" + (f" ({cve})" if cve else "") + (f" at {where}" if where else "")
        for sev, name, _t, where, cve in hits
        if sev not in ("info", "unknown")
    )
    tech = _unique(
        name for sev, name, template, _w, _c in hits
        if sev == "info" and ("tech" in template or "detect" in template)
    )
    counts: dict[str, int] = {}
    for sev, *_ in hits:
        counts[sev] = counts.get(sev, 0) + 1
    count_text = ", ".join(f"{n} {sev}" for sev, n in sorted(
        counts.items(), key=lambda kv: _SEVERITY_ORDER.get(kv[0], 5)))
    return OutputAnalysis(
        interpretation=_clip(
            f"nuclei: {len(hits)} match(es) ({count_text}). "
            + ("Top: " + "; ".join(vulns[:5]) if vulns else "No medium+ matches.")
            + " Scanner matches are leads until proven by a scoped check.",
            _MAX_INTERPRETATION,
        ),
        extracted_info=ExtractedTargetInfo(vulnerabilities=vulns[:50], technologies=tech[:30]),
        actionable_findings=[
            v for v in vulns if v.startswith(("[critical]", "[high]", "[medium]"))
        ][:10],
    )


def _naabu(rows: list[dict[str, Any]]) -> Optional[OutputAnalysis]:
    ports, hosts = [], []
    for row in rows:
        port = _port(row.get("port"))
        if port is None:
            continue
        ports.append(port)
        hosts.append(str(row.get("host") or row.get("ip") or ""))
    if not ports:
        return None
    unique_ports = sorted(set(ports))
    return OutputAnalysis(
        interpretation=_clip(
            f"naabu: {len(unique_ports)} open port(s) on {len(set(h for h in hosts if h)) or 1} "
            f"host(s): {', '.join(map(str, unique_ports[:40]))}. An open port is not a "
            "service identity; fingerprint before testing.",
            _MAX_INTERPRETATION,
        ),
        extracted_info=ExtractedTargetInfo(ports=unique_ports),
    )


_SCANNER_PARSERS = {
    "execute_httpx": _httpx,
    "execute_nuclei": _nuclei,
    "run_nuclei_scan": _nuclei,
    "execute_naabu": _naabu,
}
