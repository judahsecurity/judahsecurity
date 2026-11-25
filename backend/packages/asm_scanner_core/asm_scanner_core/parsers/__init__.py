"""Scanner output parser registry.

One pure parser per tool, keyed by tool name: raw output (+ exit code, timeout
flag) -> :class:`ParsedResult`. Shared by the platform MCP server (Prowl) and,
later, Aegis Vanguard, so ``aegis-vanguard/scanners.py`` parsing can retire.

    from asm_scanner_core.parsers import parse_tool_output
    parsed = parse_tool_output("execute_nikto", raw, exit_code=0)
    parsed.status, parsed.to_dict()

Tool names may carry the ``execute_`` / ``run_`` / ``scan_`` prefixes.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from asm_scanner_core.parsers.arjun import parse_arjun
from asm_scanner_core.parsers.base import (
    SEVERITIES, STATUSES, Observation, ParsedResult, looks_unavailable, unavailable,
)
from asm_scanner_core.parsers.cmseek import parse_cmseek
from asm_scanner_core.parsers.httpx_headers import parse_httpx
from asm_scanner_core.parsers.katana import parse_katana
from asm_scanner_core.parsers.nikto import parse_nikto
from asm_scanner_core.parsers.sqlmap import parse_sqlmap
from asm_scanner_core.parsers.testssl import parse_testssl
from asm_scanner_core.parsers.tlsx import parse_tlsx
from asm_scanner_core.parsers.wafw00f import parse_wafw00f
from asm_scanner_core.parsers.wpscan import parse_wpscan
from asm_scanner_core.parsers.xsstrike import parse_xsstrike

Parser = Callable[..., ParsedResult]

PARSERS: Dict[str, Parser] = {
    "nikto": parse_nikto,
    "wafw00f": parse_wafw00f,
    "cmseek": parse_cmseek,
    "wpscan": parse_wpscan,
    "testssl": parse_testssl,
    "tlsx": parse_tlsx,
    "httpx": parse_httpx,
    "security_headers": parse_httpx,
    "sqlmap": parse_sqlmap,
    "arjun": parse_arjun,
    "xsstrike": parse_xsstrike,
    "katana": parse_katana,
}
_ALIASES = {"testssl.sh": "testssl", "pd-httpx": "httpx"}


def canonical_tool(tool_name: str) -> str:
    name = str(tool_name or "").strip().lower()
    for prefix in ("execute_", "run_", "scan_"):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    return _ALIASES.get(name, name)


def get_parser(tool_name: str) -> Optional[Parser]:
    return PARSERS.get(canonical_tool(tool_name))


def parse_tool_output(
    tool_name: str,
    output: str,
    exit_code: Optional[int] = None,
    *,
    timed_out: bool = False,
    **context: Any,
) -> Optional[ParsedResult]:
    """Parse one tool run. ``None`` when no parser is registered for the tool.

    ``context`` passes parser-specific inputs: ``json_text`` (testssl JSON
    read from its output file), ``now`` (tlsx expiry), ``target``.
    A parser that raises yields ``inconclusive`` instead of propagating.
    """
    tool = canonical_tool(tool_name)
    parser = PARSERS.get(tool)
    if parser is None:
        return None
    text = output if isinstance(output, str) else str(output or "")
    if looks_unavailable(text, exit_code) and not context.get("json_text"):
        return unavailable(tool, text.strip()[:200] or "tool not installed or could not start")
    try:
        return parser(text, exit_code, timed_out=timed_out, **context)
    except Exception as exc:  # parsers must never break the tool call
        return ParsedResult(tool=tool, status="inconclusive",
                            reason=f"parser error: {type(exc).__name__}")


def summary_text(summary: Dict[str, Any], *, max_lines: int = 12, max_chars: int = 1500) -> str:
    """Compact, model-facing text for a ``ParsedResult.to_dict()`` summary."""
    if not isinstance(summary, dict) or not summary.get("tool"):
        return ""
    counts = summary.get("counts") or {}
    by_sev = summary.get("by_severity") or {}
    sev_text = ", ".join(f"{s} {by_sev[s]}" for s in reversed(SEVERITIES) if by_sev.get(s))
    head = (f"[parsed {summary['tool']}] status={summary.get('status')} "
            f"observations={counts.get('observations', 0)}" + (f" ({sev_text})" if sev_text else ""))
    extra = ", ".join(f"{k}={v}" for k, v in counts.items() if k != "observations")
    lines = [head + (f"; {extra}" if extra else "")]
    if summary.get("reason"):
        lines.append(f"  reason: {summary['reason']}")
    for obs in (summary.get("observations") or [])[:max(0, max_lines)]:
        where = obs.get("target") or ""
        param = f" param={obs['parameter']}" if obs.get("parameter") else ""
        lines.append(f"  - [{obs.get('severity')}] {obs.get('kind')}: {obs.get('title')}"
                     + (f" @ {where}" if where else "") + param)
    hidden = max(0, int(counts.get("observations", 0)) - min(max_lines, len(summary.get("observations") or [])))
    if hidden:
        lines.append(f"  ... {hidden} more observation(s) in the structured 'parsed' summary")
    lines.append("  (parsed observations are leads, not findings; verify before reporting)")
    text = "\n".join(lines)
    return text if len(text) <= max_chars else text[: max_chars - 15] + "\n  ... (clipped)"


__all__ = [
    "PARSERS", "SEVERITIES", "STATUSES", "Observation", "ParsedResult",
    "canonical_tool", "get_parser", "parse_tool_output", "summary_text",
]
