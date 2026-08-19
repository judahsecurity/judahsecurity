"""Normalize CLI tool results whose non-zero exit codes mean "findings found".

Several scanners (WPScan, Semgrep, Trivy) use a non-zero status to signal that
the scan *succeeded* and found issues. Treating those as failures makes the
agent retry the same scan until the turn budget is gone.
"""

from __future__ import annotations

from typing import Any, Dict, FrozenSet, Mapping, Optional

# Process completed successfully, including "interesting findings" codes.
WPSCAN_SUCCESS_EXIT_CODES: FrozenSet[int] = frozenset({0, 5})
SEMGREP_SUCCESS_EXIT_CODES: FrozenSet[int] = frozenset({0, 1})
TRIVY_SUCCESS_EXIT_CODES: FrozenSet[int] = frozenset({0, 1})

_TOOL_SUCCESS_EXITS: Mapping[str, FrozenSet[int]] = {
    "execute_wpscan": WPSCAN_SUCCESS_EXIT_CODES,
    "wpscan": WPSCAN_SUCCESS_EXIT_CODES,
    "execute_semgrep": SEMGREP_SUCCESS_EXIT_CODES,
    "execute_trivy": TRIVY_SUCCESS_EXIT_CODES,
}

_WPSCAN_COMPLETE_MARKERS = (
    "[!] Title:",
    "user(s) Identified",
    "plugin(s) Identified",
    "WordPress version",
    "[i] WordPress version",
    "Interesting finding",
    "WPScan DB API OK",
)


def _as_int(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def wpscan_output_looks_complete(output: str) -> bool:
    """True when stdout looks like a finished WPScan, not a token/abort miss."""
    text = output or ""
    aborted = "Scan Aborted" in text
    found_issue = any(marker in text for marker in _WPSCAN_COMPLETE_MARKERS)
    if aborted and not found_issue:
        return False
    return found_issue


def normalize_cli_result(tool_name: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """Mark known 'findings found' exit codes as success.

    Also recovers WPScan runs whose progress/banner landed on stderr (so
    ``error`` is non-empty) even though the scan completed and found issues.
    """
    if not isinstance(result, dict) or not tool_name:
        return result

    name = tool_name.strip()
    out = str(result.get("output") or "")
    err = str(result.get("error") or "")
    combined = out if out.strip() else err
    rc = _as_int(result.get("exit_code"))
    success_codes = _TOOL_SUCCESS_EXITS.get(name)

    looks_complete = name in ("execute_wpscan", "wpscan") and (
        wpscan_output_looks_complete(out) or wpscan_output_looks_complete(err)
    )
    exit_ok = success_codes is not None and rc in success_codes

    if not (exit_ok or looks_complete):
        return result

    updated = dict(result)
    updated["success"] = True
    # Progress bars / colour codes on stderr are not a failure. Keep a real
    # abort message only when we did *not* actually produce findings.
    if looks_complete or exit_ok:
        if "Scan Aborted" in err and not looks_complete:
            return result
        updated["error"] = None
        if not (updated.get("output") or "").strip() and err.strip():
            updated["output"] = err
    return updated
