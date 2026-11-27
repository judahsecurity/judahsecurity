"""Typed result shape and shared helpers for scanner output parsers.

Parsers are pure functions: raw tool output (plus exit code and timeout flag)
in, :class:`ParsedResult` out. No I/O, no subprocesses, no backend imports.

Status semantics (``ParsedResult.status``):

* ``ok``           the tool ran to completion and its output was understood.
                   Zero observations under ``ok`` means "ran, found nothing".
* ``partial``      the run did not complete (timeout, non-success exit) but
                   observations were salvaged. Treat as leads; rerun to finish.
* ``inconclusive`` the run produced nothing usable (timeout or error without
                   data, unparseable output, aborted scan). Not a clean result.
* ``unavailable``  the tool is not installed or could not be started.

Observations are planning hints, not proof. ``severity`` is the parser's
best mapping of what the tool reported; it never confirms a vulnerability.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

STATUSES = ("ok", "partial", "inconclusive", "unavailable")
SEVERITIES = ("info", "low", "medium", "high", "critical")

MAX_TEXT = 300
MAX_ATTR_TEXT = 200
MAX_ATTRS = 12

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-Z\\-_]")
_UNAVAILABLE = re.compile(
    r"command not found|not installed|no such file or directory|executable file not found",
    re.I,
)

# Minimal secret redaction so parsed summaries never carry credentials, even
# when used outside the backend (which applies its own redaction on top).
_REDACTIONS: Tuple[Tuple[re.Pattern, str], ...] = (
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-+=/]+"), r"\1[redacted]"),
    (re.compile(r"(?i)(authorization\s*[:=]\s*(?:basic|token|bearer)?\s*)[A-Za-z0-9._\-+=/:]+"),
     r"\1[redacted]"),
    (re.compile(r"(?i)((?:set-)?cookie\s*[:=]\s*)[^;\s]+"), r"\1[redacted]"),
    (re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)[^/\s@\"'<>?#]+@"), r"\1[redacted]@"),
    (re.compile(r"(?i)([?&;](?:token|api[_-]?key|secret|password|passwd|pwd|access_token|session(?:id)?)=)"
                r"[^&#\s]+"), r"\1[redacted]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b|\bsk_live_[A-Za-z0-9]{16,128}\b"
                r"|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "[redacted]"),
)


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text or "")


def redact(text: Any) -> str:
    value = str(text or "")
    for pattern, repl in _REDACTIONS:
        value = pattern.sub(repl, value)
    return value


def clean(text: Any, limit: int = MAX_TEXT) -> str:
    """Single-line, ANSI-free, redacted, bounded text."""
    return " ".join(redact(strip_ansi(str(text or ""))).split())[:limit]


def norm_severity(value: Any, default: str = "info") -> str:
    sev = str(value or "").strip().lower()
    aliases = {"informational": "info", "information": "info", "none": "info",
               "moderate": "medium", "med": "medium", "crit": "critical"}
    sev = aliases.get(sev, sev)
    return sev if sev in SEVERITIES else default


@dataclass
class Observation:
    """One structured thing a scanner reported. Fixed fields; extras in ``attributes``."""

    kind: str
    title: str
    severity: str = "info"
    target: str = ""
    parameter: str = ""
    detail: str = ""
    attributes: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.kind = clean(self.kind, 40) or "observation"
        self.title = clean(self.title) or self.kind
        self.severity = norm_severity(self.severity)
        self.target = clean(self.target, 2048)
        self.parameter = clean(self.parameter, 120)
        self.detail = clean(self.detail)
        attrs: Dict[str, Any] = {}
        for key, value in list((self.attributes or {}).items())[:MAX_ATTRS]:
            k = clean(key, 60)
            if value is None or isinstance(value, (bool, int, float)):
                attrs[k] = value
            elif isinstance(value, (list, tuple, set)):
                attrs[k] = [clean(v, 120) for v in list(value)[:20]]
            else:
                attrs[k] = clean(value, MAX_ATTR_TEXT)
        self.attributes = attrs

    def to_dict(self) -> Dict[str, Any]:
        row: Dict[str, Any] = {"kind": self.kind, "title": self.title, "severity": self.severity}
        for name in ("target", "parameter", "detail"):
            if getattr(self, name):
                row[name] = getattr(self, name)
        if self.attributes:
            row["attributes"] = dict(self.attributes)
        return row


@dataclass
class ParsedResult:
    tool: str
    status: str
    observations: List[Observation] = field(default_factory=list)
    counts: Dict[str, int] = field(default_factory=dict)
    reason: str = ""

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        self.reason = clean(self.reason)

    def severity_counts(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for obs in self.observations:
            out[obs.severity] = out.get(obs.severity, 0) + 1
        return out

    def to_dict(self, max_observations: int = 40) -> Dict[str, Any]:
        """Bounded, JSON-safe summary. Observations are ordered most severe first."""
        rank = {s: i for i, s in enumerate(reversed(SEVERITIES))}
        ordered = sorted(self.observations, key=lambda o: rank.get(o.severity, 99))
        shown = ordered[:max(0, max_observations)]
        out: Dict[str, Any] = {
            "tool": self.tool,
            "status": self.status,
            "counts": {"observations": len(self.observations), **self.counts},
            "by_severity": self.severity_counts(),
            "observations": [o.to_dict() for o in shown],
        }
        if len(ordered) > len(shown):
            out["observations_omitted"] = len(ordered) - len(shown)
        if self.reason:
            out["reason"] = self.reason
        return out


def looks_unavailable(output: str, exit_code: Optional[int]) -> bool:
    text = (output or "").strip()
    if exit_code == 127:
        return True
    return bool(text) and len(text) < 400 and bool(_UNAVAILABLE.search(text))


def run_status(
    *,
    exit_code: Optional[int],
    timed_out: bool,
    have_data: bool,
    success_exit_codes: Iterable[int] = (0,),
) -> Tuple[str, str]:
    """Shared status rule: completion (exit + no timeout) decides ok vs partial/inconclusive."""
    if timed_out:
        return ("partial", "timed out; output salvaged before the kill") if have_data else (
            "inconclusive", "timed out before producing usable output")
    if exit_code is not None and exit_code not in set(success_exit_codes):
        return ("partial", f"exited with code {exit_code}; output may be incomplete") if have_data else (
            "inconclusive", f"exited with code {exit_code}")
    return "ok", ""


def unavailable(tool: str, reason: str = "tool not installed or could not start") -> ParsedResult:
    return ParsedResult(tool=tool, status="unavailable", reason=reason)


def iter_json_lines(text: str) -> Iterable[Dict[str, Any]]:
    """Yield dict objects from JSON-lines output, skipping banners and noise."""
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(obj, dict):
            yield obj


def extract_json(text: str) -> Optional[Any]:
    """Parse a JSON document that may be preceded by banner/notes lines."""
    raw = (text or "").strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        pass
    decoder = json.JSONDecoder()
    for match in re.finditer(r"^[\[{]", raw, re.M):
        try:
            value, _end = decoder.raw_decode(raw[match.start():])
        except ValueError:
            continue
        if isinstance(value, (dict, list)):
            return value
    return None
