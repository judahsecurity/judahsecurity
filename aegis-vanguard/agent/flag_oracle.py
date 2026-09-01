"""
Flag Oracle — ground-truth verification for CTF / benchmark runs.

A flag is "captured" only when its exact string appears in a REAL tool
response recorded during the run — never when it appears only in an agent's
reasoning or a report's prose. This module is the single source of truth for
"did we actually capture the flag?", deliberately independent of:

  • the LLM's claims (a report saying "🚩 Flag Captured" proves nothing), and
  • the Tracer (whose span counters are gated on `enabled`, so a run with
    tracing off reports 0 tool calls even after hundreds executed).

Wire it in at the one chokepoint every tool response passes through
(`AgentRunner._execute_tool`, right after the tool executes), then grade the
run against the expected flag for a pass/fail verdict a human can trust.

On a benchmark you *know* the flag, so the oracle grades itself. On a real app
there is no flag; the same capture record — which tool produced the match and
a redacted excerpt of the exact response — is the auditable evidence that
stands in for one.
"""

import json
import logging
import os
import re
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import List, Optional

from agent.tracing import redact_value

logger = logging.getLogger("agent.flag_oracle")

# XBEN / XBOW / picoCTF-style tokens: FLAG{...}, flag{...}, CTF{...}.
# Override with AEGIS_FLAG_PATTERN for house-specific formats.
DEFAULT_FLAG_PATTERN = r"(?:FLAG|flag|CTF)\{[^}\r\n]{1,512}\}"

# How much of the surrounding response to keep as provenance (chars each side).
_CONTEXT_RADIUS = 120


@dataclass
class FlagCapture:
    """One flag string found in one real tool response."""

    flag: str
    tool_name: str
    argument_summary: str  # which url/target produced it (redacted)
    context: str           # redacted excerpt of the real response around the match
    captured_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Verdict:
    """The pass/fail result of grading captured flags against an expected one."""

    status: str  # "PASS" | "FAIL" | "NO_EXPECTED_FLAG"
    expected_flag: Optional[str]
    captured_flags: List[str]
    reason: str

    @property
    def passed(self) -> bool:
        return self.status == "PASS"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["passed"] = self.passed
        return d


def grade(expected_flag: Optional[str], captured_flags: List[str]) -> Verdict:
    """Pure grader: does the expected flag appear among captured flags?

    Kept side-effect free so the run-time oracle and the offline grader CLI
    share exactly one definition of PASS/FAIL.
    """
    uniq = sorted(set(f for f in captured_flags if f))
    expected = (expected_flag or "").strip() or None

    if expected is None:
        if uniq:
            return Verdict(
                "NO_EXPECTED_FLAG", None, uniq,
                f"No expected flag configured; {len(uniq)} flag-shaped string(s) "
                "captured from real tool responses. Set the expected flag to grade "
                "pass/fail.",
            )
        return Verdict(
            "NO_EXPECTED_FLAG", None, [],
            "No expected flag configured and no flag captured.",
        )

    if expected in uniq:
        return Verdict(
            "PASS", expected, uniq,
            "Expected flag was captured in a real tool response.",
        )

    if uniq:
        return Verdict(
            "FAIL", expected, uniq,
            f"Expected flag NOT found in any tool response; {len(uniq)} other "
            "flag-shaped string(s) were captured (target/format mismatch?).",
        )
    return Verdict(
        "FAIL", expected, [],
        "Expected flag NOT found in any real tool response. Any flag in the "
        "agent's report is unverified prose, not a capture.",
    )


def _summarize_args(arguments) -> str:
    """A short, redacted note of what the tool was pointed at."""
    if not isinstance(arguments, dict):
        return ""
    for key in ("url", "target_url", "target", "endpoint", "host", "urls"):
        val = arguments.get(key)
        if isinstance(val, str) and val.strip():
            return str(redact_value(f"{key}={val.strip()}"))[:200]
    try:
        return str(redact_value(json.dumps(arguments, default=str)))[:200]
    except Exception:
        return ""


class FlagOracle:
    """Scans real tool responses for flags and grades the run.

    Thread-safe: the parallel fireteam runs hunters concurrently on the shared
    runner, so `scan()` is called from multiple threads.
    """

    def __init__(
        self,
        expected_flag: Optional[str] = None,
        pattern: Optional[str] = None,
        enabled: bool = True,
    ):
        self.enabled = enabled
        self.expected_flag = (expected_flag or "").strip() or None
        pat = pattern or os.environ.get("AEGIS_FLAG_PATTERN") or DEFAULT_FLAG_PATTERN
        self._re = re.compile(pat)
        self._captures: List[FlagCapture] = []
        self._seen: set = set()  # (flag, tool_name) — dedup repeat matches
        self._lock = threading.Lock()

    def scan(self, tool_name: str, arguments, result_text) -> None:
        """Record every flag-shaped string in one real tool response.

        Call this with the RAW tool result, before any semantic filter that
        might truncate it. Blocked tool calls never reach here (they return
        before execution), so a flag can only be recorded from output a tool
        actually produced.
        """
        if not self.enabled or not result_text:
            return
        text = result_text if isinstance(result_text, str) else str(result_text)
        for m in self._re.finditer(text):
            flag = m.group(0)
            key = (flag, tool_name)
            with self._lock:
                if key in self._seen:
                    continue
                self._seen.add(key)
                start = max(0, m.start() - _CONTEXT_RADIUS)
                end = min(len(text), m.end() + _CONTEXT_RADIUS)
                excerpt = str(redact_value(text[start:end]))
                self._captures.append(
                    FlagCapture(
                        flag=flag,
                        tool_name=tool_name,
                        argument_summary=_summarize_args(arguments),
                        context=excerpt,
                    )
                )
            logger.info(
                "FLAG ORACLE: captured %s from a real %s response", flag, tool_name
            )

    @property
    def captures(self) -> List[FlagCapture]:
        with self._lock:
            return list(self._captures)

    def captured_flags(self) -> List[str]:
        return [c.flag for c in self.captures]

    def verdict(self) -> Verdict:
        return grade(self.expected_flag, self.captured_flags())

    def report(self) -> dict:
        """Full, serializable artifact: verdict + every capture + the pattern."""
        return {
            "verdict": self.verdict().to_dict(),
            "captures": [c.to_dict() for c in self.captures],
            "pattern": self._re.pattern,
        }


# ── Process-wide singleton ────────────────────────────────────────────────
# Every AgentRunner (top-level pipeline, per-hunter fireteam runs, the
# validate_finding runner) shares one oracle so captures from any tool on any
# thread land in the same ledger. Mirrors the `_get_bridge()` singleton style.
_ORACLE: Optional[FlagOracle] = None
_ORACLE_LOCK = threading.Lock()


def get_flag_oracle() -> FlagOracle:
    global _ORACLE
    if _ORACLE is None:
        with _ORACLE_LOCK:
            if _ORACLE is None:
                _ORACLE = FlagOracle(
                    expected_flag=os.environ.get("AEGIS_EXPECTED_FLAG"),
                    enabled=os.environ.get("AEGIS_FLAG_ORACLE", "true").lower() != "false",
                )
    return _ORACLE


def set_flag_oracle(oracle: FlagOracle) -> FlagOracle:
    """Install the oracle for this run (called once at pentest startup)."""
    global _ORACLE
    with _ORACLE_LOCK:
        _ORACLE = oracle
    return oracle


def reset_flag_oracle() -> None:
    """Drop the singleton — used by tests to isolate runs."""
    global _ORACLE
    with _ORACLE_LOCK:
        _ORACLE = None


def _load_captured_flags(payload) -> List[str]:
    """Pull flag strings out of a report() dict or a raw list of captures."""
    if isinstance(payload, dict):
        caps = payload.get("captures", [])
    elif isinstance(payload, list):
        caps = payload
    else:
        caps = []
    flags: List[str] = []
    for c in caps:
        if isinstance(c, dict) and c.get("flag"):
            flags.append(c["flag"])
        elif isinstance(c, str):
            flags.append(c)
    return flags


def _main(argv: Optional[List[str]] = None) -> int:
    """Offline grader: grade a captures/report JSON against an expected flag.

    Exit 0 = PASS or NO_EXPECTED_FLAG, 2 = FAIL. Lets an XBEN harness grade a
    finished run deterministically from artifacts alone.
    """
    import argparse

    p = argparse.ArgumentParser(
        prog="flag_oracle",
        description="Grade captured flags against an expected flag (pass/fail).",
    )
    p.add_argument("--captures", required=True,
                   help="Path to flag_captures JSON (oracle report or raw capture list).")
    p.add_argument("--expected", default=os.environ.get("AEGIS_EXPECTED_FLAG"),
                   help="Expected flag (default: AEGIS_EXPECTED_FLAG).")
    args = p.parse_args(argv)

    with open(args.captures) as fh:
        payload = json.load(fh)

    verdict = grade(args.expected, _load_captured_flags(payload))
    print(json.dumps(verdict.to_dict(), indent=2))
    return 0 if verdict.status in ("PASS", "NO_EXPECTED_FLAG") else 2


if __name__ == "__main__":
    raise SystemExit(_main())
