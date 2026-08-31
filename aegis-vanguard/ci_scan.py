#!/usr/bin/env python3
"""Aegis Vanguard — CI/CD gate.

Turns a scan's findings into CI-native output: writes SARIF 2.1 (for the GitHub
code-scanning tab / PR annotations) and exits non-zero when findings meet a
severity threshold, so a pipeline can block a merge before code reaches prod.

Typical CI usage (after a scan has produced findings.json):

    python3 ci_scan.py --findings results/app/latest/findings.json \\
        --sarif aegis.sarif --fail-on high

Diff-scoped (only fail on findings in files changed vs the base branch):

    python3 ci_scan.py --findings findings.json --sarif aegis.sarif \\
        --fail-on high --diff-base origin/main

Exit codes:  0 = pass   1 = blocked by threshold   2 = usage/config error
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent))

from agent.sarif import findings_to_sarif, finding_uri
from agent.ci_gate import severity_gate, summary_line, SEVERITY_ORDER


def load_findings(path: str) -> List[Dict[str, Any]]:
    """Load findings from a JSON list, a {'findings': [...]} object, or JSONL."""
    text = Path(path).read_text().strip()
    if not text:
        return []
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("findings", "results", "vulnerabilities"):
                if isinstance(data.get(key), list):
                    return data[key]
            return [data]
    except json.JSONDecodeError:
        # JSONL fallback
        out = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return out
    return []


def git_changed_files(base: str, root: str = ".") -> List[str]:
    """Repo-relative paths changed vs `base` (merge-base diff). Empty on error."""
    try:
        proc = subprocess.run(
            ["git", "-C", root, "diff", "--name-only", f"{base}...HEAD"],
            capture_output=True, text=True, timeout=60, check=False,
        )
        if proc.returncode != 0:
            # Fall back to a plain two-dot diff (no common ancestor available).
            proc = subprocess.run(
                ["git", "-C", root, "diff", "--name-only", base],
                capture_output=True, text=True, timeout=60, check=False,
            )
        return [ln.strip().replace("\\", "/") for ln in proc.stdout.splitlines() if ln.strip()]
    except Exception:
        return []


def filter_to_changed(findings: List[Dict[str, Any]], changed: List[str],
                      source_root: str) -> List[Dict[str, Any]]:
    """Keep findings whose file is in the changed set; keep URL/DAST findings as-is."""
    changed_set = {c.lstrip("./") for c in changed}
    kept = []
    for f in findings:
        uri = finding_uri(f, source_root)
        if uri is None or uri.lstrip("./") in changed_set:
            kept.append(f)
    return kept


def main() -> int:
    ap = argparse.ArgumentParser(description="Aegis Vanguard CI/CD gate (SARIF + severity gating).")
    ap.add_argument("--findings", required=True, help="Path to findings.json / .jsonl from a scan.")
    ap.add_argument("--sarif", help="Write SARIF 2.1 output to this path.")
    ap.add_argument("--json-out", help="Write the (possibly diff-filtered) findings back out.")
    ap.add_argument("--fail-on", default="high",
                    help=f"Min severity that fails the build: {SEVERITY_ORDER} or 'never' (default: high).")
    ap.add_argument("--diff-base", help="Only gate on findings in files changed vs this git ref (e.g. origin/main).")
    ap.add_argument("--source-root", default="", help="Absolute source root, to relativise SAST file paths.")
    ap.add_argument("--tool-version", default="1.0.0")
    args = ap.parse_args()

    fpath = Path(args.findings)
    if not fpath.exists():
        print(f"::error:: findings file not found: {fpath}", file=sys.stderr)
        return 2

    findings = load_findings(str(fpath))

    if args.diff_base:
        changed = git_changed_files(args.diff_base, args.source_root or ".")
        before = len(findings)
        findings = filter_to_changed(findings, changed, args.source_root)
        print(f">>> diff-scope vs {args.diff_base}: {len(changed)} changed file(s), "
              f"{len(findings)}/{before} finding(s) in scope")

    if args.sarif:
        sarif = findings_to_sarif(findings, tool_version=args.tool_version,
                                  source_root=args.source_root)
        Path(args.sarif).write_text(json.dumps(sarif, indent=2))
        print(f">>> wrote SARIF: {args.sarif} ({len(findings)} result(s))")

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(findings, indent=2, default=str))

    gate = severity_gate(findings, fail_on=args.fail_on)
    print(">>> " + summary_line(gate))
    if gate.get("error"):
        print(f"::error:: {gate['error']}", file=sys.stderr)
    return gate["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
