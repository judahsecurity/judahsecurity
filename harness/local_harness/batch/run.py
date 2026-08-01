"""
Batch scan driver.

    python -m local_harness.batch.run scan [--resume] [--list PATH]
    python -m local_harness.batch.run status
    python -m local_harness.batch.run collect

Reads a target list (default ``batch/REPO_LIST.txt``), runs the Aegis Vanguard
scanner against each target, and tracks progress in a JSON state file so runs
are resumable. ``collect`` aggregates every target's findings into a single
report for centralized review.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..config import HarnessConfig, default_config
from ..findings import load_findings, severity_counts, vulnerabilities
from ..runner import run_scan, slugify

DEFAULT_LIST = Path(__file__).resolve().parent / "REPO_LIST.txt"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_target_list(path: Path) -> List[Tuple[str, Optional[str]]]:
    """Parse a target list file into (target, scope) tuples."""
    targets: List[Tuple[str, Optional[str]]] = []
    if not path.exists():
        return targets
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "," in line:
            target, scope = line.split(",", 1)
            targets.append((target.strip(), scope.strip() or None))
        else:
            targets.append((line, None))
    return targets


def _load_state(path: Path) -> Dict[str, dict]:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
    return {}


def _save_state(path: Path, state: Dict[str, dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")


def cmd_scan(
    config: HarnessConfig,
    list_path: Path,
    resume: bool,
    fail_on_error: bool = False,
    fail_on_findings: bool = False,
) -> int:
    targets = parse_target_list(list_path)
    if not targets:
        print(f"No targets found in {list_path}. Add one target per line.")
        return 1

    state = _load_state(config.batch_state_path)
    out_root = config.batch_dir / "targets"
    out_root.mkdir(parents=True, exist_ok=True)

    print(f"Batch scan: {len(targets)} target(s) from {list_path}")
    print(f"Scanner:    {' '.join(config.scanner_cmd)} (cwd={config.scanner_cwd})")
    print(f"Output:     {config.batch_dir}\n")

    completed = 0
    for idx, (target, scope) in enumerate(targets, 1):
        slug = slugify(target)
        prior = state.get(slug)
        if resume and prior and prior.get("status") == "done":
            print(f"[{idx}/{len(targets)}] {target}  (skip — already done)")
            completed += 1
            continue

        print(f"[{idx}/{len(targets)}] {target}  scanning …")
        state[slug] = {
            "target": target,
            "scope": scope,
            "status": "running",
            "started_at": _now(),
        }
        _save_state(config.batch_state_path, state)

        result = run_scan(target, config, out_root, scope=scope)

        state[slug] = {
            "target": target,
            "scope": scope,
            "status": result.status,
            "started_at": state[slug]["started_at"],
            "finished_at": _now(),
            "duration_sec": round(result.duration_sec, 1),
            "finding_count": result.finding_count,
            "vuln_count": len(vulnerabilities(result.findings)),
            "out_dir": str(result.out_dir),
            "findings_path": str(result.findings_path),
            "log_path": str(result.log_path),
            "error": result.error,
        }
        _save_state(config.batch_state_path, state)

        if result.status == "done":
            completed += 1
            print(
                f"    done: {result.finding_count} findings "
                f"({len(vulnerabilities(result.findings))} vulns) "
                f"in {result.duration_sec:.0f}s"
            )
        else:
            print(f"    {result.status.upper()}: {result.error}")

    print(f"\nBatch complete: {completed}/{len(targets)} succeeded.")

    errored = [s for s, e in state.items() if e.get("status") not in ("done", "running")]
    total_vulns = sum(e.get("vuln_count", 0) or 0 for e in state.values())

    if fail_on_error and errored:
        print(f"[gate] {len(errored)} target(s) errored → exit 3")
        return 3
    if fail_on_findings and total_vulns > 0:
        print(f"[gate] {total_vulns} vulnerabilit(ies) found → exit 2")
        return 2
    return 0


def cmd_status(config: HarnessConfig) -> int:
    state = _load_state(config.batch_state_path)
    if not state:
        print("No batch state yet. Run `scan` first.")
        return 0

    rows = []
    for slug, entry in state.items():
        rows.append(
            (
                entry.get("target", slug),
                entry.get("status", "?"),
                entry.get("vuln_count", entry.get("finding_count", "-")),
                entry.get("duration_sec", "-"),
            )
        )

    width = max((len(str(r[0])) for r in rows), default=6)
    print(f"{'TARGET'.ljust(width)}  STATUS    VULNS  DURATION(s)")
    print(f"{'-' * width}  --------  -----  -----------")
    for target, status, vulns, dur in rows:
        print(f"{str(target).ljust(width)}  {status:<8}  {str(vulns):>5}  {str(dur):>11}")

    done = sum(1 for e in state.values() if e.get("status") == "done")
    print(f"\n{done}/{len(state)} done.")
    return 0


def cmd_collect(config: HarnessConfig) -> int:
    state = _load_state(config.batch_state_path)
    if not state:
        print("No batch state yet. Run `scan` first.")
        return 0

    aggregate = {
        "generated_at": _now(),
        "targets": {},
        "totals": {"findings": 0, "vulnerabilities": 0, "by_severity": {}},
    }
    all_sev: Dict[str, int] = {}

    for slug, entry in state.items():
        fp = entry.get("findings_path")
        findings = load_findings(Path(fp)) if fp else []
        vulns = vulnerabilities(findings)
        sev = severity_counts(vulns)
        for k, v in sev.items():
            all_sev[k] = all_sev.get(k, 0) + v
        aggregate["targets"][slug] = {
            "target": entry.get("target"),
            "status": entry.get("status"),
            "finding_count": len(findings),
            "vuln_count": len(vulns),
            "by_severity": sev,
            "vulnerabilities": [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.category,
                    "host": f.host,
                    "endpoint": f.endpoint,
                    "confirmed": f.is_confirmed,
                }
                for f in vulns
            ],
        }
        aggregate["totals"]["findings"] += len(findings)
        aggregate["totals"]["vulnerabilities"] += len(vulns)

    aggregate["totals"]["by_severity"] = all_sev

    out_path = config.batch_dir / "collected_findings.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(aggregate, indent=2, default=str), encoding="utf-8")

    print(f"Collected findings from {len(state)} target(s):")
    print(f"  total findings:        {aggregate['totals']['findings']}")
    print(f"  total vulnerabilities: {aggregate['totals']['vulnerabilities']}")
    print(f"  by severity:           {all_sev}")
    print(f"\nWritten to {out_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="local_harness.batch.run",
        description="Batch-scan many targets with the Aegis Vanguard scanner.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan every target in the list")
    p_scan.add_argument("--resume", action="store_true", help="Skip completed targets")
    p_scan.add_argument(
        "--list", type=Path, default=DEFAULT_LIST, help="Path to the target list file"
    )
    p_scan.add_argument(
        "--fail-on-error", action="store_true",
        help="CI gate: exit 3 if any target failed to scan",
    )
    p_scan.add_argument(
        "--fail-on-findings", action="store_true",
        help="CI gate: exit 2 if any vulnerabilities were found",
    )

    sub.add_parser("status", help="Show per-target progress")
    sub.add_parser("collect", help="Aggregate all findings into one report")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    config = default_config()

    if args.command == "scan":
        return cmd_scan(
            config, args.list, args.resume,
            fail_on_error=args.fail_on_error,
            fail_on_findings=args.fail_on_findings,
        )
    if args.command == "status":
        return cmd_status(config)
    if args.command == "collect":
        return cmd_collect(config)
    return 1


if __name__ == "__main__":
    sys.exit(main())
