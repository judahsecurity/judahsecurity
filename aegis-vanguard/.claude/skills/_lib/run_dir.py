#!/usr/bin/env python3
"""Mint or locate results/<target>/<timestamp>/ for Claude Code skills.

Prints the directory path on stdout. Skills should capture it and write artifacts
there. Does not invent findings — layout only.

    python3 .claude/skills/_lib/run_dir.py mint <target> [--fresh]
    python3 .claude/skills/_lib/run_dir.py latest <target>
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "results"


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name.strip() or "target")


def _target_root(target: str) -> Path:
    path = ROOT / _safe(target)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _runs(target: str) -> list[Path]:
    root = _target_root(target)
    return sorted(p for p in root.iterdir() if p.is_dir())


def mint(target: str, fresh: bool) -> Path:
    runs = _runs(target)
    if runs and not fresh:
        return runs[-1]
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = _target_root(target) / ts
    n = 2
    while path.exists():
        path = _target_root(target) / f"{ts}-{n}"
        n += 1
    path.mkdir(parents=True, exist_ok=False)
    return path


def latest(target: str) -> Path:
    runs = _runs(target)
    if not runs:
        raise SystemExit(f"no runs for {target!r} under {ROOT}")
    return runs[-1]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=["mint", "latest"])
    p.add_argument("target")
    p.add_argument("--fresh", action="store_true")
    args = p.parse_args()
    if args.action == "mint":
        print(mint(args.target, args.fresh))
    else:
        print(latest(args.target))
    return 0


if __name__ == "__main__":
    sys.exit(main())
