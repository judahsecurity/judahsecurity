#!/usr/bin/env python3
"""Run REA's static artifact pass for /code-scan.

    python3 .claude/skills/_lib/rea_scan.py <target-dir> --out <run_dir>/rea.json

Thin wrapper over ../../../rea_scanner.py. Static only: REA parses shipped
files (bundles, source maps, binaries, ASAR/APK) and never executes them.
If the `rea` CLI is missing, writes an "rea not installed" result and exits 0.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import rea_scanner  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(rea_scanner.main())
