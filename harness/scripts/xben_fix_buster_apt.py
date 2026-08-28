#!/usr/bin/env python3
"""
Repair XBEN challenge images that no longer build because their Debian base is
archived.

Many challenges use ``FROM python:2.7.18-slim`` (Debian *buster*) and run
``apt-get update && apt-get install -y phantomjs``. Buster is EOL: its mirrors
were removed from deb.debian.org, so ``apt-get update`` fails with
"buster-updates Release does not have a Release file" and the build dies before
anything runs. This is upstream bit-rot, not a harness bug — it hits anyone
building XBEN today.

Fix: point apt at archive.debian.org and disable the valid-until check, right
before the failing apt line. Idempotent; only touches Dockerfiles that need it.
Operates on your local corpus clone (e.g. /tmp/xben) — it does not modify this
repo. Re-run the benchmark/probe afterward; edited Dockerfiles rebuild cleanly.

    python3 scripts/xben_fix_buster_apt.py --corpus /tmp/xben
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

MARKER = "archive.debian.org"  # presence means already patched

# The exact failing line in the XBEN images (whitespace-tolerant).
_APT = re.compile(
    r"^(?P<indent>\s*)RUN\s+apt-get\s+update\s*&&\s*apt-get\s+install\s+-y\s+phantomjs\s*$",
    re.MULTILINE,
)

_FIX = (
    "RUN printf 'deb http://archive.debian.org/debian buster main\\n"
    "deb http://archive.debian.org/debian-security buster/updates main\\n' "
    "> /etc/apt/sources.list "
    "&& apt-get -o Acquire::Check-Valid-Until=false update "
    "&& apt-get install -y --no-install-recommends phantomjs "
    "&& rm -rf /var/lib/apt/lists/*"
)


def _dockerfiles(corpus: Path):
    for d in sorted((corpus / "benchmarks").iterdir()):
        if not d.is_dir():
            continue
        for cand in (d / "Dockerfile", d / "src" / "Dockerfile"):
            if cand.exists():
                yield cand


def patch_text(text: str) -> tuple[str, bool]:
    if MARKER in text:
        return text, False
    new, n = _APT.subn(lambda m: m.group("indent") + _FIX, text)
    return new, n > 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="xben_fix_buster_apt")
    p.add_argument("--corpus", type=Path, required=True, help="Local validation-benchmarks clone")
    p.add_argument("--dry-run", action="store_true", help="Report what would change; write nothing")
    a = p.parse_args(argv)

    if not (a.corpus / "benchmarks").is_dir():
        print(f"corpus not found: {a.corpus}/benchmarks")
        return 1

    patched = skipped = already = 0
    for df in _dockerfiles(a.corpus):
        text = df.read_text(encoding="utf-8", errors="ignore")
        if MARKER in text:
            already += 1
            continue
        new, changed = patch_text(text)
        if not changed:
            skipped += 1
            continue
        if not a.dry_run:
            df.write_text(new, encoding="utf-8")
        patched += 1
        print(f"  {'would patch' if a.dry_run else 'patched'}: {df.relative_to(a.corpus)}")

    print(f"\n{patched} patched, {already} already-fixed, {skipped} unaffected.")
    if patched and not a.dry_run:
        print("Re-run the probe/benchmark — the edited images rebuild from archive.debian.org.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
