"""
Import the XBOW/XBEN validation-benchmarks corpus into harness ground truth.

XBEN is the 104-challenge CTF corpus Strix reports against (96% solved). Each
challenge is a self-contained Docker Compose app; success = extracting the
injected flag. The flag is deterministic (see the corpus ``common.mk``):

    FLAG{ sha256( <CHALLENGE-DIR-NAME> ) }

so this importer computes each expected flag offline — no need to read the
per-challenge ``.env`` secrets. A challenge's local ``.env`` FLAG override, if
present, takes precedence (matching the corpus Makefile behavior).

Usage:
    # clone the corpus first (only scan/run what you're authorized to):
    #   git clone https://github.com/xbow-engineering/validation-benchmarks
    python -m local_harness.benchmark.xben_import \
        --corpus /path/to/validation-benchmarks \
        --out local_harness/benchmark/ground_truth/XBEN.json

Then benchmark against it:
    python -m local_harness.benchmark.run \
        --ground-truth local_harness/benchmark/ground_truth/XBEN.json \
        --setup --min-success-rate 0.8
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Dict, Optional

from local_harness.benchmark.compose_utils import container_port_of


def compute_flag(challenge_name: str) -> str:
    """Deterministic XBEN flag: FLAG{sha256(<CHALLENGE-NAME-UPPER>)}."""
    digest = hashlib.sha256(challenge_name.upper().encode()).hexdigest()
    return "FLAG{" + digest + "}"


def _env_flag_override(challenge_dir: Path) -> Optional[str]:
    env = challenge_dir / ".env"
    if not env.exists():
        return None
    for line in env.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line.startswith("FLAG=") and len(line) > 5:
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


def build_corpus(corpus_root: Path, container_port: int = 80) -> Dict[str, dict]:
    benchmarks_dir = corpus_root / "benchmarks"
    if not benchmarks_dir.is_dir():
        # Some layouts put challenges at the root.
        benchmarks_dir = corpus_root

    out: Dict[str, dict] = {
        "_comment": (
            "Generated from the XBOW validation-benchmarks corpus by "
            "xben_import.py. Flag mode: a challenge is solved when its flag "
            "appears in the scanner's findings. Run with --setup to docker "
            "up/down each challenge. Only run challenges you are authorized to."
        )
    }

    for child in sorted(benchmarks_dir.iterdir()):
        meta_path = child / "benchmark.json"
        if not child.is_dir() or not meta_path.exists():
            continue
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue

        name = child.name
        # The built flag is common.mk's FLAG{sha256(UPPER(name))}: the Makefile
        # bakes it via `docker compose build --build-arg FLAG=...`, which
        # OVERRIDES the compose `args: [FLAG]` that would read .env — and
        # secret.txt ships as the @FLAG@ placeholder. So the per-challenge .env
        # value is a decoy; use the sha256 flag. (Verified against the corpus
        # build chain 2026-08. `make FLAG=...` would override, but the harness
        # runs plain `make run`.)
        flag = compute_flag(name)
        compose_file = child / "docker-compose.yml"
        # Detect the container port per challenge — 42/104 are not on :80, and a
        # wrong port makes --setup's readiness/port discovery fail (silent miss).
        cport = container_port_of(compose_file, default=container_port)

        out[name] = {
            "name": meta.get("name", name),
            "level": meta.get("level"),
            "tags": meta.get("tags", []),
            "flag": flag,
            "scope": "localhost",
            "setup": {
                "up": f"make -C {child.resolve()} run",
                "down": f"make -C {child.resolve()} stop",
                "compose_file": str(compose_file.resolve()),
                "container_port": cport,
                "ready_timeout": 180,
                "up_timeout": 900,
            },
        }

    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="local_harness.benchmark.xben_import",
        description="Generate harness ground truth from the XBOW/XBEN corpus.",
    )
    parser.add_argument(
        "--corpus", type=Path, required=True,
        help="Path to a local clone of xbow-engineering/validation-benchmarks",
    )
    parser.add_argument("--out", type=Path, required=True, help="Output ground-truth JSON path")
    parser.add_argument(
        "--container-port", type=int, default=80,
        help="Container port the challenge app listens on (default 80)",
    )
    args = parser.parse_args(argv)

    if not args.corpus.is_dir():
        print(f"corpus path not found: {args.corpus}")
        return 1

    corpus = build_corpus(args.corpus, args.container_port)
    challenge_count = sum(1 for k in corpus if not k.startswith("_"))
    if challenge_count == 0:
        print(f"no challenges found under {args.corpus} (expected benchmark.json dirs)")
        return 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(corpus, indent=2), encoding="utf-8")
    print(f"Imported {challenge_count} XBEN challenge(s) → {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
