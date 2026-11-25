"""Benchmark scanner command that runs the in-product Prowl agent.

The benchmark runner launches a scanner as ``<cmd> --target URL [--scope S]``
with ``AEGIS_FINDINGS_SINK`` set. This module is the default scanner; the
explicit settings below add XBEN's synthetic flag capture:

    export AEGIS_HARNESS_SCANNER_CMD="python -m local_harness.prowl_scanner --benchmark-proof"
    export AEGIS_HARNESS_SCANNER_CWD="$PWD"          # the harness directory
    export AEGIS_ASSESSMENT_DATABASE_URL=...         # dedicated assessment database
    export AEGIS_PROWL_ORG_ID=... AEGIS_PROWL_USER_ID=...
    python -m local_harness.benchmark.run --ground-truth .../XBEN.json --setup

Budgets and mode come from ``AEGIS_PROWL_*`` variables so every target in a
suite runs with the same settings, and they are recorded in
``product_assessment.json`` next to the findings.

XBEN publishes challenges on ``localhost:<port>``. Prowl's Lictor guard denies
loopback to every CLI tool, so the target and scope are rewritten to a
non-loopback address of this machine that reaches the same published port:
``AEGIS_PROWL_LOOPBACK_ALIAS`` if set, else the ``docker0`` bridge address, else
the primary interface address. The guard itself is not relaxed.

Unlike the class-lab adapter, a run that stops on its budget is still a valid
benchmark result: the challenge is scored on what Prowl published. Only a run
that could not start, or that crashed, exits non-zero.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import re
import socket
import subprocess
from pathlib import Path

_LOOPBACK_HOST = re.compile(r"(?<![\w.-])(localhost|127\.0\.0\.1)(?![\w-])", re.IGNORECASE)


def _docker_bridge_address() -> str:
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show", "docker0"],
                             capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/", out)
    return match.group(1) if match else ""


def _primary_address() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            # UDP connect sends nothing; it only selects the outbound interface.
            sock.connect(("192.0.2.1", 9))
            return sock.getsockname()[0]
    except OSError:
        return ""


def loopback_alias() -> str:
    """A non-loopback address of this host for reaching published ports."""
    for candidate in (os.environ.get("AEGIS_PROWL_LOOPBACK_ALIAS", "").strip(),
                      _docker_bridge_address(), _primary_address()):
        if not candidate:
            continue
        try:
            if ipaddress.ip_address(candidate).is_loopback:
                continue
        except ValueError:
            pass  # a hostname alias is allowed
        return candidate
    raise SystemExit(
        "No non-loopback address found for a localhost target; set AEGIS_PROWL_LOOPBACK_ALIAS"
    )


def rewrite_loopback(value: str, alias: str) -> str:
    return _LOOPBACK_HOST.sub(alias, value or "")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name) or default)
    except ValueError as exc:
        raise SystemExit(f"{name} must be an integer") from exc


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name) or default)
    except ValueError as exc:
        raise SystemExit(f"{name} must be a number") from exc


def build_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", "-u", required=True)
    parser.add_argument("--scope", "-s", default="")
    parser.add_argument("--benchmark-proof", action="store_true")
    parser.add_argument("--assessment-mode", choices=("standard", "deep"),
                        default=os.environ.get("AEGIS_PROWL_MODE") or "standard")
    args, unknown = parser.parse_known_args(argv)
    if unknown:
        # Vanguard-only flags (e.g. --fast) may be left in shared configs.
        print(f"[prowl_scanner] ignoring unsupported arguments: {' '.join(unknown)}")
    missing = [name for name in ("AEGIS_PROWL_ORG_ID", "AEGIS_PROWL_USER_ID")
               if not os.environ.get(name)]
    if missing:
        raise SystemExit("Set " + ", ".join(missing) + " for the assessment tenant")
    args.organization_id = _env_int("AEGIS_PROWL_ORG_ID", 0)
    args.user_id = _env_int("AEGIS_PROWL_USER_ID", 0)
    args.identities = os.environ.get("AEGIS_PROWL_IDENTITIES") or None
    args.max_turns = _env_int("AEGIS_PROWL_MAX_TURNS", 4)
    args.max_iterations = _env_int("AEGIS_PROWL_MAX_ITERATIONS", 60)
    args.price_limit_usd = _env_float("AEGIS_PROWL_PRICE_LIMIT_USD", 10.0)
    args.require_oast = False
    if _LOOPBACK_HOST.search(args.target) or _LOOPBACK_HOST.search(args.scope):
        alias = loopback_alias()
        args.target = rewrite_loopback(args.target, alias)
        args.scope = rewrite_loopback(args.scope, alias)
    return args


def scanner_exit_code(output_dir: Path) -> int:
    """0 when the agent ran and left a summary; 1 when it never produced one."""
    try:
        summary = json.loads((output_dir / "product_assessment.json").read_text())
    except (OSError, ValueError):
        return 1
    if summary.get("ledger_export_error"):
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_args(argv)
    from local_harness.product_agent import assess

    sink = Path(os.environ.get("AEGIS_FINDINGS_SINK", "findings.jsonl")).resolve()
    # The runner pre-creates an empty sink so a missing file means the scanner
    # failed. The adapter wants a fresh file, so hand it an empty one.
    if sink.exists() and sink.stat().st_size == 0:
        sink.unlink()
    asyncio.run(assess(args))
    return scanner_exit_code(sink.parent)


if __name__ == "__main__":
    raise SystemExit(main())
