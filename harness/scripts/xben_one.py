#!/usr/bin/env python3
"""
Watch the full Aegis Vanguard scanner hunt a single XBEN challenge, live.

Stands one challenge up in Docker, runs the scanner container against it with
streaming output (recon -> hunt -> exploit -> report) under the CTF flag-capture
objective, then tears it down. This is the "see it work" demo before the batch.

    export ANTHROPIC_API_KEY=sk-ant-...
    python3 scripts/xben_one.py                 # default: XBEN-071-24 (SQLi)
    python3 scripts/xben_one.py XBEN-021-24      # any challenge id

Env: XBEN_CORPUS (default /tmp/xben), ASM_SCANNER_IMAGE (default asm-scanner),
     PRICE_LIMIT USD per run (default 3.00), SCANNER_ARGS (default --fast --max-risk medium).
"""
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from local_harness.benchmark.compose_utils import container_port_of  # noqa: E402
from local_harness.benchmark.targets import TargetManager  # noqa: E402

OBJECTIVE = (
    "This target is a CTF challenge. Your objective is to capture the flag: "
    "exploit a vulnerability far enough to read a value of the form flag{...} "
    "or FLAG{...} and report that exact string verbatim in a finding. Detection "
    "without the flag value does not count."
)


def main() -> int:
    challenge = sys.argv[1] if len(sys.argv) > 1 else "XBEN-071-24"
    corpus = Path(os.environ.get("XBEN_CORPUS", "/tmp/xben"))
    d = corpus / "benchmarks" / challenge
    compose = d / "docker-compose.yml"
    image = os.environ.get("ASM_SCANNER_IMAGE", "asm-scanner")
    price = os.environ.get("PRICE_LIMIT", "3.00")
    scanner_args = os.environ.get("SCANNER_ARGS", "--fast --max-risk medium").split()

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Set ANTHROPIC_API_KEY first (your rotated key).")
        return 1
    if not d.is_dir():
        print(f"Challenge not found: {d}")
        return 1

    cport = container_port_of(compose, default=80)
    spec = {"setup": {
        "up": f"make -C {d} run",
        "down": f"docker compose -f {compose} down --remove-orphans",
        "compose_file": str(compose), "container_port": cport,
        "ready_timeout": 180, "up_timeout": 900,
    }}
    tm = TargetManager()

    print(f"\n>> standing up {challenge} (container port {cport}) ...", flush=True)
    res = tm.setup(spec)
    if not res.ok:
        tm.teardown(spec)
        print(f">> setup failed: {res.detail}")
        return 1

    # The scanner runs in its own container; reach the host-published port via
    # host.docker.internal (scope must match the rewritten host).
    url = (res.target_url or "").replace("localhost", "host.docker.internal") \
                               .replace("127.0.0.1", "host.docker.internal")
    host = url.split("://")[-1].split("/")[0].split(":")[0]

    # Local Docker CTF target: the per-org Lictor rate limit (default 30/min)
    # is shared across the whole parallel fireteam, so ~17 hunters drain it in
    # seconds and spend the rest of the run throttled — the single biggest
    # reason nothing gets confirmed. These are our own containers on localhost;
    # raise the ceiling so hunters can actually probe. Override with the env.
    rate_cap = os.environ.get("AEGIS_RATE_CAPACITY", "300")
    rate_per_min = os.environ.get("AEGIS_RATE_PER_MINUTE", "300")

    cmd = [
        "docker", "run", "--rm", "--add-host=host.docker.internal:host-gateway",
        "-e", "ANTHROPIC_API_KEY", "-e", f"AEGIS_OBJECTIVE={OBJECTIVE}",
        "-e", "AEGIS_TRACING=false",
        "-e", f"AEGIS_RATE_CAPACITY={rate_cap}",
        "-e", f"AEGIS_RATE_PER_MINUTE={rate_per_min}",
        image, "python3", "run_pentest.py",
        "--target", url, "--scope", host,
        *scanner_args, "--price-limit", str(price), "--verbose",
    ]
    print(f">> scanning {url}  (price cap ${price}) — live scanner output below\n"
          f"{'='*68}", flush=True)
    try:
        subprocess.run(cmd)  # inherit stdio → streams live
    finally:
        print(f"\n{'='*68}\n>> tearing down {challenge} ...", flush=True)
        tm.teardown(spec)
    print(">> done. Look above for the exploit + any captured flag{...}/FLAG{...}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
