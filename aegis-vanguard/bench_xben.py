#!/usr/bin/env python3
"""
XBEN suite runner — measure the agent across the XBOW validation-benchmarks.

`grade_xben.py` grades ONE finished run. This drives the whole loop: for each
benchmark it builds + launches the challenge, points the agent at it, collects
the real flag captures, tears the challenge down, and grades — then reports a
pass-rate across the suite. Run it before and after a change and the delta is
the answer to "is the agent getting better?".

Ground truth comes from XBOW's own `common.mk`, so nothing here is guessed:

  * the flag is deterministic — `FLAG{sha256(UPPERCASE_BENCHMARK_NAME)}` — so we
    compute the expected flag for every challenge with zero configuration;
  * `make run` builds (with that flag) and `docker compose up --wait`;
  * the web app publishes container port 80 to a random host port (internal
    services only `expose`), so the host port is read from `docker compose ps`
    after it is up;
  * `make stop` / `docker compose down -v` tears it down.

A finding counts only if the expected flag appears in a REAL tool response
recorded by agent.flag_oracle — never the agent's report prose (same discipline
as grade_xben.py).

    # preview what would run (no docker, no agent) — safe anywhere:
    python3 bench_xben.py --bench-root ../validation-benchmarks/benchmarks --dry-run

    # run one, or a level, or all (needs docker + an LLM key + run_pentest deps):
    python3 bench_xben.py --bench-root .../benchmarks --only XBEN-020-24 --out results/bench
    python3 bench_xben.py --bench-root .../benchmarks --level 1 --out results/bench

    # gate on regression vs a committed baseline:
    python3 bench_xben.py --bench-root .../benchmarks --out results/bench \\
        --baseline bench_baseline.json
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from agent.flag_oracle import grade, _load_captured_flags  # noqa: E402


# ── pure core (unit-tested) ──────────────────────────────────────────────

def expected_flag(name: str) -> str:
    """XBOW common.mk: ``FLAG{sha256(UPPERCASE_NAME)}``.

    Verified against the real XBEN-020-24 flag. This is why the suite needs no
    stored answer key — the flag is a function of the benchmark name.
    """
    digest = hashlib.sha256(name.upper().encode()).hexdigest()
    return "FLAG{" + digest + "}"


def load_benchmark_meta(path: Path) -> dict:
    for fn in ("benchmark.json", "benchmark-config.json"):
        p = Path(path) / fn
        if p.exists():
            try:
                return json.loads(p.read_text())
            except Exception:
                return {}
    return {}


def discover_benchmarks(bench_root, only=None, levels=None, win="flag"):
    """Enumerate runnable benchmarks under ``bench_root``.

    A directory qualifies if it has a docker-compose.yml. ``only`` filters by
    name, ``levels`` by benchmark level, ``win`` by win_condition (default
    "flag" — question-type challenges aren't flag-gradable here).
    """
    root = Path(bench_root)
    only_set = set(only) if only else None
    level_set = set(levels) if levels else None
    out = []
    for d in sorted(p for p in (root.iterdir() if root.exists() else []) if p.is_dir()):
        if not (d / "docker-compose.yml").exists():
            continue
        if only_set is not None and d.name not in only_set:
            continue
        meta = load_benchmark_meta(d)
        if win and meta.get("win_condition", "flag") != win:
            continue
        if level_set is not None and meta.get("level") not in level_set:
            continue
        out.append({
            "name": d.name,
            "dir": str(d),
            "level": meta.get("level"),
            "win_condition": meta.get("win_condition", "flag"),
            "tags": meta.get("tags", []),
            "expected": expected_flag(d.name),
        })
    return out


def _load_ps(text: str):
    """Parse `docker compose ps --format json` (json-array or json-lines)."""
    text = (text or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]


def parse_published_port(ps_output: str, prefer_target: int = 80) -> int:
    """Host port the challenge web app is published on, from `compose ps` JSON.

    XBOW's web service maps container 80 → a random host port; internal
    services have no Publishers. Prefer the one targeting port 80, else the
    first published port found. Raises if none is published.
    """
    candidates = []
    for entry in _load_ps(ps_output):
        for pub in (entry.get("Publishers") or []):
            pp = pub.get("PublishedPort")
            if pp:
                candidates.append((pub.get("TargetPort"), int(pp)))
    if not candidates:
        raise RuntimeError("no published host port in `docker compose ps` output")
    for target_port, host_port in candidates:
        if target_port == prefer_target:
            return host_port
    return candidates[0][1]


def summarize(results: list) -> dict:
    """Roll per-benchmark verdicts into a suite scorecard."""
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    ungraded = len(results) - passed - failed
    graded = passed + failed
    return {
        "passed": passed, "failed": failed, "ungraded": ungraded,
        "graded": graded,
        "pass_rate": (passed / graded * 100) if graded else 0.0,
        "results": {r["name"]: r["status"] for r in results},
    }


def compare_baseline(summary: dict, baseline: dict) -> dict:
    """Regressions vs a prior suite summary: any benchmark that was PASS and is
    no longer PASS, plus a drop in overall pass-rate."""
    base_results = baseline.get("results", {})
    regressed = [name for name, st in base_results.items()
                 if st == "PASS" and summary["results"].get(name) != "PASS"]
    rate_drop = baseline.get("pass_rate", 0.0) - summary["pass_rate"]
    return {"regressed": regressed, "rate_drop": rate_drop,
            "regressed_count": len(regressed)}


# ── live driver (needs docker + run_pentest deps) ────────────────────────

def _sh(cmd, cwd=None, env=None, timeout=None, check=True):
    return subprocess.run(cmd, cwd=cwd, env=env, timeout=timeout, check=check,
                          capture_output=True, text=True)


def target_host_for(opts) -> str:
    """127.0.0.1 for a host-run agent; host.docker.internal when the agent runs
    in a container (a challenge on host docker is reached via that name)."""
    if opts.target_host:
        return opts.target_host
    return "host.docker.internal" if opts.docker_image else "127.0.0.1"


def build_agent_invocation(target: str, flag: str, traces, opts):
    """Return (cmd, cwd, env) for one agent pass — host subprocess or docker run.

    Docker mode runs the agent inside the built image (flag oracle, proof gate,
    recon CLIs all included) with the traces dir bind-mounted to /agent/results
    and ANTHROPIC_API_KEY passed through from the caller's environment (never
    inlined). Host mode runs run_pentest.py directly.
    """
    traces = Path(traces)
    passthrough = ["--expected-flag", flag, *opts.agent_args]
    if opts.docker_image:
        cmd = [
            "docker", "run", "--rm",
            "-e", "ANTHROPIC_API_KEY",
            "-e", f"AEGIS_EXPECTED_FLAG={flag}",
            "-e", "AEGIS_TRACES_DIR=/agent/results",
            "-v", f"{traces.resolve()}:/agent/results",
            opts.docker_image,
            "python3", "run_pentest.py", "--target", target, *passthrough,
        ]
        return cmd, None, dict(os.environ)
    env = dict(os.environ)
    env["AEGIS_TRACES_DIR"] = str(traces)
    env["AEGIS_EXPECTED_FLAG"] = flag
    cmd = [sys.executable, str(HERE / "run_pentest.py"),
           "--target", target, *passthrough]
    return cmd, str(HERE), env


def run_one(bench: dict, opts) -> dict:
    """Build+launch one challenge, run the agent, grade, tear down."""
    d = Path(bench["dir"])
    flag = bench["expected"]
    traces = Path(opts.out) / bench["name"]
    traces.mkdir(parents=True, exist_ok=True)
    result = {"name": bench["name"], "status": "ERROR", "expected": flag,
              "captures": None, "target": None, "detail": ""}

    try:
        _sh(["make", "run"], cwd=d, timeout=opts.up_timeout)
    except Exception as e:
        result["detail"] = f"build/up failed: {e}"
        return result

    try:
        ps = _sh(["docker", "compose", "ps", "--format", "json"], cwd=d).stdout
        port = parse_published_port(ps)
        target = f"http://{target_host_for(opts)}:{port}/"
        result["target"] = target

        agent_cmd, agent_cwd, agent_env = build_agent_invocation(
            target, flag, traces, opts)
        try:
            _sh(agent_cmd, cwd=agent_cwd, env=agent_env,
                timeout=opts.run_timeout, check=False)
        except subprocess.TimeoutExpired:
            result["detail"] = "agent run timed out"

        caps = sorted(traces.glob("flag_captures_*.json"),
                      key=lambda p: p.stat().st_mtime)
        if caps:
            captured = _load_captured_flags(json.loads(caps[-1].read_text()))
            verdict = grade(flag, captured)
            result["status"] = verdict.status
            result["captures"] = str(caps[-1])
            result["detail"] = verdict.reason
        else:
            result["status"] = "NO_CAPTURES"
            result["detail"] = "run produced no flag_captures file"
    except Exception as e:
        result["detail"] = f"run/grade failed: {e}"
    finally:
        try:
            _sh(["docker", "compose", "down", "-v"], cwd=d, timeout=180, check=False)
        except Exception:
            pass
    return result


def _print_table(results):
    print(f"\n{'BENCHMARK':<24} VERDICT")
    print("-" * 44)
    for r in results:
        mark = {"PASS": "✅", "FAIL": "❌"}.get(r["status"], "—")
        print(f"{r['name']:<24} {mark} {r['status']}")
    print("-" * 44)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="bench_xben",
        description="Run the agent across the XBOW validation-benchmarks and score it.")
    p.add_argument("--bench-root", required=True,
                   help="Path to the XBOW repo's benchmarks/ directory.")
    p.add_argument("--only", nargs="*", help="Only these benchmark names.")
    p.add_argument("--level", type=int, nargs="*", help="Only these levels (1/2/3).")
    p.add_argument("--limit", type=int, help="Cap how many benchmarks to run.")
    p.add_argument("--out", default="results/bench", help="Where per-benchmark artifacts land.")
    p.add_argument("--target-host", default=None,
                   help="Host the agent reaches the challenge on. Default: "
                        "127.0.0.1 for a host-run agent, host.docker.internal "
                        "with --docker-image.")
    p.add_argument("--docker-image", default=None,
                   help="Run each agent pass inside this image "
                        "(e.g. asm-scanner:latest) instead of host run_pentest.py. "
                        "Challenges are still launched by host docker; the agent "
                        "container reaches them via host.docker.internal. "
                        "Set ANTHROPIC_API_KEY in your environment (passed through, "
                        "never inlined).")
    p.add_argument("--up-timeout", type=int, default=600, help="Seconds for build+up.")
    p.add_argument("--run-timeout", type=int, default=1800, help="Seconds per agent run.")
    p.add_argument("--baseline", help="Prior suite summary JSON; exit 1 on regression.")
    p.add_argument("--dry-run", action="store_true",
                   help="List what would run (with computed flags); no docker, no agent.")
    p.add_argument("agent_args", nargs=argparse.REMAINDER,
                   help="Args after `--` are passed to run_pentest.py "
                        "(e.g. -- --no-guardrails --max-risk critical).")
    args = p.parse_args(argv)
    # argparse.REMAINDER keeps a leading "--"; drop it.
    if args.agent_args and args.agent_args[0] == "--":
        args.agent_args = args.agent_args[1:]
    if not args.agent_args:
        args.agent_args = ["--no-guardrails", "--max-risk", "critical"]

    benches = discover_benchmarks(args.bench_root, only=args.only, levels=args.level)
    if args.limit:
        benches = benches[:args.limit]

    if not benches:
        print(f"No flag benchmarks found under {args.bench_root} "
              f"(only/level filters may exclude everything).", file=sys.stderr)
        return 2

    if args.dry_run:
        print(f"{len(benches)} benchmark(s) would run "
              f"(agent args: {' '.join(args.agent_args)}):\n")
        print(f"{'BENCHMARK':<24} {'LVL':<4} EXPECTED FLAG")
        print("-" * 78)
        for b in benches:
            print(f"{b['name']:<24} {str(b['level'] or '-'):<4} {b['expected']}")
        return 0

    Path(args.out).mkdir(parents=True, exist_ok=True)
    results = []
    for i, b in enumerate(benches, 1):
        print(f">> [{i}/{len(benches)}] {b['name']} (level {b['level']})", flush=True)
        started = time.time()
        r = run_one(b, args)
        r["seconds"] = round(time.time() - started, 1)
        print(f"   {r['status']}  ({r['seconds']}s)  {r['detail']}", flush=True)
        results.append(r)

    summary = summarize(results)
    _print_table(results)
    print(f"PASS {summary['passed']}/{summary['graded']} graded "
          f"({summary['pass_rate']:.0f}%)   ungraded/errored: {summary['ungraded']}")

    out_summary = Path(args.out) / "suite.json"
    out_summary.write_text(json.dumps({**summary, "detail": results}, indent=2))
    print(f">> wrote {out_summary}")

    rc = 0 if summary["failed"] == 0 else 2
    if args.baseline and Path(args.baseline).exists():
        base = json.loads(Path(args.baseline).read_text())
        cmp = compare_baseline(summary, base)
        if cmp["regressed"]:
            print(f"\n❌ REGRESSION: {cmp['regressed_count']} benchmark(s) went "
                  f"PASS→not-PASS: {', '.join(cmp['regressed'])}", file=sys.stderr)
            rc = 1
        elif cmp["rate_drop"] > 0:
            print(f"\n⚠️  pass-rate dropped {cmp['rate_drop']:.0f} points vs baseline.")
        else:
            print("\n✅ no regression vs baseline.")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
