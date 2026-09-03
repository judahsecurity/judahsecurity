# Benchmarking the agent against XBOW (`bench_xben.py`)

The question this answers: **is the agent working, and is it getting better?**
You measure that by running it across the [XBOW
validation-benchmarks](https://github.com/xbow-engineering/validation-benchmarks)
and tracking the pass-rate over time.

## The pieces

| Tool | Scope |
|---|---|
| `run_pentest.py --expected-flag` | run the agent against **one** target, record real flag captures |
| `grade_xben.py` | grade **one** run's captures (or a hand-written suite manifest) PASS/FAIL |
| `bench_xben.py` | **the loop**: launch each challenge, run the agent, grade, tear down, report a suite pass-rate |

## Why there's no answer key

XBOW's `common.mk` computes each flag deterministically:

```
FLAG = FLAG{ sha256(UPPERCASE_BENCHMARK_NAME) }
```

`bench_xben.expected_flag()` reproduces that exactly (unit-tested against the
real XBEN-020-24 flag), so the runner knows the expected flag for every
challenge with **zero configuration** — no stored secrets, no manifest to keep
in sync. A benchmark passes only if that flag appears in a **real tool
response** recorded by `agent.flag_oracle`, never in the agent's prose.

## What the runner drives (from `common.mk`, not guessed)

For each `benchmarks/<NAME>/`:

1. `make run` → builds with the computed flag, then `docker compose up --wait`.
2. Reads the published host port from `docker compose ps --format json` (the web
   app maps container 80 → a random host port; internal services only `expose`).
3. Runs `run_pentest.py --target http://<host>:<port>/ --expected-flag <flag>`
   with `AEGIS_TRACES_DIR` per-benchmark.
4. Grades the resulting `flag_captures_*.json`.
5. `docker compose down -v`.

## Usage

```bash
cd aegis-vanguard

# 1. Preview — no docker, no agent, safe anywhere. Confirms discovery + flags.
python3 bench_xben.py --bench-root ../validation-benchmarks/benchmarks --dry-run

# 2. Smoke one benchmark end-to-end (needs docker + LLM key + run_pentest deps).
python3 bench_xben.py --bench-root ../validation-benchmarks/benchmarks \
    --only XBEN-020-24 --out results/bench

# 3. A whole level, capped for a first pass.
python3 bench_xben.py --bench-root ../validation-benchmarks/benchmarks \
    --level 1 --limit 10 --out results/bench

# 4. Commit results/bench/suite.json as a baseline, then gate future runs:
python3 bench_xben.py --bench-root ../validation-benchmarks/benchmarks \
    --out results/bench --baseline bench_baseline.json
```

Anything after `--` is passed to `run_pentest.py`; the default is
`--no-guardrails --max-risk critical` (required for internal/benchmark hosts —
guardrails reject them, the original all-blocked run).

### Running the agent in Docker (no host pip install)

If you'd rather not install the agent's Python deps on your machine, run each
agent pass inside the built image — challenges are still launched by host
docker, and the agent container reaches them via `host.docker.internal`:

```bash
# build the image from the repo ROOT (not from inside aegis-vanguard/):
docker build -f aegis-vanguard/Dockerfile -t asm-scanner:latest .

export ANTHROPIC_API_KEY=sk-ant-...        # passed through, never inlined
python3 bench_xben.py --bench-root ~/validation-benchmarks/benchmarks \
    --only XBEN-020-24 --out results/bench --docker-image asm-scanner:latest
```

`--docker-image` bind-mounts the per-benchmark traces dir to `/agent/results`
and passes `ANTHROPIC_API_KEY` through by name. `--target-host` defaults to
`host.docker.internal` in this mode (127.0.0.1 for a host-run agent).

## Output

`results/bench/suite.json`:

```json
{
  "passed": 7, "failed": 2, "ungraded": 1, "graded": 9, "pass_rate": 77.8,
  "results": {"XBEN-001-24": "PASS", "XBEN-004-24": "FAIL", ...},
  "detail": [ {"name": "...", "status": "...", "captures": "...", "seconds": 214.3}, ... ]
}
```

Exit codes: `0` all graded benchmarks passed, `2` at least one FAIL, `1`
regression vs `--baseline` (a benchmark went PASS→not-PASS).

## The iterate loop

1. `bench_xben.py … --out results/bench` → commit `suite.json` as the baseline.
2. Change a hunter / prompt / tool.
3. Re-run with `--baseline <that suite.json>`. Exit 1 = you regressed a
   benchmark that used to pass. A rising `pass_rate` with no regressions = the
   agent got better, measured.

Wire step 3 into CI (same shape as `scorecard.py --baseline`) and a change that
drops the pass-rate fails the build.

## Testable core vs live driver

Flag computation, discovery/filtering, `compose ps` port parsing, suite summary,
and regression detection are pure functions and unit-tested
(`tests/test_bench_xben.py`). The driver (`make` / `docker compose` /
`run_pentest.py`) needs docker and an LLM key and is exercised by real runs.
