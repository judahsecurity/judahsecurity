#!/usr/bin/env bash
#
# xben_smoke.sh — turnkey, cost-bounded XBEN smoke run for Aegis Vanguard.
#
# Runs the real scanner (full Docker toolchain) against the 3 flag-verified
# Level-1 XBEN challenges in ground_truth/XBEN_SMOKE.json (SQLi / SSRF / IDOR)
# and scores flag capture. This is the cheap "does the whole live pipeline
# work end-to-end" check to run BEFORE committing to all 104 challenges.
#
# It is a thin, opinionated wrapper over:
#     python -m local_harness.benchmark.run --setup --ground-truth XBEN_SMOKE.json
# with the Docker scanner launcher, a per-challenge price cap, and preflight
# checks so a missing prerequisite fails loudly instead of scoring a false 0%.
#
# Authorization: XBEN challenges run locally in Docker on localhost — you are
# testing your own containers. Do not point this at anything else.
#
# Usage:
#     export ANTHROPIC_API_KEY=sk-ant-...
#     git clone https://github.com/xbow-engineering/validation-benchmarks /tmp/xben
#     bash scripts/xben_smoke.sh
#
# Config (all optional, shown with defaults):
#     XBEN_CORPUS=/tmp/xben              # local clone of validation-benchmarks
#     ASM_SCANNER_IMAGE=asm-scanner      # the built aegis-vanguard image
#     PRICE_LIMIT=3.00                   # USD cap per challenge (--price-limit)
#     MIN_SUCCESS_RATE=0.66              # gate: 2 of 3 must solve (exit 2 if below)
#     SCAN_TIMEOUT=1800                  # seconds per challenge
#     SCANNER_ARGS="--fast --max-risk medium"   # cost/scope preset
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS_ROOT="$(cd "$HERE/.." && pwd)"
GT_SRC="$HARNESS_ROOT/local_harness/benchmark/ground_truth/XBEN_SMOKE.json"

XBEN_CORPUS="${XBEN_CORPUS:-/tmp/xben}"
ASM_SCANNER_IMAGE="${ASM_SCANNER_IMAGE:-asm-scanner}"
PRICE_LIMIT="${PRICE_LIMIT:-3.00}"
MIN_SUCCESS_RATE="${MIN_SUCCESS_RATE:-0.66}"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-1800}"
SCANNER_ARGS="${SCANNER_ARGS:---fast --max-risk medium}"

# The 3 challenges in the smoke corpus. Kept in sync with XBEN_SMOKE.json.
SMOKE_CHALLENGES="XBEN-071-24 XBEN-020-24 XBEN-021-24"

fail() { printf '\n[xben-smoke] ERROR: %s\n' "$1" >&2; exit 1; }
note() { printf '[xben-smoke] %s\n' "$1"; }

# --- Preflight -------------------------------------------------------------
note "preflight…"
command -v docker >/dev/null 2>&1 || fail "docker not found on PATH."
command -v python3 >/dev/null 2>&1 || fail "python3 not found on PATH."
[ -n "${ANTHROPIC_API_KEY:-}" ] || fail "ANTHROPIC_API_KEY is not set (the scanner needs it)."
docker image inspect "$ASM_SCANNER_IMAGE" >/dev/null 2>&1 \
  || fail "scanner image '$ASM_SCANNER_IMAGE' not found. Build it (see aegis-vanguard/Dockerfile) or set ASM_SCANNER_IMAGE."
[ -f "$GT_SRC" ] || fail "smoke ground truth missing: $GT_SRC"

if [ ! -d "$XBEN_CORPUS/benchmarks" ]; then
  fail "XBEN corpus not found at '$XBEN_CORPUS' (expected a benchmarks/ dir).
       Clone it first:
         git clone https://github.com/xbow-engineering/validation-benchmarks $XBEN_CORPUS
       or set XBEN_CORPUS to your clone."
fi
for c in $SMOKE_CHALLENGES; do
  [ -d "$XBEN_CORPUS/benchmarks/$c" ] \
    || fail "challenge dir missing: $XBEN_CORPUS/benchmarks/$c (is the corpus fully cloned?)"
done

# --- Portable ground truth -------------------------------------------------
# XBEN_SMOKE.json bakes an absolute corpus path (/tmp/xben). If the operator's
# clone lives elsewhere, rewrite the setup paths into a host-local copy so
# `make -C <dir> run` points at the real challenge. Never edits the committed file.
WORK="$HARNESS_ROOT/runs/xben_smoke"
mkdir -p "$WORK"
GT_HOST="$WORK/XBEN_SMOKE.host.json"
if [ "$XBEN_CORPUS" = "/tmp/xben" ]; then
  cp "$GT_SRC" "$GT_HOST"
else
  note "rewriting corpus path /tmp/xben → $XBEN_CORPUS in a host-local ground truth"
  python3 - "$GT_SRC" "$GT_HOST" "$XBEN_CORPUS" <<'PY'
import json, sys
src, dst, corpus = sys.argv[1], sys.argv[2], sys.argv[3].rstrip("/")
data = json.load(open(src))
def fix(v):
    return v.replace("/tmp/xben", corpus) if isinstance(v, str) else v
for k, spec in data.items():
    if k.startswith("_") or not isinstance(spec, dict):
        continue
    setup = spec.get("setup", {})
    for key in ("up", "down", "compose_file"):
        if key in setup:
            setup[key] = fix(setup[key])
json.dump(data, open(dst, "w"), indent=2)
PY
fi

# --- Run -------------------------------------------------------------------
REPOS="$(echo "$SMOKE_CHALLENGES" | tr ' ' ',')"
export AEGIS_HARNESS_SCANNER_CMD="bash $HERE/xben_scanner_docker.sh"
export AEGIS_HARNESS_SCANNER_CWD="$HARNESS_ROOT"
export AEGIS_HARNESS_SCANNER_ARGS="$SCANNER_ARGS --price-limit $PRICE_LIMIT"
export AEGIS_HARNESS_SCAN_TIMEOUT="$SCAN_TIMEOUT"
export AEGIS_HARNESS_WORK_DIR="${AEGIS_HARNESS_WORK_DIR:-$HARNESS_ROOT/runs}"
export ASM_SCANNER_IMAGE

note "scanning 3 challenges via image '$ASM_SCANNER_IMAGE' (price cap \$$PRICE_LIMIT each, timeout ${SCAN_TIMEOUT}s)…"
note "flags: XBEN_SMOKE.json values are the sha256 build flags (common.mk --build-arg; .env is a decoy)."

set -x
python3 -m local_harness.benchmark.run \
  --ground-truth "$GT_HOST" \
  --repos "$REPOS" \
  --setup \
  --min-success-rate "$MIN_SUCCESS_RATE" \
  --fail-on-scan-error
rc=$?
set +x

# --- Report ----------------------------------------------------------------
REPORT="$AEGIS_HARNESS_WORK_DIR/benchmark/benchmark_report.json"
echo
if [ "$rc" -eq 0 ]; then
  note "SMOKE PASSED (success rate ≥ $MIN_SUCCESS_RATE)."
elif [ "$rc" -eq 2 ]; then
  note "SMOKE BELOW GATE (success rate < $MIN_SUCCESS_RATE)."
  note "If a challenge captured the flag but still scored unsolved, suspect the flag scheme"
  note "(exact-match judge). Re-check ground_truth against the built image before trusting it."
else
  note "SMOKE ERRORED (rc=$rc) — a challenge failed to set up or scan. See the log above."
fi
[ -f "$REPORT" ] && note "report: $REPORT"
echo
note "Next, the full 104 (Strix reports 96% here). Three steps:"
note "  1) RE-IMPORT on this host (committed XBEN.json has macOS-only paths):"
note "        python3 -m local_harness.benchmark.xben_import \\"
note "            --corpus $XBEN_CORPUS --out local_harness/benchmark/ground_truth/XBEN.json"
note "  2) VERIFY the flag scheme (one command, auto up/down) so scoring is truthful:"
note "        python3 -m local_harness.benchmark.verify_flags \\"
note "            --ground-truth local_harness/benchmark/ground_truth/XBEN.json \\"
note "            --repos XBEN-001-24 --live --setup --fix \\"
note "            --out local_harness/benchmark/ground_truth/XBEN.json"
note "  3) RUN the corpus:"
note "        python3 -m local_harness.benchmark.run \\"
note "            --ground-truth local_harness/benchmark/ground_truth/XBEN.json \\"
note "            --setup --min-success-rate 0.8 --max-cost-per-tp 2.0"
exit "$rc"
