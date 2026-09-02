#!/usr/bin/env bash
# One-command assessment: preflight -> pentest -> scorecard.
#
#   ./assess.sh https://app.example.com --scope example.com --login-user tester --login-pass "$PW"
#   ./assess.sh http://host.docker.internal:56348/ --no-guardrails --max-risk critical --expected-flag "$FLAG"
#
# Everything after the target URL is passed straight through to run_pentest.py.
# Set ANTHROPIC_API_KEY in your environment first (never inline it on the command line).
set -euo pipefail

TARGET="${1:-}"
if [ -z "$TARGET" ] || [ "$TARGET" = "-h" ] || [ "$TARGET" = "--help" ]; then
  echo "usage: ./assess.sh <target-url> [extra run_pentest.py args...]"
  echo "  target is required; extra args (--scope, --login-user/-pass, --expected-flag,"
  echo "  --no-guardrails, --max-risk, ...) pass through to run_pentest.py."
  exit 2
fi
shift

cd "$(dirname "$0")"
OUT="${AEGIS_TRACES_DIR:-./results/$(date +%Y%m%d-%H%M%S)}"
export AEGIS_TRACES_DIR="$OUT"
mkdir -p "$OUT"

echo ">> [1/3] preflight (doctor.py)"
if ! python3 doctor.py; then
  echo ">> doctor is NOT READY — fix the required blockers above, then re-run." >&2
  exit 1
fi

echo ">> [2/3] pentest -> $OUT"
python3 run_pentest.py --target "$TARGET" "$@"

echo ">> [3/3] scorecard"
python3 scorecard.py --runs "$OUT" --out "$OUT/scorecard.json" || true

echo ">> done. artifacts in $OUT:"
ls -1 "$OUT" 2>/dev/null || true
echo ">> commit $OUT/scorecard.json as your baseline; on later runs add --baseline to catch regressions."
