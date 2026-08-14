#!/usr/bin/env bash
# Convenience launcher for Mac / Ubuntu Interceptor workers.
# Usage: ./scripts/run_interceptor_worker.sh mac
#        ./scripts/run_interceptor_worker.sh ubuntu ubuntu-ec2-1
set -euo pipefail
KIND="${1:-}"
WORKER_ID="${2:-}"
if [[ -z "$KIND" || ( "$KIND" != "mac" && "$KIND" != "ubuntu" ) ]]; then
  echo "usage: $0 mac|ubuntu [worker-id]" >&2
  exit 2
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PYTHONPATH="${PYTHONPATH:-$ROOT/backend}"
cd "$ROOT/backend"
ARGS=(--kind "$KIND")
if [[ -n "$WORKER_ID" ]]; then
  ARGS+=(--worker-id "$WORKER_ID")
fi
exec python -m app.services.interceptor_worker "${ARGS[@]}"
