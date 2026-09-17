#!/usr/bin/env bash
#
# Scanner launcher for XBEN benchmarking: runs the Aegis Vanguard scanner
# inside its Docker image (full toolchain) against a dockerized challenge.
#
# The harness invokes this as the scanner command:
#     bash xben_scanner_docker.sh --target <url> [--scope <s>] <extra args...>
# with AEGIS_FINDINGS_SINK pointed at a host findings.jsonl path.
#
# Networking: XBEN challenges publish their app on a host port. From inside the
# scanner container, the host is reachable via host.docker.internal, so we
# rewrite localhost/127.0.0.1 in --target and --scope accordingly (the scanner
# enforces scope, so scope must match the rewritten host).
#
set -uo pipefail

IMAGE="${ASM_SCANNER_IMAGE:-asm-scanner}"

args=()
benchmark_proof_seen=0
while [ $# -gt 0 ]; do
  case "$1" in
    --target|--scope|-u|-s)
      key="$1"; val="${2:-}"
      val="${val//localhost/host.docker.internal}"
      val="${val//127.0.0.1/host.docker.internal}"
      args+=("$key" "$val"); shift 2 ;;
    --benchmark-proof)
      benchmark_proof_seen=1
      args+=("$1"); shift ;;
    *)
      args+=("$1"); shift ;;
  esac
done

# This launcher is exclusively for the authorized local XBEN corpus. Enable
# synthetic proof capture without exposing any expected flag to the scanner.
if [ "$benchmark_proof_seen" -eq 0 ]; then
  args+=(--benchmark-proof)
fi

sink="${AEGIS_FINDINGS_SINK:-}"
mount=()
sinkenv=()
if [ -n "$sink" ]; then
  sdir="$(cd "$(dirname "$sink")" && pwd)"
  sfile="$(basename "$sink")"
  mount=(-v "${sdir}:/sink")
  sinkenv=(
    -e "AEGIS_FINDINGS_SINK=/sink/${sfile}"
    -e "AEGIS_TRACES_DIR=/sink"
  )
fi

# Only pass -e VAR when the host has a value. Bare `-e VAR` would otherwise
# override --env-file with an empty string.
passthrough=(-e AEGIS_TRACING=true)
for v in ANTHROPIC_API_KEY OPENAI_API_KEY AEGIS_MODEL AEGIS_LLM_BACKEND; do
  if [ -n "${!v:-}" ]; then
    passthrough+=(-e "$v")
  fi
done

docker_args=(run --rm --add-host=host.docker.internal:host-gateway)
if [ -n "${AEGIS_ENV_FILE:-}" ] && [ -f "$AEGIS_ENV_FILE" ]; then
  docker_args+=(--env-file "$AEGIS_ENV_FILE")
fi
docker_args+=("${passthrough[@]}")
if [ -n "$sink" ]; then
  docker_args+=("${sinkenv[@]}" "${mount[@]}")
fi
docker_args+=("$IMAGE" python3 run_pentest.py "${args[@]}")

exec docker "${docker_args[@]}"
