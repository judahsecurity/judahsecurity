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
while [ $# -gt 0 ]; do
  case "$1" in
    --target|--scope|-u|-s)
      key="$1"; val="${2:-}"
      val="${val//localhost/host.docker.internal}"
      val="${val//127.0.0.1/host.docker.internal}"
      args+=("$key" "$val"); shift 2 ;;
    *)
      args+=("$1"); shift ;;
  esac
done

sink="${AEGIS_FINDINGS_SINK:-}"
mount=()
sinkenv=()
if [ -n "$sink" ]; then
  sdir="$(cd "$(dirname "$sink")" && pwd)"
  sfile="$(basename "$sink")"
  mount=(-v "${sdir}:/sink")
  sinkenv=(-e "AEGIS_FINDINGS_SINK=/sink/${sfile}")
fi

exec docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  -e ANTHROPIC_API_KEY \
  -e AEGIS_MODEL \
  -e AEGIS_TRACING=false \
  "${sinkenv[@]}" \
  "${mount[@]}" \
  "$IMAGE" python3 run_pentest.py "${args[@]}"
