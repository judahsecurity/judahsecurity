#!/bin/bash
# Start the private Caido instance or activate it for the Interceptor browser.
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/asm}"
MODE="${1:-start}"
CAIDO_PROXY_SERVER="${CAIDO_PROXY_SERVER:-http://127.0.0.1:8082}"
CAIDO_CA_CERT="${CAIDO_CA_CERT:-/etc/asm/caido-ca.crt}"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this script as root." >&2
  exit 1
fi
if [ ! -f "$APP_DIR/docker-compose.yml" ]; then
  echo "ASM checkout not found at $APP_DIR" >&2
  exit 1
fi

cd "$APP_DIR"
docker compose --profile caido up -d caido

if [ "$MODE" = "start" ]; then
  echo "Caido is listening privately on UI port 8081 and proxy port 8082."
  echo "Register it through an SSH tunnel, then rerun this script with: activate"
  exit 0
fi
if [ "$MODE" != "activate" ]; then
  echo "Usage: $0 [start|activate]" >&2
  exit 2
fi

install -d -m 0755 "$(dirname "$CAIDO_CA_CERT")"
for attempt in $(seq 1 30); do
  if curl -fsS "$CAIDO_PROXY_SERVER/ca.crt" -o "$CAIDO_CA_CERT"; then
    break
  fi
  if [ "$attempt" -eq 30 ]; then
    echo "Caido did not serve its CA certificate. Finish instance registration first." >&2
    exit 1
  fi
  sleep 2
done
chmod 0644 "$CAIDO_CA_CERT"

APP_DIR="$APP_DIR" \
INTERCEPTOR_PROXY_SERVER="$CAIDO_PROXY_SERVER" \
INTERCEPTOR_PROXY_CA_CERT="$CAIDO_CA_CERT" \
RUN_E2E_SMOKE=1 \
  "$APP_DIR/scripts/install-interceptor-host.sh"

echo "Interceptor is now browsing through Caido."
