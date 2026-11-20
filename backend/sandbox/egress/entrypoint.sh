#!/bin/sh
# Start the recording egress proxy and publish only its CA certificate.
set -eu
CONF=/home/mitmproxy/.mitmproxy
PUBLIC=/ca-public/egress-ca.pem

mitmdump \
  --listen-host 0.0.0.0 --listen-port 8080 \
  --set confdir="$CONF" \
  --set connection_strategy=lazy \
  --set block_global=false \
  --set http2=true \
  --set stream_large_bodies=8m \
  -s /opt/prowl-egress/addon.py &
PID=$!

for _ in $(seq 1 60); do
  [ -s "$CONF/mitmproxy-ca-cert.pem" ] && break
  sleep 1
done
# The private key stays in $CONF; the runner only ever sees the certificate.
cp "$CONF/mitmproxy-ca-cert.pem" "$PUBLIC.tmp" && mv "$PUBLIC.tmp" "$PUBLIC"
wait "$PID"
