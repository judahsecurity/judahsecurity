#!/bin/sh
# Install the sandbox egress firewall, then start the runner API.
#
# Sandbox commands run as uids 20000-29999. Those uids may open TCP
# connections only to the egress proxy; everything else (other containers,
# the runner API on loopback, DNS, IPv6) is rejected. The runner refuses to
# start unless this chain is installed, so a failure here fails closed.
set -eu

UID_RANGE="20000-29999"
EGRESS="${SANDBOX_EGRESS_PROXY:-prowl-sandbox-egress:8080}"
EGRESS_HOST="${EGRESS%:*}"
EGRESS_PORT="${EGRESS##*:}"

EGRESS_IPS=""
for _ in $(seq 1 30); do
  EGRESS_IPS="$(getent ahostsv4 "$EGRESS_HOST" | awk '{print $1}' | sort -u)"
  [ -n "$EGRESS_IPS" ] && break
  sleep 1
done
if [ -z "$EGRESS_IPS" ]; then
  echo "prowl-sandbox: cannot resolve egress proxy $EGRESS_HOST" >&2
  exit 1
fi

iptables -N PROWL_SANDBOX 2>/dev/null || iptables -F PROWL_SANDBOX
for ip in $EGRESS_IPS; do
  iptables -A PROWL_SANDBOX -p tcp -d "$ip" --dport "$EGRESS_PORT" -j ACCEPT
done
iptables -A PROWL_SANDBOX -j REJECT
iptables -C OUTPUT -m owner --uid-owner "$UID_RANGE" -j PROWL_SANDBOX 2>/dev/null \
  || iptables -I OUTPUT 1 -m owner --uid-owner "$UID_RANGE" -j PROWL_SANDBOX

if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -C OUTPUT -m owner --uid-owner "$UID_RANGE" -j REJECT 2>/dev/null \
    || ip6tables -I OUTPUT 1 -m owner --uid-owner "$UID_RANGE" -j REJECT \
    || { echo "prowl-sandbox: ip6tables rule failed" >&2; exit 1; }
fi

# The egress CA certificate is published by the proxy container.
CA="${SANDBOX_CA_BUNDLE:-/etc/prowl-sandbox/egress-ca.pem}"
for _ in $(seq 1 60); do
  [ -s "$CA" ] && break
  sleep 1
done
if [ ! -s "$CA" ]; then
  echo "prowl-sandbox: egress CA certificate not found at $CA" >&2
  exit 1
fi

# Sandbox uids have no DNS, so commands get the proxy by address. Pin the
# first resolved address, the one the firewall rule above allows.
SANDBOX_EGRESS_ADDR="$(echo "$EGRESS_IPS" | head -n 1):$EGRESS_PORT"
export SANDBOX_EGRESS_ADDR

exec python3 /opt/prowl-sandbox/server.py
