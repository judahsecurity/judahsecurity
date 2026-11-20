# Explorer sandbox runner: a shell and Python for Prowl's explorer specialist.
# Build context: backend/sandbox
#
# The image holds no platform credentials. Network reach is limited to the
# egress proxy by the entrypoint firewall (needs CAP_NET_ADMIN).
ARG BASE_IMAGE=python:3.11-slim-bookworm
FROM ${BASE_IMAGE}

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      iptables procps ca-certificates curl wget jq git netcat-openbsd \
      openssl xxd unzip \
 && rm -rf /var/lib/apt/lists/*

# Sandbox Python: common HTTP, parsing and exploit-scripting libraries.
RUN python3 -m venv /opt/sandbox-venv \
 && /opt/sandbox-venv/bin/pip install --no-cache-dir \
      requests==2.32.3 "httpx[http2]==0.27.2" beautifulsoup4==4.12.3 lxml==5.3.0 \
      pyjwt==2.9.0 cryptography==43.0.1 sqlmap==1.8.11 websocket-client==1.8.0 \
      pyyaml==6.0.2

COPY runner/server.py runner/entrypoint.sh /opt/prowl-sandbox/
RUN chmod 0555 /opt/prowl-sandbox/entrypoint.sh \
 && mkdir -p /work /etc/prowl-sandbox && chmod 0711 /work

ENV SANDBOX_PYTHON=/opt/sandbox-venv/bin/python
EXPOSE 8090
ENTRYPOINT ["/opt/prowl-sandbox/entrypoint.sh"]
