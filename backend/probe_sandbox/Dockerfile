# probe-egress (relay + recording scope proxy) and probe-runner (script and
# shell executor). Build context: backend/. Neither image gets backend code,
# secrets or volumes.
FROM python:3.11-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY probe_sandbox/egress.py probe_sandbox/runner.py /app/

# --- probe-egress: holds the interception CA key; no tools ---------------
FROM base AS egress
RUN pip install --no-cache-dir cryptography==41.0.7 \
    && useradd --system --no-create-home --uid 10001 egress
CMD ["python", "-I", "/app/egress.py"]

# --- probe-runner: the toolbox model-written commands run in --------------
FROM base AS runner
RUN apt-get update \
    && apt-get install -y --no-install-recommends bash curl wget jq ca-certificates \
       nmap proxychains4 netcat-openbsd \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir httpx==0.25.2 requests==2.31.0 pyjwt==2.8.0 sqlmap==1.9.12
ARG FFUF_VERSION=2.1.0
RUN ARCH=$(dpkg --print-architecture) \
    && case "$ARCH" in arm64) FFUF_ARCH=arm64 ;; *) FFUF_ARCH=amd64 ;; esac \
    && curl -fsSL -o /tmp/ffuf.tgz \
       "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${FFUF_ARCH}.tar.gz" \
    && tar -xzf /tmp/ffuf.tgz -C /usr/local/bin ffuf \
    && rm -f /tmp/ffuf.tgz
COPY wordlists/ /opt/wordlists/
CMD ["python", "-I", "/app/runner.py"]
