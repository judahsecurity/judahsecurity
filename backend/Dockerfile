# syntax=docker/dockerfile:1.4
# Judah Security ASM - Backend Dockerfile (Optimized)
# Uses pre-built binaries instead of compiling for faster builds

FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# ============================================
# Stage 1: Download pre-built binaries (FAST)
# ============================================
FROM base AS tool-downloader

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget unzip git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tools

# Detect architecture and download appropriate binaries
ARG TARGETARCH=amd64

# ProjectDiscovery tools - download pre-built binaries (much faster than compiling)
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then PD_ARCH="arm64"; else PD_ARCH="amd64"; fi && \
    # Each tool is downloaded independently so a single failure doesn't abort the build
    (wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_${PD_ARCH}.zip" && \
     unzip -o -q "nuclei_3.3.7_linux_${PD_ARCH}.zip" -d /tools && \
     rm -f "nuclei_3.3.7_linux_${PD_ARCH}.zip") || echo "nuclei download skipped" && \
    (wget -q "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_linux_${PD_ARCH}.zip" && \
     unzip -o -q "subfinder_2.6.7_linux_${PD_ARCH}.zip" -d /tools && \
     rm -f "subfinder_2.6.7_linux_${PD_ARCH}.zip") || echo "subfinder download skipped" && \
    (wget -q "https://github.com/projectdiscovery/httpx/releases/download/v1.6.10/httpx_1.6.10_linux_${PD_ARCH}.zip" && \
     unzip -o -q "httpx_1.6.10_linux_${PD_ARCH}.zip" -d /tools && \
     rm -f "httpx_1.6.10_linux_${PD_ARCH}.zip") || echo "httpx download skipped" && \
    (wget -q "https://github.com/projectdiscovery/dnsx/releases/download/v1.2.1/dnsx_1.2.1_linux_${PD_ARCH}.zip" && \
     unzip -o -q "dnsx_1.2.1_linux_${PD_ARCH}.zip" -d /tools && \
     rm -f "dnsx_1.2.1_linux_${PD_ARCH}.zip") || echo "dnsx download skipped" && \
    (wget -q "https://github.com/projectdiscovery/naabu/releases/download/v2.3.3/naabu_2.3.3_linux_${PD_ARCH}.zip" && \
     unzip -o -q "naabu_2.3.3_linux_${PD_ARCH}.zip" -d /tools && \
     rm -f "naabu_2.3.3_linux_${PD_ARCH}.zip") || echo "naabu download skipped" && \
    (wget -q "https://github.com/projectdiscovery/katana/releases/download/v1.1.0/katana_1.1.0_linux_${PD_ARCH}.zip" && \
     unzip -o -q "katana_1.1.0_linux_${PD_ARCH}.zip" -d /tools && \
     rm -f "katana_1.1.0_linux_${PD_ARCH}.zip") || echo "katana download skipped" && \
    (wget -q "https://github.com/projectdiscovery/chaos-client/releases/download/v0.5.2/chaos-client_0.5.2_linux_${PD_ARCH}.zip" && \
     unzip -o -q "chaos-client_0.5.2_linux_${PD_ARCH}.zip" -d /tools && \
     rm -f "chaos-client_0.5.2_linux_${PD_ARCH}.zip") || echo "chaos download skipped" && \
    (wget -q "https://github.com/projectdiscovery/tlsx/releases/download/v1.1.7/tlsx_1.1.7_linux_${PD_ARCH}.zip" && \
     unzip -o -q "tlsx_1.1.7_linux_${PD_ARCH}.zip" -d /tools && \
     rm -f "tlsx_1.1.7_linux_${PD_ARCH}.zip") || echo "tlsx download skipped" && \
    (wget -q "https://github.com/projectdiscovery/vulnx/releases/download/v2.0.1/vulnx_2.0.1_linux_${PD_ARCH}.zip" && \
     unzip -o -q "vulnx_2.0.1_linux_${PD_ARCH}.zip" -d /tools && \
     rm -f "vulnx_2.0.1_linux_${PD_ARCH}.zip") || echo "vulnx download skipped"

# Other Go tools (pre-built releases)
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then ARCH_SUFFIX="arm64"; else ARCH_SUFFIX="amd64"; fi && \
    # ffuf
    wget -q "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_${ARCH_SUFFIX}.tar.gz" && \
    tar -xzf "ffuf_2.1.0_linux_${ARCH_SUFFIX}.tar.gz" -C /tools && \
    rm "ffuf_2.1.0_linux_${ARCH_SUFFIX}.tar.gz" && \
    # Amass
    wget -q "https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_${ARCH_SUFFIX}.zip" && \
    unzip -o -q "amass_Linux_${ARCH_SUFFIX}.zip" -d /tmp/amass && \
    cp /tmp/amass/amass_Linux_${ARCH_SUFFIX}/amass /tools/ && \
    rm -rf /tmp/amass "amass_Linux_${ARCH_SUFFIX}.zip"

# Build masscan and massdns from source (no pre-built releases)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/robertdavidgraham/masscan.git /tmp/masscan \
    && cd /tmp/masscan && make -j$(nproc) \
    && cp bin/masscan /tools/ \
    && rm -rf /tmp/masscan

RUN git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns \
    && cd /tmp/massdns && make -j$(nproc) \
    && cp bin/massdns /tools/ \
    && rm -rf /tmp/massdns

# Download waybackurls, assetfinder, and GAU (smaller Go tools)
RUN apt-get update && apt-get install -y --no-install-recommends golang \
    && rm -rf /var/lib/apt/lists/* \
    && go install github.com/tomnomnom/waybackurls@latest \
    && go install github.com/tomnomnom/assetfinder@latest \
    && go install github.com/lc/gau/v2/cmd/gau@latest \
    && (go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest || echo "interactsh-client build skipped") \
    && (GOTOOLCHAIN=go1.25.1 go install -v github.com/melvinsh/subfaster/v2/cmd/subfaster@latest || echo "subfaster build skipped") \
    && (go install github.com/hahwul/dalfox/v2@latest || echo "dalfox build skipped") \
    && cp /root/go/bin/* /tools/

# Feroxbuster (Rust — download release binary)
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then FX_ARCH="aarch64"; else FX_ARCH="x86_64"; fi && \
    (wget -q "https://github.com/epi052/feroxbuster/releases/download/v2.11.0/${FX_ARCH}-linux-feroxbuster.zip" -O /tmp/ferox.zip && \
     unzip -o -q /tmp/ferox.zip -d /tmp/ferox && \
     find /tmp/ferox -type f -name feroxbuster -exec cp {} /tools/ \; && \
     rm -rf /tmp/ferox /tmp/ferox.zip) || echo "feroxbuster download skipped"

# Download Gitleaks (secret scanner - Go binary)
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then GL_ARCH="arm64"; else GL_ARCH="x64"; fi && \
    wget -q "https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_${GL_ARCH}.tar.gz" -O gitleaks.tar.gz && \
    tar -xzf gitleaks.tar.gz -C /tools && \
    rm gitleaks.tar.gz || echo "Gitleaks download skipped"

# Download Kiterunner (API endpoint brute-forcer)
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then KR_ARCH="arm64"; else KR_ARCH="amd64"; fi && \
    wget -q "https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_${KR_ARCH}.tar.gz" -O kiterunner.tar.gz && \
    tar -xzf kiterunner.tar.gz -C /tools && \
    rm kiterunner.tar.gz || echo "Kiterunner download skipped (release may not exist for ${KR_ARCH})"

RUN chmod +x /tools/*

# ============================================
# Stage 2: Final image with all dependencies
# ============================================
FROM base AS final

# Install system dependencies
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    curl \
    dnsutils \
    nmap \
    libpcap0.8 \
    chromium \
    chromium-driver \
    xvfb \
    libnss3 \
    libxss1 \
    libasound2t64 \
    fonts-liberation \
    xdg-utils \
    python3-venv \
    libgbm1 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    git \
    jq \
    openssl \
    openssh-client \
    hydra

# Copy pre-built binaries
# Copy tools that were successfully downloaded (skips missing files gracefully)
COPY --from=tool-downloader /tools/ /tmp/downloaded-tools/
RUN mkdir -p /opt/projectdiscovery && \
    for tool in nuclei subfinder subfaster httpx dnsx naabu katana tlsx ffuf amass masscan massdns waybackurls assetfinder gau gitleaks vulnx interactsh-client dalfox feroxbuster; do \
        [ -f "/tmp/downloaded-tools/${tool}" ] && cp "/tmp/downloaded-tools/${tool}" /usr/local/bin/ && echo "installed ${tool}" || echo "skipped ${tool}"; \
    done && \
    # Keep a durable copy of ProjectDiscovery httpx — pip's httpx package later
    # installs a Python CLI that would otherwise overwrite /usr/local/bin/httpx.
    [ -f /usr/local/bin/httpx ] && cp /usr/local/bin/httpx /opt/projectdiscovery/httpx && \
        cp /usr/local/bin/httpx /usr/local/bin/pd-httpx && chmod +x /opt/projectdiscovery/httpx /usr/local/bin/pd-httpx || true && \
    [ -f "/tmp/downloaded-tools/chaos-client" ] && cp /tmp/downloaded-tools/chaos-client /usr/local/bin/chaos || true && \
    [ -f "/tmp/downloaded-tools/kr" ] && cp /tmp/downloaded-tools/kr /usr/local/bin/kiterunner || true && \
    rm -rf /tmp/downloaded-tools && \
    chmod +x /usr/local/bin/* 2>/dev/null || true

# Install EyeWitness
RUN git clone --depth 1 https://github.com/RedSiege/EyeWitness.git /opt/EyeWitness \
    && cd /opt/EyeWitness \
    && python3 -m venv eyewitness-venv \
    && ./eyewitness-venv/bin/pip install --upgrade pip \
    && ./eyewitness-venv/bin/pip install selenium netaddr rapidfuzz psutil \
    && chmod +x Python/EyeWitness.py

ENV EYEWITNESS_PATH="/opt/EyeWitness/Python/EyeWitness.py"
ENV EYEWITNESS_VENV="/opt/EyeWitness/eyewitness-venv/bin/python"
ENV SCREENSHOTS_DIR="/app/data/screenshots"

# Install Python dependencies (install BEFORE copying code for better caching).
# We must also copy the local `packages/` tree here because requirements.txt
# contains editable installs (`-e packages/asm_scanner_core`, etc.) that pip
# needs to resolve at install time.
COPY requirements.txt .
COPY packages/ ./packages/
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -r requirements.txt

# Restore ProjectDiscovery httpx after pip (Python httpx CLI would shadow it).
RUN if [ -x /opt/projectdiscovery/httpx ]; then \
      cp /opt/projectdiscovery/httpx /usr/local/bin/httpx && \
      cp /opt/projectdiscovery/httpx /usr/local/bin/pd-httpx && \
      chmod +x /usr/local/bin/httpx /usr/local/bin/pd-httpx && \
      echo "restored ProjectDiscovery httpx"; \
    fi
ENV PD_HTTPX_BIN=/opt/projectdiscovery/httpx
# Keep the managed browser inside /app so the later `chown -R appuser /app`
# leaves it readable to the non-root runtime user.
ENV PLAYWRIGHT_BROWSERS_PATH=/app/.playwright-browsers
# Guaranteed system Chromium (from the apt install above). deep_crawl falls back
# to CHROME_BIN if the Playwright-managed browser is ever missing at runtime.
ENV CHROME_BIN=/usr/bin/chromium
# Best-effort managed install; the apt chromium + CHROME_BIN fallback guarantees
# a working browser even if this download is flaky in a cloud build.
RUN playwright install --with-deps chromium \
    || playwright install chromium \
    || echo "WARNING: playwright browser install failed; deep_crawl will use CHROME_BIN=$CHROME_BIN"
# Fail the build if NEITHER browser is present (so cloud images never ship without one).
RUN test -x "$CHROME_BIN" || ls "$PLAYWRIGHT_BROWSERS_PATH"/chromium* >/dev/null 2>&1 \
    || (echo "FATAL: no Chromium (managed or system) in image" && exit 1)

# Install ParamSpider
RUN pip install paramspider || echo "ParamSpider installation skipped"

# Install Knockpy (subdomain brute-forcer)
RUN pip install knockpy || echo "Knockpy installation skipped"

# Install Schemathesis (API fuzzer for OpenAPI/GraphQL schemas)
RUN pip install schemathesis || echo "Schemathesis installation skipped"

# Install SQLMap (SQL injection automation)
RUN pip install sqlmap || echo "SQLMap installation skipped"

# Install wafw00f (WAF detection)
RUN pip install wafw00f || echo "wafw00f installation skipped"

# Install Arjun (HTTP parameter discovery)
RUN pip install arjun || echo "Arjun installation skipped"

# Install SSLyze (TLS/SSL scanner - Python)
RUN pip install sslyze || echo "SSLyze installation skipped"

# Install XSStrike (XSS scanner)
RUN pip install XSStrike || echo "XSStrike installation skipped"

# Install CMSeeK (CMS detection)
RUN pip install cmseek || echo "CMSeeK installation skipped"

# Retire.js (vulnerable JavaScript library detection) — needs Node.js
RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm \
    && npm install -g retire \
    && rm -rf /var/lib/apt/lists/* || echo "Retire.js installation skipped"

# jwt_tool (JWT testing & exploitation - ticarpi/jwt_tool). Wrapper on PATH so
# `jwt_tool <token> <flags>` works from the MCP handler.
RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool \
    && pip install --no-cache-dir pycryptodomex termcolor cprint requests \
    && printf '#!/bin/sh\nexec python3 /opt/jwt_tool/jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool \
    && chmod +x /usr/local/bin/jwt_tool \
    || echo "jwt_tool installation skipped"

# Semgrep (source-aware SAST — whitebox analysis of local checkouts)
RUN pip install --no-cache-dir semgrep || echo "Semgrep installation skipped"

# Trivy (container / filesystem / IaC vulnerability scanner)
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
        | sh -s -- -b /usr/local/bin \
    || echo "Trivy installation skipped"

# Install subcat (passive subdomain enumeration — 19 sources)
RUN pip install subcat || echo "Subcat installation skipped"

# Create minimal subcat config so free-tier modules work immediately.
# Paid modules (virustotal, securitytrails, shodan, etc.) can be enabled at
# runtime by mounting a populated config at /root/.subcat/config.yaml.
RUN mkdir -p /root/.subcat && printf '# Subcat API keys\n# virustotal:\n#   - YOUR_KEY\n# securitytrails:\n#   - YOUR_KEY\n# shodan:\n#   - YOUR_KEY\n' > /root/.subcat/config.yaml

# Install Nikto (web server scanner)
RUN apt-get update && apt-get install -y --no-install-recommends nikto \
    && rm -rf /var/lib/apt/lists/* || echo "Nikto installation skipped"

# WhatWeb (tech fingerprint — was vanguard-only)
RUN git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb \
    && ln -sf /opt/whatweb/whatweb /usr/local/bin/whatweb \
    || echo "WhatWeb installation skipped"

# Commix (command injection)
RUN pip install --no-cache-dir commix || echo "Commix installation skipped"

# Install testssl.sh (TLS/SSL testing)
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl \
    && chmod +x /opt/testssl/testssl.sh \
    && ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl \
    || echo "testssl.sh installation skipped"

# Install WPScan (WordPress scanner - Ruby gem)
RUN apt-get update && apt-get install -y --no-install-recommends ruby ruby-dev build-essential \
    && gem install wpscan --no-document \
    && apt-get purge -y build-essential ruby-dev \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* || echo "WPScan installation skipped"

# Update nuclei templates
RUN nuclei -update-templates || true

# Copy application code LAST (changes most frequently)
COPY . .

# Create non-root user
RUN adduser --disabled-password --gecos '' appuser \
    && chown -R appuser:appuser /app \
    && mkdir -p /home/appuser/.config/nuclei \
    && cp -r /root/.config/nuclei/* /home/appuser/.config/nuclei/ 2>/dev/null || true \
    && chown -R appuser:appuser /home/appuser \
    && mkdir -p /app/data/screenshots \
    && chown -R appuser:appuser /app/data \
    && chown -R appuser:appuser /opt/EyeWitness

USER appuser
ENV PATH="/usr/local/bin:${PATH}"

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--timeout-keep-alive", "300"]
