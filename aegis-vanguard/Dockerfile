FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# ── System dependencies ──────────────────────────────────────────────
RUN apt-get update && apt-get install -y \
    curl wget git unzip jq python3 python3-pip python3-venv \
    dnsutils nmap masscan libpcap-dev whois \
    nikto ruby ruby-dev build-essential libffi-dev \
    openssl openssh-client hydra \
    && rm -rf /var/lib/apt/lists/*

# ── Go toolchain (for ProjectDiscovery + Praetorian tools) ──────────
# Go 1.25+ required by Praetorian pius; older tools build fine on 1.25.
ARG GO_VERSION=1.25.0
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-$(dpkg --print-architecture).tar.gz" \
    | tar -C /usr/local -xz

# ── ProjectDiscovery tools ───────────────────────────────────────────
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/melvinsh/subfaster/v2/cmd/subfaster@latest \
    && go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install -v github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest

# ── Additional Go-based security tools ───────────────────────────────
RUN go install -v github.com/owasp-amass/amass/v4/...@master \
    && go install -v github.com/tomnomnom/waybackurls@latest \
    && go install -v github.com/lc/gau/v2/cmd/gau@latest \
    && go install -v github.com/ffuf/ffuf/v2@latest \
    && go install -v github.com/hahwul/dalfox/v2@latest \
    && go install -v github.com/s0md3v/smap/cmd/smap@latest \
    && go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest

# ── Feroxbuster (Rust release) ───────────────────────────────────────
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then FX_ARCH="aarch64"; else FX_ARCH="x86_64"; fi && \
    (wget -q "https://github.com/epi052/feroxbuster/releases/download/v2.11.0/${FX_ARCH}-linux-feroxbuster.zip" -O /tmp/ferox.zip && \
     unzip -o -q /tmp/ferox.zip -d /tmp/ferox && \
     find /tmp/ferox -type f -name feroxbuster -exec cp {} /usr/local/bin/ \; && \
     chmod +x /usr/local/bin/feroxbuster && \
     rm -rf /tmp/ferox /tmp/ferox.zip) || echo "feroxbuster download skipped"

# ── Aegis Vanguard: Atlas + Argus (Praetorian-backed) ───────────────
# Atlas (pius binary):  organizational asset cartographer — 24+ OSINT
#                       plugins, all 5 RIRs, domains + CIDRs from an org name
# Argus (titus binary): all-seeing secrets scanner — 487 detection rules,
#                       optional live credential validation
RUN go install -v github.com/praetorian-inc/pius/cmd/pius@latest \
    && go install -v github.com/praetorian-inc/titus/cmd/titus@latest

# ── Aegis Vanguard: Hermes (TruffleHog v3) ──────────────────────────
# Hermes: remote secrets-finder — GitHub/GitLab orgs, S3/GCS/Azure,
#         Docker images, Postman, Jenkins, Jira/Confluence, + live
#         credential verification. Complement to Argus (local paths).
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sh -s -- -b /usr/local/bin

# ── Aegis Vanguard: Janus (OWASP ZAP) ───────────────────────────────
# Janus: two-faced DAST gatekeeper — baseline (passive, CI-safe) and
#        full (active attack scan). Wraps OWASP ZAP 2.16.x; needs JRE.
ARG ZAP_VERSION=2.16.1
RUN apt-get update && apt-get install -y --no-install-recommends default-jre-headless \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" \
        -o /tmp/zap.tgz \
    && mkdir -p /opt/zap \
    && tar -xzf /tmp/zap.tgz -C /opt/zap --strip-components=1 \
    && rm /tmp/zap.tgz \
    && ln -sf /opt/zap/zap-baseline.py /usr/local/bin/zap-baseline.py \
    && ln -sf /opt/zap/zap-full-scan.py /usr/local/bin/zap-full-scan.py \
    && ln -sf /opt/zap/zap-api-scan.py  /usr/local/bin/zap-api-scan.py \
    && ln -sf /opt/zap/zap.sh           /usr/local/bin/zap.sh

# ── gitleaks ─────────────────────────────────────────────────────────
ARG GITLEAKS_VERSION=8.18.4
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then GL_ARCH="x64"; else GL_ARCH="$ARCH"; fi && \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}.tar.gz" \
    | tar -C /usr/local/bin -xz gitleaks

# ── testssl.sh ───────────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh \
    && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# ── XSStrike ─────────────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/s0md3v/XSStrike.git /opt/xsstrike

# ── CMSeeK ───────────────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/Tuhinshubhra/CMSeeK.git /opt/cmseek

# ── Arjun (HTTP parameter discovery) ────────────────────────────────
RUN python3 -m pip install --break-system-packages arjun

# ── WhatWeb ──────────────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb \
    && ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb

# ── wafw00f ──────────────────────────────────────────────────────────
RUN python3 -m pip install --break-system-packages wafw00f

# ── subcat (passive subdomain enumeration — 19 sources) ──────────────
RUN python3 -m pip install --break-system-packages subcat \
    && mkdir -p /root/.subcat \
    && printf '# Subcat API keys\n# virustotal:\n#   - YOUR_KEY\n# securitytrails:\n#   - YOUR_KEY\n# shodan:\n#   - YOUR_KEY\n' > /root/.subcat/config.yaml

# ── sslyze ───────────────────────────────────────────────────────────
RUN python3 -m pip install --break-system-packages sslyze

# ── AutoSwagger (intruder-io) ────────────────────────────────────────
# Discover, parse, and test OpenAPI/Swagger endpoints; PII + secret detection
RUN git clone --depth 1 https://github.com/intruder-io/autoswagger.git /opt/autoswagger \
    && python3 -m pip install --break-system-packages \
        -r /opt/autoswagger/requirements.txt \
        presidio-analyzer presidio-anonymizer \
    && python3 -m spacy download en_core_web_lg 2>/dev/null || \
       python3 -m spacy download en_core_web_sm || true \
    && ln -sf /opt/autoswagger/autoswagger.py /usr/local/bin/autoswagger.py

# ── sqlmap ───────────────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

# ── Commix (command injection) ───────────────────────────────────────
RUN python3 -m pip install --break-system-packages commix || echo "commix skipped"

# ── WPScan (Ruby gem) ───────────────────────────────────────────────
RUN gem install wpscan --no-document

# ── Nuclei templates ────────────────────────────────────────────────
RUN nuclei -update-templates 2>/dev/null || true

# ── Wordlists for fuzzing ───────────────────────────────────────────
RUN mkdir -p /usr/share/wordlists/dirb && \
    curl -fsSL -o /usr/share/wordlists/dirb/common.txt \
    https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt

# ── Python dependencies for the bridge ──────────────────────────────
# Build from monorepo root so shared packages are available:
#   docker build -f aegis-vanguard/Dockerfile .
WORKDIR /agent
COPY backend/packages/asm_scanner_core /packages/asm_scanner_core
COPY backend/packages/aegis_praetorium /packages/aegis_praetorium
RUN python3 -m pip install --break-system-packages -e /packages/asm_scanner_core \
    && python3 -m pip install --break-system-packages -e /packages/aegis_praetorium
COPY aegis-vanguard/requirements.txt ./
RUN python3 -m pip install --break-system-packages -r requirements.txt

# ── Playwright + Chromium for browser-based dynamic testing ─────────
RUN playwright install --with-deps chromium

# ── Agent files ─────────────────────────────────────────────────────
COPY aegis-vanguard/asm_bridge.py aegis-vanguard/scanners.py aegis-vanguard/healthcheck.py aegis-vanguard/CLAUDE.md \
     aegis-vanguard/run_pentest.py aegis-vanguard/validate_finding.py aegis-vanguard/reporter.py ./
COPY aegis-vanguard/agent/ ./agent/

# Default env vars (override at runtime)
ENV ASM_API_URL=""
ENV ASM_API_KEY=""
ENV ASM_AGENT_ID="aegis-vanguard"
ENV ANTHROPIC_API_KEY=""
ENV AEGIS_MODEL="claude-sonnet-4-6"
ENV AEGIS_GUARDRAILS="true"
ENV AEGIS_TRACING="true"
# Aegis Praetorium guard layer (Lictor / Censor / Augur) — shared with the
# platform agent. See backend/packages/aegis_praetorium/README.md.
ENV AEGIS_LICTOR_ENABLED="true"
ENV AEGIS_CENSOR_ENABLED="true"
ENV AEGIS_AUGUR_ENABLED="true"
ENV AEGIS_AUGUR_VERBOSE="false"
ENV AEGIS_ENFORCE_SCOPE="true"
ENV AEGIS_RATE_CAPACITY="30"
ENV AEGIS_RATE_PER_MINUTE="30"
ENV AEGIS_TOOL_OUTPUT_MAX_CHARS="20000"

HEALTHCHECK --interval=60s --timeout=10s --retries=3 \
    CMD python3 /agent/healthcheck.py --quick || exit 1

CMD ["bash"]
