# Aegis Vanguard — Deployment Guide

Aegis Vanguard is harness-agnostic: it runs as a **standalone Python CLI** or in
**any Docker container**. This guide covers both deployment shapes.

Phase-1 status: the parallel OWASP fireteam (Shannon/RedAmon-inspired
scatter-gather ReAct) is the default vuln-phase pipeline. See
`agent/parallel_subagents.py` and `agent/owasp_hunters.py`.

---

## 1. Local / Standalone Python

The simplest way to run or develop against Vanguard. Best for CI smoke tests,
air-gapped engagements, and local tuning.

### Prerequisites

- Python 3.11+
- An LLM API key. Anthropic remains the default, but Phase 2 adds LiteLLM
  routing for OpenAI/ChatGPT, Gemini, Bedrock, OpenRouter, Ollama, and any
  OpenAI-compatible endpoint.
- Offensive scanners on `$PATH`. Missing tools degrade gracefully — the agent
  skips them — but for full coverage install at least:

  ```
  subfinder, subcat, dnsx, httpx, naabu, nmap, whatweb, wafw00f,
  katana, waybackurls, gau, ffuf, arjun, nuclei, nikto,
  tlsx, sqlmap, XSStrike, wpscan, testssl, gitleaks,
  trufflehog, OWASP ZAP (via docker for Janus)
  ```

  `subcat` is a pip package (`pip install subcat`) — no binary needed. Free-tier
  modules (dnsdumpster, hackertarget, anubis, crt.sh, wayback, threatcrowd,
  dnsarchive) work out of the box. Paid modules activate via
  `~/.subcat/config.yaml`.

### Setup

```bash
cd aegis-vanguard

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# If you want Aegis Praetorium (Censor/Lictor/Augur) guardrails:
pip install -e ../backend/packages/aegis_praetorium

export ANTHROPIC_API_KEY=sk-ant-...
# Or, for OpenAI / ChatGPT-family models:
export OPENAI_API_KEY=sk-...
# Or Gemini:
export GEMINI_API_KEY=...
# Optional:
export AEGIS_MODEL=claude-sonnet-4-6        # override default model
export AEGIS_LLM_BACKEND=auto                       # auto|anthropic|litellm
export AEGIS_TRACING=true                           # default on
# Optional internal trace sink (self-hosted Phoenix or Langfuse OTLP). Redacts
# cookies/Authorization before export. Do not point this at Langfuse Cloud.
# export AEGIS_TRACES_DIR=/tmp/aegis-traces
# export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:6006/v1/traces
export AEGIS_GUARDRAILS=true                        # default on
export ASM_API_URL=http://your-asm-platform:8000    # if shipping findings
export ASM_API_KEY=tfasm_...                        # agent API key from platform
export WHOISXML_API_KEY=...                         # optional, enables reverse_whois_search
export GITLAB_HASH_DB_PATH=/agent/data/gitlab_hashes.json  # optional, GitLab asset hash -> version DB
```

### Run a scan

```bash
# Default: parallel OWASP fireteam (5 concurrent specialists)
python3 run_pentest.py --target https://example.com --scope example.com

# Legacy sequential mode (single vuln_agent)
python3 run_pentest.py --target https://example.com --vuln-mode sequential

# Tune per-hunter turn budget (default 12)
python3 run_pentest.py --target https://example.com --hunter-turns 20

# Force enterprise perimeter hunters (Entra/Okta/SharePoint/VPN/vCenter/cloud IAM)
python3 run_pentest.py --target https://example.com --enterprise

# Force every API/framework + enterprise specialist
python3 run_pentest.py --target https://example.com --all-specialists

# Webapp-only: skip enterprise + API specialists
python3 run_pentest.py --target https://example.com --no-enterprise --no-api-specialists

# Limit tool risk ceiling
python3 run_pentest.py --target https://example.com --max-risk medium
```

Specialist hunters activate automatically when recon/app-mapper text matches
signals (GraphQL, Next.js, Okta, VPN portals, AKIA keys, etc.). Files:

| Module | Coverage |
|--------|----------|
| `agent/owasp_hunters.py` | Core 17 hunters + `create_hunters_for_engagement()` |
| `agent/api_framework_hunters.py` | GraphQL, gRPC, WebSocket, frameworks, deserialization |
| `agent/enterprise_hunters.py` | Entra, Okta, SharePoint, VPN, vCenter, cloud IAM, supply-chain |
| `agent/hunt_patterns.py` | Pattern packs + kill/chain tables |

### Multi-model routing (Phase 2)

Vanguard keeps the existing ReAct loop intact — the same pentester prompts,
tool schemas, Censor/Lictor/Augur guardrails, and Thought → Action →
Observation flow. The only change is the LLM call layer. You can now route
different phases or specialist hunters to different models:

```bash
# Default model for anything not explicitly routed.
export AEGIS_MODEL=claude-sonnet-4-6

# Force LiteLLM for non-Claude providers. In auto mode, models beginning with
# "claude-" use the native Anthropic SDK; all others go through LiteLLM.
export AEGIS_LLM_BACKEND=auto

# Phase-level routing.
export AEGIS_MODEL_RECON=gpt-5.5
export AEGIS_MODEL_VULN=claude-sonnet-4-6
export AEGIS_MODEL_EXPLOIT=claude-opus-4-1
export AEGIS_MODEL_REPORT=gpt-5.5

# Parallel OWASP fireteam routing.
export AEGIS_MODEL_HUNTER=claude-sonnet-4-6
export AEGIS_MODEL_INJECTION=claude-opus-4-1
export AEGIS_MODEL_AUTHZ=gpt-5.5

# Exact agent override wins over every other setting.
export AEGIS_MODEL_RECON_AGENT=gemini/gemini-2.5-pro
export AEGIS_MODEL_INJECTION_HUNTER=openai/gpt-5.5
```

Routing precedence:

1. Exact agent env var: `AEGIS_MODEL_<AGENT_NAME>` (for example
   `AEGIS_MODEL_EXPLOIT_AGENT`, `AEGIS_MODEL_INJECTION_HUNTER`)
2. Category env var: `AEGIS_MODEL_RECON`, `AEGIS_MODEL_EXPLOIT`,
   `AEGIS_MODEL_HUNTER`, `AEGIS_MODEL_INJECTION`, `AEGIS_MODEL_AUTHZ`, etc.
3. `agent.model` set in code
4. `AEGIS_MODEL` default

Common model examples:

```bash
# Native Anthropic SDK path (default for claude-* models in auto mode)
export AEGIS_MODEL=claude-sonnet-4-6

# OpenAI / ChatGPT via LiteLLM
export AEGIS_LLM_BACKEND=litellm
export AEGIS_MODEL=openai/gpt-5.5

# Gemini via LiteLLM
export AEGIS_MODEL=gemini/gemini-2.5-pro

# AWS Bedrock via LiteLLM
export AEGIS_MODEL=bedrock/us.anthropic.claude-sonnet-4-20250514-v1:0

# OpenRouter via LiteLLM
export AEGIS_MODEL=openrouter/deepseek/deepseek-chat

# Local Ollama via LiteLLM
export AEGIS_MODEL=ollama/llama3.1
```

Output:

- Console log of each phase with per-hunter tool-call summary
- Trace JSON at `./traces/trace_<session_id>.json` (or `/agent/traces/` when
  running under the Docker image — overridable with the `Tracer(output_dir=)`
  argument)
- Findings streamed to your ASM platform if `ASM_API_URL` / `ASM_API_KEY`
  are set; otherwise to the trace file only

---

## 2. Docker (own image)

Use this if you want Vanguard as a reproducible container with all scanners
pre-installed.

### Build

```bash
# From the monorepo root (Dockerfile COPY paths expect this context)
docker build -f aegis-vanguard/Dockerfile -t aegis-vanguard:latest .
```

The image installs every scanner listed above so no host dependencies are
required.

### Run

```bash
docker run --rm \
    -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
    -e ASM_API_URL=http://asm-platform:8000 \
    -e ASM_API_KEY="$ASM_API_KEY" \
    -e AEGIS_MODEL=claude-sonnet-4-6 \
    -v "$(pwd)/traces:/agent/traces" \
    aegis-vanguard:latest \
    --target https://example.com --scope example.com
```

### Compose example

```yaml
# docker-compose.vanguard.yml
services:
  vanguard:
    build:
      context: ./aegis-vanguard
      dockerfile: Dockerfile
    image: aegis-vanguard:latest
    environment:
      ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY}
      ASM_API_URL: http://asm-backend:8000
      ASM_API_KEY: ${ASM_API_KEY}
      AEGIS_MODEL: claude-sonnet-4-6
      AEGIS_TRACING: "true"
    volumes:
      - ./traces:/agent/traces
    command: ["--target", "https://example.com", "--scope", "example.com"]
    networks:
      - asm-net

networks:
  asm-net:
    external: true
```

Spin up with `docker compose -f docker-compose.vanguard.yml run --rm vanguard`.

---

## 3. Isolated / sandboxed Docker runs

For customer-facing scans, run the same image with tighter network and volume
isolation. The agent expects:

| Path            | Purpose                                                   |
|-----------------|-----------------------------------------------------------|
| `/agent/`       | Working directory for the CLI + traces                    |
| `/agent/traces/`| Mount or volume for persisted trace JSON                  |
| `/agent/workspaces/latest/deliverables/` | Where reports are written       |
| `$ANTHROPIC_API_KEY` | LLM credential                                   |
| `$ASM_API_URL` / `$ASM_API_KEY` | ASM platform ingestion credentials        |

Example:

```bash
docker run --rm \
    --network scan-egress \
    -e ANTHROPIC_API_KEY \
    -e ASM_API_URL \
    -e ASM_API_KEY \
    -e AEGIS_MODEL=claude-sonnet-4-6 \
    -e AEGIS_GUARDRAILS=true \
    -v "$(pwd)/traces:/agent/traces" \
    -v "$(pwd)/reports:/agent/workspaces/latest/deliverables" \
    aegis-vanguard:latest \
    python3 /agent/run_pentest.py \
        --target https://example.com \
        --scope example.com
```

Notes:

- The `CLAUDE.md` in `aegis-vanguard/` is the Claude-side system card for the
  agent. It is not required for CLI operation.
- Keep `AEGIS_GUARDRAILS=true` (and Praetorium Lictor/Censor/Augur) enabled for
  defense-in-depth even when the host applies its own egress controls.

---

## Configuration reference

All configuration is environment-variable driven; no `.env` file is required.

| Variable                | Default                             | Effect                                            |
|-------------------------|-------------------------------------|---------------------------------------------------|
| `ANTHROPIC_API_KEY`     | — (required)                        | Anthropic API credential                          |
| `OPENAI_API_KEY`        | — (optional)                        | OpenAI/ChatGPT credential when using LiteLLM      |
| `GEMINI_API_KEY`        | — (optional)                        | Gemini credential when using LiteLLM              |
| `AEGIS_LLM_BACKEND`     | `auto`                              | `auto`, `anthropic`, or `litellm`                 |
| `AEGIS_MODEL`           | `claude-sonnet-4-6`          | Default LLM model used by all agents/hunters      |
| `AEGIS_MODEL_RECON`     | —                                   | Override model for recon phase                    |
| `AEGIS_MODEL_VULN`      | —                                   | Override model for legacy vuln agent              |
| `AEGIS_MODEL_EXPLOIT`   | —                                   | Override model for exploit validation             |
| `AEGIS_MODEL_REPORT`    | —                                   | Override model for report generation              |
| `AEGIS_MODEL_HUNTER`    | —                                   | Override model for all OWASP parallel hunters     |
| `AEGIS_MODEL_INJECTION` | —                                   | Override model for injection hunter               |
| `AEGIS_MODEL_XSS`       | —                                   | Override model for XSS hunter                     |
| `AEGIS_MODEL_AUTH`      | —                                   | Override model for auth hunter                    |
| `AEGIS_MODEL_AUTHZ`     | —                                   | Override model for authz hunter                   |
| `AEGIS_MODEL_SSRF`      | —                                   | Override model for SSRF hunter                    |
| `OLLAMA_FALLBACK_ENABLED` | `true`                            | On cloud credit/quota errors, retry via local Ollama |
| `OLLAMA_MODEL`          | `qwen2.5:14b`                       | Local model used for credit/quota fallback        |
| `OLLAMA_BASE_URL` / `OLLAMA_API_BASE` | `http://127.0.0.1:11434` | Ollama daemon base (LiteLLM strips trailing `/v1`) |
| `AEGIS_TRACING`         | `true`                              | Enable OpenTelemetry-style span capture           |
| `AEGIS_GUARDRAILS`      | `true`                              | Enable legacy regex guardrail engine              |
| `AEGIS_LICTOR_ENABLED`  | `true`                              | Praetorium Lictor pre/post hooks                  |
| `AEGIS_CENSOR_ENABLED`  | `true`                              | Praetorium Censor tool-input validation           |
| `AEGIS_AUGUR_ENABLED`   | `true`                              | Praetorium Augur semantic output filter           |
| `AEGIS_ENFORCE_SCOPE`   | `true`                              | Drop tool calls targeting out-of-scope hosts      |
| `AEGIS_RATE_CAPACITY`   | `10`                                | Per-tool token-bucket capacity                    |
| `AEGIS_RATE_PER_MINUTE` | `60`                                | Per-tool token-bucket refill rate                 |
| `AEGIS_TOOL_OUTPUT_MAX_CHARS` | `50000`                       | Hard clip for a single tool's output              |
| `ASM_API_URL`           | — (optional)                        | ASM ingestion endpoint (e.g. `http://backend:8000`) |
| `ASM_API_KEY`           | — (optional)                        | Agent API key (starts with `tfasm_`)              |
| `ASM_ORGANIZATION_ID`   | — (optional)                        | Tag all findings with this org                    |
| `ASM_AGENT_ID`          | — (optional)                        | Unique identifier for this agent instance         |
| `WHOISXML_API_KEY`      | — (optional)                        | Enables WhoisXML reverse WHOIS OSINT pivots       |
| `WHOISXML_API`          | — (optional)                        | Legacy alias for `WHOISXML_API_KEY`               |
| `GITLAB_HASH_DB_PATH`   | — (optional)                        | JSON database mapping GitLab stylesheet SHA-256 hashes to versions |

---

## CLI flags

```
--target, -u URL           target URL (required)
--scope, -s DOMAIN         root domain scope (default: target hostname)
--model, -m MODEL          override $AEGIS_MODEL
--max-risk {safe,low,medium,high,critical}   tool-risk ceiling (default: high)
--vuln-mode {parallel,sequential}            vuln phase shape (default: parallel)
--hunter-turns N           per-hunter turn budget (default: 50)
--enterprise               force all enterprise perimeter hunters
--no-enterprise            disable enterprise specialists
--all-specialists          force API/framework + enterprise specialists
--no-api-specialists       disable GraphQL/gRPC/framework specialists
--no-guardrails            disable legacy guardrails + Praetorium (not recommended)
--no-tracing               disable trace capture
--verbose, -v              DEBUG logging
```

---

## Troubleshooting

**`ANTHROPIC_API_KEY not set — agent loop will fail`**
Export the key. All five OWASP hunters + every phase agent need it.

**`aegis_praetorium` import warning on startup**
The agent runs without Praetorium (legacy guardrail engine still active).
Install the package from `backend/packages/aegis_praetorium/` to enable
Censor/Lictor/Augur. See `aegis-vanguard/agent/core.py` for the import
site — the agent is tolerant of the missing package.

**Hunter hangs at high turn counts**
Drop `--hunter-turns` to 8 and raise only if scans finish early with under-
coverage. Each hunter is capped independently, so one slow hunter won't
starve the others.

**Finding-deduplication merges across too many findings**
Adjust `_finding_key()` in `agent/parallel_subagents.py`. The default
fingerprint is `(template_id, name, matched_at, severity)`. Add or remove
fields to loosen/tighten the merge.

**Parallel mode finds fewer vulns than sequential**
Check per-hunter traces (`trace_*.json` → `children[*].attributes`) for
early termination. Raise `--hunter-turns` or expand each hunter's tool list
in `agent/owasp_hunters.py`.

**Want to A/B compare parallel vs sequential**
Run the same target in both modes with the same `--model` and `--max-risk`
and diff the generated `trace_*.json` summaries — Phase 2's LiteLLM swap
will additionally let you compare models side-by-side.
