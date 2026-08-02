# Environment Configuration

Copy this to `.env` in your project root:

```bash
# =============================================================================
# ASM Platform - Environment Configuration
# =============================================================================

# Database
POSTGRES_USER=asm_user
POSTGRES_PASSWORD=CHANGE_ME_TO_A_SECURE_PASSWORD
POSTGRES_DB=asm_db
DB_PORT=5432

# Backend
BACKEND_PORT=8000
SECRET_KEY=GENERATE_WITH_openssl_rand_hex_32
DEBUG=false

# Frontend
# When running behind the bundled nginx + Let's Encrypt (recommended), leave
# NEXT_PUBLIC_API_URL EMPTY. The frontend will use window.location.origin in
# the browser and nginx will proxy /api/ to the backend.
# Only set this if you bypass nginx (e.g. http://YOUR_PUBLIC_IP:8000).
NEXT_PUBLIC_API_URL=
# FRONTEND_PORT is unused when nginx is running (nginx owns 80/443). Kept
# for backward compatibility if you re-enable the direct port publish in
# docker-compose.yml.
FRONTEND_PORT=80

# CORS Origins - IMPORTANT:
#   - With nginx + HTTPS: include https://YOUR_DOMAIN
#   - Without nginx: include http://YOUR_PUBLIC_IP and http://YOUR_PUBLIC_IP:8000
CORS_ORIGINS=["https://YOUR_DOMAIN","http://localhost"]

# =============================================================================
# HTTPS / Let's Encrypt (used by scripts/init-letsencrypt.sh and the nginx
# service in docker-compose.yml). DOMAIN must have an A record pointing at
# this server's public IP, and ports 80 + 443 must be open in the security
# group BEFORE running the bootstrap script.
# =============================================================================
DOMAIN=your.domain.com
LETSENCRYPT_EMAIL=you@example.com
# Set to 1 to use Let's Encrypt's STAGING server while testing (avoids hitting
# the strict production rate limits). Switch back to 0 and re-run the script
# with --force when you're ready for a real cert.
LETSENCRYPT_STAGING=0

# Redis
REDIS_PORT=6379

# =============================================================================
# Auth hardening: CAPTCHA + rate limiting (brute-force / bot protection)
# =============================================================================

# --- CAPTCHA (login + registration) ---
# Disabled by default so local/dev logins work with no setup. Turn ON in prod.
# Provider-agnostic: "turnstile" (Cloudflare, recommended/free), "hcaptcha",
# or "recaptcha" (Google reCAPTCHA v2). The backend fails CLOSED when enabled,
# so if the verifier is unreachable the login is rejected.
#
# Cloudflare Turnstile setup (free):
#   1. https://dash.cloudflare.com → Turnstile → Add site
#   2. Add your domain (e.g. aegis.judahsecurity.io)
#   3. Copy the Site Key -> CAPTCHA_SITE_KEY (public, safe for the browser)
#      and the Secret Key -> CAPTCHA_SECRET_KEY (keep private)
CAPTCHA_ENABLED=false
CAPTCHA_PROVIDER=turnstile
CAPTCHA_SITE_KEY=
CAPTCHA_SECRET_KEY=

# --- Rate limiting ---
# On by default. Uses in-process memory storage (fine for a single backend
# worker). For multiple workers/instances, point at Redis so limits are shared.
RATE_LIMIT_ENABLED=true
# RATE_LIMIT_STORAGE_URI=redis://redis:6379
RATE_LIMIT_LOGIN=5/minute
RATE_LIMIT_REGISTER=5/hour
RATE_LIMIT_REFRESH=20/minute

# AWS Configuration (optional)
AWS_REGION=us-east-1
SQS_QUEUE_URL=

# ProjectDiscovery Cloud (optional - for Chaos subdomain dataset)
# Get API key at: https://cloud.projectdiscovery.io
PDCP_API_KEY=

# =============================================================================
# AI Agent Configuration (optional)
# =============================================================================

# AI Provider: "openai" or "anthropic" (default: openai)
# The agent will auto-detect based on which API key is set.
# These keys also enable Katana AI secrets scan (set ai_secrets_scan: true in Katana scan config).
AI_PROVIDER=openai

# OpenAI Configuration
# Get API key at: https://platform.openai.com/api-keys
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o

# Anthropic/Claude Configuration (use API key from Console, NOT Cursor/Claude Code)
# Get key at: https://console.anthropic.com/ → API Keys (must start with sk-ant-)
ANTHROPIC_API_KEY=
ANTHROPIC_MODEL=claude-sonnet-4-6

# =============================================================================
# Aegis Vanguard (autonomous pentest agent + on-demand finding validator)
# Code lives in aegis-vanguard/. See aegis-vanguard/DEPLOYMENT.md.
# =============================================================================
# How the scanner worker invokes validate_finding.py: docker | subprocess
# AEGIS_VALIDATOR_MODE=docker
# AEGIS_VANGUARD_IMAGE=aegis-vanguard:latest
# AEGIS_VANGUARD_PATH=/path/to/aegis-vanguard   # only for subprocess mode
# AEGIS_VALIDATE_MAX_TURNS=20
# AEGIS_VALIDATE_TIMEOUT=900
# Agent-side (also used inside the Vanguard container):
# AEGIS_MODEL=claude-sonnet-4-6
# AEGIS_GUARDRAILS=true
# AEGIS_TRACING=true

# DeepSeek (OpenAI-compatible). Optional. Provider string in task_models: "deepseek"
# Get key at: https://platform.deepseek.com/
# DEEPSEEK_API_KEY=
# DEEPSEEK_MODEL=deepseek-chat

# Moonshot / Kimi (OpenAI-compatible). Optional. Provider string in task_models: "kimi"
# Get key at: https://platform.kimi.ai/
# Per-org keys can also be saved in Settings → API Keys (service name: kimi).
# MOONSHOT_API_KEY=
# KIMI_MODEL=kimi-k3

# Groq (OpenAI-compatible, free tier). Provider string: "groq"
# Get key at: https://console.groq.com/keys
# GROQ_API_KEY=
# GROQ_MODEL=llama-3.3-70b-versatile

# Local Ollama (no cloud key). Provider string: "ollama"
# Docker Compose (recommended on EC2): enable the ollama profile so the
# `ollama` + `ollama-init` services start and pull the model automatically.
#   COMPOSE_PROFILES=ollama
#   OLLAMA_BASE_URL=http://ollama:11434/v1
#   docker compose --profile ollama up -d
# Host / Docker Desktop instead: OLLAMA_BASE_URL=http://host.docker.internal:11434/v1
# Smaller instances: OLLAMA_MODEL=qwen2.5:7b  (~8 GB RAM). 14b needs ~12–16 GB.
# When a preferred cloud provider has no API key, the agent falls back to Ollama
# if it is reachable (disable with OLLAMA_FALLBACK_ENABLED=false).
# COMPOSE_PROFILES=ollama
# OLLAMA_BASE_URL=http://ollama:11434/v1
# OLLAMA_MODEL=qwen2.5:14b
# OLLAMA_FALLBACK_ENABLED=true

# Per-task model routing (bring-your-own-key):
#   These env vars are the GLOBAL default keys/models. Each organization can
#   override provider + model per task (reasoning / offensive / report) and
#   supply its own encrypted keys via Settings → API Keys (or the API-config
#   store) — see the "agent" module in project settings
#   ("task_models": {"offensive": "anthropic:claude-sonnet-4-6",
#                    "reasoning": "groq:llama-3.3-70b-versatile", ...}).
#   Provider keys are only ever handed to the model SDK; they are never placed
#   into prompts, tool output, or agent state.

# Optional: Tavily API for agent web search (CVE/exploit research, RedAmon-style)
# Get key at: https://tavily.com (free tier available)
# TAVILY_API_KEY=

# Agent LLM max output tokens (default 4096; increase for long answers, e.g. 8192, 16384, 64000)
# AGENT_MAX_OUTPUT_TOKENS=4096

# Agent tool output truncation (chars passed to LLM; default 20000)
# AGENT_TOOL_OUTPUT_MAX_CHARS=20000

# Agent request timeout in seconds (default 660; increase for complex multi-tool runs)
# AGENT_REQUEST_TIMEOUT_SECONDS=660

# Agent max iterations per REST request (default 15; increase for longer tool chains)
# AGENT_REST_MAX_ITERATIONS=15

# =============================================================================
# Neo4j Graph Database (optional - for asset relationship modeling)
# =============================================================================

# Enable with: docker compose --profile graph up -d
NEO4J_USER=neo4j
NEO4J_PASSWORD=neo4j_password
NEO4J_HTTP_PORT=7474
NEO4J_BOLT_PORT=7687

# =============================================================================
# GitHub Secret Scanning (optional)
# =============================================================================

# GitHub Personal Access Token for secret scanning
# Create at: https://github.com/settings/tokens
GITHUB_TOKEN=

# =============================================================================
# Scanner Performance Tuning (optional)
# =============================================================================

# Max concurrent scans the worker can process (default 5)
# MAX_CONCURRENT_SCANS=5

# Scanner poll interval in seconds (default 10)
# POLL_INTERVAL=10

# Port scan rate for Masscan (packets/sec, default 2000)
# PORT_SCAN_RATE=2000

# Nuclei rate limit (requests/sec, default 300)
# NUCLEI_RATE_LIMIT=300

# Schedule check interval in seconds (default 60)
# SCHEDULE_CHECK_INTERVAL=60

```

## Production example (HTTPS + single domain)

For a deployment like `https://aegis.judahsecurity.io`:

```bash
# Database
POSTGRES_USER=asm_user
POSTGRES_PASSWORD=CHANGE_ME_SECURE_PASSWORD
POSTGRES_DB=asm_db

# Security - generate: openssl rand -hex 32
SECRET_KEY=your-generated-secret-key

# Frontend / API (use your real domain)
NEXT_PUBLIC_API_URL=https://aegis.judahsecurity.io
CORS_ORIGINS=["https://aegis.judahsecurity.io"]

# Auth hardening — enable CAPTCHA to stop credential brute-forcing.
# Keys from Cloudflare dashboard → Turnstile (see main config block above).
CAPTCHA_ENABLED=true
CAPTCHA_PROVIDER=turnstile
CAPTCHA_SITE_KEY=0x4AAAAAAA_your_site_key
CAPTCHA_SECRET_KEY=0x4AAAAAAA_your_secret_key

# Ports
BACKEND_PORT=8000
FRONTEND_PORT=80

# AWS (one entry each)
SQS_QUEUE_URL=https://sqs.us-east-1.amazonaws.com/YOUR_ACCOUNT_ID/asm-scan-jobs
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_iam_access_key
AWS_SECRET_ACCESS_KEY=your_iam_secret_key

# ProjectDiscovery Cloud (one entry)
PDCP_API_KEY=your-pdcp-key

# AI Agent
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-api03-your-key-from-console-anthropic

# Neo4j (if using graph)
NEO4J_URI=bolt://neo4j:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_neo4j_password
```

- No duplicate variables (e.g. only one `SQS_QUEUE_URL`, one `PDCP_API_KEY`).
- `CORS_ORIGINS` must be valid JSON (one string or list of strings).
- After editing `.env`, run `docker compose restart backend` (or `sudo docker compose restart backend` on the server).

---

## Quick Setup

Use the auto-configure script instead:

```bash
chmod +x scripts/quick-deploy.sh
./scripts/quick-deploy.sh
```

This automatically:
- Detects your public IP
- Generates secure passwords
- Configures CORS
- Builds and starts all services

---

## Troubleshooting: 401 invalid x-api-key (Anthropic/Claude)

If the AI agent returns **Error code: 401 - invalid x-api-key**:

1. **Use the correct key**  
   The app needs an **Anthropic API key** from [console.anthropic.com](https://console.anthropic.com) → **API Keys** (create/copy there).  
   Do **not** use a key from Cursor, “Claude for Code,” or other products — those are not valid for the Claude API.

2. **Check key format**  
   The key must start with `sk-ant-` (e.g. `sk-ant-api03-...`). If it doesn’t, you’re likely using the wrong type of key.

3. **Fix .env**  
   In the project root `.env` (same folder as `docker-compose.yml`):
   - Use one line: `ANTHROPIC_API_KEY=sk-ant-api03-your-key-here`
   - No space after `=`, no extra quotes unless the key contains spaces
   - No leading/trailing spaces or line breaks in the key

4. **Restart backend**  
   After changing `.env`: `docker compose restart backend` (or on AWS: `sudo docker compose restart backend`).

5. **Create a new key**  
   In [Anthropic Console](https://console.anthropic.com) → API Keys, create a new key and replace the value in `.env` in case the previous one was revoked or incorrect.

---

## Troubleshooting: Agent not running when key is configured

If you set `ANTHROPIC_API_KEY` (or `OPENAI_API_KEY`) but the Agent page still shows "Agent is not available":

1. **Restart the backend after adding the key**  
   The backend reads env vars only at startup. After editing `.env`, run:
   ```bash
   docker compose up -d backend
   ```
   On AWS (EC2): `cd /opt/asm` then the same command with `sudo` if needed.

2. **Use the correct `.env` and variable name**  
   - The `.env` file must be in the **same directory as `docker-compose.yml`** (e.g. project root or `/opt/asm` on the server).
   - Variable must be exactly: `ANTHROPIC_API_KEY=sk-ant-api03-...` (no space around `=`; no typo like `ANTHROPIC_KEY`).

3. **Use an Anthropic API key, not Cursor/Claude Code**  
   Get the key from [Anthropic Console → API Keys](https://console.anthropic.com). Keys from Cursor or "Claude Code" are not valid for this API. Valid keys start with `sk-ant-`.

4. **Confirm the key is in the container**  
   On the server:
   ```bash
   sudo docker exec asm_backend env | grep ANTHROPIC
   ```
   You should see `ANTHROPIC_API_KEY=sk-ant-...` (the value is shown). If it’s missing or empty, fix `.env` and restart the backend.

5. **Check the Agent page message**  
   After the latest frontend/backend updates, the Agent page shows a hint when the agent is unavailable (e.g. "Set ANTHROPIC_API_KEY in .env and restart the backend") or the error from the status request (e.g. network or auth). Use that to narrow down the issue.

---

## Troubleshooting: 504 Gateway Timeout (Agent)

If the agent shows **Request failed with status code 504**:

- **Cause:** A reverse proxy (nginx, ALB, Cloudflare, etc.) in front of the backend stopped waiting for the response. Agent requests can take a long time (LLM calls plus tool runs). Many proxies default to 60 seconds.
- **What to do:** Increase the proxy’s timeout for the API (or at least for agent paths).

  **Nginx** (in the `location` that proxies to the backend):
  ```nginx
  proxy_connect_timeout 300s;
  proxy_send_timeout 300s;
  proxy_read_timeout 300s;
  ```
  Use 300–600 seconds for the agent; you can use a longer timeout only for `/api/v1/agent/` if you prefer.

  **AWS Application Load Balancer:**  
  ALB idle timeout defaults to 60 seconds. Increase it (e.g. to 300 seconds):
  - Console: EC2 → Load Balancers → your ALB → Attributes → Idle timeout.
  - CLI: `aws elbv2 modify-load-balancer-attributes --load-balancer-arn <ARN> --attributes Key=idle_timeout.timeout_seconds,Value=300`

  **Cloudflare / other CDN:**  
  Increase the proxy timeout in the dashboard (e.g. 300s) or use a “stream”/passthrough so the CDN doesn’t time out long requests.

  After changing the proxy, reload nginx or wait for ALB changes to apply, then try the agent again.

---

## Troubleshooting: 529 / Overloaded (Agent)

If the agent shows **Error code: 529** or **overloaded_error / "Overloaded"**:

- **Cause:** Anthropic’s API is temporarily overloaded and is rejecting requests.
- **What to do:** Wait a few minutes and try again. The app now shows a friendly message: *"The AI provider (Anthropic/Claude) is temporarily overloaded. Please try again in a few minutes."*
- **Optional:** You can switch to OpenAI by setting `AI_PROVIDER=openai` and `OPENAI_API_KEY` in `.env` so the agent uses GPT instead when Claude is overloaded.
