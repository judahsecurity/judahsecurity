# Aegis Vanguard — ASM Scanner Agent

An AI-powered Attack Surface Management agent that runs as a standalone CLI or
Docker container and reports findings back to Judah Security ASM platform.

For **batch scanning and detection benchmarks**, use the sibling
[Aegis Harness](../harness/README.md). For the **in-product ASM agent** tester
process (engagement brain, fireteam, differentials), see
[docs/TESTER_PROCESS_AND_ENGAGEMENT_BRAIN.md](../docs/TESTER_PROCESS_AND_ENGAGEMENT_BRAIN.md).

## Architecture

```
┌─────────────────────────────────────┐     ┌──────────────────────────────────┐
│       Aegis Vanguard Container      │     │     ASM Platform                 │
│                                     │     │                                  │
│  ReACT multi-agent pipeline         │     │  POST /api/v1/ingest/findings    │
│  recon → parallel OWASP hunters     │     │       │                          │
│       → exploit → report            │     │       ▼                          │
│       │                             │────▶│  Ingestion Service               │
│       ▼                             │     │       │                          │
│  scanners.py (nuclei, httpx, …)     │     │       ▼                          │
│  asm_bridge.py (API + findings sink)│     │  Assets, Vulns → Postgres        │
│  CLAUDE.md / agent/* hunters        │     │  Dashboard (Next.js)             │
└─────────────────────────────────────┘     └──────────────────────────────────┘
              │
              │ AEGIS_FINDINGS_SINK=findings.jsonl
              ▼
         Aegis Harness (batch + benchmark)
```

## Parallel hunters (fireteam)

Phase 2 fans out specialist hunters (injection, XSS, auth, authz, SSRF, business
logic, host-header, …) with surface-selected API/enterprise packs. See
`agent/owasp_hunters.py`, `agent/hunt_patterns.py`, and
`docs/vanguard-system-card.md`. Claude Code playbook: `CLAUDE.md` +
`.claude/skills/` (see `docs/skills/README.md`). Pass a real checkout or URL.

## Setup

### 1. Build the scanner container

```bash
cd aegis-vanguard
docker build -t aegis-vanguard:latest -f Dockerfile ..
```

Build from the monorepo root so shared packages under `backend/packages/` are available.

### 2. Generate an API key on your ASM platform

```bash
# Via API (requires admin JWT token)
curl -X POST http://your-asm-platform:8000/api/v1/ingest/api-keys \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "aegis-vanguard-01", "agent_type": "aegis_vanguard"}'

# Save the returned api_key (starts with tfasm_) - it's only shown once
```

### 3. Run standalone tests

```bash
# Dry-run test (no API connection needed)
docker run --rm aegis-vanguard:latest python3 asm_bridge.py test

# Test against your platform
docker run --rm \
  -e ASM_API_URL=http://your-asm-platform:8000 \
  -e ASM_API_KEY=tfasm_YOUR_KEY_HERE \
  -e ASM_AGENT_ID=test-scanner-01 \
  aegis-vanguard:latest python3 asm_bridge.py test

# Run a real subdomain scan
docker run --rm \
  -e ASM_API_URL=http://your-asm-platform:8000 \
  -e ASM_API_KEY=tfasm_YOUR_KEY_HERE \
  aegis-vanguard:latest python3 -c "
from asm_bridge import ASMBridge
from scanners import run_subfinder
bridge = ASMBridge()
subs = run_subfinder('example.com', bridge)
print(f'Found {len(subs)} subdomains')
print(bridge.stats)
"
```

### 4. Run a full pentest

```bash
docker run --rm \
  -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  -e ASM_API_URL=http://your-asm-platform:8000 \
  -e ASM_API_KEY=tfasm_YOUR_KEY_HERE \
  -e AEGIS_MODEL=claude-sonnet-4-6 \
  aegis-vanguard:latest \
  --target https://example.com --scope example.com
```

See [DEPLOYMENT.md](./DEPLOYMENT.md) for local Python setup, compose examples, and the full env var reference.

## Production notes

#### API Key Rotation
- Create API keys with expiration dates
- Rotate keys periodically via the admin API
- Monitor key usage via `GET /api/v1/ingest/api-keys`

#### Multiple Agents
Deploy multiple scanner agents with different scopes:
```
aegis-vanguard-01: Subdomain enumeration + DNS
aegis-vanguard-02: Port scanning
aegis-vanguard-03: Vulnerability scanning
```

#### Monitoring
- Use the heartbeat endpoint for health checks
- Monitor `usage_count` and `last_used_at` on API keys
- Check ingestion batch responses for error rates

#### Network Security
- Run Aegis Vanguard containers in an isolated network
- Only allow outbound traffic to scan targets and the ASM platform
- Use TLS for all API communication

## Harness (batch + accuracy)

From the monorepo:

```bash
cd ../harness
pip install -e ".[dev]"
python -m local_harness.batch.run scan
python -m local_harness.benchmark.run
```

The harness sets `AEGIS_FINDINGS_SINK` so each `run_pentest.py` invocation
writes machine-readable `findings.jsonl` for judging. Details:
[harness/README.md](../harness/README.md).

## Files

| File | Purpose |
|------|---------|
| `asm_bridge.py` | Python client for the ASM platform ingestion API + optional findings sink |
| `scanners.py` | Wrappers around security scanning tools |
| `agent/` | ReACT agents, OWASP hunters, guardrails, parallel fireteam |
| `run_pentest.py` | Main ReACT pentest entrypoint |
| `CLAUDE.md` | Claude Code runbook (skills front door) |
| `.claude/skills/` | Thin playbook skills (`/aegis`, `/threat-model`, `/code-scan`, `/pentest`, `/triage`) |
| `docs/vanguard-system-card.md` | ReAct CLI agent system card |
| `validate_finding.py` | On-demand single-finding validator |
| `Dockerfile` | Container image with all scanning tools pre-installed |
| `DEPLOYMENT.md` | Local Python / compose / env reference |

## API Endpoints Used

| Method | Endpoint | Auth | Purpose |
|--------|----------|------|---------|
| `POST` | `/api/v1/ingest/findings` | API Key | Submit findings batch |
| `POST` | `/api/v1/ingest/heartbeat` | API Key | Agent health check |
| `POST` | `/api/v1/ingest/api-keys` | JWT | Create agent API key |
| `GET` | `/api/v1/ingest/api-keys` | JWT | List API keys |
| `DELETE` | `/api/v1/ingest/api-keys/{id}` | JWT | Revoke API key |
