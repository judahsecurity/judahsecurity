# Aegis Vanguard — ASM Scanner Agent

An AI-powered Attack Surface Management agent that runs as a standalone CLI or
Docker container and reports findings back to The Force Security ASM platform.

## Architecture

```
┌─────────────────────────────────────┐     ┌──────────────────────────────────┐
│       Aegis Vanguard Container      │     │     ASM Platform                 │
│                                     │     │                                  │
│  Claude Agent (ReACT pipeline)      │     │  POST /api/v1/ingest/findings    │
│       │                             │     │       │                          │
│       ▼                             │     │       ▼                          │
│  scanners.py                        │────▶│  Ingestion Service               │
│  (subfinder, naabu, nuclei, etc.)   │     │       │                          │
│       │                             │     │       ▼                          │
│       ▼                             │     │  Assets, Vulns, Ports → Postgres │
│  asm_bridge.py (API client)         │     │       │                          │
│                                     │     │       ▼                          │
│  CLAUDE.md (agent instructions)     │     │  Dashboard (Next.js)             │
└─────────────────────────────────────┘     └──────────────────────────────────┘
```

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

## Files

| File | Purpose |
|------|---------|
| `asm_bridge.py` | Python client for the ASM platform ingestion API |
| `scanners.py` | Wrappers around security scanning tools |
| `CLAUDE.md` | Instructions for the Aegis Vanguard Claude agent |
| `run_pentest.py` | Main ReACT pentest entrypoint |
| `validate_finding.py` | On-demand single-finding validator |
| `Dockerfile` | Container image with all scanning tools pre-installed |

## API Endpoints Used

| Method | Endpoint | Auth | Purpose |
|--------|----------|------|---------|
| `POST` | `/api/v1/ingest/findings` | API Key | Submit findings batch |
| `POST` | `/api/v1/ingest/heartbeat` | API Key | Agent health check |
| `POST` | `/api/v1/ingest/api-keys` | JWT | Create agent API key |
| `GET` | `/api/v1/ingest/api-keys` | JWT | List API keys |
| `DELETE` | `/api/v1/ingest/api-keys/{id}` | JWT | Revoke API key |
