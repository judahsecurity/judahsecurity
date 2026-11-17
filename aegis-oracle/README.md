# Aegis Oracle

**Aegis Oracle** is a practical exploitability scoring engine for your ASM platform. It enriches CVE findings with structured precondition analysis, reconciles CVSS scoring discrepancies across sources, and produces the **Oracle Practical Exploitability Score (OPES)** — a deterministic 0–10 score that reflects real-world exploitability, not theoretical severity.

## Why it exists

NVD rated CVE-2025-55130 as Critical (9.1, AV:N). Aegis Oracle scores it **OPES 4.2 / P3 Conditional** — because the exploit requires Node.js permission-model flags that aren't active in most Express apps, plus in-process JavaScript execution. Both preconditions are unverifiable from external HTTP probing. Until they're verified, the finding is capped at P3 with actionable verification tasks filed automatically.

That gap — between NVD's theoretical severity and practical exploitability — is what this bot closes.

## How it works

```
CVE sources         Phase A (LLM)              Phase B (rules)         OPES (math)
──────────────  →   ──────────────────────  →  ─────────────────  →  ──────────────
cvelistV5           Extract preconditions       Match preconditions    6-component
NVD, OSV, KEV       Reconcile CVSS vectors      against asset          score 0–10
EPSS, HackerOne     Attack chain summary        signals               → P0..P4
PoC indexers        (cached, content-hashed)    sat / unsat / unknown  + verification
                                                                        tasks
```

The LLM **never emits a score**. It extracts structured facts (preconditions, CVSS reconciliation, attack chain). OPES math converts those facts into a score deterministically — same inputs always produce the same score.

## Architecture

```
cmd/
  aegis-oracle/          # daemon (HTTP API + pipeline)
  aegis-oracle-cli/      # analyst CLI (analyze + kb commands)
internal/
  pipeline/              # orchestrates Phase A → B → OPES → store
  modules/reasoners/
    intrinsic/           # Phase A: LLM-based CVE analysis
    contextual/          # Phase B: precondition evaluation
    priority/opes/       # OPES deterministic scoring
  llm/                   # Anthropic + OpenAI provider abstraction
  knowledgebase/         # YAML loader + validator
  store/pg/              # Postgres adapter (reads ASM assets, writes findings)
knowledgebase/
  cwe/                   # Curated CWE profiles (CWE-22, CWE-59, ...)
  patterns/              # Exploitable dev patterns per ecosystem
pkg/
  schema/                # Shared types (CVE, Asset, Finding, OPES, ...)
  module/                # Module interfaces (Source, Enricher, Reasoner, Sink)
```

## Prerequisites

- Go 1.23+
- Postgres 15+ (shared with your ASM platform)
- Anthropic or OpenAI API key

## Quick start

### 1. Install Go

```bash
mkdir -p ~/.local
curl -Lo /tmp/go.tar.gz https://go.dev/dl/go1.24.2.darwin-arm64.tar.gz
tar -C ~/.local -xzf /tmp/go.tar.gz
echo 'export PATH="$HOME/.local/go/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc
go version
```

### 2. Get dependencies

```bash
cd ~/code/aegis-oracle
go mod download
```

### 3. Run tests

```bash
go test ./...
# opes, contextual, knowledgebase tests should all PASS
```

### 4. CLI — score a single CVE against an asset (no DB needed)

```bash
go build -o bin/aegis-oracle-cli ./cmd/aegis-oracle-cli

./bin/aegis-oracle-cli analyze \
  --intrinsic   examples/cve-2025-55130/intrinsic.json \
  --asset       examples/cve-2025-55130/asset.json \
  --cve         examples/cve-2025-55130/cve.json \
  --exploitation examples/cve-2025-55130/exploitation.json \
  --pretty --human
```

Expected: **OPES 4.2 / P3 Conditional** with two unknown-blocker verification tasks.

### 5. Validate the knowledge base

```bash
./bin/aegis-oracle-cli kb validate
./bin/aegis-oracle-cli kb stats
./bin/aegis-oracle-cli kb show CWE-22
./bin/aegis-oracle-cli kb pattern nodejs.permissions-symlink-escape
```

### 6. Apply DB migrations

```bash
psql "$DATABASE_URL" -f internal/store/migrations/0001_initial.sql
```

This creates the `oracle` schema inside your ASM database with all findings, intrinsic analysis, and verification task tables.

### 7. Configure the daemon

```bash
cp cmd/aegis-oracle/config.yaml config.local.yaml
# Edit config.local.yaml: fill in db.dsn, llm.anthropic.api_key or llm.openai.api_key
```

Or use environment variables:

```bash
export ORACLE_DB_DSN="postgres://oracle:password@localhost:5432/asm"
export ANTHROPIC_API_KEY="sk-ant-..."
# or
export OPENAI_API_KEY="sk-..."
```

### 8. Run the daemon

```bash
go build -o bin/aegis-oracle ./cmd/aegis-oracle
./bin/aegis-oracle -config config.local.yaml
# Listening on :8742
```

### 9. Trigger an analysis via the API

```bash
# Score CVE-2025-55130 on asset ftds-tenant-prod-7421
curl -s -X POST http://localhost:8742/analyze \
  -H "Content-Type: application/json" \
  -d '{"cve_id":"CVE-2025-55130","asset_id":"ftds-tenant-prod-7421"}' | jq .

# List all open findings
curl -s http://localhost:8742/findings | jq .

# Filter by category
curl -s "http://localhost:8742/findings?cve_id=CVE-2025-55130" | jq .

# Health check
curl -s http://localhost:8742/health
```

## ASM integration

Aegis Oracle writes findings to the `oracle.findings` table inside your shared ASM Postgres database. Your ASM UI can query this directly:

```sql
-- Open findings by priority, highest first
SELECT
  f.cve_id,
  f.asset_id,
  f.opes_category,
  f.opes_score,
  f.opes_label,
  f.recommendation_text,
  f.opes_dampener,
  f.created_at
FROM oracle.findings f
WHERE f.status = 'open'
ORDER BY f.opes_score DESC, f.created_at DESC;

-- Verification tasks needing action
SELECT
  vt.finding_id,
  vt.precondition_id,
  vt.task_kind,
  vt.command,
  vt.expected_signal_path
FROM oracle.verification_tasks vt
WHERE vt.status = 'open'
ORDER BY vt.created_at DESC;
```

The `asset_table` config key points Aegis Oracle at your existing asset inventory — no data migration needed.

## OPES scoring

| Component | Weight | What it measures |
|---|---|---|
| **X** — Active exploitation | 0.25 | KEV listing, inthewild observations, PoC recency |
| **P** — Preconditions | 0.20 | Fraction of blockers satisfied vs unknown |
| **R** — Reachability | 0.15 | Network reach per AV vector + asset exposure |
| **E** — Exploit difficulty | 0.15 | AC vector, attacker capability, blocker count (inverted) |
| **C** — Asset criticality | 0.15 | Blast radius if compromised |
| **T** — Time pressure | 0.10 | Days since disclosure + patch availability |

**Overrides and verdicts** (deterministic, not weighted):
- CVE in **KEV** (X ≥ 9.0) → floor at 8.5, "Actively Exploited"
- Any blocker precondition **unsatisfied** → `contextual_assessment.state = documented_path_blocked`. OPES itself is not zeroed (alternate paths aren't ruled out); the ASM risk model reads the blocked blocker and sets exploit realism to **blocked** (likelihood 0) with the observed value as evidence.
- Asset **isolated** → reachability R = 0
- Any blocker precondition **unknown** → confidence drops to low and a dampener note is added; the score is *not* lowered for missing evidence, and nothing is ever called safe because a check couldn't run.

Weights, thresholds, and bucketing are all configurable per deployment in `config.yaml → opes`.

## Host checks (resolving preconditions from inside the server)

Many blockers live inside the host — regreSSHion (CVE-2024-6387) needs sshd
running **and** a non-zero `LoginGraceTime`; a banner can't show either.
Phase A writes those preconditions against `host.*` signals:

| Signal | Meaning |
|---|---|
| `host.os.id`, `host.os.version_id`, `host.kernel.release` | OS and kernel |
| `host.package.<name>` / `.installed` | installed package version / presence |
| `host.process.<name>.running` / `.args` | running process / its command line |
| `host.sshd.<keyword>` | effective sshd config (`sshd -T`) |
| `host.sysctl.<key>`, `host.listening.tcp` | kernel settings, listening ports |

The ASM backend collects them with a read-only SSH login and a fixed probe
catalog (`backend/app/services/host_evidence_service.py`), or accepts them
pushed from osquery/EDR, and sends them inline as `signals.host`. Evidence is
recorded per probe (`signal_evidence["host.sshd.*"]`) and must be fresh and
scoped to the asset. A probe or login that fails is recorded as an error, and
Phase B reports `could not check <signal>: <why>`, never "not exploitable".
Unknown host preconditions produce `host_probe` verification tasks, which the
backend's `/host-checks` routes resolve and re-score without a person.

Worked example — one CVE, three servers:

```bash
for h in 12 07 03; do
  ./bin/aegis-oracle-cli analyze --intrinsic examples/cve-2024-6387/intrinsic.json \
    --asset examples/cve-2024-6387/asset-lnx-web-$h.json --cve examples/cve-2024-6387/cve.json \
    --exploitation examples/cve-2024-6387/exploitation.json --human
done
```

- `lnx-web-12`: sshd running, `logingracetime 120` → every condition met
- `lnx-web-07`: `logingracetime 0` → `value "0" did not match` → documented path blocked
- `lnx-web-03`: SSH login rejected → both conditions unknown, "could not check … authentication rejected"

## Knowledge base

The `knowledgebase/` directory is the institutional memory of the bot:

- `cwe/<CWE-ID>.yaml` — how a weakness class manifests in production code per ecosystem
- `patterns/<pattern-id>.yaml` — specific exploitable patterns with reusable precondition IDs

Phase A uses KB entries as priors, so the LLM reasons about CVE-2025-55130 knowing "this CWE-22/CWE-59 combination in Node.js is the permission-model symlink escape pattern" rather than deriving it cold.

Add new patterns via PR. The loader validates required fields at startup and in CI.

```bash
# Validate after adding a pattern
./bin/aegis-oracle-cli kb validate
```

## Project status

| Component | Status |
|---|---|
| OPES scoring engine | ✅ Production-ready with golden tests |
| Phase B contextual evaluator | ✅ Production-ready |
| Knowledge base (CWE-22, CWE-59, Node.js patterns) | ✅ Seeded |
| Phase A intrinsic reasoner (LLM) | ✅ Wired — needs API key |
| Postgres store + migrations | ✅ Ready to apply |
| Daemon + HTTP API | ✅ Ready to run |
| CLI | ✅ analyze + kb commands |
| CVE ingest pipeline (cvelistV5, NVD, EPSS, KEV) | 🔜 Phase 2 |
| Asset fingerprinting (Tier 2+) | 🔜 Phase 2 |
| Verification loop — host checks (`host_probe` tasks) | ✅ Backend `/host-checks` |
| Verification loop — ticketing (Linear/Jira/Slack) | 🔜 Phase 2 |
