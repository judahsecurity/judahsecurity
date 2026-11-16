# Aegis Claude Code skills

Run this like Glasswing: open the harness folder in Claude Code, invoke slash
skills, point them at **your** checkout or URL. No bundled canary.

```bash
cd aegis-vanguard
claude
# then:
/aegis
/threat-model bootstrap /path/to/their/app
/code-scan /path/to/their/app
/triage results/<app-basename>/<timestamp>/
```

Live (authorized URL). Write a scope file first (format in
`.claude/skills/_lib/scope.py`: exact hosts, `*.root` wildcards, `!exclusions`):

```
export AEGIS_API_URL=http://localhost:8000      # platform; /api/v1 optional
export AEGIS_API_TOKEN=<user JWT access token>  # from POST /api/v1/auth/login
/recon   https://app.example.com --scope-file scope.txt
/pentest https://app.example.com --scope-file scope.txt
/triage  results/app.example.com/<timestamp>/ --reprobe --scope-file scope.txt
/chain   results/app.example.com/<timestamp>/
```

`/pentest` hands execution to **Prowl** (the platform agent) through
`prowl_client.py`: Prowl owns the scoped browser, OOB callbacks, deterministic
proof probes, the independent verifier and the publication gate. curl in the
session is for leads only. `--local` hunts without Prowl (medium+ stays
`improve`). `--cli` runs `python3 run_pentest.py --target …` instead.

## Cycle

```
/aegis → /recon (live, scoped) → /threat-model
       → /code-scan  (checkout, static; Claude is the scanner)
       → /pentest    (live URL; Prowl executes)
       → /triage     (gate + root-cause dedup + Prowl re-probe)
       → /chain      (chain-required table; end-to-end proof only)
```

## Shared class list and gate

`data/vuln_classes.json` is generated from Prowl's
`backend/app/services/agent/proof_policy.py:PROOFS_BY_CLASS` and
`vulnerability_catalog.py` coverage classes:

```bash
python3 scripts/sync_vuln_classes.py          # regenerate
python3 scripts/sync_vuln_classes.py --check  # CI drift check
```

`tests/test_vuln_classes_sync.py` asserts the JSON matches the backend when the
backend is importable (skips otherwise). Rule shared with Prowl: medium or
above only with a proof kind for the class; classes without proof kinds and
`known_cve` cap at low. Gate details: `.claude/skills/triage/gate.md`
(validation discipline adapted from elementalsouls/Claude-BugHunter, CC BY 4.0).

## prowl_client.py endpoints

| Command | Endpoint (under `/api/v1`) | Auth |
|---------|----------------------------|------|
| `status` | `GET /agent/status` | none |
| `asset --host` | `GET /assets/?search=&in_scope=true` | JWT |
| `start` | `POST /agent/query` (`mode=agent`, `target`, `playbook_id`, `assessment_policy`) | JWT |
| `start --executor` | `POST /agent/scoped-assessments` (legacy scoped executor) | JWT |
| `poll` | `GET /agent/conversations/{sid}`, `GET /agent/conversations/{sid}/ledger` | JWT |
| `findings` | `GET /vulnerabilities/?asset_id=&detected_by=agent_family` | JWT |
| `verify` | `POST /agent/query` with `playbook_id=finding_validation` + redacted packet | JWT |
| `verdict` | ledger receipts (`create_finding` published / `independent_verify`) | JWT |
| `stop` | `POST /agent/sessions/{sid}/stop` | JWT |
| `tool` | `POST /mcp/call` (subfinder, dnsx, httpx, katana, waybackurls; scope-checked) | JWT |
| `classes` | local `data/vuln_classes.json` | — |

### API gaps (documented, not invented)

1. **No external candidate intake to Prowl's verifier.** Candidates and the
   verifier capability live inside a Prowl session (`submit_candidate`,
   `independent_verify`); no REST route accepts a Vanguard candidate.
   `verify` asks Prowl to reproduce from scratch via the `finding_validation`
   playbook. With `playbook_id`, the backend keeps only the text after
   `Operator note:` (≤4000 chars), so the packet is trimmed and redacted.
2. **`POST /prowl/findings` is not usable by Vanguard.** It requires the
   `PROWL_INGEST_KEY` service key and paired hunter/verifier observations with
   run/candidate/verification IDs produced by the scoped executor. Vanguard
   must not fabricate those.
3. **No endpoint exposes `PROOFS_BY_CLASS` or coverage classes**; hence the
   synced JSON.
4. **Findings are not linked to a session in the list API**
   (`VulnerabilityResponse` has no session id); per-run results come from the
   ledger receipts, per-asset results from `/vulnerabilities`.
5. **JWT only.** `/agent/*` uses user access tokens (expire); ingest API keys
   (`tfasm_…`) are not accepted. `/agent/status` and `/agent/playbooks` are
   unauthenticated.
6. **No per-probe REST.** Browser, OOB and scoped proof probes are agent tools
   only; `/mcp/call` exposes CLI wrappers (nuclei, httpx, curl …), not proofs.
7. `POST /ingest/findings` (API key) bypasses the gate; do not use it for
   medium+ Vanguard findings.

## Requirements

- Claude Code CLI, launched from `aegis-vanguard/`
- Local path: a checkout the operator names. Nothing else for `/threat-model`.
- Live path: authorization, a scope file, `curl` on `$PATH`; `AEGIS_API_URL` +
  `AEGIS_API_TOKEN` for Prowl. `ANTHROPIC_API_KEY` if using `--cli`.
  Optional local recon tools: subfinder, dnsx, httpx, katana.

## Run directories

Outputs go to `aegis-vanguard/results/<target>/<timestamp>/` (gitignored).
Repeat runs resume the latest dir unless `--fresh`.

## Size rule

`SKILL.md` stays under 150 lines. Methodology lives in sibling files
(`schema.md`, `researchers.md`, `gate.md`), `_lib/*.py`, or Python
(`run_pentest.py`, `prowl_client.py`).
Do not grow skills by pasting platform playbooks.

## Platform agent (optional)

In-product Joshua is a different harness:

```bash
cd ../backend
python -m app.cli run --target https://app.example.com --playbook tester_process
```
