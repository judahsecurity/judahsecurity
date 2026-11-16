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
| `verify` (live session) | `POST /agent/sessions/{sid}/candidates`, then `POST /agent/query` (resume `sid`) when idle (201), or `POST /agent/sessions/{sid}/steer` when the run is active (202 `queued`; `mode=intake_queued`) | JWT |
| `verify` (fallback) | `POST /agent/query` with `playbook_id=finding_validation` + redacted packet | JWT |
| `candidates` | `GET /agent/sessions/{sid}/candidates` | JWT |
| `verdict` | candidate status from `candidates` when intake was used; else ledger receipts | JWT |
| `stop` | `POST /agent/sessions/{sid}/stop` | JWT |
| `tool` | `POST /mcp/call` (subfinder, dnsx, httpx, katana, waybackurls; scope-checked) | JWT |
| `classes` | local `data/vuln_classes.json` | — |
| `classes --remote` | `GET /agent/proof-classes` | JWT |

### Candidate intake (closed gap)

`POST /agent/sessions/{sid}/candidates` (JWT; owner user + org of that
conversation, agent-mode sessions only) takes
`{title, target, vulnerability_class, description, claimed_request (<=2000),
severity, parameter?, evidence_note?}`:

- `target` must be inside the session's scope (the session's saved seed,
  checked with `assessment_scope.assert_url_in_scope`); `vulnerability_class`
  must be a `PROOFS_BY_CLASS` key (resolve aliases client side).
- The candidate is appended as **pending** through `submit_candidate` with
  `specialist=vanguard_external`, no `evidence_ids` and empty `evidence`.
  Text is length-capped, control characters stripped, and wrapped in
  `[OPERATOR-SUPPLIED CANDIDATE CLAIM ...]` markers because the verifier LLM
  sees it. Severity is capped at `low` for `known_cve` and classes with no
  proof kind.
- An existing candidate with the same id or root cause is reported as
  `duplicate_of` and left untouched: external text cannot reopen or rewrite a
  session verdict. At most 25 external candidates per session (429).
- Persistence: the brain lives in LangGraph state during a run and in the run
  snapshot (`run_snapshot.py`, `~/.aegis/sessions` or the DB for `sched-`
  sessions) between runs; every resume restores it from that snapshot. Idle
  intake writes the snapshot (**201**). While a run is active the same
  validation runs, then the wrapped payload goes into the session's
  durable candidate inbox (`run_control`: written through to
  `~/.aegis/sessions/{org}_{sid}.inbox.jsonl` before the response, with an
  in-memory cache) and the route returns **202** `{accepted, queued: true, next_step}`. The
  orchestrator drains the inbox where it drains steers (start of each think
  turn), submits each item through the same `submit_candidate` path into the
  live brain, and records an `external_candidate_intake` trace step plus a
  `candidates_ingested` status event; a root-cause duplicate found at drain
  time is reported as `duplicate_of` and not modified. The 25 cap counts
  queued items, including ones left on disk by an earlier process. **409** only
  when the session has no snapshot/target. Delivery is at-least-once: an item
  is removed from the inbox only after the run snapshot holding it is saved; a
  re-delivered item merges as a duplicate (never inserted twice). A backend
  restart before the drain keeps the item; the next think turn of the resumed
  run (same `session_id`) drains it. A run ending without a drain also keeps it.
  The file lock covers one host; `sched-` sessions are checked against their DB
  snapshot but their inbox is still the file on the host that ran them.
- Nothing is confirmed by intake. Resuming an idle session (`POST /agent/query`,
  same `session_id`), or the live run after the inbox drains, lets Prowl verify it: the tester loop forces
  `independent_verify` for pending `sql_injection`/`xss`; for other classes the
  resume note (or, for a running session, a steer) names the candidate id. Deterministic replays need a hunter
  receipt from that session; without one the class is re-hunted or the LLM
  verifier attempts it, and `inconclusive` is expected.

`GET /agent/sessions/{sid}/candidates` lists id, title, class, severity,
status, verifier_summary, root_cause, duplicate_titles (no evidence bodies,
nonces or requests) from the last snapshot, plus undrained inbox items with
status `queued`, plus `run_in_progress`. `verdict` maps `queued` to `pending`.

`GET /agent/proof-classes` returns `PROOFS_BY_CLASS` (sorted kinds), coverage
classes with their proof class and lane, `severity_caps` and
`non_confirmable`. `data/vuln_classes.json` stays as the offline copy.

### Remaining API gaps (documented, not invented)

1. **`POST /prowl/findings` is not usable by Vanguard.** It requires the
   `PROWL_INGEST_KEY` service key and paired hunter/verifier observations with
   run/candidate/verification IDs produced by the scoped executor. Vanguard
   must not fabricate those. Use candidate intake instead.
2. **Candidate inbox is single-host.** Intake into a running session is queued
   (202) in a file-locked inbox beside the run snapshot and survives restarts,
   but backends on several hosts do not share it (no DB inbox table yet).
   Without a live session `verify` uses the `finding_validation` playbook; with
   `playbook_id` the backend keeps only the text after `Operator note:`
   (<=4000 chars), so that packet is trimmed and redacted.
3. **Findings are not linked to a session in the list API**
   (`VulnerabilityResponse` has no session id); per-run results come from the
   ledger receipts and `candidates`, per-asset results from `/vulnerabilities`.
4. **JWT only.** `/agent/*` uses user access tokens (expire); ingest API keys
   (`tfasm_…`) are not accepted. `/agent/status` and `/agent/playbooks` are
   unauthenticated.
5. **No per-probe REST, by design.** Browser, OOB and scoped proof probes run
   only inside a Prowl session, where coverage leases, scope, operator write
   approvals and budget apply. Exposing them over REST would bypass all four.
   Reach them with `start` (or an existing session) + candidate intake +
   resume. `/mcp/call` exposes CLI recon wrappers, not proofs.
6. `POST /ingest/findings` (API key) bypasses the gate; do not use it for
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
