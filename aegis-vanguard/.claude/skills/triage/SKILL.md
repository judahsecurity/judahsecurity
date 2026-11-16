---
name: triage
description: >-
  Independent verify of findings.json in a results/<target>/<timestamp>/
  directory. Applies the 7-question gate and discipline rules in gate.md,
  dedups by root cause, re-probes live candidates through Prowl's verifier
  (prowl_client.py verify), and writes TRIAGE.md + verdicts.json
  (confirmed|refuted|improve). Use after /code-scan, /pentest or /recon, or
  when asked to triage, judge, or independently verify findings. Do not read
  hunter transcripts.
argument-hint: "<results-dir> [--reprobe] [--scope-file <file>]"
allowed-tools:
  - Read
  - Glob
  - Grep
  - Write
  - AskUserQuestion
  - Bash(python3 .claude/skills/_lib/dedup.py:*)
  - Bash(python3 .claude/skills/_lib/scope.py:*)
  - Bash(python3 prowl_client.py:*)
---

# /triage

You are a fresh reviewer. If it is not in the run directory (or a Prowl
verifier receipt for it), it did not happen.

**Invoke:** `/triage results/<target>/<timestamp>/ [--reprobe] [--scope-file <file>]`

## Inputs

Read only:

- `findings.json` (required)
- `THREAT_MODEL.md` / `threat_model.json` if present (severity calibration)
- `tested_clean.json`, `coverage.json`, `recon.json`, `chains.json` if present
- `prowl_verify/*.json`, `prowl/*.json` (Prowl receipts) and short evidence files
- `data/vuln_classes.json` (class aliases and proof kinds)

Do **not** read Claude chat, hunter traces, or files outside the run dir except
[gate.md](gate.md) and `data/vuln_classes.json`. Read gate.md before scoring.

## 1. Dedup by root cause (before scoring)

```bash
python3 .claude/skills/_lib/dedup.py <run-dir>/findings.json --out <run-dir>/clusters.json
```

Clusters key on (class, normalized endpoint, parameter/sink), never the title.
Score each cluster's `primary`; every other member is `refuted` with
`duplicate_of: <primary>`. If two clusters look like one bug (same sink,
different route alias), say so in TRIAGE.md but keep them separate unless the
artifacts show the same code path.

## 2. Score each primary

Apply gate.md in order: logical sanity → 7 questions → class proof → discipline
rules → never-submit list → chain-required table.

- medium+ needs a Prowl proof kind for its class (`data/vuln_classes.json`).
  `known_cve` and classes with `confirmable: false` cap at `low`.
- Never-submit rows without a demonstrated chain are `refuted`. If a chain looks
  plausible, say "run `/chain <run-dir>`" in the reason.

## 3. Re-probe through Prowl (`--reprobe`, live findings only)

Only for `improve` candidates with a live endpoint, a class that has proof
kinds, and operator authorization. Confirm authorization with AskUserQuestion
if `--reprobe` was not passed. Check scope first:

```bash
python3 .claude/skills/_lib/scope.py check <scope-file> <endpoint>
python3 prowl_client.py verify --run-dir <run-dir> --finding-id <id> \
    --target <origin> --scope-file <scope-file> [--session <prowl_session>]
python3 prowl_client.py poll --session <session_id> --wait --run-dir <run-dir>
python3 prowl_client.py candidates --session <session_id>   # status, no evidence bodies
python3 prowl_client.py verdict --run-dir <run-dir> --finding-id <id>
```

With a live Prowl session (`--session`, or `prowl_run.json` from `/pentest`),
`verify` queues the finding as a **pending** candidate in that session
(`POST /agent/sessions/S/candidates`) and resumes it so Prowl's own
`independent_verify` runs with fresh in-session receipts. The intake never
confirms anything; the claim is labeled operator-supplied, untrusted text.
Without a hunter receipt in that session, deterministic classes are re-hunted
or the LLM verifier attempts them, so `inconclusive` is a normal answer. If the
session is busy, cold or the class is unknown, `verify` falls back to the
`finding_validation` playbook (Prowl reproduces from scratch). `verdict` reads
the candidate status when intake was used, else the ledger. Map the receipt:

| Prowl verdict | Your status |
|---------------|-------------|
| `confirmed` (verifier / published) | `confirmed` — cite `prowl_verify/<id>.json` |
| `refuted` (control exchange recorded) | `refuted` |
| `improve` / inconclusive | `improve` with Prowl's missing test as `next_step` |
| `pending` | `improve`, next_step = re-run `verdict` later |

Without AEGIS_API_URL / AEGIS_API_TOKEN, or for static `/code-scan` findings, do
not re-probe: mark `improve` with a concrete `next_step` (exact request,
identity pair, marker, trial count, or the `verify` command above).

Do not run curl or exploits yourself. Do not add new vulns.

## Write

`verdicts.json`:

```json
[{ "finding_id": "", "status": "confirmed|improve|refuted",
   "vuln_class": "", "severity": "", "reasoning": "",
   "gate_failed": "Q6|marker|timing|layer|never_submit|chain|null",
   "next_step": "", "duplicate_of": null, "prowl_receipt": null }]
```

`TRIAGE.md`: table of id / class / severity / status / one-line reason; then
clusters merged, drops, and the `next_step` for each `improve`. Redact secrets.

Stop. Next: `/chain <run-dir>` if two or more confirmed rows could link, else
report. No `/pentest` unless the operator asks to re-test.
