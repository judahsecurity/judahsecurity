---
name: triage
description: >-
  Independent verify of findings.json in a results/<target>/<timestamp>/
  directory. Writes TRIAGE.md + verdicts.json (confirmed|refuted|improve).
  Use after /code-scan or /pentest, or when asked to triage, judge, or
  independently verify findings. Do not read hunter transcripts.
argument-hint: "<results-dir>"
allowed-tools:
  - Read
  - Glob
  - Grep
  - Write
---

# /triage

You are a fresh reviewer. If it is not in the run directory, it did not happen.

**Invoke:** `/triage results/<target>/<timestamp>/`

## Inputs

Read only:

- `findings.json` (required)
- `THREAT_MODEL.md` / `threat_model.json` if present (severity calibration)
- `tested_clean.json`, `coverage.json` if present
- short evidence files in that directory

Do **not** read Claude chat, hunter traces, or files outside the run dir except
[gate.md](gate.md). Read gate.md before scoring.

## Score each finding

Verdicts: `confirmed` | `improve` | `refuted`.

Write `verdicts.json`: `[{ "finding_id", "status", "reasoning" }]`.

Write `TRIAGE.md`: table of id / title / status / one-line reason, then drops
and what would make each `improve` into `confirmed`.

Do not add new vulns. Do not run live exploits. If proof requires a live
re-probe, mark `improve` and say which request is missing.

Stop. No `/pentest` unless the operator asks to re-test.
