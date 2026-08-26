---
name: code-scan
description: >-
  White-box security audit of a local checkout. Claude is the scanner (same
  shape as Glasswing /ccsec-detection): map the app, spawn researchers on
  threat-model focus areas, adversarially verify, write findings. Use for
  code-scan, SAST, source audit. Do not execute target binaries.
argument-hint: "<target-dir> [--fresh]"
allowed-tools:
  - Read
  - Glob
  - Grep
  - Write
  - Task
  - Bash(python3 .claude/skills/_lib/run_dir.py:*)
  - Bash(ls:*)
  - Bash(rg:*)
---

# /code-scan

You are the scanner in this session. Static only: Read / Glob / Grep / Task.
Do not run the target, its tests, its Docker image, or a second LLM CLI.

**Invoke:** `/code-scan <target-dir> [--fresh]`

`<target-dir>` is the operator's checkout. Do not substitute a demo app.

## Run directory

```bash
python3 .claude/skills/_lib/run_dir.py mint <target-basename> [--fresh]
```

If `THREAT_MODEL.md` is missing in that dir, stop and tell them to run
`/threat-model bootstrap <dir>` first. Read [researchers.md](researchers.md)
before spawning Task agents.

## Hunt

1. Map architecture from the checkout (languages, entry points, auth, data
   stores). Skip `node_modules`, `.git`, `.venv`, `dist`, `vendor`.
2. Allocate researchers to **focus areas in the threat model**, not a CWE walk.
   Spawn Task subagents in parallel. They must not execute target code.
3. Each candidate needs a concrete exploit scenario (who, where, what happens).
   No "might be bad."
4. Adversarial pass (orchestrator): try to refute each candidate (unreachable,
   mitigated one layer up, docs-only, duplicate). Refuted hits are not findings.

Optional tools if already installed: Semgrep / Gitleaks. Skip quietly if missing.
Keep a hit only if it instantiates a threat row.

## Write

`findings.json` — objects: `id`, `title`, `severity`, `location` (path + symbol),
`category`, `threat_id`, `evidence`, `exploit_scenario`, `confirmed` (false until
`/triage`).

Also `VULN-FINDINGS.md` and `tested_clean.json` (surfaces reviewed with no hit).

Stop. Next: `/triage results/<target>/<ts>/`.
