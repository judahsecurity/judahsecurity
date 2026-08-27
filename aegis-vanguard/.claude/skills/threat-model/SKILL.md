---
name: threat-model
description: >-
  Build a durable threat model for a local checkout (or notes about a URL).
  Writes THREAT_MODEL.md + threat_model.json into results/<target>/<timestamp>/.
  Aims /code-scan and /pentest. Use when asked to threat-model, map attack
  surface, or decide where hunters should look. Not a vulnerability scan.
argument-hint: "[bootstrap|interview] <target-dir-or-url> [--fresh]"
allowed-tools:
  - Read
  - Glob
  - Grep
  - Write
  - Bash(python3 .claude/skills/_lib/run_dir.py:*)
  - Bash(git:*)
  - Bash(ls:*)
  - AskUserQuestion
---

# /threat-model

The map, not the metal detector. A threat still stands after a one-line patch;
a CVE at a line number does not. Produce threats. Do not execute target code.

**Invoke:** `/threat-model [bootstrap|interview] <target> [--fresh]`

- `bootstrap` (default) — inventory the checkout (or URL notes). No owner required.
- `interview` — ask the four questions below, then merge onto bootstrap if a
  model already exists in the latest run dir.
- `--fresh` — mint a new timestamped dir instead of resuming the latest.

`<target>` is whatever the operator named (absolute path or URL). Do not fall
back to a bundled demo app.

## Run directory

```bash
python3 .claude/skills/_lib/run_dir.py mint <target-basename> [--fresh]
```

Use the printed path for every write. Schema: [schema.md](schema.md). Read it
before writing files.

## Bootstrap (static)

If `<target>` is a directory, read the tree. Skip `node_modules`, `.git`,
`.venv`, `dist`, `vendor`, `results`.

1. Languages, frameworks, entry points (routes, parsers, CLIs, jobs, webhooks).
2. Rank actor → outcome rows. Describe **shapes** (untrusted input becomes
   query/template syntax; identifier trusted as authz; secret in a public
   bundle). Not a CWE checklist.
3. Partition 3–6 focus areas with a specialist name and surfaces.
4. List open questions. Do not invent owner intent.

If `<target>` is a URL, work from the operator's notes / pasted
HTML / headers / JS (offline — live fetching is `/pentest`'s job, after
authorization). Read [../_lib/curiosity.md](../_lib/curiosity.md) and turn each
observed surface into a **hypothesis**: bug class + the one signal that would
confirm it. Rank with the map's rank-then-hunt order. Each hypothesis becomes a
Threat row (surface + shape) and feeds a Focus area. Same artifact schema.

## Interview

Ask only: (1) what must not leak, (2) who is in scope as an actor, (3) where
trust boundaries sit, (4) what is explicitly out of scope. Merge answers into
the model; do not restart from a blank page if `THREAT_MODEL.md` exists.

## Write

- `THREAT_MODEL.md` — headings in [schema.md](schema.md)
- `threat_model.json` — same fields as `backend/app/services/agent/threat_model.py`

Stop. Do not run Semgrep, Nuclei, or `/code-scan` unless the operator asks.
Next: `/code-scan <dir>` (checkout) or `/pentest <url>` (live).
