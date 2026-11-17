---
name: aegis
description: >-
  Front door for the Aegis Vanguard Claude Code runbook. Empty args: 30-second
  orientation and the next skill. With a question: answer from this repo's
  CLAUDE.md, docs/skills, and skills — cite paths. Use for "how do I",
  "where is", "run a playbook", or just /aegis.
argument-hint: "[question]   (blank = intro)"
allowed-tools:
  - Read
  - Glob
  - Grep
  - AskUserQuestion
---

# /aegis

Two modes. `$ARGUMENTS` empty → intro. Otherwise → help.

## Intro

Keep it short.

> Aegis is a staged offensive playbook. You are the operator. This session
> aims, finds, and verifies. Cycle:
> `/recon` (live) → `/threat-model` → `/code-scan` (checkout) or `/pentest`
> (live URL, executed by Prowl) → `/triage` → `/chain`.
> Artifacts land in `results/<target>/<timestamp>/` under aegis-vanguard.
> Live skills need a scope file. Prowl (the platform agent) is reached with
> `prowl_client.py` (`AEGIS_API_URL`, `AEGIS_API_TOKEN`); medium+ needs a
> Prowl proof kind (`data/vuln_classes.json`).
> There is no bundled canary — pass the path or URL you are authorized to test.

Ask which path (AskUserQuestion):

1. **Local checkout** (static) → they give the directory, then
   `/threat-model bootstrap <dir>` then `/code-scan <dir>`
2. **Live URL** (authorized) → they give the URL and a scope file, then
   `/recon <url> --scope-file <f>` then `/pentest <url> --scope-file <f>`
3. **I'll read** → point at `CLAUDE.md` and `docs/skills/README.md`, stop

Do not start a scan from intro. Do not invent a target.

## Help

Read, in order, only what the question needs:

- `CLAUDE.md`
- `docs/skills/README.md`
- `.claude/skills/README.md`
- `.claude/skills/triage/gate.md` (verdict rules, never-submit, chain table)
- `prowl_client.py --help` (Prowl endpoints and API gaps)

Cite file paths. End with one next command (`/threat-model bootstrap <dir>`,
`/recon <url> --scope-file <f>`, `/pentest <url> --scope-file <f>`,
`/triage <run-dir>`, `/chain <run-dir>`, or `python3 prowl_client.py status`). Do not dump tool catalogs.
