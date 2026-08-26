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
> `/threat-model` → `/code-scan` (checkout) or `/pentest` (live URL) → `/triage`.
> Artifacts land in `results/<target>/<timestamp>/` under aegis-vanguard.
> There is no bundled canary — pass the path or URL you are authorized to test.

Ask which path (AskUserQuestion):

1. **Local checkout** (static) → they give the directory, then
   `/threat-model bootstrap <dir>` then `/code-scan <dir>`
2. **Live URL** (authorized) → they give the URL, then `/pentest <url>`
3. **I'll read** → point at `CLAUDE.md` and `docs/skills/README.md`, stop

Do not start a scan from intro. Do not invent a target.

## Help

Read, in order, only what the question needs:

- `CLAUDE.md`
- `docs/skills/README.md`
- `.claude/skills/README.md`

Cite file paths. End with one next command (`/threat-model bootstrap <dir>`,
`/pentest <url>`, or `python3 run_pentest.py --help`). Do not dump tool catalogs.
