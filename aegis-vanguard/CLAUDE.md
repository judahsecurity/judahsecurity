# Aegis Vanguard — Claude Code runbook

This directory is the offensive playbook. In Claude Code you are the
**operator** (same shape as Glasswing): skills aim, find, and verify.
Python (`run_pentest.py`) is optional for a fully autonomous live fireteam.

```
/threat-model  →  /code-scan   (local checkout you name)
               →  /pentest     (live URL you authorize)
               →  /triage
```

Start with `/aegis`. There is no bundled canary. Pass the checkout or URL.

## Two ways in

| Mode | When | Who hunts |
|------|------|-----------|
| Interactive skills | Default. You have a repo path or an authorized URL | This Claude Code session |
| Autonomous CLI | Operator asks for the fireteam | `python3 run_pentest.py --target <url>` |

## Rules

1. Only authorized targets. Ask before any live request.
2. `/code-scan` is static: read source. Do not execute target code or tests.
3. A threat survives a one-line patch; a vulnerability does not. `/threat-model` produces threats.
4. Every run writes `results/<target>/<timestamp>/` under this directory. Never overwrite an older run.
5. `/triage` must not read hunter transcripts. Verdicts from artifacts only.
6. Keep `SKILL.md` small. Details live in linked files. See `.claude/skills/README.md`.

## Artifacts

`THREAT_MODEL.md`, `findings.json` / `VULN-FINDINGS.md`, `TRIAGE.md` / `verdicts.json`,
plus `coverage.json` when a live hunt recorded what was tested.

## Pointers

- Skills: `.claude/skills/`
- How to run: `docs/skills/README.md`
- ReAct CLI system card (not this session): `docs/vanguard-system-card.md`
