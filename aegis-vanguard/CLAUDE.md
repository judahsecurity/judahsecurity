# Aegis Vanguard — Claude Code runbook

This directory is the offensive playbook. In Claude Code you are the
**operator** (same shape as Glasswing): skills aim, find, and verify.
All live testing runs in Prowl, the platform agent.

```
/recon         (live, scope file enforced)
/threat-model  →  /code-scan   (local checkout you name)
               →  /pentest     (live URL you authorize; Prowl executes)
               →  /triage      (gate + root-cause dedup + Prowl re-probe)
               →  /chain       (every link confirmed; chain severity only end to end)
```

Live work goes through Prowl (the platform agent) with `prowl_client.py`
(`AEGIS_API_URL`, `AEGIS_API_TOKEN`). Classes and proof kinds come from
`data/vuln_classes.json`, synced from Prowl's `proof_policy.PROOFS_BY_CLASS`.

Start with `/aegis`. There is no bundled canary. Pass the checkout or URL.

## Rules

1. Only authorized targets. Ask before any live request.
2. `/code-scan` is static: read source. Do not execute target code or tests.
3. A threat survives a one-line patch; a vulnerability does not. `/threat-model` produces threats.
4. Every run writes `results/<target>/<timestamp>/` under this directory. Never overwrite an older run.
5. `/triage` must not read hunter transcripts. Verdicts from artifacts or Prowl verifier receipts only.
6. Keep `SKILL.md` small. Details live in linked files. See `.claude/skills/README.md`.
7. Live skills need a scope file (`.claude/skills/_lib/scope.py`). Check every host.
8. medium+ only with a Prowl proof kind for the class; curl output is a lead.

## Artifacts

`recon.json`, `THREAT_MODEL.md`, `findings.json` / `VULN-FINDINGS.md`,
`TRIAGE.md` / `verdicts.json` / `clusters.json`, `CHAINS.md` / `chains.json`,
`prowl_run.json` / `prowl/` / `prowl_verify/` (Prowl receipts), plus
`coverage.json` when a live hunt recorded what was tested.

## Pointers

- Skills: `.claude/skills/`
- How to run (and Prowl API gaps): `docs/skills/README.md`
- Prowl client: `prowl_client.py --help`
- Test identities: `prowl_client.py identities` logs them in here and hands Prowl only the session (`agent/identity_sessions.py`)
