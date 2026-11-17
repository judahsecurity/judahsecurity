# Claude Code skills — size budget

Skills are the playbook front door. They must stay small so Claude Code does not
load a second copy of `playbooks.py` into context.

## Hard limits

| File | Max lines | Loaded when |
|------|-----------|-------------|
| `SKILL.md` | **150** | Skill is invoked |
| Linked reference (`schema.md`, `gate.md`, `researchers.md`) | **200** | Skill tells Claude to Read it |
| `_lib/*.py` helpers (`run_dir`, `scope`, `dedup`) | n/a | Skill runs them via Bash |
| This README / operator docs | unbounded | Humans, not the session |

`tests/test_skills_size.py` enforces the SKILL.md cap.

## Progressive disclosure

Put in `SKILL.md`: when to use, arguments, the next command, artifact names, stop conditions.

Put in a sibling file (one hop only): schemas, researcher protocol, judge questions.

Never: CWE catalogs, Nuclei flags, or paste from
`backend/app/services/agent/playbooks.py`.

## Cycle

```
/aegis            front door
/recon            scoped map of a live target (scope file enforced) -> recon.json
/threat-model     aim (Claude reads the checkout or URL notes)
/code-scan        find on a checkout (Claude is the scanner)
/pentest          find on a live URL (Prowl executes via prowl_client.py; curl = leads)
/triage           gate + root-cause dedup + Prowl re-probe -> verdicts.json
/chain            chain-required table over confirmed links -> chains.json
```

Shared pieces:

- `_lib/scope.py` — scope file format and checks (`check`, `filter`, `wildcards`)
- `_lib/dedup.py` — root-cause clusters (class, normalized endpoint, parameter)
- `../../data/vuln_classes.json` — Prowl's class -> proof-kind map, synced by
  `scripts/sync_vuln_classes.py` from `backend/app/services/agent/proof_policy.py`
- `../../prowl_client.py` — the only route to Prowl's browser, OOB, proof probes,
  verifier and publication gate

Launch Claude Code from `aegis-vanguard/`. Pass whatever checkout or URL the
operator names. There is no bundled target.

User-scoped copy: `cp -r .claude/skills/<name> ~/.claude/skills/`
