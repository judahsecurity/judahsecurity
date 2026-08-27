# Claude Code skills — size budget

Skills are the playbook front door. They must stay small so Claude Code does not
load a second copy of `playbooks.py` into context.

## Hard limits

| File | Max lines | Loaded when |
|------|-----------|-------------|
| `SKILL.md` | **150** | Skill is invoked |
| Linked reference (`schema.md`, `gate.md`, `researchers.md`, `_lib/curiosity.md`) | **200** | Skill tells Claude to Read it |
| This README / operator docs | unbounded | Humans, not the session |

`tests/test_skills_size.py` enforces the SKILL.md cap.

## Progressive disclosure

Put in `SKILL.md`: when to use, arguments, the next command, artifact names, stop conditions.

Put in a sibling file (one hop only): schemas, researcher protocol, judge questions.

Shared across skills: `_lib/curiosity.md` — the observe → hypothesis → signal
map (page-type → bug-class), rank-then-hunt order, and never-submit-alone
rules. `/threat-model` (URL branch) and `/pentest` (Observe) both read it. It
is the session-mode distillation of `agent/hunt_patterns.py`; keep the two in
sync when either changes.

Never: CWE catalogs, Nuclei flags, or paste from
`backend/app/services/agent/playbooks.py`.

## Cycle

```
/aegis            front door
/threat-model     aim (Claude reads the checkout or URL notes)
/code-scan        find on a checkout (Claude is the scanner)
/pentest          find on a live URL (Claude hunts; optional run_pentest.py)
/triage           verify from artifacts only
```

Launch Claude Code from `aegis-vanguard/`. Pass whatever checkout or URL the
operator names. There is no bundled target.

User-scoped copy: `cp -r .claude/skills/<name> ~/.claude/skills/`
