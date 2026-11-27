# Aegis Vanguard

Claude Code skills for authorized security testing, with live work executed by
**Prowl**, the platform's in-product agent.

```
/recon         scoped recon (scope file enforced)
/threat-model  →  /code-scan   static review of a local checkout
               →  /pentest     live test of an authorized URL, run by Prowl
               →  /triage      gate + root-cause dedup + Prowl re-probe
               →  /chain       chains of independently confirmed findings
```

Start Claude Code in this directory and run `/aegis`. See [CLAUDE.md](CLAUDE.md)
for the rules and [docs/skills/README.md](docs/skills/README.md) for how each
skill drives Prowl.

## What is here

| Path | Purpose |
|---|---|
| `.claude/skills/` | The skills and their `_lib` helpers (scope, run dirs, dedup) |
| `prowl_client.py` | CLI for the Prowl API: start/poll runs, verify findings, operator-directed probes, test identities, HAR/capture handoff |
| `agent/identities.py`, `agent/identity_sessions.py` | Load an identity file and log identities in locally; only cookies/headers go to Prowl |
| `agent/web_security_topics.json` | Topic cards `/pentest` uses to pick tests |
| `data/vuln_classes.json` | Offline copy of Prowl's proof classes (`scripts/sync_vuln_classes.py --check`) |

Live testing needs `AEGIS_API_URL` and `AEGIS_API_TOKEN` (a user JWT). Every
live skill checks hosts against a scope file. Writes only touch records Prowl
creates and verifies as its own.

The former standalone CLI (`run_pentest.py`, its hunters, scanner wrappers and
the `aegis-vanguard` container) was removed; its capabilities now live in
Prowl. See [docs/VANGUARD_PROWL_PARITY.md](../docs/VANGUARD_PROWL_PARITY.md).

## Tests

```bash
pip install -r requirements.txt
python -m pytest tests -q
python3 scripts/sync_vuln_classes.py --check
```
