# Aegis Claude Code skills

Run this like Glasswing: open the harness folder in Claude Code, invoke slash
skills, point them at **your** checkout or URL. No bundled canary.

```bash
cd aegis-vanguard
claude
# then:
/aegis
/threat-model bootstrap /path/to/their/app
/code-scan /path/to/their/app
/triage results/<app-basename>/<timestamp>/
```

Live (authorized URL):

```
/pentest https://app.example.com --scope app.example.com
```

Claude hunts in-session by default. Add `--cli` (or ask for the fireteam) to
run `python3 run_pentest.py --target …` instead.

## Cycle

```
/aegis → /threat-model → /code-scan  (checkout, static; Claude is the scanner)
                       → /pentest    (live URL)
         → /triage
```

## Requirements

- Claude Code CLI, launched from `aegis-vanguard/`
- Local path: a checkout the operator names. Nothing else for `/threat-model`.
- Live path: authorization, `curl` on `$PATH`. `ANTHROPIC_API_KEY` if using `--cli`.

## Run directories

Outputs go to `aegis-vanguard/results/<target>/<timestamp>/` (gitignored).
Repeat runs resume the latest dir unless `--fresh`.

## Size rule

`SKILL.md` stays under 150 lines. Methodology lives in sibling files
(`schema.md`, `researchers.md`, `gate.md`) or in Python (`run_pentest.py`).
Do not grow skills by pasting platform playbooks.

## Platform agent (optional)

In-product Joshua is a different harness:

```bash
cd ../backend
python -m app.cli run --target https://app.example.com --playbook tester_process
```
