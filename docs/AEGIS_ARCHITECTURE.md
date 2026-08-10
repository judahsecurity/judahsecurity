# Aegis architecture (Praetorian-competitive)

Judah Security’s agent is built for **real-world bug classes**, not CTF.
Architecture mirrors Praetorian Guard’s shape: a commander, bounded specialists,
operation directives, a judge gate, and deterministic tool guardrails.

## Map to Praetorian

| Praetorian | Aegis / Judah |
|------------|---------------|
| Marcus (orchestrator) | **Joshua** — main ReAct agent |
| Bounded Caesars | Fireteam specialists with allowlists + skill packs |
| Operation directives | `OperationDirective` per specialist |
| Multi-vector fronts | `fireteam_dispatch` / `asyncio.gather` |
| Judge / FP control | **Solomon** (`finding_judge` + hard `create_finding` gate) |
| Pre/Post tool hooks | **Praetorium** (Censor / Lictor / Augur) |
| Credential assault | **Samson** (`credential_assault`) |
| Skills / workflows | `/skill` + playbooks + `specialist_skills.py` |
| Demonstrated compromise | `compare_requests` + validate → receipt → create |

## Control loop

```text
Joshua (orchestrator)
  → execute_deep_crawl / capability map
  → sync_engagement_brain (hypotheses)
  → fireteam_dispatch(auto)
       ├─ Raphael (app_mapper)
       ├─ Samson (credential_assault)
       ├─ Ezra / Daniel / Judah / Joseph / David / …
       └─ Solomon (finding_judge)
  → each specialist gets an OperationDirective
  → medium+ findings: validate_finding (SUBMIT receipt) → create_finding
  → queue_finding_followups (chains)
```

Specialists **cannot** call `fireteam_dispatch` (not on any allowlist).

## Key modules

| Module | Role |
|--------|------|
| `aegis_pantheon.py` | Epithets (Samson, Daniel, Solomon, …) |
| `operation_directive.py` | Scoped hunt orders |
| `finding_gate.py` | SUBMIT receipts for medium+ |
| `fireteam_service.py` | Specialist profiles + mini-ReAct |
| `specialist_skills.py` | Lane skill packs |
| `engagement_brain.py` | Hypotheses / creds / chains |
| `aegis_praetorium` | Tool lifecycle guards |

## Pantheon

See [AEGIS_PANTHEON.md](./AEGIS_PANTHEON.md).

## Out of scope

CTF REV/PWN/STEGO stacks, open Kali bash, Metasploit — Copilot-style workstation
features that do not improve production ASM bug finding.
