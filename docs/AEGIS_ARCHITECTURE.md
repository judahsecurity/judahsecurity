# Aegis architecture (Praetorian-competitive)

Judah Security’s agent is built for **real-world bug classes**, not CTF.
Architecture mirrors Praetorian Guard’s shape: a commander, bounded specialists,
operation directives, a judge gate, and deterministic tool guardrails.

## Map to Praetorian

| Praetorian | Aegis / Judah |
|------------|---------------|
| Marcus (orchestrator) | **Joshua** — scheduler (does not hunt) |
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
Joshua (scheduler only — does not hunt)
  → execute_deep_crawl / capability map
  → sync_engagement_brain
       (hypotheses + Penetration Task Graph)
  → fireteam_dispatch(auto)  ← ready graph nodes only
       ├─ short-lived executors (fresh context + summary contract)
       ├─ auto-prompter rewrite wave if a hunter soliloquizes / fails
       └─ independent_verify (Deborah) on candidates
  → apply executor summaries onto the graph (prove/kill/spawn)
  → queue_finding_followups (chain nodes)
  → coverage leftover node unblocks after high-pri logic is attempted
```

Joshua reads **executor summaries** and the **task graph**, never raw nmap dumps.
Specialists **cannot** call `fireteam_dispatch` (not on any allowlist).
Failed hunters are rewritten once (`auto_prompter.py`); they are not looped
on the same prompt. Medium+ findings still require Solomon's evidence gate.

## Swarm shape

| Piece | Role |
|-------|------|
| Engagement brain | Shared memory (hypotheses, creds, approaches) |
| Penetration Task Graph | Planner: cards as nodes, deps as edges, ready-wave schedule |
| Joshua | Scheduler only |
| Fireteam specialists | Short-lived executors, compact mission + directive slice |
| Auto-prompter | Rewrite failed hunter instructions (soliloquy / empty verdict) |
| Finding gate | Unchanged: evidence before publish |

## Key modules

| Module | Role |
|--------|------|
| `aegis_pantheon.py` | Epithets (Samson, Daniel, Solomon, …) |
| `operation_directive.py` | Scoped hunt orders + executor brain slice |
| `finding_gate.py` | SUBMIT receipts for medium+ |
| `fireteam_service.py` | Specialist profiles + mini-ReAct + summary contract |
| `penetration_task_graph.py` | Task graph / ready wave / executor summaries |
| `auto_prompter.py` | Rewrite failed hunters instead of looping |
| `specialist_skills.py` | Lane skill packs |
| `engagement_brain.py` | Hypotheses / creds / chains / `task_graph` |
| `aegis_praetorium` | Tool lifecycle guards |

## Pantheon

See [AEGIS_PANTHEON.md](./AEGIS_PANTHEON.md).

## Out of scope

CTF REV/PWN/STEGO stacks, open Kali bash, Metasploit — Copilot-style workstation
features that do not improve production ASM bug finding.
