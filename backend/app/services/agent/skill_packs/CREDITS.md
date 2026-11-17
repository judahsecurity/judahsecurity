# Skill pack credits

Several Prowl skill packs adapt attack-pattern knowledge from
**Claude-BugHunter** by elementalsouls: https://github.com/elementalsouls/Claude-BugHunter

That repository is dual-licensed:

* Content (skill methodology, wordlists, docs): Creative Commons Attribution 4.0
  International (CC BY 4.0), https://creativecommons.org/licenses/by/4.0/
* Code (Python helpers, shell scripts): MIT

Only content was used; no code was copied. Every adapted pack was **modified and
distilled**: rewritten for Prowl's tools and proof rules (deterministic scoped
tool receipt + independent verifier replay for medium+), reduced to
non-destructive testing, and stripped of RCE escalation chains, webshell /
reverse-shell / persistence material, destructive commands, mass enumeration,
and agent-steering text unrelated to the vulnerability class. Discipline rules
(marker, body-diff, statistical-sample) are adapted from
`skills/bb-methodology/SKILL.md`.

| Pack | Source path (branch `main`) | License |
|---|---|---|
| `ssti/SKILL.md` | `skills/hunt-ssti/SKILL.md` (+ `skills/bb-methodology/SKILL.md`) | CC BY 4.0, modified |
| `command_injection/SKILL.md` | `skills/hunt-rce/SKILL.md` (+ `skills/bb-methodology/SKILL.md`) | CC BY 4.0, modified |
| `path_traversal/SKILL.md` | `skills/hunt-lfi/SKILL.md` (+ `skills/bb-methodology/SKILL.md`) | CC BY 4.0, modified |
| `csrf/SKILL.md` | `skills/hunt-csrf/SKILL.md` (+ `skills/bb-methodology/SKILL.md`) | CC BY 4.0, modified |
| `jwt/SKILL.md` | `skills/hunt-jwt-crypto/SKILL.md` (+ `skills/bb-methodology/SKILL.md`) | CC BY 4.0, modified |
| `nosql/SKILL.md` | `skills/hunt-nosqli/SKILL.md` (+ `skills/bb-methodology/SKILL.md`) | CC BY 4.0, modified |
| `idor/SKILL.md` | `skills/hunt-idor/SKILL.md` (+ `skills/bb-methodology/SKILL.md`) | CC BY 4.0, modified |

Each adapted pack ends with an attribution line naming its source skill.
Packs not listed here (sqli, xss, ssrf, wordpress, js_analysis, ...) are original
Judah content.
