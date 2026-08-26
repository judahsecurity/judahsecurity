# Threat model artifact contract

Headings in `THREAT_MODEL.md` are a contract. Downstream skills grep them.

```markdown
# Threat Model: <system_name>

## 1. System context
## 2. Assets
## 3. Entry points & trust boundaries
## 4. Threats
## 5. Deprioritized
## 6. Open questions
## 7. Provenance
## 8. Recommended mitigations
## Focus areas
```

## Threats table columns

`id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence`

- `actor`: `remote_unauth` | `remote_auth` | `adjacent_network` | `local_user` | `local_admin` | `supply_chain` | `insider`
- `impact`: `low` | `medium` | `high` | `critical` | `existential`
- `likelihood`: `very_rare` | `rare` | `possible` | `likely` | `almost_certain`
- `status`: `unmitigated` | `partially_mitigated` | `mitigated` | `risk_accepted`
- `id`: stable `T1`, `T2`, … for the run

## Focus areas

Each bullet: `**FA-id** (specialist): title — why` plus optional `surfaces:`.

Specialist names should match Vanguard hunters when obvious (`authz`,
`injection`, `xss`, `ssrf`, `business-logic`, `code_sast`). Unknown is fine.

## JSON

`threat_model.json` mirrors `ThreatModel.to_dict()`: `system_name`, `target`,
`mode`, `context`, `assets`, `entry_points`, `threats`, `deprioritized`,
`open_questions`, `mitigations`, `surfaces`, `focus_areas`, `provenance`,
`languages`, `frameworks`. Extra keys are ignored by the platform parser.
