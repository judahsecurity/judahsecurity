---
name: chain
description: >-
  Evaluate exploit chains across confirmed findings in a results/<target>/<ts>/
  directory using the chain-required table (open redirect + OAuth redirect_uri
  → ATO, subdomain takeover + OAuth redirect → critical, self-XSS + CSRF,
  SSRF + cloud metadata, IDOR + PII). Every link must be independently
  confirmed; chain severity only when demonstrated end to end. Writes
  chains.json + CHAINS.md. Use after /triage or when asked to chain findings.
argument-hint: "<results-dir> [--scope-file <file>] [--prove]"
allowed-tools:
  - Read
  - Write
  - Grep
  - Glob
  - AskUserQuestion
  - Bash(python3 .claude/skills/_lib/dedup.py:*)
  - Bash(python3 .claude/skills/_lib/scope.py:*)
  - Bash(python3 prowl_client.py:*)
  - Bash(python3 .claude/skills/_lib/publish_chains.py:*)
---

# /chain

A chain is only as real as its weakest independently confirmed link.

**Invoke:** `/chain results/<target>/<timestamp>/ [--scope-file <file>] [--prove]`

## Inputs

- `verdicts.json` (required — run `/triage` first) and `findings.json`
- `clusters.json` (from `/triage`; else run
  `python3 .claude/skills/_lib/dedup.py <run-dir>/findings.json --out <run-dir>/clusters.json`)
- `recon.json`, `THREAT_MODEL.md`, `prowl_verify/*.json` if present
- `.claude/skills/triage/gate.md` sections 4–5 (never-submit list, chain table)

A link is **confirmed** only if its verdict is `confirmed`. Never-submit rows
(open redirect, self-XSS, introspection …) count as links when their own
behaviour is confirmed, even though `/triage` refuted them as standalone
findings — record them as `link_confirmed` from the artifact, not as findings.

## Chain-required table

| Link A (confirmed) | Link B (must also be confirmed) | Chain impact |
|--------------------|---------------------------------|--------------|
| Open redirect on the IdP/app origin | OAuth `redirect_uri` accepts that redirect; code/token reaches attacker origin | Account takeover — high/critical |
| Subdomain takeover (claimable CNAME) | Host is a registered OAuth redirect / trusted CORS or CSP origin | Critical |
| Self-XSS | CSRF or login-CSRF delivers the payload to a victim session | XSS on victim — medium/high |
| SSRF (internal HTTP body) | Cloud metadata returns credentials (IMDS v1/v2, GCP, Azure) | Credential exposure — critical |
| IDOR / authz bypass | Response carries another identity's PII or secrets | Data breach — high |
| Host header injection | Password-reset link uses injected host | Account takeover |
| CORS reflected origin + ACAC true | Credentialed read of PII/tokens | High |
| CSRF | Sensitive state change with independent readback | High |
| GraphQL introspection | Auth bypass or cross-user `node()` | High |
| Cache poisoning | Poisoned response served to a second client | High |

Also consider chains the threat model names. Same rules apply.

## Evaluate

For each candidate chain:

1. Map links to finding IDs (cluster `primary` only). Same host/origin or a
   documented trust relationship must connect them (redirect origin is in the
   OAuth client's allowlist, takeover host is the registered callback …).
2. Classify:
   - `demonstrated` — an end-to-end artifact shows the final impact (code
     captured on attacker origin, metadata credential redacted, victim PII
     returned), every link confirmed, all within scope.
   - `links_confirmed_not_demonstrated` — each link confirmed, end-to-end proof
     missing.
   - `incomplete` — at least one link unconfirmed.
3. Severity: chain severity **only** for `demonstrated`. Otherwise report each
   confirmed link separately at its own severity (never-submit links stay
   refuted/low) and give the missing link or end-to-end step as `next_step`.

## Prove (`--prove`, live, authorized only)

AskUserQuestion to confirm authorization. Check every host with
`python3 .claude/skills/_lib/scope.py check <scope-file> <url>`. Hand the
end-to-end attempt to Prowl, which holds the browser, OOB and identities:

```bash
python3 prowl_client.py start --target <origin> --scope-file <scope-file> \
    --playbook chain_detection --run-dir <run-dir> \
    --objective "Chain: <A id> + <B id>. Prove <impact> end to end; stop at first proof."
python3 prowl_client.py poll --session <id> --wait --run-dir <run-dir>
```

Never use real victim accounts; only operator test identities. No credential
use beyond showing it exists (redact). Stop at the first proof.

## Write

`chains.json`:

```json
[{ "chain_id": "", "name": "", "links": [{ "finding_id": "", "role": "A|B",
   "verdict": "confirmed|improve|refuted", "link_confirmed": true }],
   "status": "demonstrated|links_confirmed_not_demonstrated|incomplete",
   "severity": "", "evidence": "", "next_step": "", "prowl_session": null }]
```

`CHAINS.md`: one section per chain (links, status, severity, evidence or
missing step). List confirmed links that belong to no chain under
"reported separately". Redact secrets.

## Publish (optional)

To send `demonstrated` chains to the ASM platform (each link becomes a step
anchored to its asset; the platform ranks the path by exploitability), run
`python3 .claude/skills/_lib/publish_chains.py <run-dir> --dry-run`, show the
operator the output, and only after AskUserQuestion approval run it again
without `--dry-run` (needs `ASM_API_URL`, `ASM_API_KEY`).

Stop. Next: report, or `/triage <run-dir>` again after new proof.
