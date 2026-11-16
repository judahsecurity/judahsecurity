# Independent verify gate

Score what is in the run directory, or what Prowl's verifier returned for it.
Status 200 is never enough.

Validation discipline adapted from elementalsouls/Claude-BugHunter (CC BY 4.0).
Same gate as the CLI validator (`agent/agents.py` `create_validator_agent`) and
the never-submit / chain tables in `agent/hunt_patterns.py`.

## 0. Logical sanity (first)

Does the claim fit the observed host, port and service? LDAP/SSH/SMTP/DB claims
on an HTTP port, or a template whose protocol the live response contradicts →
`refuted`.

## 1. The 7 questions (in order; first NO decides)

| # | Question | NO means |
|---|----------|----------|
| Q1 | Can an attacker trigger it now with a real request (or file:line + reachable entry point for `/code-scan`)? Template match or "code suggests" alone is not yes. | `improve` (missing request) or `refuted` (unreachable) |
| Q2 | Is the impact type meaningful? Version banner, missing header alone → no. | `refuted` |
| Q3 | Is the asset in scope (scope file / threat model)? Third-party CDN, chat, analytics → no. | `refuted` |
| Q4 | Does it work without privileges the attacker cannot get? "Admin can admin" → no. For authz: which identity proved it (anonymous / A / B / privileged)? Own-data-only → no. | `refuted`; unknown identity → `improve` |
| Q5 | Is it not already known / accepted in this instance? | `refuted` (duplicate) |
| Q6 | Is impact demonstrated, not theoretical? (XSS executes; SSRF returns internal HTTP data; IDOR returns another identity's object; SQLi gives a controlled differential.) | `improve` |
| Q7 | Is severity calibrated to the achieved impact and preconditions? | `confirmed` at the lower severity (downgrade, do not drop) |

## 2. Class proof (Prowl alignment)

Resolve the class through `data/vuln_classes.json` (`vanguard_aliases`,
`coverage_to_class`). **medium or above requires a matching Prowl proof kind**
(`classes.<class>.proof_kinds`) from a Prowl verifier receipt
(`prowl_verify/<id>.json` with `verdict.status = confirmed`) or an equivalent
deterministic artifact in the run dir. Otherwise:

- class has proof kinds but no receipt → `improve`, next_step = `prowl_client.py verify`
- class has no proof kinds (`confirmable: false`) → at most `low`, labelled lead
- `known_cve` is never confirmable and is capped at `low` (version in range is a lead)

## 3. Discipline rules (each failure → `improve` or `refuted`)

1. **Random marker.** Reflection / injection / OOB proof uses a fresh random
   marker of ≥8 characters that is absent from the baseline response. A marker
   that also appears in the baseline proves nothing.
2. **Bypass needs a body diff.** Auth / 403 / authz bypass needs a response-body
   difference showing protected content (hash or field names), not just a status
   change. 200 vs 403 with the same error page is not a bypass.
3. **Timing.** Time-based claims need ≥10 interleaved trials (payload, control,
   payload, control …) and a payload mean ≥ control mean + 2σ of the control.
   One slow response is noise.
4. **Layer ordering.** A 400/422 on a malformed body comes from the parser or
   validator before auth runs; it is not an auth bypass or injection. Retest with
   a well-formed minimal body; only the well-formed result counts.
5. **One variable.** Baseline and mutant differ in exactly one input.
6. **Repeatable.** The verifier's reproduction uses its own request and a new
   marker; copying the hunter's response is not reproduction.
7. **Non-destructive.** No state-changing SQL, no data dumps, no shells. A write
   proof needs a bounded canary write, an independent readback and cleanup.

## 4. Never submit alone (instant `refuted` without a demonstrated chain)

- Missing CSP/HSTS/X-Frame-Options or other headers; missing cookie flags
- Version / banner disclosure without a working exploit (`known_cve`: low max)
- GraphQL introspection (needs authz bypass or cross-user `node()`)
- Self-XSS (needs CSRF or other delivery to a victim)
- Open redirect (needs OAuth token theft or SSRF)
- CORS `*` without `Access-Control-Allow-Credentials: true` and credentialed data read
- SSRF that is DNS/OOB ping only (needs internal HTTP body or metadata)
- Host header injection (needs password-reset poisoning proof)
- OpenAPI/Swagger found (a foothold, not a finding)
- SPA exposing an OAuth `client_id` (public by design)
- Clickjacking on non-sensitive pages; missing rate limit on non-auth / non-OTP forms
- Default or weak login alone (needs a privileged action after login)
- 400/500 on malformed input; stack trace without secrets

## 5. Chain-required table

A standalone row stays `refuted` (or `low`) until **every** link is
independently confirmed and the chain is demonstrated end to end. `/chain`
evaluates these; `/triage` only checks whether the chain artifact proves it.

| Standalone link | Required second link | Demonstrated impact |
|-----------------|----------------------|---------------------|
| Open redirect | OAuth `redirect_uri` accepts it → code/token reaches attacker | Account takeover (high/critical) |
| Subdomain takeover | Host is a registered OAuth redirect / trusted origin | Critical |
| Self-XSS | CSRF (or login CSRF) delivers it to a victim | Stored/reflected XSS on victim |
| SSRF | Cloud metadata returns credentials (IMDS / GCP / Azure) | Credential exposure (critical) |
| IDOR | Response carries another identity's PII | Data breach (high) |
| Host header injection | Reset email link uses the injected host | Account takeover |
| CORS reflected origin | ACAC true + credentialed PII read | High |
| CSRF | Sensitive state change with readback | High |
| GraphQL introspection | Auth bypass or cross-user `node()` | High |
| Cache poisoning | Poisoned response served to another client | High |

If a link is unconfirmed: report confirmed links separately at their own
severity, and the chain as `improve` with the missing link as next_step.

## 6. Verdicts

**confirmed** — passes 0–5; concrete request/response or file:line with the
failing check; not a duplicate of another confirmed root cause.

**improve** — real signal, missing proof. Always give one concrete
`next_step`: the exact request, identity pair, marker, trial count, or the
`prowl_client.py verify` call. Never invent that probe's result.

**refuted** — unreachable / dead code / docs-only; mitigated one layer up
(WAF is not a kill; an app-layer check is); theoretical CWE; never-submit row
without its chain; out of scope; duplicate root cause.

## 7. Root-cause dedup

Cluster with `.claude/skills/_lib/dedup.py`: key = (class, normalized endpoint,
parameter/sink). Normalized endpoint: lowercase host, default port dropped, no
query/fragment, numeric/UUID/long-hex path segments → `{id}`; for source
findings, drop the line number. Titles never decide duplicates. Keep the
cluster `primary`; mark the rest `refuted` with `duplicate_of`.

## Hygiene

Redact tokens, cookies, passwords, PII in TRIAGE.md and anything sent to Prowl.
Keep endpoint, status, field names, hashes, artifact IDs.
