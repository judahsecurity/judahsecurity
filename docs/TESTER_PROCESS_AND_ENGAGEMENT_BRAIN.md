# Tester Process & Engagement Brain

How the ASM AI agent works like a human tester: **observe → methodology cards (CWE/CAPEC) → Penetration Task Graph → dispatch ready specialists → differential proof → chain follow-ups → coverage leftovers**.

Related code:

| Piece | Path |
|-------|------|
| Methodology catalog | `backend/app/services/agent/methodology_catalog.py` |
| Engagement brain | `backend/app/services/agent/engagement_brain.py` |
| Grounded LLM hypothesis planner | `backend/app/services/agent/brain_hypothesis_planner.py` |
| Input/class assignment ledger | `backend/app/services/agent/coverage_cells.py` |
| Observation → follow-up assignment | `backend/app/services/agent/observation_followups.py` |
| Penetration Task Graph | `backend/app/services/agent/penetration_task_graph.py` |
| Auto-prompter | `backend/app/services/agent/auto_prompter.py` |
| Capability map | `backend/app/services/agent/capability_map.py` |
| Fireteam specialists | `backend/app/services/agent/fireteam_service.py` |
| Specialist skill packs | `backend/app/services/agent/specialist_skills.py` |
| Pantheon epithets | `backend/app/services/agent/aegis_pantheon.py` |
| Operation directives | `backend/app/services/agent/operation_directive.py` |
| Finding judge gate | `backend/app/services/agent/finding_gate.py` |
| Tools (`compare_requests`, brain APIs) | `backend/app/services/agent/tools.py` |
| Orchestrator injection | `backend/app/services/agent/orchestrator.py` |
| Skills / playbooks | `skills_service.py`, `playbooks.py` |
| Tests | `backend/tests/test_methodology_catalog.py`, `test_engagement_brain.py`, `test_penetration_task_graph.py` |

Standalone pentester (parallel fireteam): [`aegis-vanguard/`](../aegis-vanguard/README.md)  
Batch / accuracy harness: [`harness/README.md`](../harness/README.md)

---

## Control loop

```text
execute_deep_crawl (+ katana/gau → ingest_urls_into_map)
        │
        ▼
page assessment (app kind + how a human would start)
        │
        ▼
sync_engagement_brain          ← seeds CWE/CAPEC cards and input/class cells;
        │                         reasoning model proposes cell-linked hypotheses
        │
        ▼
fireteam_dispatch(auto)        ← Joshua leases one ready hypothesis per specialist
        │                         directive, result and evidence bind to that lease
        │                         sibling hypotheses remain untouched
        │                         auto-prompter rewrites a failed hunter once
        ▼
compare_requests               ← baseline vs one mutation (logic/authz/tenant)
        │
        ▼
update_hypothesis(proven|killed) + get_methodology_progress
        │
        ▼
queue_finding_followups        ← chain cards + CVE→CWE loop-back (new graph nodes)
        │
        ▼
coverage Nuclei (graph-unblocked leftovers) → validate → create_finding
        │
        ▼
complete                       ← blocked while high-pri methodology cards remain open
```

**Swarm rules:** engagement brain is shared memory; the task graph is the planner;
Joshua only schedules; specialists are short-lived executors; imagined tool output
(soliloquy) is a retry, not a finding. **Rule:** scanners find candidates; specialists
prove impact. Status `200` alone is never a finding.
**Gates:** Nuclei/sqlmap/etc. require a capability map + seeded methodologies; `complete` requires high-priority methodology cards proven/killed (or `completion_reason` includes `defer methodologies`).

Each scheduled node gets an execution-owned lease with an attempt number and
deadline. The executor receives exactly one hypothesis card. Only a summary carrying
the matching lease can update that node, and its structured evidence IDs are retained
on the graph. If the process restarts after a lease expires, Judah quarantines the
node for evidence reconciliation because an external side effect may already have
happened; it does not automatically repeat the action.

Run snapshots are atomically replaced with owner-only permissions. They preserve the
capability map, graph, lease state, and redacted planning context. Credentials and the
active authentication session are deliberately omitted, so resumed runs must register
their test identities again. Historical evidence references remain context only and
cannot authorize a finding after restart.

---

## Engagement brain

Session-scoped memory injected into the ReAct system prompt:

- **Hypotheses** — `open` / `in_progress` / `proven` / `killed` cards with assumption, test, pass/kill criteria, specialist
- **Credentials** — stashed after default-login hits (redacted in prompts)
- **Approaches tried** — avoid blind retries
- **Next steps** — derived dispatch hints

### Grounded model hypotheses for observed inputs

`sync_engagement_brain` and direct `fireteam_dispatch` send a bounded,
value-free set of eligible coverage cells to the engagement's reasoning model.
The model proposes a possible
failure, a next check, and a priority for up to eight existing cell IDs. The
planner accepts only IDs from that batch; method, host, identity, parameter,
test class, specialist, and evidence references always come from the ledger.
Accepted proposals are stored on their cells and included in the specialist's
lead packet. A high-priority proposal can move an eligible cell earlier in its
specialist's claim order. It cannot mark a cell tested, create a candidate, or
publish a finding.

Each cell records a digest of the observation revision reviewed by the model.
Repeated Brain syncs do not repeat the call; a new capture or first-pass
evidence causes a new review. If the model is unavailable or returns malformed
JSON, the sync reports `hypothesis_planning.status=unavailable` and existing
coverage work remains assignable. These cell-linked hypotheses do not create
separate task graph nodes, so the same request is not assigned twice through
two scheduling lanes.

### Observation events → follow-up work

`observation_followups.py` turns a new fact into the next assignment. Coverage
cells stay the execution record; this path only decides which cell to create or
reuse.

1. **Event.** `commit_observation` records a capture, worker result, credential
   discovery (identity name only), or verified finding with run ID, evidence
   IDs, identity, host scope, and timestamp. Captures are stored by shape
   (`capture_facts` drops query values). The same fact seen again adds evidence
   and `seen_count` to the existing event and is not planned again.
2. **Proposal.** `FollowupPlanner.drain` sends the model a short, value-free
   packet: the event, the catalog-applicable classes per observed input, the
   approved identities, and existing work on that surface. The model returns
   `{target, test_class, reason, prerequisites{identities, depends_on},
   evidence_ids}`.
3. **Validation and deduplication.** Each proposal must match the observed
   method/host/path and an observed parameter, be in scope, use an applicable
   class, and cite evidence on the event. `authz` needs an approved identity
   other than the observer. Proposals that name an unapproved identity are
   **held** (no cell) until `release_held_proposals` sees the approval. A
   proposal maps to the same `coverage_cell_id` the inventory lane would
   produce, so work that already exists is linked (`merged`), not duplicated,
   and a later event proposing the same work is a `duplicate`. Per-event and
   per-run budgets apply. Validation runs against the live brain after the
   model returns.
4. **Wake and claim.** `commit_observation(on_commit=planner.notify)` wakes the
   planner. `claim_followup` leases one eligible cell for a specialist (approved
   identities re-checked, dependencies settled) with no `await` between check
   and write. `complete_followup` requires the live lease and evidence IDs,
   releases the cell, and commits a `worker_result` event, which can produce
   the next follow-up.
5. **Measurement.** `chain_report` gives observation → accept → claim → first
   request → verdict durations, plus time spent waiting on the planner, the
   model, identity approval, and a worker.

**Live wiring** (`followup_runtime.py`):

| Where | What happens |
|-------|--------------|
| Browser capture, `discover_parameters`, `sync_engagement_brain`, `fireteam_dispatch` | Inventory rows backed by a capture artifact become one capture event per request shape; the planner is queued in the background (never awaited) |
| Next sync or dispatch | Finished model results are validated against the live brain; held proposals are released if their identities are now approved |
| `fireteam_dispatch` | Specialists with claimable follow-ups join `auto` waves and claim them before ordinary coverage work; the directive's `allowed_identities` is narrowed to the follow-up's approved identities |
| End of the wave | Each follow-up lease closes through `finish_followup`: with evidence it commits a `worker_result` event, without evidence it is released as inconclusive |
| `add_engagement_credential` | Records a `credential` event (identity name only; recorded, not planned) |
| `create_finding` | Records a `verified_finding` event for the published candidate's coverage cell |
| Restart recovery | Events left mid-planning return to `committed` |

**Approved identities** are `anonymous`, identities registered with the
assessment identity registry, and the engagement's own sessions on the brain.
A scheduled turn narrows them to its `allowed_identities`. **Scope** is the
assessment's observation scope.

Settings: `PROWL_FOLLOWUP_PLANNER_ENABLED` (default `true`) turns the path off
entirely; `PROWL_FOLLOWUP_MAX_EVENTS_PER_RUN` (default `60`) caps model calls
per run. Sync and dispatch report `followup_planning`; dispatch also reports
`followup_leases`.

Known limits: the background model call and the claim lock are per process.
Authz cells seeded by the parameter-inventory lane do not yet require an
approved second identity. Acceptance tests: `backend/tests/test_observation_followups.py`.

### Agent tools

| Tool | Purpose |
|------|---------|
| `sync_engagement_brain` | Seed/refresh hypotheses from the capability map |
| `get_engagement_brain` | Inspect queue, redacted creds, next steps |
| `update_hypothesis` | Mark proven/killed with evidence |
| `queue_finding_followups` | Enqueue chain cards after a confirmed finding |
| `add_engagement_credential` | Store working creds for authenticated follow-ups |
| `log_engagement_approach` | Record technique outcomes |
| `compare_requests` | Differential HTTP proof (baseline vs mutant) |
| `fireteam_dispatch` | Spawn specialists; `specialists="auto"` uses open hypotheses |

### Skills / playbooks

```text
/skill tester-process target=https://app.example.com
/skill host-tenant-bypass target=https://tenant-a.example.com
```

Playbook IDs: `tester_process`, `host_tenant_bypass` (also woven into `external_assessment`).

---

## Hypothesis cards (map-seeded)

Seeded from the capability map hunt queue when the map is attack-ready:

| Hunt / specialist | Trust boundary |
|-------------------|----------------|
| `auth_logic` | Login, session, forced browsing |
| `api_authz` | IDOR / BOLA / missing auth |
| `host_tenant` | Host / `X-Forwarded-Host` tenant isolation |
| `business_logic` | Workflow skip, mass assignment, state tamper |
| `injection` | SQLi / XSS / SSTI on mapped params (legacy combined lane) |
| `xss` / `sqli` / `ssrf` | Split from injection when search, params, or URL-fetch fields are observed |
| `graphql_api` | Introspection + authz on GraphQL |
| `file_upload` / `saml_sso` / `spa_client` / `js_secrets` | Surface-specific |
| `coverage` | Nuclei / known CVE leftovers (after logic hunts) |

Multi-host / subdomain maps automatically add a **host-tenant** card.

---

## Chain cards (finding → follow-up)

Call `queue_finding_followups(vuln_type=..., title=..., target=..., evidence=...)` after a confirmed hit.

| Trigger class | Example follow-ups |
|---------------|-------------------|
| `default_login` | Grafana Server Admin APIs (`/api/admin/settings`, `/api/datasources`, `/api/serviceaccounts/search`); **existing Prometheus datasource proxy → cluster enum**; **CouchDB `_config` secret + admin salts**; **CouchDB AuthSession cookie forgery** (HMAC secret+admin salt, not `_users` derived_key); authenticated Nuclei with `-var`; Grafana CVE-2024-9264; Grafana admin → new-datasource SSRF → AKS/K8s; generic admin URL-fetch SSRF |
| `js_secrets` | Hostname-keyed `client_id`/`client_secret` maps in `/_next/static/chunks`; **live API impact with leaked headers** (bounded sample); cross-env leak (sandbox UI ships prod); **EmailJS `user_id`/`service_id`/`template_id` → one browser-context canary send** (engagement inbox only) |
| `elasticsearch_unauth` | Unauth GET `/` + `/_cluster/health` + `/_cat/indices` + sample read; PUT+DELETE `aegis_test_index`; no Painless RCE |
| `azure_function_env_dump` | Anonymous HTTP trigger (`Tester`) returns process env JSON; classify Cosmos/Storage/MACHINEKEY/EasyAuth/AAD; Cosmos list-only; storage list-only; peer `-dev-` hostname; MI/Key Vault **prerequisites only** (no code injection); rotate AAD secrets last |
| `host_header` | Tenant isolation bypass; password-reset poisoning |
| `idor` | Write/export variants on the same object family; **OpenAPI/DRF mass assignment of `id`/`user`/`owner`** (schema first) |
| `mass_assignment` | Count request serializers missing `readOnly` on `id`/`created`/`user`/`schedule`; writable ownership; list ops that document **shared across all users**. **DB down is still SUBMIT**. Also enqueue unauth `/api/auth/account/` lookup on the same schema |
| `unauth_account_lookup` | OpenAPI `security: {}` on `/api/auth/account/?email=` returning `is_staff`/`role`/`valid_through`; **sibling 401 vs lookup 200/404/500 is SUBMIT Critical**. 404 is an existence oracle. One canary email; do not spray; do not invent a 200 role body. **DB down is still SUBMIT** |
| `unauth_settings_write` | Sibling write 401 (e.g. `POST /api/TaskAdmin/UpdateTask`) vs unauth `POST /api/Settings/SaveSettings` **200 Content-Length: 0** (ASP.NET void). **SUBMIT High**. GET GetSettings 500 is **not** a kill. One `aegis-verify-*` key; do not replace production settings or flip `enableNotifications`/`createPlannerTasks`/`powerBIReportId`. `use_auth_session=false`. `*.azurewebsites.net` is App Service, not a Function env dump |
| `cors_credentials` | Canary Origin reflected in ACAO **and** `Access-Control-Allow-Credentials: true`; OPTIONS allows `Authorization` + POST; **Keycloak `webOrigins=*`** on token/userinfo/admin. Header proof is SUBMIT (no victim tab). Socket.IO `url_key` only |
| `keycloak_password_grant` | **admin-cli public + password grant** (`invalid_grant` without `client_secret`); **no 429/lockout on ≤8 fake attempts**. Do not hydra. Guessing a valid password is not required. Tiny defaults only |
| `ssrf` | Metadata / internal pivot canaries |

Grafana-specific cards (`grafana-*` suffixes), CouchDB-specific cards (`couchdb-*`), Elasticsearch (`es-*`), Azure Function cards (`azfn-*`), Keycloak (`keycloak-*`), and Socket.IO (`socketio-*`) only enqueue when the title/target/evidence looks like that product.

### Romulus-style examples this encodes

1. **Grafana default creds** (`admin:prom-operator`, kube-prometheus-stack Helm default / CWE-1393) → stash creds  
2. **Server Admin APIs** — `GET /api/admin/settings` (pod identity, DB config), `GET /api/datasources`, `GET /api/serviceaccounts/search` (token inventory)  
3. **Existing Prometheus datasource proxy** — relay PromQL via `/api/datasources/proxy/<id>/api/v1/targets` to enumerate in-cluster exporters (Redis, Mongo, Kafka, Postgres, kubelets, …) without creating a new datasource  
4. **CVE-2024-9264** — Viewer+ `POST /api/ds/query` `type=sql` forks DuckDB. **Missing binary is still SUBMIT** (`fork/exec ... duckdb: no such file`). `sqlExpressions=0` in `/metrics` is UI-only in 11.0.x — not a kill. Patch: Grafana **11.2.2+**; do not install DuckDB; disable SQL expressions in backend config; least-privilege SA tokens.  
5. **New datasource SSRF → internal AKS** (`kubernetes.default.svc` / metadata) — only if no existing Prometheus DS  
6. **Host-header tenant isolation bypass**
7. **JS-leaked OAuth client secrets** — hostname-keyed `client_id`/`client_secret` in Next.js admin chunks → one in-scope API read (count + redacted sample); rotate **all** env pairs; never ship secrets to the browser
8. **EmailJS keys in production JS** — `service_id` / `user_id` / `template_id` → one browser-origin POST to `api.emailjs.com` with an engagement-controlled canary (not employees). Origin allowlists that block curl but allow any website embedding the keys are still a finding. Rotate `user_id`; move send server-side; EmailJS domain allowlist + rate limit.
9. **CouchDB default/weak admin** → GET `/_node/_local/_config` (secret, timeout, `[admins]` salts) → forge AuthSession with HMAC-SHA1(secret+admin_salt) → GET `/_session` `_admin` + `/_all_dbs` without the password. Independent of password rotation until the secret is rotated. Failed `_users` derived_key HMACs go in **not_demonstrated**.
10. **Anonymous Azure Function `Tester`** (`authLevel:anonymous`, `*.azurewebsites.net`) → process env JSON (Cosmos master keys, Storage keys, MACHINEKEY, EasyAuth, AAD, App Insights). Classify secret classes; Cosmos/storage **list-only**; probe the `-dev-` peer; MI/Key Vault ACE is **not_demonstrated** (do not inject code). Remove Tester or set `authLevel=function`; rotate leaked keys; rotate AAD secrets last.
11. **OpenAPI/DRF mass assignment** (CWE-915 / API3) — `GET /api/schema/` (or swagger.json). Count `*Request` serializers where `id`, `created`, `updated`, `user`/`owner`, `schedule`, or `periodic_task` are writable (not `readOnly`). Quote list operations that say **shared across all users**. **Missing database is still SUBMIT** (schema proves the contract). One bounded canary write if the DB is up; do not enable ICS/OT schedules; do not dump the hierarchy. Fix: `read_only=True` / `extra_kwargs`; object-level permissions; tenant-scope lists.
12. **Keycloak / CORS `webOrigins=*`** (CWE-942) — canary `Origin` reflected in `Access-Control-Allow-Origin` **with** `Access-Control-Allow-Credentials: true` on token, userinfo, JWKS, and `/auth/admin/realms/<realm>/*`. OPTIONS allows `Authorization` + POST/PUT/DELETE. **Header proof is SUBMIT** (no victim browser tab). Do not dump `/users`; do not ship an HTML exploit. Fix: client `webOrigins` explicit allowlist or `+` (valid redirect URIs), never `*`; audit reverse-proxy CORS overrides.
13. **Keycloak `admin-cli` password grant / no lockout** (CWE-307) — public client (no `client_secret`) with Direct Access Grants on `master` and app realms. `invalid_grant` without a secret proves the grant. **≤8 failed attempts with no 429/lockout is SUBMIT** — do not hydra/rockyou; do not kill because a valid password was not guessed. Disable Direct Access Grants; enable Brute Force Detection; if the grant must stay, confidential client + network ACL.
14. **Unauth OpenAPI account lookup** (CWE-204 / CWE-200 / CWE-862) — `GET /api/auth/account/?email=` documented with `security: {}` (“public API … without authentication”) returning `email`, `is_active`, `valid_through`, `is_staff`, `role`. Quote the schema **or** prove JWT skip: protected siblings (`/api/auth/profile/`, `/api/auth/users/me/`) return **401** while the lookup is **200**, **404** (`User does not exist!` — existence oracle), or **500** (app/DB error still reached application code). **Missing database is still SUBMIT. File Critical.** One canary email (`aegis-enum-canary@example.invalid`); do not spray employee inboxes; do not dump ICS/OT users. Do not claim a 200 UserAccount payload unless stdout contains those bytes. `Access-Control-Allow-Origin: *` is extra, not the CORS-credentials finding. Fix: require JWT; if a pre-login check is needed, boolean `is_active` only + rate limit; do not confirm account existence.

Findings must be demonstrated-compromise writeups: **Vulnerability Description**, **Impact** (what was retrieved), **Assets Affected**, **Recommendation** — not “login succeeded”.

---

## Fireteam specialists

Attack profiles in `fireteam_service.py` (allowlisted tools + short ReAct loops):

`app_mapper`, `auth_logic`, `api_authz`, `host_tenant`, `business_logic`, `injection`, `file_upload`, `saml_sso`, `spa_client`, `graphql_api`, `js_secrets`, `coverage`, `vuln_triage` (+ recon profiles).

`fireteam_dispatch(specialists="auto")` preference order:

1. **Penetration Task Graph ready wave** (deps satisfied; coverage blocked until high-pri logic is attempted)
2. Open / in-progress hypotheses (engagement brain)
3. Else capability-map hunt queue
4. Else recon triad

Prefer **3–6** specialists per wave — not every hunter every time. Each specialist
leases one highest-priority ready hypothesis, even when several cards share its lane.
Each executor returns a summary contract (`verdict`, `evidence`, `spawn`) for that
single leased card.
A soliloquy (summary with no tool calls) is rewritten once by the auto-prompter.

---

## Differential proof (`compare_requests`)

```python
compare_requests(
  baseline={"method": "GET", "url": "https://a.app/api/me"},
  mutant={"method": "GET", "url": "https://a.app/api/me",
          "headers": {"Host": "b.app"}},
  interest_fields=["owner_id", "email", "tenant"],
  hypothesis_id="<optional>",
)
```

Verdicts: `LIKELY_IMPACT`, `MUTANT_BYPASS_CANDIDATE`, `NO_MATERIAL_DIFF`, `MUTANT_DENIED`, `NEEDS_INTERPRETATION`.

Use for IDOR, host-tenant, authz, and workflow tampers. Then `update_hypothesis` + `validate_finding` + `create_finding`.

---

## Efficiency notes

- **Prompt caching** — the planner system message holds only session-stable text
  (rules, proof guidance) and the phase's tool list; per-step state (iteration,
  trace, brain, recommendations) goes in the user turn (`render_prompt_parts` in
  `prompts.py`). `prompt_cache.py` adds Anthropic `cache_control` breakpoints
  only when the concrete model is `ChatAnthropic`, including per member of the
  fallback chain; other providers get a plain string. Fireteam specialists also
  mark their newest message, so each loop turn reads earlier turns from cache.
- **No paid repeats** — a gated `complete`, a blocked phase transition or an
  unparseable reply runs no tool. Its rejection reason now appears in the next
  planner prompt until a tool runs (`planner_progress.py`). If the same prompt,
  ignoring the iteration counter, would be sent a third time in a row, the turn
  stops with a "Coverage is incomplete" reason instead of calling the model.
- **Logic before spray** — broad Nuclei is gated until a capability map exists (unless `force=true` / non-browser).  
- **Coverage specialist** — deep / authenticated Nuclei after creds or high-value hits.  
- **Future `nuclei_scout`** — optional thin early Nuclei lead-generator that only enqueues cards (does not judge impact). See harness docs for measuring chain recall.

---

## Evaluating with the harness

Use [`harness/`](../harness/README.md) to batch-scan and benchmark Aegis Vanguard (and, by extension, detection quality for logic/chains):

```bash
cd harness
pip install -e ".[dev]"
python -m local_harness.benchmark.run --ground-truth local_harness/benchmark/ground_truth/EXAMPLE.json
```

Add ground-truth tags for chain classes (`default_credentials`, `ssrf`, `idor`, host-tenant) so recall tracks tester-process outcomes, not only CVE template hits.
