# Tester Process & Engagement Brain

How the ASM AI agent works like a human tester: **observe → hypothesize → dispatch specialists → differential proof → chain follow-ups → coverage leftovers**.

Related code:

| Piece | Path |
|-------|------|
| Engagement brain | `backend/app/services/agent/engagement_brain.py` |
| Capability map | `backend/app/services/agent/capability_map.py` |
| Fireteam specialists | `backend/app/services/agent/fireteam_service.py` |
| Specialist skill packs | `backend/app/services/agent/specialist_skills.py` |
| Tools (`compare_requests`, brain APIs) | `backend/app/services/agent/tools.py` |
| Orchestrator injection | `backend/app/services/agent/orchestrator.py` |
| Skills / playbooks | `skills_service.py`, `playbooks.py` |
| Tests | `backend/tests/test_engagement_brain.py` |

Standalone pentester (parallel fireteam): [`aegis-vanguard/`](../aegis-vanguard/README.md)  
Batch / accuracy harness: [`harness/README.md`](../harness/README.md)

---

## Control loop

```text
execute_deep_crawl
        │
        ▼
sync_engagement_brain          ← seeds open hypothesis cards from capability map
        │
        ▼
fireteam_dispatch(auto)        ← 3–6 specialists from open hypotheses
        │
        ▼
compare_requests               ← baseline vs one mutation (logic/authz/tenant)
        │
        ▼
update_hypothesis(proven|killed)
        │
        ▼
queue_finding_followups        ← chain cards (creds → auth CVE / SSRF / …)
        │
        ▼
coverage Nuclei (-var if creds) → validate_finding → create_finding
```

**Rule:** scanners find candidates; specialists prove impact. Status `200` alone is never a finding.

---

## Engagement brain

Session-scoped memory injected into the ReAct system prompt:

- **Hypotheses** — `open` / `in_progress` / `proven` / `killed` cards with assumption, test, pass/kill criteria, specialist
- **Credentials** — stashed after default-login hits (redacted in prompts)
- **Approaches tried** — avoid blind retries
- **Next steps** — derived dispatch hints

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
| `injection` | SQLi / XSS / SSTI on mapped params |
| `graphql_api` | Introspection + authz on GraphQL |
| `file_upload` / `saml_sso` / `spa_client` / `js_secrets` | Surface-specific |
| `coverage` | Nuclei / known CVE leftovers (after logic hunts) |

Multi-host / subdomain maps automatically add a **host-tenant** card.

---

## Chain cards (finding → follow-up)

Call `queue_finding_followups(vuln_type=..., title=..., target=..., evidence=...)` after a confirmed hit.

| Trigger class | Example follow-ups |
|---------------|-------------------|
| `default_login` | Authenticated Nuclei with `-var`; Grafana CVE-2024-9264; **Grafana admin → datasource-proxy SSRF → AKS/K8s**; generic admin URL-fetch SSRF |
| `host_header` | Tenant isolation bypass; password-reset poisoning |
| `idor` | Write/export variants on the same object family |
| `ssrf` | Metadata / internal pivot canaries |

Grafana-specific cards (`grafana-*` suffixes) only enqueue when the title/target looks like Grafana.

### Romulus-style examples this encodes

1. **Grafana default creds** (`admin:prom-operator`) → stash creds → authenticated probes  
2. **CVE-2024-9264** SQL expressions (post-auth)  
3. **Server Admin → datasource proxy SSRF → internal AKS** (`kubernetes.default.svc` / metadata)  
4. **Host-header tenant isolation bypass**

---

## Fireteam specialists

Attack profiles in `fireteam_service.py` (allowlisted tools + short ReAct loops):

`app_mapper`, `auth_logic`, `api_authz`, `host_tenant`, `business_logic`, `injection`, `file_upload`, `saml_sso`, `spa_client`, `graphql_api`, `js_secrets`, `coverage`, `vuln_triage` (+ recon profiles).

`fireteam_dispatch(specialists="auto")` preference order:

1. Open / in-progress hypotheses (engagement brain)  
2. Else capability-map hunt queue  
3. Else recon triad  

Prefer **3–6** specialists per wave — not every hunter every time.

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
