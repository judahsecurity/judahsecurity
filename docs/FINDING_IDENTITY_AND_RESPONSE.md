# Finding identity and response automation

Two layers that let Judah take findings from many tools (its own scanners,
Tenable, Wiz, and later CrowdStrike, Censys, Praetorian, SecurityScorecard,
BitSight) and act on each real problem once.

1. **Finding identity** (shipped): one canonical finding per real problem, one
   observation per source that reported it.
2. **Response automation** (proposed): Blink-style workflows in Loom that react
   to changes in canonical findings, not to raw vendor events.

---

## 1. Finding identity

### Model

| Table | Role | Key |
|---|---|---|
| `vulnerabilities` | Canonical issue. Status, owner, ticket and SLA live here. | `asset_id` + `dedup_key` |
| `finding_observations` | What one source saw: vendor ID, vendor severity, `open`/`fixed`, first/last seen. | `(organization_id, source, vendor_finding_id)` |
| `port_services` | Canonical exposure (open port). Vulnerabilities point at it via `port_service_id` rather than copying it. | `(asset_id, port, protocol)` |

New columns on `vulnerabilities`:

- `cves`: every CVE the finding covers. `cve_id` still holds the first one, for display.
- `dedup_key`: `cve:<lowest CVE>` for CVE-backed findings. Otherwise
  `<source>:<rule + location>`, e.g. `tenable:2002:443/tcp`.
- `port_service_id`: the exposure the finding sits on, when known.

Schema changes are applied at startup by `apply_finding_identity_migrations`
in `backend/app/main.py`. `db/migrations/add_finding_observations.sql` has the
same changes for manual deploys.

### Matching (`backend/app/services/finding_identity.py`)

For each incoming source finding:

1. **The source's own observation.** Keeps re-syncs stable after a merge.
2. **The importer's legacy key** (Tenable `template_id`, Wiz `wiz:<id>`), so
   rows created before this change keep updating in place.
3. **Canonical match** on the same asset or a related one (domain ↔ resolved
   IP, via `FindingDeduplicationService.get_related_assets`): same
   `dedup_key`, or **any overlap** between CVE sets. A Tenable plugin listing
   12 CVEs matches a Wiz or Nuclei finding for any one of them.

The port is part of the key only for findings without a CVE. Falcon and Wiz
don't report ports, so including it would stop CVE matches.

### Merge rules

- The source that created the row owns its title, description and evidence.
  Other sources only widen `cves`, raise `severity` (highest wins), extend
  `last_detected`, and add a `source:<name>` tag.
- **Open if any source still sees it.** A source reporting a fix marks its
  observation `fixed`. The canonical row resolves only when every observation
  is fixed and the owning source is one of them. A Nuclei-created row that
  Tenable also reported is not closed by Tenable alone.
- Analyst decisions (`accepted`, `false_positive`, `mitigated`) are never
  changed by merges or vendor fixes.

### Importers wired in

| Importer | Observation key | Notes |
|---|---|---|
| Tenable VM | `<tenable asset uuid>:tenable:<plugin>:<port>` | Sets `cves`, `dedup_key`, `port_service_id`. Stats now include `vulns_merged`. |
| Wiz | Wiz finding ID | A Wiz resolve no longer overrides analyst statuses. |
| Nuclei | `<asset>:<template>` | Recorded only when Nuclei merges into another source's row, so that row can't be closed while Nuclei still sees it. |

`FindingDeduplicationService.find_duplicate_finding` also matches a CVE
anywhere in `cves`.

Tests: `backend/tests/test_finding_identity.py`.

### Adding a source

Write a mapper that produces `(asset, cves, rule_id + location, severity,
state, vendor_finding_id)`. Then call `find_observed` → legacy lookup →
`find_canonical`, followed by `merge_into` or create, and `record_observation`.
For sources without CVEs (SecurityScorecard, BitSight, Censys), map their
issue types to a shared Judah taxonomy key, e.g. `tls.protocol.tls10` or
`service.exposed.rdp`, so different vendors agree.

### Not done yet

- `asset_identifiers` table, mapping Falcon AID, Wiz resource ID, Tenable UUID,
  IPs and FQDNs to one asset. Needed before CrowdStrike.
- Taxonomy mapping for non-CVE ratings and exposure findings.
- Open-port reports from external sources should update `port_services`,
  rather than `port_findings_service` creating parallel "Port N/tcp"
  vulnerability rows.
- A review queue for near-duplicates (similar titles or CWEs). These should be
  suggested to an analyst, never merged automatically.
- A "seen by" badge in the frontend, reading `finding_observations`.

---

## 2. Response automation: Blink-style capability in Loom

### Recommendation

Build the **response** half natively. Don't rebuild Blink's connector catalog.

Judah already has the hard parts Blink would otherwise hold: the canonical
finding store, the asset model, re-testing (`finding_revalidation_service`),
severity scoring, and Jira and ServiceNow clients. It also has a DAG engine,
Loom (`backend/app/services/workflow/`), with nodes, modules, runs and
artifacts. What it lacks is triggers driven by findings and action nodes.
That's a narrow addition, and keeping it in Judah avoids having two systems
each decide what counts as a duplicate.

Keep Blink, or any automation platform, as an optional consumer: a
"send webhook" action node lets customers hand off to their own tooling for
the hundreds of vendor actions Judah shouldn't maintain.

### Mapping Blink concepts to Judah

| Blink | Judah equivalent |
|---|---|
| Tables | Not needed. Use Judah's own tables (`vulnerabilities`, `finding_observations`, `assets`). |
| Event / polling / scheduled triggers | **New:** `finding.created`, `finding.severity_raised`, `finding.reopened`, `finding.all_sources_fixed`, `finding.sla_breached`, plus cron. Raised from the identity layer when a canonical row changes, never per observation. |
| Vendor adapters | Existing importers (Tenable, Wiz, Nuclei) and future ones. They write observations only and make no decisions. |
| Subflows (sync/async, inputs locked once published) | Loom **modules** (`WorkflowKind.MODULE`) already serve this role. Add a sync/async flag and version pinning. |
| Steps / actions | **New action nodes:** `jira.create_issue`, `jira.transition`, `servicenow.create_record`, `notify.slack` / `notify.teams` / `notify.email`, `judah.revalidate`, `judah.set_status`, `judah.assign_owner`, `http.webhook`. |
| Human approval (`Web Form Response` wait) | **New** `approval` node. It parks the run and resumes on approve or deny in the UI or Slack. Required in front of any remediating or status-changing step. |
| Draft / test run / publish, blast-radius warnings | Draft and published versions per workflow. A test run against a **dry-run** action mode, which Blink lacks: actions log what they would do. Show a blast-radius summary before publish (loops over findings, bulk messaging, status changes). |
| Agents with workflows as abilities | Later. The Aegis agent stack could call published Loom workflows as tools. |
| Dashboards | Existing frontend, plus SLA and multi-source views over `finding_observations`. |

### Default "Process finding" workflow (seeded)

```
trigger: finding.created | finding.reopened | finding.severity_raised
  → enrich       (KEV / EPSS / Delphi breach intel, asset owner, business app)
  → score        (sev_score; independent sources and Praetorian-validated raise confidence)
  → route        (severity_map: P1..P4 → team, SLA)
  → dedupe ticket (one open ticket per canonical finding; reuse on reopen)
  → create/update Jira or ServiceNow
  → notify       (owner channel; P1 pages)
  → [approval] → optional remediation step
trigger: finding.all_sources_fixed
  → judah.revalidate → close ticket on pass, reopen on fail
```

### Build order

1. Emit finding transition events from `finding_identity` and importers (an outbox table).
2. Add Loom trigger types for those events and cron. Node types: action, approval, webhook.
3. Jira and ServiceNow action nodes on the existing services. Slack/Teams notify nodes.
4. Seed the "Process finding" workflow. Add a `severity_map` setting in project settings.
5. Dry-run test mode and a blast-radius check before publish.
6. Outbound webhook node, so Blink or other automation platforms can consume Judah events.
