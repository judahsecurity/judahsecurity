# CrowdStrike Falcon Exposure Management in Judah

## Current connector

The Integrations page can add a read-only Falcon API client per Judah organization. It supports the US 1, US 2, EU 1, and US Gov 1 clouds. Credentials are encrypted with Judah's existing API-key cipher. The selected modules run immediately on demand and, when enabled, on the configured schedule.

| Falcon source | Falcon endpoint | Judah record | Required scope |
| --- | --- | --- | --- |
| External asset inventory | `GET /fem/queries/external-assets/v2` and `GET /fem/entities/external-assets/v1` | Asset, observed service/port | Assets: Read |
| Managed hosts | `GET /devices/combined/devices/v1` | Asset | Hosts: Read |
| Spotlight findings | `GET /spotlight/combined/vulnerabilities/v1` | Vulnerability and FindingSourceEvidence linked to Falcon host ID | Vulnerabilities: Read |

Create a dedicated Falcon OAuth API client with only the scopes for the enabled modules. Spotlight also requires Hosts: Read so findings can be attached to a stable host identity. In Judah, open **Integrations → CrowdStrike Falcon Exposure Management**, select the Falcon cloud, enter the client ID and secret, choose modules, and connect. The connection test checks the selected endpoints. Deployments that manage schema outside Judah's startup `create_all` should apply `db/migrations/add_crowdstrike_integration.sql` first.

The importer pages through the full selected datasets, retries transient responses, and commits only after a successful sync. Source IDs are retained in `crowdstrike_asset_links` so later syncs update the same asset. New imported assets start outside Judah scan scope and are not automatically marked as public or owned. Analysts must review ownership and scope before active validation. Existing Judah analyst tags and remediation decisions survive a normal Falcon update; an explicit Falcon closed status resolves its imported finding, and a later open status reopens it. A failed fetch never bulk-closes findings that were absent from that response.

After a successful sync, Judah's existing Neo4j graph receives the imported assets, services, and findings on a best-effort basis. Judah can include them in its **potential attack paths** where topology relationships already exist; an imported host and CVE alone do not create a path. A graph link or a Falcon CVE is not proof that an exploit path is reachable. A scoped analyst can use Judah's existing finding validation endpoint to request a recheck.

## Data-model mapping and proof

| Falcon input | Judah identity and evidence | Interpretation |
| --- | --- | --- |
| External asset `id`, `dns_domain.fqdn` or `ip.ip_address` | `CrowdStrikeAssetLink(source_kind=external)` → domain, subdomain, or IP `Asset` | Stable provider identity; DNS and observed service data stay attached to the asset. |
| Host `cid` + `device_id`/AID | `CrowdStrikeAssetLink(source_kind=host)` → host `Asset` | Hosts are not merged by shared hostname or IP. |
| External `ip.services` / `dns_domain.services` | `PortService` plus source observation metadata | Provider-observed service, not Judah-verified reachability. |
| Spotlight finding `id`, `aid`, `cid`, `cve` | `Vulnerability` on the exact linked host | CVE and provider status describe the affected asset; missing host matches are not guessed from IP. |
| Spotlight `assessment_status`, `assessment_reason`, `evaluation_logic`, `rule`, `exploit_validation_status` | `FindingSourceEvidence` with `source_finding_id`, `detection_method=falcon_spotlight`, provider timestamps, and structured details | Explains **what Falcon reported and why**. Its basis is `provider_assertion`; `exploit_validation_status` remains a provider field. Judah does not promote it to its own proof verdict. |
| Judah recheck of a finding | Existing `FindingValidation` row, with verdict, evidence, method output, and time | Independent Judah result. A failed or inconclusive run cannot silently turn a provider claim into a confirmed exploit. |

The finding detail's Evidence tab shows the Falcon source record separately from Judah validation. `detection_confidence` starts as `unknown` for a Falcon import because the Spotlight API response alone does not prove whether the specific detection came from a version match, live service, or exploit replay. A later Judah validator result remains separate and is not overwritten by the next Falcon sync.

The schema also includes `ExposurePath` and ordered `ExposurePathStep` rows for a future supported Falcon path feed. A path is keyed by organization, provider, connection ID, and provider path ID. Each step can keep provider `from_source_ref`/`to_source_ref` even when no Judah asset exists. Exact `host:<aid>` and `external:<asset-id>` references resolve through `CrowdStrikeAssetLink`; unknown or cross-organization references stay unmatched. `vulnerability_id` optionally ties a step to a finding. `source_claim` and `evidence` retain what the provider asserted, while `proof_state` starts at `asserted`; Judah reachability observations and validation runs can later advance or block each edge independently.

Canonical path-step example (an internal Judah shape, **not** a claimed Falcon response format):

```json
{
  "position": 0,
  "from_source_ref": "external:provider-asset-id",
  "to_source_ref": "host:falcon-aid",
  "edge_type": "network_reachability",
  "source_claim": "Provider reports a possible route",
  "proof_state": "asserted",
  "evidence": [{"source": "crowdstrike", "kind": "path_edge", "observed_at": "2026-10-17T00:00:00Z"}]
}
```

The later Falcon adapter must translate the tenant's supported path API/export into this shape and keep the original provider IDs. A Judah validation can add a separate evidence reference, timestamp, and `finding_validation_id` to the step; it must not overwrite the provider claim.

## Attack-path and validation expansion

The public Falcon Exposure Management API collection documents external assets and subsidiaries, but does not currently document a general Attack Path Analysis export endpoint. CrowdStrike's product supports attack path analysis in its console; that does not establish an export contract. Do not scrape console traffic or label Judah-generated graph paths as Falcon-provided paths.

For the next phase, obtain a tenant-scoped Falcon Attack Path Analysis API specification or supported export sample. Adapt its node and edge fields into the canonical path tables, then validate each edge against network controls already available to Judah (NetBrain, F5, ZPA, and observed ports) and validate affected CVEs with a scope-approved method. Show the source assertion, Judah proof state, evidence, and age per edge. A path should never inherit a “validated” label solely from a vulnerability's CVSS score or Falcon priority.

Before production rollout, verify the mappings with redacted response samples from this Falcon tenant, especially EASM `dns_domain`/`ip` shapes, Spotlight finding status and host IDs, and pagination metadata. Run a canary sync in a test Judah organization and compare source counts, asset links, and representative findings before enabling schedules.

## References

- [CrowdStrike Exposure Management API](https://developer.crowdstrike.com/api-reference/collections/exposure-management/)
- [CrowdStrike Hosts API](https://developer.crowdstrike.com/api-reference/collections/hosts/)
- [CrowdStrike Spotlight Vulnerabilities API](https://developer.crowdstrike.com/api-reference/collections/spotlight-vulnerabilities/)
- [CrowdStrike Predictive Path Analysis](https://www.crowdstrike.com/en-gb/platform/exposure-management/attack-path-analysis/)
