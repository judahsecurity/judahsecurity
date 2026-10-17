# CrowdStrike Falcon Exposure Management in Judah

## Current connector

The Integrations page can add a read-only Falcon API client per Judah organization. It supports the US 1, US 2, EU 1, and US Gov 1 clouds. Credentials are encrypted with Judah's existing API-key cipher. The selected modules run immediately on demand and, when enabled, on the configured schedule.

| Falcon source | Falcon endpoint | Judah record | Required scope |
| --- | --- | --- | --- |
| External asset inventory | `GET /fem/queries/external-assets/v2` and `GET /fem/entities/external-assets/v1` | Asset, observed service/port | Assets: Read |
| Managed hosts | `GET /devices/combined/devices/v1` | Asset | Hosts: Read |
| Spotlight findings | `GET /spotlight/combined/vulnerabilities/v1` | Vulnerability linked to Falcon host ID | Vulnerabilities: Read |

Create a dedicated Falcon OAuth API client with only the scopes for the enabled modules. Spotlight also requires Hosts: Read so findings can be attached to a stable host identity. In Judah, open **Integrations → CrowdStrike Falcon Exposure Management**, select the Falcon cloud, enter the client ID and secret, choose modules, and connect. The connection test checks the selected endpoints. Deployments that manage schema outside Judah's startup `create_all` should apply `db/migrations/add_crowdstrike_integration.sql` first.

The importer pages through the full selected datasets, retries transient responses, and commits only after a successful sync. Source IDs are retained in `crowdstrike_asset_links` so later syncs update the same asset. New imported assets start outside Judah scan scope and are not automatically marked as public or owned. Analysts must review ownership and scope before active validation. Existing Judah analyst tags and remediation decisions survive a normal Falcon update; an explicit Falcon closed status resolves its imported finding, and a later open status reopens it. A failed fetch never bulk-closes findings that were absent from that response.

After a successful sync, Judah's existing Neo4j graph receives the imported assets, services, and findings on a best-effort basis. Judah can include them in its **potential attack paths** where topology relationships already exist; an imported host and CVE alone do not create a path. A graph link or a Falcon CVE is not proof that an exploit path is reachable. A scoped analyst can use Judah's existing finding validation endpoint to request a recheck; CrowdStrike-only CVEs generally have version evidence until the validator collects stronger evidence. The connector deliberately records `detection_confidence=version_only` and keeps Falcon's assessment/evaluation fields in source metadata.

## Attack-path and validation expansion

The public Falcon Exposure Management API collection documents external assets and subsidiaries, but does not currently document a general Attack Path Analysis export endpoint. CrowdStrike's product supports attack path analysis in its console; that does not establish an export contract. Do not scrape console traffic or label Judah-generated graph paths as Falcon-provided paths.

For the next phase, obtain a tenant-scoped Falcon Attack Path Analysis API specification or supported export sample. Preserve the source path ID, node and edge IDs, timestamps, prerequisite/technique, target, and evidence. Map each node to a Judah asset through Falcon AID or external asset ID, then store unmatched nodes for review. Keep both the Falcon path assertion and Judah's independent reachability evidence. Validate each edge against network controls already available to Judah (NetBrain, F5, ZPA, and observed ports), then validate affected CVEs with a scope-approved method. Present path state as **observed**, **inferred**, **validated**, or **blocked**, with evidence and age shown per edge. A path should never inherit a “validated” label solely from a vulnerability's CVSS score or Falcon priority.

Before production rollout, verify the mappings with redacted response samples from this Falcon tenant, especially EASM `dns_domain`/`ip` shapes, Spotlight finding status and host IDs, and pagination metadata. Run a canary sync in a test Judah organization and compare source counts, asset links, and representative findings before enabling schedules.

## References

- [CrowdStrike Exposure Management API](https://developer.crowdstrike.com/api-reference/collections/exposure-management/)
- [CrowdStrike Hosts API](https://developer.crowdstrike.com/api-reference/collections/hosts/)
- [CrowdStrike Spotlight Vulnerabilities API](https://developer.crowdstrike.com/api-reference/collections/spotlight-vulnerabilities/)
- [CrowdStrike Predictive Path Analysis](https://www.crowdstrike.com/en-gb/platform/exposure-management/attack-path-analysis/)
