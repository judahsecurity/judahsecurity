# CrowdStrike Falcon integration

Judah imports CrowdStrike Falcon **Hosts** and **Spotlight** data, so internal endpoints and their CVEs become part of the inventory and the Neo4j attack-path graph. The connection is read-only.

- **Hosts** become internal assets (`is_public = false`), keyed by the Falcon agent ID (`aid`).
- **Spotlight** findings become vulnerabilities on those assets, correlated by the same `aid`.
- After each sync, the touched assets are pushed to Neo4j. The graph layer is described in [GRAPH_SCHEMA.md](./GRAPH_SCHEMA.md#internal--endpoint-layer-crowdstrike-falcon).

Spotlight reports a CVE when a vulnerable version is installed. It does not say whether the CVE is exploitable from where an attacker can reach the host. That is the job of the exploitability validation phase that follows. Each finding stores `metadata.evaluation_logic` verbatim so that phase can see what Falcon actually checked.

## Falcon prerequisites

1. In Falcon, open **Support & Resources → API Clients & Keys → Create API Client**.
2. Grant read-only scopes: **Hosts: Read**, plus **Vulnerabilities: Read** for Spotlight. Spotlight needs Hosts: Read too, because findings are mapped to hosts by agent ID.
3. Copy the Client ID and Client Secret. Note the cloud region: `us-1`, `us-2`, `eu-1` or `us-gov-1`.

## Configure Judah

1. Open **Integrations → CrowdStrike Falcon → Connect CrowdStrike**.
2. Enter a name, region, Client ID and Secret, and choose the modules.
3. **Connect and validate** checks authentication and each enabled module. If a module is not licensed or the scope is missing, you see: *The CrowdStrike `<module>` module is not licensed or not available for this tenant*.

API: `GET/POST /integrations/crowdstrike`, `PUT/DELETE /integrations/crowdstrike/{id}`, `POST /integrations/crowdstrike/{id}/test`, `POST /integrations/crowdstrike/{id}/sync`.

## What is synced

### Hosts → assets

- Devices seen within the last `host_lookback_days` (default 7). Devices without an agent ID, hostname, or valid local IP are skipped and counted as `hosts_skipped`.
- An existing asset is matched in this order: one already carrying the same `aid`, then an asset whose value is the FQDN (`hostname.machine_domain`) or the hostname, then an `IP_ADDRESS` asset for the local IP. An asset claimed by a different `aid` is never re-used.
- Matched assets discovered by another source keep their exposure classification. They are enriched with `metadata.crowdstrike`, the `source:crowdstrike` tag, and `is_owned = true`.
- New assets are created as `asset_type = OTHER`, `value = fqdn`, `is_public = false`, `hosting_type = owned`, `status = verified`. Their local IP is replaced on each sync, to follow DHCP.
- `metadata.crowdstrike` holds: aid, hostname, fqdn, machine_domain, local/external/connection IP, MAC, OU, site, platform, OS, product type, agent version, status, Falcon tags and groups. An external IP in private address space is dropped, because it is not internet egress.

### Spotlight → vulnerabilities

- **First sync:** every `open`/`reopen` finding.
- **Later syncs:** every finding updated since the last successful Spotlight pass, minus a one-day overlap, in any status. This is how closures in Falcon reach Judah.
- In **prioritized** mode (default), a finding is imported if it meets at least one of:
  - ExPRT rating High or Critical **and** a network attack vector (`AV:N`)
  - listed in CISA KEV (any vector)
  - its CVE is in the connection's **attack-chain CVEs** list

  **All** mode imports every open CVE. The reasons a finding matched are stored in `metadata.prioritization_reasons`.
- Findings are de-duplicated by `template_id = crowdstrike:<spotlight id>`.
  - A finding closed in Falcon resolves the Judah finding.
  - A finding open again reopens a resolved one.
  - Analyst statuses (accepted, false positive, mitigated) are never overwritten.
- Findings whose `aid` matches no host asset are counted as `findings_uncorrelated` and skipped.

## Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| Validation says Spotlight is not licensed | Missing `Vulnerabilities: Read`, or no Spotlight licence | Add the scope or licence |
| Spotlight connects but nothing imports | Findings are below the prioritized filter, or uncorrelated | Check `findings_filtered` and `findings_uncorrelated` in the sync stats; switch to **All**, or add CVEs to the attack-chain list |
| Hosts missing | Not seen within the window, or missing hostname / local IP | Raise `host_lookback_days`; check the device in Falcon |
| Graph not updated | Neo4j unreachable | The Postgres import still succeeds. `graph_synced` is `null`; run `POST /graph/sync` once Neo4j is back |
