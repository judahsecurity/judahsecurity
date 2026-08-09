# Graph Database Schema

## Layers

The graph has two layers:

1. **Technical topology** — what infrastructure exists and how it connects
2. **Discovery provenance** — how each asset was found and what it shares with other assets

## Technical topology chain

```
Domain → Subdomain → IP → Port → Service → Technology → Vulnerability → CVE
                                                          Vulnerability → MITRE (CWE)
```

## Discovery provenance chain

```
Asset ──[DISCOVERED_VIA]──> DiscoverySource   (subfinder, whoxy, certspotter, etc.)
Asset ──[HOSTED_BY]──────> HostingProvider    (aws, cloudflare, azure, etc.)
IP    ──[BELONGS_TO_ASN]──> ASN               (AS number + ISP)
Asset ──[SIGNED_BY]──────> Certificate
Certificate ──[ALSO_COVERS]──> Subdomain      (SAN expansion → shadow IT discovery)
IP    ──[HOSTED_BY]──────> HostingProvider
```

## Full entity-relationship table

| From            | Relationship      | To                | Notes                                       |
|-----------------|-------------------|-------------------|---------------------------------------------|
| Domain          | HAS_SUBDOMAIN     | Subdomain         | Canonical chain                             |
| Subdomain       | RESOLVES_TO       | IP                | DNS A/AAAA resolution                       |
| IP              | HAS_PORT          | Port              | Canonical chain                             |
| Port            | RUNS_SERVICE      | Service           | Canonical chain                             |
| Service         | USES_TECHNOLOGY   | Technology        | Canonical chain                             |
| Technology      | HAS_VULNERABILITY | Vulnerability     | Canonical chain                             |
| Vulnerability   | REFERENCES        | CVE               | CVE linkage                                 |
| Vulnerability   | MAPS_TO           | CWE               | Weakness mapping                            |
| CVE             | EXPLOITS_WEAKNESS | CWE               | Cross-reference                             |
| Subdomain       | SAME_IP_AS        | Subdomain         | Co-hosted assets (same IP)                  |
| Asset           | HAS_CHILD         | Asset             | Hierarchical parent→child                   |
| Asset           | SERVES_URL        | BaseURL           | Live HTTP endpoint                          |
| Service         | SERVES_URL        | BaseURL           | Port 80/443 → BaseURL                       |
| Asset           | HAS_ENDPOINT      | Endpoint          | Discovered paths                            |
| Asset           | HAS_PARAMETER     | Parameter         | Discovered URL params                       |
| Vulnerability   | FOUND_AT          | Endpoint          | Vuln located at a specific path             |
| **Asset**       | **DISCOVERED_VIA**| **DiscoverySource** | **Provenance: how asset was found**       |
| **Asset**       | **HOSTED_BY**     | **HostingProvider** | **Cloud/CDN hosting context**             |
| **IP**          | **BELONGS_TO_ASN**| **ASN**           | **Network block ownership**                 |
| **IP**          | **HOSTED_BY**     | **HostingProvider** | **CDN/cloud routing context**             |
| **Asset**       | **SIGNED_BY**     | **Certificate**   | **TLS certificate linkage**                 |
| **Certificate** | **ALSO_COVERS**   | **Subdomain**     | **SAN expansion → shadow IT discovery**     |
| **IP**          | **FORWARDS_TO**   | **IP**            | **LB reachability: VIP → pool member (F5)** |

**Bold rows** are the discovery provenance relationships added in the June 2026 update.

**SAME_IP_AS** is created between Subdomains that resolve to the same IP (per organization). Use it to answer "what else is on this IP?" and to reason about shared infrastructure (RedAmon-style graph robustness).

**FORWARDS_TO** links an internet-facing VIP IP to internal pool-member IPs discovered via the F5 BIG-IP integration. Edge properties: `source` (`f5`), `pool`, `virtual`, `port`, `organization_id`. Use it to answer "what internal IPs are reachable from the internet through this VIP?"

## Logical connections (query patterns)

- **Same IP** – Subdomains that share an IP (co-hosted):
  `(s1:Subdomain)-[:SAME_IP_AS]-(s2:Subdomain)`

- **Same technology** – Assets using the same technology:
  `MATCH (t:Technology {name: 'WordPress'})<-[:USES_TECHNOLOGY]-(a:Asset) WHERE a.organization_id = $org_id RETURN a`

- **Technology → CVE** – Technologies with critical CVEs:
  `MATCH (t:Technology)-[:HAS_VULNERABILITY]->(v:Vulnerability)-[:REFERENCES]->(c:CVE) WHERE v.severity = 'critical' AND v.organization_id = $org_id RETURN t, c`

- **Discovery chain** – How an asset was found:
  `MATCH (a:Asset {asset_id: $id})-[r:DISCOVERED_VIA]->(ds:DiscoverySource) RETURN ds.name, r.step, r.confidence`

- **Shared hosting** – All assets on the same provider:
  `MATCH (a:Asset)-[:HOSTED_BY]->(h:HostingProvider {name: 'cloudflare'}) WHERE a.organization_id = $org_id RETURN a`

- **SAN expansion** – Subdomains sharing a TLS cert:
  `MATCH (a:Asset)-[:SIGNED_BY]->(cert:Certificate)-[:ALSO_COVERS]->(san:Subdomain) WHERE a.value = $domain RETURN san.name`

- **ASN cluster** – All IPs in the same autonomous system:
  `MATCH (ip:IP)-[:BELONGS_TO_ASN]->(asn:ASN {asn_number: $asn}) RETURN ip.address`

## Node types and properties

### Domain (root)
- `name` (string) – root domain name
- `organization_id` (number)
- `discovered_at` (datetime)

### Subdomain
- `name` (string)
- `status` (string) – discovered, verified, etc.
- `organization_id` (number)

### IP
- `address` (string)
- `type` (string) – ipv4, ipv6
- `is_cdn` (boolean)
- `is_internet_facing` (boolean) – true for publicly routable IPs
- `is_live` (boolean) – responded to probes
- `organization_id` (number)

### Port
- `number` (int)
- `protocol` (string) – tcp, udp
- `state` (string) – open, closed, filtered
- `is_risky` (boolean)

### Service
- `name` (string)
- `version` (string)
- `banner` (string)

### Technology
- `name` (string)
- `version` (string)
- `category` (string)
- `cpe` (string)

### Vulnerability
- `id` (string)
- `severity` (string) – critical, high, medium, low, info
- `description` (string)
- `cvss_score` (number)

### CVE
- `cve_id` (string)
- `cvss_score` (number)
- `cwe_id` (string)

### CWE (MITRE)
- `cwe_id` (string)

### DiscoverySource *(new)*
- `name` (string) – tool/method name: `subfinder`, `whoxy_reverse_whois`, `certspotter`, `manual`, etc.
- `display_name` (string) – human-readable label
- `organization_id` (number)

### ASN *(new)*
- `asn_number` (string) – e.g. `AS15169`
- `isp` (string) – ISP/org name
- `country` (string)
- `organization_id` (number)

### HostingProvider *(new)*
- `name` (string) – e.g. `cloudflare`, `aws`, `azure`
- `hosting_type` (string) – cdn, cloud, owned, third_party

### Certificate *(new)*
- `fingerprint` (string) – SHA-256 fingerprint (unique key)
- `common_name` (string) – certificate CN
- `issuer` (string) – issuing CA
- `expiry` (string) – not-after date
- `san_count` (number) – number of SANs
- `organization_id` (number)

## Multi-tenant filtering

All queries must filter by `organization_id` so indexes are used and data is tenant-isolated.

## Implementation notes

- **DiscoverySource**: Created from `asset.discovery_chain` JSON during sync. Each step in the chain becomes a `DISCOVERED_VIA` edge with `step`, `confidence`, and `found_value` properties.
- **ASN**: Created from `asset.asn` and linked to all resolved IPs via `BELONGS_TO_ASN`.
- **HostingProvider**: Created from `asset.hosting_provider` and linked to both the asset and its IPs via `HOSTED_BY`.
- **Certificate**: Created from `asset.ssl_info` JSON. SAN entries are expanded into `Subdomain` nodes via `ALSO_COVERS` — this surfaces shadow IT not yet in the asset inventory.
- **is_internet_facing** on `IP` nodes: derived from `asset.is_public`. This is the boundary marker for internal-hop modeling (e.g. F5 VIP → pool member via `FORWARDS_TO`).

## Troubleshooting: graphs not working on /graph

If https://aegis.judahsecurity.io/graph (or your deployment) shows no data or "Disconnected":

1. **Neo4j not configured**
   Without Neo4j you still get the **Attack Surface** tab using PostgreSQL fallback. The **Relationships**, **Discovery**, **Attack Paths**, and **Vulnerability Impact** tabs only appear when Neo4j is connected.
   - Set `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD` and start Neo4j:
     `docker compose --profile graph up -d`
   - Open the Graph page, select an organization, click **Sync Data**.

2. **Discovery provenance nodes not appearing**
   These are populated during sync from `asset.discovery_chain`, `asset.hosting_provider`, `asset.asn`, and `asset.ssl_info`. If these fields are empty for your assets, the provenance nodes won't exist yet. Run your discovery scanners and re-sync.

3. **API not reachable**
   The frontend calls `/api/v1/graph/status`, `/api/v1/graph/discovery-tree`, etc. Ensure your nginx proxy forwards `/api` to the backend.

4. **Attack Surface tab empty**
   The PostgreSQL fallback returns `risk_distribution`, `discovery_sources`, technologies, and ports. If empty, check backend logs for 401/500 on `/graph/fallback/*`. Ensure the user is in an organization with assets.

5. **Relationships / Explorer tab missing data**
   Populated only after **Sync Data** is run. New ports, tech, and vulns won't appear until you re-sync after scanning.
