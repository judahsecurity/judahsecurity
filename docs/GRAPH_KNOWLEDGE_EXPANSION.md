# Neo4j knowledge graph expansion

The existing Neo4j graph remains a projection of PostgreSQL scan data. This
extension adds JavaScript evidence, an optional commit-stamped source graph,
and bounded agent retrieval. EvoGraph continues to store agent execution
history; Palace Memory continues to provide hybrid keyword/embedding search
for notes. Neither requires a second Neo4j deployment.

## Enable and verify the existing deployment

Set a strong `NEO4J_PASSWORD`, `NEO4J_URI=bolt://neo4j:7687`, and
`COMPOSE_PROFILES=graph` in the Compose environment. Start the stack and check
`docker compose ps neo4j` and the authenticated `GET /api/v1/graph/status`
endpoint. A Compose service definition alone does not mean Neo4j is running.
The Neo4j HTTP and Bolt ports bind to `HOST_BIND_ADDRESS` (localhost by
default). The backend does not require Neo4j to start, and graph features
remain optional.

The image is currently `neo4j:5-community`, which does not pin a minor
release. Verify the running server version before installing Neo4j's official
GraphRAG library; that library requires Neo4j 5.18.1 or later.

## Data model

| Evidence | Nodes and edges | Source |
| --- | --- | --- |
| Live scan | `Asset → Port → ServiceObservation → Service` | PostgreSQL port/service rows |
| Web crawl | `Asset → JSResource → Endpoint` | `asset.js_files`, jsluice paths |
| Finding | `Vulnerability → JSResource` | jsluice `source_js` metadata |
| Agent memory | `ChainFinding → Asset` | EvoGraph findings with an exact in-org target |
| Code | `SourceRepository → SourceCommit → SourceFile → CodeSymbol` | JS/TS AST manifest |
| Code routes | `SourceFile → SourceRoute` | Next.js page and route modules |
| Dependencies | `SourceFile → PackageVersion` | imports and npm lockfile |
| Verified mapping | `JSResource → SourceFile` | explicit source map or build manifest |

`Service` represents a shared product name. Version, banner, product and CPE
belong to the port's `ServiceObservation` so scans of different assets cannot
overwrite each other. `JSResource` URLs exclude query strings and fragments to
avoid persisting token-bearing URLs; jsluice records a content hash after a
successful fetch. The new JS and source nodes do not copy raw JS or secret
values into Neo4j. Source files are identified by organization, repository, commit and
path; they store hashes, symbol names and line numbers, not source text.

ASN, Certificate, DiscoverySource, HostingProvider, Service, and Technology
are shared reference nodes. Globally routable IPs are shared by default, while
an explicit network scope takes precedence for any address. Non-global IPs use a
network-scoped identity; without explicit `metadata.network_scope_id`, each
asset keeps its own private IP identity. Tenant observations are stored on edges from an
organization-owned asset or on organization-keyed edges between shared nodes.
In particular, a finding on an asset is not automatically attributed to every
technology or service on that asset.
F5 imports preserve explicit BIG-IP route domain IDs as network scopes. When
a route domain is omitted, F5 addresses use a partition-scoped fallback because
the partition may have a default route domain that the import has not resolved.
Panorama address objects with the same value in different device groups remain separate
assets. Other private-address sources need a stable network or VRF identifier
in `metadata.network_scope_id` to establish shared-IP relationships. Without
that identifier, graph sync intentionally makes no co-hosting inference.
If a source has already collapsed two networks into one PostgreSQL asset, the
graph cannot recover that distinction; the importer must first persist separate
source assets with their network context.

Wiz VM assets retain Wiz resource IDs and provider IDs. The graph projects
Wiz-reported subscription, region, and internet exposure as cloud context.
These relationships identify ownership and location; they do not prove that
two VMs can communicate. The current Wiz query imports vulnerable VMs and
findings, not Wiz Security Graph network paths. Importing those paths requires
a verified Wiz API query and explicit endpoint IDs, direction, and evidence.
Within on-premises and hybrid networks, routing edges should come from a
network integration that supplies a VRF or route domain, interfaces, routes,
policy or ACL evaluation, direction, and observation time. The current
NetBrain integration checks device configuration for specific findings; it does
not yet import routes or forwarding decisions. F5 VIP-to-member forwarding is
the one supported internal reachability edge today. Attack-path results use
Wiz-reported direct internet exposure or an F5 forwarding edge tied to its
exact VIP and member assets. Shared IP, account, region, ASN, provider, or
subdomain relationships are context, not proof of network reachability.

Successful Censys ASM, Wiz, HackerOne, Panorama, F5, Akamai WAF, and NetBrain
imports now project their touched PostgreSQL assets and findings into Neo4j
after commit, for both manual and scheduled runs. The import still succeeds if
Neo4j is unavailable; the next graph refresh can catch up. Cloudflare's scanner
whitelist and Jira/ServiceNow ticket operations do not currently create graph
entities because they do not import topology or new findings.

### Upgrade an existing graph

Pause scheduled graph writers and graph reads, back up Neo4j, and deploy the
new backend. Rerun F5 and Panorama imports so their source records capture
route domains and distinct address objects. Then run the bounded, idempotent
cleanup once and refresh **every** organization's assets from PostgreSQL.
The cleanup drops the old address-only IP constraint,
deletes projected IP nodes and same-IP links, and removes legacy tenant
properties from shared nodes, unscoped links, and unsupported inferred
service/technology/finding edges. A refresh restores organization-keyed links
and per-asset technology observations. Run it for every organization that has
assets; refreshing just one leaves the others' shared links incomplete.

```sh
docker exec asm_backend python /app/scripts/migrate_graph_shared_references.py --apply
docker exec asm_backend python /app/scripts/backfill_graph.py --organization-id 1 --refresh-existing
```

Repeat the second command with each real organization ID. Use its batch and
resume flags for a large organization. Do not run the cleanup concurrently
with scans or graph reads; the graph is partial until all refreshes complete.
Review previously conflated inventory rows after the F5 and Panorama reimport;
the importer marks obsolete source rows inactive, and a refresh carries that
state into the graph.

Existing PostgreSQL data can be backfilled with the authenticated
`POST /api/v1/graph/sync` endpoint for the current organization. Later
jsluice scans attach all extracted paths to their source JS resource after the
normal graph sync. This scan syncs only assets whose JS URLs were analyzed,
instead of replaying the entire organization. Older jsluice finding metadata contributes JS evidence on
backfill; older paths without findings need a new jsluice run for exact
script-to-path attribution.

For a large organization, run a bounded backfill from the backend container
instead of making one long API request. The command writes one asset per
transaction, reports progress after each batch, and resumes by skipping assets
already represented in Neo4j. First run a small sample; then rerun without
`--max-assets` to process the rest:

```sh
docker exec asm_backend python /app/scripts/backfill_graph.py --organization-id 1 --max-assets 20
docker exec asm_backend python /app/scripts/backfill_graph.py --organization-id 1
```

Use `--refresh-existing` after a graph schema or evidence mapping change to
rebuild nodes that were synced before that change. This command does not run
the expensive same-IP sibling-link pass; run the organization sync when that
relationship is specifically needed.

## Import source code

Run the exporter from a checkout of the commit you want to index. It uses the
TypeScript parser already declared by `frontend/package.json`. The default
roots are `frontend/src` and `website/src`; set `GRAPH_SOURCE_ROOTS` to a
comma-separated list to change them. The importer needs the Python Neo4j
driver from `backend/requirements.txt` and network access to Bolt.

```sh
npm ci --prefix frontend
GRAPH_ORGANIZATION_ID=1 node scripts/export_source_graph.cjs > source-manifest.json
PYTHONPATH=backend python -m app.services.graph_source_ingest source-manifest.json
```

Set `NEO4J_URI`, `NEO4J_USER`, and `NEO4J_PASSWORD` for the import command.
On the Docker host, the default URI is `bolt://127.0.0.1:7687`; within the
Compose network it is `bolt://neo4j:7687`. Re-running the same manifest is
idempotent. A new commit creates a new snapshot, retaining historical links.

Only map a deployed bundle to source when build evidence supports it. Pass a
JSON array with `--mappings`, for example:

```json
[{"script_url":"https://app.example/_next/static/chunks/app.js","source_path":"frontend/src/app/page.tsx","evidence":"build-manifest"}]
```

`evidence` must be `source-map` or `build-manifest`, and the source path must
exist in the manifest. A matching filename alone is not accepted. The
organization and commit are taken from the source manifest.
Only set `GRAPH_ORGANIZATION_ID` to an organization that owns the repository
being indexed. Do not attach the Judah Security platform repository to a
customer organization merely to make its source files searchable.

## Agent retrieval

`query_graph` takes `kind`, `value`, and `limit` instead of generated Cypher.
Kinds are `asset`, `port`, `service`, `technology`, `endpoint`, `script`,
`finding`, `memory`, `source_file`, `source_route`, `package`, and `search`. The exact kinds follow known graph
edges. `search` uses Neo4j full-text search as a lexical discovery step; the
agent can then use a specific kind for connected evidence. Queries start at
organization-scoped nodes or filter to that organization and cap output at 50
rows. Palace Memory supplies the existing vector reranking for narrative
notes. This keeps identifier lookups out of the embedding path.

For example, ask which JS file revealed `/admin`, which asset loaded it, and
which finding cites it. The answer should include the script URL, endpoint,
asset, finding ID, and `last_seen` where available. Treat links from a public
bundle to a repository file as unverified until `MAPS_TO_SOURCE` exists.

Track answer correctness on a small set of these questions, graph freshness
after scans, lookup p95 latency, and agent tool calls per answer. Use Cypher
`PROFILE` on any lookup that grows slow; add indexes for measured query paths.

## Production rollout order

1. Deploy the tenant-scoped graph API and organization-aware UI before adding
   new data. Verify a user in one organization cannot retrieve another
   organization's asset relationships or attack paths.
2. Record the running Neo4j version and inspect constraints and indexes. Count
   nodes by label, relationships by type, and isolated nodes per organization;
   the total node count alone is not a coverage metric.
3. Backfill one organization with `POST /api/v1/graph/sync`, then compare graph
   counts with PostgreSQL assets, ports, technologies, endpoints, JS resources,
   and findings. Check a few complete evidence chains manually.
4. Run the source exporter and importer for each deployed commit. Automate this
   in the release pipeline, including build-manifest/source-map bundle mappings,
   so source links remain current after deployments.
5. Turn on incremental graph sync from scan events and expose last successful
   sync, failures, and lag for each source. Measure p95 lookup latency and agent
   tool calls per answer before adding vector retrieval to Neo4j.
