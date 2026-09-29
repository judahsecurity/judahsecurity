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

Existing PostgreSQL data can be backfilled with the authenticated
`POST /api/v1/graph/sync` endpoint for the current organization. Later
jsluice scans attach all extracted paths to their source JS resource after the
normal graph sync. This scan syncs only assets whose JS URLs were analyzed,
instead of replaying the entire organization. Older jsluice finding metadata contributes JS evidence on
backfill; older paths without findings need a new jsluice run for exact
script-to-path attribution.

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
