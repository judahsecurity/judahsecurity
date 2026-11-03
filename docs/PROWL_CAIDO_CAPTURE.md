# Prowl assessment capture through Caido

Prowl's own evidence receipts remain the source of truth for verification.
Caido is an optional analyst view of HTTP requests and responses. With this
configuration, Prowl's structured `_http_exchange` calls, local scoped GET/POST
probes, and scoped Playwright browser use Caido. This captures baseline and
modified requests from locally executed observed-input checks and their
verifier. Prowl still applies scope checks before sending traffic.

MCP command-line scanners, remote scoped services, and remote recon workers
use separate transports. Their requests are **not** guaranteed to appear in Caido. Do not treat a Caido
count as total assessment coverage or a Caido request ID as proof by itself.
The existing run-scoped evidence IDs, controls, and verifier gate remain
required for findings.

## Start on the Compose host

Build the backend image, then start the dedicated Caido assessment profile
to initialize its persistent CA and proxy. Enable proxy routing in `.env`
and recreate only the backend. This order lets the backend import the CA into Chromium's NSS trust
store when it starts.

```bash
cd /opt/asm
git pull --ff-only origin main
sudo docker compose build backend
sudo docker compose --profile caido-assessment up -d caido-assessment
```

Before enabling proxy routing, open the Caido UI through the loopback SSH tunnel,
sign in, and create/select a project for this assessment. Caido needs an
active project to retain traffic. Keep Intercept turned off so probes are
not paused waiting for a manual forward.

Set these two values in `/opt/asm/.env`:

```dotenv
AEGIS_ASSESSMENT_PROXY_URL=http://caido-assessment:8082
AEGIS_ASSESSMENT_CA_BUNDLE=/app/certs/caido/ca.crt
```

Then:

```bash
sudo docker compose up -d --no-deps --force-recreate backend
sudo docker compose ps backend caido-assessment
sudo docker compose exec -T backend python -c 'from app.services.agent.assessment_proxy import assessment_httpx_options; print(assessment_httpx_options())'
```

The last command confirms the backend selected Caido and a readable CA. It
does not send target traffic. Before the full assessment, send one authorized
in-scope read-only request and confirm its request and response appear in
the selected Caido project. A failed CA import or missing certificate stops
backend startup rather than turning off TLS verification. To inspect Caido,
tunnel the loopback UI port (`ssh -L 8083:127.0.0.1:8083 <host>`) and open
`http://localhost:8083` locally. The assessment proxy has no host-published
port and is reachable only on the Compose network. Do not publish the UI.

The assessment Caido instance uses its own persistent volumes. The private
CA is mounted only in that container; the backend receives the public
certificate. The existing host Interceptor Caido instance and CA are
unchanged. The assessment instance is shared by this Compose deployment,
so restrict its UI to authorized
analysts and avoid treating its traffic store as a per-tenant isolation
boundary. Disable routing by removing the two environment values and
recreating the backend; its native evidence receipts continue to work.

## IDOR / BOLA lead extraction

`list_idor_leads` turns already-captured, value-free traffic into object-level
authorization *leads* — candidates for cross-identity replay. It reads only the
paths, input names, methods, and identity labels already in the capability map
and this session's browser captures. It sends no requests, charges no budget,
and copies no request values, cookies, or auth headers. Every row is a lead,
never a finding and never proof. Confirming a lead still requires an
operator-declared exact resource, two named identities, `scoped_owner_only`
(read) or `scoped_owner_only_write` (write), and the independent verifier gate.

### Optional: augment leads from the assessment Caido history

By default Prowl does not read back from Caido; Caido is a one-way analyst view.
An operator may opt a session in to also mine the assessment Caido project's
in-scope HTTP history for the same value-free leads. This is gated twice:

1. Set the GraphQL endpoint (and token if the project requires one) in
   `/opt/asm/.env`:

   ```dotenv
   AEGIS_ASSESSMENT_CAIDO_GRAPHQL_URL=http://caido-assessment:8080/graphql
   AEGIS_ASSESSMENT_CAIDO_TOKEN=
   ```

2. Enable it for the session through the operator-supplied assessment policy
   (`caido_idor_leads: true`). The model cannot enable it on its own.

The reader issues a single bounded GraphQL **query** (never a mutation), keeps
only records whose origin is in the current assessment scope, and extracts
methods, paths, and parameter names only. Caido's GraphQL schema changes between
releases, so this source is best-effort: if the endpoint is unreachable or the
schema shifted, `list_idor_leads` simply reports `caido_history.ok = false` and
returns the leads it derived from Prowl's own captures. Prowl's receipts remain
the source of truth; a Caido-derived lead is still only a lead.

## Write-style IDOR (cross-identity write authorization)

`scoped_owner_only` proves a second identity can *read* an owner's object.
`scoped_owner_only_write` proves a second identity can *modify* it, using a
bounded canary write and an owner-side readback:

1. owner readback — neither fresh canary present (baseline)
2. owner writes canary A (authorized self-write)
3. owner readback — canary A present (the field is writable and reflected)
4. the other identity writes canary B to the owner's object
5. owner readback — canary B present ⇒ the other identity mutated the owner's
   object (cross-account write confirmed)
6. owner restores the field (cleanup) and a final readback confirms neither test
   canary remains

Only step 5 confirms the finding; a rejected (4xx) or unreflected other-identity
write does not. Every write targets one operator-declared, bounded field with
short random nonces, and the owner restores the field at the end. Cleanup never
affects `proof_confirmed`.

This is gated by the operator, never the model. The operator declares each write
resource in the assessment policy and must also list its write path among
`body_replay_paths`:

```json
{
  "body_replay_paths": ["/api/orders/42"],
  "owner_only_write_resources": [{
    "target": "https://app.example.test/api/orders/42",
    "readback_target": "https://app.example.test/api/orders/42/view",
    "method": "PUT",
    "field": "/note",
    "owner_identity": "owner",
    "other_identity": "attacker"
  }]
}
```

The hunter result is one actor's evidence. The independent verifier must repeat
the proof with a fresh execution-owned capture and fresh canaries; the
publication gate requires two confirmed runs with distinct captures and distinct
canaries before a finding can be created.

## Per-engagement isolation

The shared `caido-assessment` service keeps one active project at a time, so it
pools traffic and must not be treated as a per-tenant boundary. To isolate
concurrent engagements, give each its own assessment Caido instance.

### Isolated instance per engagement

`docker-compose.assessment-caido-instance.yml` is a self-contained, parameterized
instance. Run it under a per-engagement compose project name so Docker namespaces
its container and volumes, with its own loopback UI/proxy ports:

```bash
BACKEND_IMAGE=asm-backend:latest \
ASSESSMENT_UI_PORT=8183 ASSESSMENT_PROXY_PORT=8184 \
docker compose -p caido-acme2026 \
  -f docker-compose.assessment-caido-instance.yml up -d
```

Select a persistent project named for the engagement in that instance's UI, then
bind that engagement's backend to it:

```dotenv
AEGIS_ASSESSMENT_PROXY_URL=http://<instance-host>:8082
AEGIS_ASSESSMENT_CA_BUNDLE=/app/certs/caido/ca.crt
AEGIS_ASSESSMENT_CAIDO_GRAPHQL_URL=http://<instance-host>:8080/graphql
AEGIS_ASSESSMENT_CAIDO_PROJECT=acme2026
```

Each instance has its own CA and volumes; one engagement's traffic store is
never visible to another. Ports bind to loopback only.

### Binding attribution

`AEGIS_ASSESSMENT_CAIDO_PROJECT` records which engagement/project the deployment
is bound to. `list_idor_leads` echoes this under `caido_history.binding`:

* `isolation: "labeled"` — a project label is set (attributable to one engagement)
* `isolation: "unlabeled_shared"` — a Caido endpoint is configured but no project
  label, so traffic cannot be attributed to a single engagement (pooled)
* `isolation: "unconfigured"` — no Caido history source

Set a project label whenever the Caido history source is enabled so the active
binding is explicit and auditable. Isolation itself still comes from running a
separate instance per engagement, not from the label.
