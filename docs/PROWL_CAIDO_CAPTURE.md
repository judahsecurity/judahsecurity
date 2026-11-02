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

## Import analyst-browsed history (optional)

An analyst can browse an authenticated or multi-step flow through the same
Caido project, then let Prowl fingerprint it. `fingerprint_api` with
`source="caido"` reads that project's history back through Caido's GraphQL API.

Create a Caido API token in the assessment instance's UI, then set in
`/opt/asm/.env` and recreate the backend:

```dotenv
AEGIS_CAIDO_API_URL=http://caido-assessment:8080
AEGIS_CAIDO_API_TOKEN=<token>
# Optional extra HTTPQL clause, AND-ed with the host filter:
# AEGIS_CAIDO_IMPORT_FILTER=req.created_at.gt:"2026-11-01T00:00:00Z"
```

The URL is the UI listener on the Compose network, not the 8082 proxy port.
The import:

- keeps only hosts under the target's apex and drops static assets;
- skips requests carrying Prowl's own probe markers (`X-Prowl-Probe`,
  `X-Aegis-Verify`, and Prowl's assessment user agents);
- never reads request bodies, and redacts `Authorization`, API-key headers,
  and cookie values (cookie *names* are kept for stack detection);
- returns samples to the fingerprint report only. They are not added to the
  replayable `api_samples`, so mutation tools never resend an analyst request.

Imported traffic is a lead. Re-observe an endpoint in the current run before
testing or reporting it. Without the two variables, `source="caido"` reports
that the import was skipped and fingerprints the capability map as before.
