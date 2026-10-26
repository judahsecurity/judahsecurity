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
