# Dual Interceptor workers (Mac + Ubuntu)

ASM prefers real [Hacker-Valley-Media/Interceptor](https://github.com/Hacker-Valley-Media/Interceptor) browsers for **pentester-style** interaction-first crawls, with Playwright `deep_crawl` as last-resort fallback.

## Goal

Walk the customer app the way a tester would: scroll, open menus, click safe tabs/buttons, follow functional routes (login, demos, products, forms, APIs). Build an **Application Capability Map**, then assess — not page-count spray.

Site Spider skill model: **katana running inside a real Chrome tab**. Interaction is primary; BFS is secondary; `--robots` / `--sitemap` are opt-in.

## Preference order

1. **Mac** Interceptor worker (online heartbeat)
2. **Ubuntu** Interceptor worker (Xvfb / GUI host)
3. Local `interceptor` CLI on the agent host (rare)
4. Playwright **deep_crawl** (same pentester depth/interact defaults)

On each Interceptor host, the worker prefers **native `interceptor spider`** with `--max-pages`, `--depth`, `--max-clicks`. If the binary has no `spider` verb, it falls back to a **functionality-first** open/act/net verb-loop (auth/forms/products prioritized over static marketing URLs).

## Pentester defaults (auto-applied)

When the agent passes a bare URL, ASM fills:

| Knob | Default |
|------|---------|
| `depth` | 3 |
| `max_pages` | 25 |
| `interact` | true |
| `max_clicks` | 14 |
| `prefer_spider` | true |

Example agent call:

```json
{"url":"https://customer.example.com/","depth":3,"max_pages":25,"interact":true,"max_clicks":14}
```

After a successful crawl the tool output includes:
`NEXT: sync_engagement_brain → fireteam_dispatch(auto) → compare_requests`.

## Architecture

```
Agent execute_interceptor
        │
        ▼
 POST /api/v1/recon/jobs   ──►  Mac worker poller
        │                       Ubuntu worker poller
        ▼
 wait + WS thinking heartbeats (page/depth progress)
        │
        ▼
 POST /api/v1/recon/jobs/{id}/complete
        │
        ├─ capability_map + auth_session → live agent session (WS)
        └─ AgentKnowledge document
```

## Env (ASM backend)

```bash
# Shared secret for worker pollers (also accepted as X-Worker-Token)
INTERCEPTOR_WORKER_TOKEN=$(openssl rand -hex 24)

# How long a worker heartbeat counts as "online" (default 90)
INTERCEPTOR_WORKER_HEARTBEAT_TTL_SEC=90

# Max wait for a remote crawl before deep_crawl fallback (default 900)
RECON_JOB_TIMEOUT_SEC=900

# Prefer remote workers when any are online (default true)
INTERCEPTOR_PREFER_REMOTE_WORKERS=true

# Optional: local interceptor binary if colocated with the API
# INTERCEPTOR_BIN=/usr/local/bin/interceptor
```

Add the same `INTERCEPTOR_WORKER_TOKEN` to `docker-compose` backend `environment` (or `.env`).

## Mac desktop worker

1. Install Interceptor Browser pkg from upstream Releases; load the extension in Chrome/Brave (Developer mode).
2. Confirm CLI: `interceptor status` then `interceptor open https://example.com`
3. From a checkout with the backend package on `PYTHONPATH`:

```bash
cd /path/to/theforcesecurity_ASM/backend
export ASM_API_BASE=https://<your-asm-host>/api/v1
export INTERCEPTOR_WORKER_TOKEN=...   # same as server
export PYTHONPATH=.
python -m app.services.interceptor_worker --kind mac
```

Optional launchd / `tmux` keep-alive.

### One-shot (no poller)

```bash
python -m app.services.interceptor_recon https://www.emulate3d.com/ \
  --max-pages 25 --depth 3 \
  --post https://<asm>/api/v1/recon/ingest \
  --token "$ASM_TOKEN" --org 1
```

## Ubuntu Interceptor worker (production)

Run Interceptor on the host because the native messaging daemon, browser
extension, and persistent Brave profile share a per-user runtime. The backend
container only owns the queue API.

The production installer pins Interceptor `v1.0.1`, verifies the official Linux
x64 release SHA-256, installs Brave from its official apt repository, enables
extension developer mode in a dedicated profile, and creates two systemd units:

- `asm-interceptor-browser.service`: Brave + Xvfb + unpacked Interceptor extension
- `asm-interceptor-worker.service`: authenticated ASM job poller

From the production checkout:

```bash
cd /opt/asm
sudo APP_DIR=/opt/asm scripts/install-interceptor-host.sh
```

The installer preserves an existing `INTERCEPTOR_WORKER_TOKEN` or generates one,
updates `/opt/asm/.env`, recreates the backend, and runs an end-to-end job against
`https://example.com`. The gate only passes when the stored result has an
`interceptor_*` engine and came from the Ubuntu worker.

## Capture Interceptor traffic in Caido

The optional Caido service is pinned and bound to host loopback. Start it without
changing the working browser route:

```bash
sudo APP_DIR=/opt/asm scripts/configure-interceptor-caido.sh start
```

From an operator workstation, open an SSH tunnel and visit
`http://127.0.0.1:8081` to register or sign in to the private instance:

```bash
ssh -L 8081:127.0.0.1:8081 aegis
```

After registration, activate capture. This downloads the instance CA from its
loopback proxy, trusts it only in the dedicated Interceptor browser account,
adds Brave's explicit proxy flag, and reruns the real-browser smoke gate:

```bash
sudo APP_DIR=/opt/asm scripts/configure-interceptor-caido.sh activate
```

Keep request interception disabled for unattended crawls so requests do not
pause waiting for an operator. Use HTTP History, HTTPQL, Replay, and Automate on
the captured project. The proxy port is intentionally not exposed publicly.

Use `RUN_E2E_SMOKE=0` to omit the queued smoke job during a repeat installation.
Normal deployments restart an installed host worker and require a ready heartbeat.
Expect roughly 2–4 GB RAM for Brave.

## Verify

```bash
# As analyst JWT
curl -s -H "Authorization: Bearer $TOKEN" \
  https://<asm>/api/v1/recon/workers
# Expect online_kinds: ["mac"] and/or ["ubuntu"]

# Agent path: paste a customer URL — UI should show thinking
# "Queued Interceptor pentester crawl …" then page/depth progress, then capability map.
```

## Ops notes

- If both workers are down, behaviour falls back to deep_crawl with the same depth/interact defaults.
- A fresh heartbeat is only online when its metadata contains
  `interceptor_ready: true`; an installed CLI with an unreachable extension
  cannot claim jobs.
- Mac is preferred when both are online (job claim skips Ubuntu while Mac is healthy).
- Job tables: `recon_jobs`, `recon_worker_heartbeats` (created via SQLAlchemy `create_all` / migration SQL).
- For customer assessments: keep at least one worker online so WAF/SPA apps get a real Chrome walkthrough.

## License boundary

Interceptor is distributed under the Elastic License 2.0. Internal organizational
use is permitted by the upstream commercial-use guidance. If Judah Security makes
Interceptor functionality available as a hosted or managed customer service, or
embeds it as a substantial part of a sold product, confirm a commercial license
with Hacker Valley Media before offering that use.
