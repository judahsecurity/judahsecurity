# Dual Interceptor workers (Mac + Ubuntu)

ASM prefers real [Hacker-Valley-Media/Interceptor](https://github.com/Hacker-Valley-Media/Interceptor) browsers for interaction-first crawls, with Playwright `deep_crawl` as last-resort fallback.

## Preference order

1. **Mac** Interceptor worker (online heartbeat)
2. **Ubuntu** Interceptor worker (Xvfb / GUI host)
3. Local `interceptor` CLI on the agent host (rare)
4. Playwright **deep_crawl**

## Architecture

```
Agent execute_interceptor
        │
        ▼
 POST /api/v1/recon/jobs   ──►  Mac worker poller
        │                       Ubuntu worker poller
        ▼
 wait + WS thinking heartbeats
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
  --max-pages 25 \
  --post https://<asm>/api/v1/recon/ingest \
  --token "$ASM_TOKEN" --org 1
```

## Ubuntu Interceptor worker (same EC2 or sibling host)

Do **not** bake Interceptor into the backend Docker image. Run on the host (or a dedicated GUI box):

1. Install Brave/Chrome + Xvfb (or a real desktop session).
2. Build/install Interceptor browser-only from upstream (`scripts/install.sh --browser-only`).
3. One-time: enable Developer mode and load the unpacked extension (use x11vnc / VNC if headless).
4. Persist the browser profile under e.g. `/var/lib/asm-interceptor/chrome-profile`.
5. Start the poller:

```bash
export DISPLAY=:99
export ASM_API_BASE=http://127.0.0.1:8000/api/v1   # or public URL
export INTERCEPTOR_WORKER_TOKEN=...
export PYTHONPATH=/opt/asm/backend
python -m app.services.interceptor_worker --kind ubuntu --worker-id ubuntu-ec2-1
```

Compose helper service (profile `interceptor`) mounts the host display and profile — see `docker-compose.yml` comments for `interceptor-worker`. Expect ~2–4 GB RAM for Chrome.

## Verify

```bash
# As analyst JWT
curl -s -H "Authorization: Bearer $TOKEN" \
  https://<asm>/api/v1/recon/workers
# Expect online_kinds: ["mac"] and/or ["ubuntu"]

# Agent path: ask for a crawl of a URL — UI should show thinking
# "Queued Interceptor crawl job …" then capability map updates.
```

## Ops notes

- If both workers are down, behaviour matches today’s deep_crawl fallback.
- Mac is preferred when both are online (job claim skips Ubuntu while Mac is healthy).
- Job tables: `recon_jobs`, `recon_worker_heartbeats` (created via SQLAlchemy `create_all` / migration SQL).
