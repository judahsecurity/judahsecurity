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

# Agent path: paste a customer URL — UI should show thinking
# "Queued Interceptor pentester crawl …" then page/depth progress, then capability map.
```

## Ops notes

- If both workers are down, behaviour falls back to deep_crawl with the same depth/interact defaults.
- Mac is preferred when both are online (job claim skips Ubuntu while Mac is healthy).
- Job tables: `recon_jobs`, `recon_worker_heartbeats` (created via SQLAlchemy `create_all` / migration SQL).
- For customer assessments: keep at least one worker online so WAF/SPA apps get a real Chrome walkthrough.
