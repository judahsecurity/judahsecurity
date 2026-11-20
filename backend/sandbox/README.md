# Explorer sandbox

A real shell and Python for Prowl's deep assessment mode. Fixed-payload probes
confirm the bugs Prowl already suspects; the explorer finds the rest by
improvising — custom scripts, adapted payloads, multi-step flows — without ever
touching the platform.

## Why it is safe to give the model a shell

The model never runs commands here directly. The in-product agent calls the
runner API (`app/services/agent/explorer_sandbox.py`), which is the only client.
Two containers, started only under the `explorer-sandbox` Compose profile:

- **`prowl-sandbox` (runner)** — runs each command as a per-assessment
  unprivileged uid (20000–29999) in its own workspace, with CPU/memory/file/
  process `rlimit`s, its own process group, and a hard timeout. Holds no
  database, Redis, or cloud credentials. Its entrypoint installs an iptables
  rule so sandbox uids can reach **only** the egress proxy; the runner refuses
  to start if that rule is missing (fail closed), so it needs `CAP_NET_ADMIN`.
- **`prowl-sandbox-egress` (proxy)** — a mitmproxy addon
  (`egress/addon.py` + `egress/policy.py`) that authenticates each request to a
  per-assessment token, admits only that assessment's scoped hosts, resolves the
  host and **pins the connection to a validated public address** (so DNS
  rebinding cannot reach loopback, link-local, or cloud-metadata addresses even
  if a scoped host resolves there), enforces a request budget, and records every
  exchange to Redis. Scope is enforced on the wire, not by parsing shell text.

Recorded exchanges flow into the normal evidence store, so a candidate built
from sandbox work cites real evidence IDs and still goes through independent
verification before anything is published. A text pre-check (Lictor's
destructive-flag denylist, metadata/loopback patterns, credential-guessing tools
without operator opt-in) is defence in depth; the proxy is the boundary.

Availability: deep mode only, and never under pilot mode, scheduled runs with
autonomy limits, or an operator method/path approval policy.

## Running it

```bash
export PROWL_SANDBOX_TOKEN=$(openssl rand -hex 24)   # runner API bearer token
docker compose --profile explorer-sandbox up -d --build prowl-sandbox-egress prowl-sandbox
```

Point the backend at the runner:

```bash
PROWL_SANDBOX_URL=http://prowl-sandbox:8090
PROWL_SANDBOX_TOKEN=<same token>
```

Then run an assessment in deep mode (`assessment_mode: "deep"`). The agent gets
`sandbox_exec`, `sandbox_python` and `sandbox_write_file`, and can dispatch the
`explorer` specialist.

Key settings (`app/core/config.py`): `PROWL_SANDBOX_URL`, `PROWL_SANDBOX_TOKEN`,
`PROWL_SANDBOX_MAX_REQUESTS` (egress budget per assessment),
`PROWL_SANDBOX_EXEC_TIMEOUT_SECONDS`.

## Tests

- `egress/test_policy.py` — the egress decision function (scope, rebinding,
  budget, metadata). Pure, runs anywhere: `python -m pytest backend/sandbox/egress`.
- `backend/tests/test_explorer_sandbox.py` — the backend client: availability
  gating, prechecks, evidence capture.
- End-to-end (needs Docker): build both images and exercise in-scope success,
  out-of-scope refusal, rebinding/metadata denial, proxy-bypass denial, request
  budget, workspace isolation, and timeout.

> Only run assessments against targets you are authorized to test. The sandbox
> narrows what the agent can reach; it does not authorize the engagement.
