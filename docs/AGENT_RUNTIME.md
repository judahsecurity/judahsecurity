# Durable agent runtime

Judah's agent runtime has one canonical control plane for product runs, CLI runs,
workers, and future MCP callers. The existing orchestrator, fireteams, playbooks,
model router, scheduler, Praetorium policy hooks, Palace memory, and WebSocket UI
remain the execution layer.

## Runtime contract

`backend/packages/aegis_runtime` defines stable run statuses, lifecycle events,
and versioned skill manifests. Orchestrator callbacks, finding verification,
memory access, and operator commands are persisted to `agent_events` using that
vocabulary.

PostgreSQL stores:

- restart-safe run status and leases in `agent_runs`;
- append-only lifecycle records in `agent_events`;
- cross-process stop, steer, load, and compact commands in `agent_commands`;
- resumable snapshots in `agent_checkpoints`;
- reviewed skill versions and notification delivery state.

Apply `db/migrations/add_agent_runtime.sql` and
`db/migrations/add_agent_memory_governance.sql` before deploying. Local JSON
snapshots remain as an upgrade/development fallback.

Operators can use:

```bash
python -m app.cli runs --org 1
python -m app.cli run-status --org 1 --session SESSION
python -m app.cli events --org 1 --session SESSION
python -m app.cli stop --org 1 --session SESSION --issued-by analyst@example.com
```

The same data is available under `GET /agent/runs`,
`GET /agent/runs/{session_id}`, and `GET /agent/runs/{session_id}/events`.
Authenticated WebSocket disconnects no longer cancel a run; operators can
reconnect, inspect its durable events, or issue an explicit stop command.

## Skills and evaluations

Built-in `/skill` workflows expose signed-by-content, semantic-versioned
manifests with risk class, approval requirement, input contract, budget, and
evaluation-suite name. `POST /agent/skills/sync` snapshots manifests for review;
pass `enable=true` only after approval. Existing Praetorium controls remain the
enforcing per-tool policy while manifests are introduced in audit-only mode.

The harness has a deterministic skill gate:

```bash
python -m local_harness.eval_gate \
  artifacts/benchmark_report.json --skill external-assessment
```

Thresholds live in `harness/evals/skill_suites.json`. Failed recall, precision,
cost, scope-control, or scan-health criteria return exit code 2 for CI.

## Notifications

Admins configure email, generic webhook, Slack, or Teams endpoints through
`/agent/notifications`. Records store an environment-variable name, never a URL
or credential. For example, configure `config_ref=AGENT_SLACK_WEBHOOK` and set
that variable only in the runtime secret store.

Notifications are emitted only for actionable run/finding events and are
deduplicated by endpoint and event ID. Webhooks require HTTPS, reject userinfo
and non-public destinations by default, and can be HMAC-signed with
`AGENT_NOTIFICATION_SIGNING_SECRET`.

## Execution boundary

`backend/packages/aegis_executor` runs workflow scripts with an allowlisted
environment, bounded output, wall/CPU/memory/process/file limits, no stdin, and
process-group termination. Secret-like environment variables fail closed unless
explicitly authorized by policy.

The API container drops all Linux capabilities. The scanner retains only its
raw-network capabilities. Docker-socket validation is removed from the default
deployment; use `docker-compose.validator.yml` only on a dedicated trusted
worker. Chromium sandboxing is on by default.
