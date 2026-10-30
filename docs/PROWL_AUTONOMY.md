# Prowl scheduled autonomy pilot

Prowl's existing tester process remains the assessment engine. A schedule with
`config.autonomous_followup: true` now enqueues one durable work item per target
and due time. The `autonomy-worker` service claims one item, runs one bounded
agent turn, saves its redacted engagement state in Postgres, and queues another
turn only when the saved hypothesis graph has new work. Other schedules keep
their existing execution path.

## Enable in AWS

1. Deploy the backend and scanner images and start `autonomy-worker` alongside
   `scheduler`. The backend creates `agent_autonomy_work` and
   `agent_run_snapshots` tables on startup; the matching SQL is in
   `db/migrations/add_agent_autonomy_work.sql` for managed migrations.
2. Configure the same database, AI provider, RoE, egress IP, and assessment
   proxy settings used by Prowl's existing agent. Confirm the worker is healthy
   before enabling a schedule.
3. On a `tester_process` schedule, enable autonomous follow-up. The schedule
   config may also set `max_turns` (default 3, cap 4), `price_limit_usd`
   (default 8), `max_total_seconds` (default 3600, cap 7200),
   `max_specialist_tool_calls` (default 12, cap 40),
   `max_specialist_seconds` (default 300, cap 600), and
   `max_parallel_specialists` (default 3, cap 6).
4. Query `GET /api/v1/scan-schedules/{id}/autonomy-work` for work status,
   turns, spend, recon leads, open hypotheses, verified candidates, and stop
   reason. A lead is not a verified finding.

The opted-in early recon pack adds a bounded CNAME lookup. Recognized provider
CNAMEs on allowed hosts and first-party script API paths become deduplicated
hypotheses. Specialists receive the hypothesis target and per-member limits;
Prowl's existing proof checks still decide whether a candidate is verified.

The worker resumes queued turns after a restart using the Postgres snapshot.
If it restarts while a tool call is in flight, the lease expires and the work
item is blocked for action-ledger and spend reconciliation; that uncertain
call is never replayed automatically. Disabling the schedule or autonomous
follow-up prevents a queued item from starting.

## Offline benchmark

Run `PYTHONPATH=backend python backend/scripts/benchmark_autonomy_handoffs.py`.
The checked-in fixture uses non-routable, sanitized patterns from the NanoClaw
takeover and API discovery examples. It tests observation-to-hypothesis lead
recall and false leads without target traffic. `verified_recall` remains `null`
until AWS pilot outcomes are supplied with `--results`; use only the endpoint's
receipt-backed `verified_candidates` counts as those results. Report lead
recall and verified recall separately when comparing Prowl with NanoClaw.
