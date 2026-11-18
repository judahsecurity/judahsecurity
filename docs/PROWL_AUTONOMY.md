# Prowl scheduled autonomy

Prowl's existing tester process remains the assessment engine. New
`tester_process` schedules enable `config.autonomous_followup` by default and
enqueue one durable work item per target and due time. An explicit `false`
disables it, and existing schedules retain their saved setting. The
`autonomy-worker` service claims one item, runs one bounded
agent turn, saves its redacted engagement state in Postgres, and queues another
turn only when the saved hypothesis graph has new work. Other schedules keep
their existing execution path.

## Enable in AWS

1. If using the EC2 deployment workflow, its script now stops
   `autonomy-worker`, applies the agent-ledger and autonomy table migration,
   then starts and checks the worker. For a manual or other deployment path,
   apply `db/migrations/add_agent_autonomy_work.sql` before starting the worker;
   `create_all` only creates missing tables.
2. Configure the same database, AI provider, RoE, egress IP, and assessment
   proxy settings used by Prowl's existing agent. Confirm the worker is healthy
   before enabling a schedule.
3. On a new `tester_process` schedule, autonomous follow-up is already enabled.
   Each work item uses its target host as its default observation and specialist
   scope. The schedule
   config may also set `max_turns` (default 3, cap 4), `price_limit_usd`
   (default 8), `max_total_seconds` (default 3600, cap 7200),
   `max_specialist_tool_calls` (default 12, cap 40),
   `max_specialist_seconds` (default 300, cap 600), and
   `max_parallel_specialists` (default 3, cap 6). The saved work contract also
   accepts `allowed_hosts`, `allowed_identities`, `allowed_actions` (`read`,
   `probe`, `state_change`), `max_specialist_requests`,
   `specialist_interval_ms`, `max_parallel_tool_calls`,
   `max_specialist_spend_usd`, `max_recon_tool_starts`, and
   `request_rate_per_second`. Extra hosts must pass the current RoE check.
4. Query `GET /api/v1/scan-schedules/{id}/autonomy-work` for work status,
   turns, spend, recon leads, open hypotheses, verified candidates, and stop
   reason. A lead is not a verified finding.
5. Open the schedule's timeline button, or query
   `GET /api/v1/scan-schedules/{id}/autonomy-work/{work_id}/timeline`, to see
   observations, linked hypotheses, specialist attempts, evidence references,
   verdicts, stop reasons, and reported cost without raw tool logs.

The opted-in early recon pack adds a bounded CNAME lookup. DNS, live hosts,
technologies, API endpoints, and first-party scripts enter a shared observation
contract with a target, source, timestamp, evidence reference, scope, and
dedupe key. The takeover scanner saves compatible CNAME events; a scheduled
hunt imports recent in-scope scanner events. One observation produces one
deduplicated specialist hypothesis. Prowl's existing proof checks still decide
whether a candidate is verified.

The worker resumes queued turns after a restart using the Postgres snapshot.
For an expired in-flight lease, it checks the action ledger and a newer costed
snapshot. Only completed read-only work with a new continuation revision is
requeued. Missing receipts, actionful tools, or an unknown spend are explicitly
blocked for operator reconciliation. Disabling the schedule or autonomous
follow-up prevents a queued item from starting.

The per-specialist contract enforces tool starts, identity names in structured
arguments, explicit URL hosts, action class, elapsed time, and parallel tool
calls. Common recon CLIs also receive a request-rate flag. A CLI can still
issue several outbound requests inside one tool start, and a model call can
exceed a reported dollar threshold before usage is returned. Reported token
spend need not gate a small, controlled pilot. If its authorized scope includes a
hard HTTP request count, enforce that count at the request boundary; tool-start
limits alone do not meet it. Compare AWS pilot traffic and finding quality
before widening the scope or changing existing schedules.

## Offline benchmark

Run `PYTHONPATH=backend python backend/scripts/benchmark_autonomy_handoffs.py`.
The checked-in fixture uses non-routable, sanitized NanoClaw patterns and
current Prowl regression controls. It measures asset, endpoint, and hypothesis
lead recall plus extra leads without target traffic. Candidate recall,
receipt-backed verified recall, false positives, requests, time, and spend
remain `null` until AWS pilot outcomes are supplied with `--results`. The
results JSON accepts a `cases` array with `id`, `candidates`,
`verified_candidates`, `false_positives`, `requests`, `time_seconds`, and
`spend_usd`. Use the timeline and verified count from Prowl for those results.
Compare pilot results before enabling existing schedules or widening target
scope.

## Budget stops and provider failover

Every specialist report now carries a `stop_reason`: `done` (it concluded),
`exhausted` (a turn, tool-call, time or spend budget cut it off) or `blocked`
(a model failure, or a timeout with a tool still in flight).

- **Wrap-up.** After a turn, tool-call or time stop, the specialist gets up to
  two more model turns and three calls limited to `submit_finding_candidate`,
  `record_surface_coverage`, `save_note` and `store_memory`. No probing tool is
  offered, and the per-specialist request, scope, identity and action checks
  still apply. It records evidenced leads and a `progress` note (what was
  tested, where it stopped, the next step). A spend stop makes no further model
  call.
- **Time reserve.** With `max_specialist_seconds` set, a specialist stops
  starting new tool turns 45 seconds (or 20% of the limit, if smaller) before
  the limit, so the wrap-up can finish before the hard timeout cancels it.
- **Retries.** An `exhausted` retry is told to continue from its `progress`
  note and not repeat completed tools. Exhausted and provider-error retries
  keep their full turn budget instead of being cut to four.
- **Dispatch output.** `fireteam_dispatch` returns a compact `wave_changes`
  block first (per-specialist verdict, stop reason and progress; candidates
  lifted; spawned and retried lanes). It is kept when large fields are dropped
  for size.
- **Shared provider breakers.** When an LLM key fails with a credit, quota or
  auth error, every task in the process skips that key for 1 minute, then 5,
  then 30 on repeated failures, and a success resets it. Breakers are keyed by
  provider, model and a hash of the key, so one organization's failing key
  does not affect another's. The orchestrator's default model is not tracked.
