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
   config may also set `max_turns` (default 12, cap 24), `price_limit_usd`
   (default 8), `max_total_seconds` (default 3600, cap 14400),
   `max_stalled_replans` (default 2, cap 4; 0 stops on the first stalled turn),
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

## Turn budget and independent verification

Spend and wall time are the limits a run is expected to reach; `max_turns` is a
backstop. After each turn the worker queues another while open hypotheses,
coverage cells or pending candidates change. When a turn leaves the same work
open, the next turn is asked to re-plan with a different specialist, technique,
identity or input, up to `max_stalled_replans` times.

The last turn, 15% of the spend limit and a few minutes of wall time are held
back for verification. If any finding candidate is still pending when
exploration stops, the worker queues one final turn that only runs
`independent_verify` on those candidates, publishes those the fresh verifier
confirmed, and closes open coverage cells with their proof gaps. A run never
reports `completed` while a candidate is pending; if the budget runs out first,
the stop reason lists the candidates still awaiting independent verification.
Existing schedules keep their saved `max_turns`; raise it to opt them in.

## Continuous dispatch and signal-earned budget

Within an automatic `attack` dispatch, a finished specialist's result is folded
into the task graph as soon as it returns. Hypotheses it unblocks, or follow-ups
it spawns, are leased and started in the freed slot while the rest of the wave
keeps running. A specialist runs at most once per dispatch, at most 12 run per
dispatch, and none starts with less than 90 seconds of the wave left. Its lease
is checkpointed before it acts, and its result is applied to the graph once.
The dispatch result lists these as `refilled_specialists`. Explicit specialist
lists and the recon, observed-input and coverage follow-up modes keep their
fixed waves.

During a scheduled turn, a specialist whose own tool result is a signal (a
submitted finding candidate, a queued proof escalation, or a `LIKELY_IMPACT`,
`MUTANT_BYPASS_CANDIDATE` or `TIME_BASED_INJECTION_CANDIDATE` verdict) receives
`signal_bonus_step` more tool calls and requests (default 4, cap 20) from a pool
shared by the turn (`signal_bonus_pool`, default 24, cap 200; 0 disables it).
Ordinary successful probes do not count. No specialist exceeds three times its
base allowance. The specialist's spend and time limits and the turn's spend
and time limits are unchanged, and a signal remains a lead until the
independent verifier confirms it.

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
