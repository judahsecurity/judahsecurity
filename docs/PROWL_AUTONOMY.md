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

## Peer trace search

Specialists can call `search_peer_traces(q)` to read what other specialists'
tool calls returned in the same session: an error body, a hidden parameter, a
token format. Every term must match; an empty query lists the newest results.
It is answered from an in-memory board on the session's tools manager (the
newest 400 results, 1,500 characters each), so it sends no target traffic and
cannot cross tenants. It excludes the caller's own run but not earlier runs of
the same specialist, so a retry can read its predecessor's results. Each run
gets at most four searches, and they do not count against the tool budget.
Bounded pilots do not get the tool, so their tool list stays exact.

## Out-of-lane leads

A specialist's final JSON may include `leads`: endpoints a tool result
revealed outside its lane (a path in an error body, a hidden API, a linked
admin route), each with a method, URL, one-line reason and the evidence ID of
the tool result that showed it. The specialist does not test them. After the
round, `fireteam_dispatch` keeps a lead only if its host is an engagement
target, its method is a standard HTTP method, and it cites evidence from one of
that specialist's own successful tool calls. Each kept lead is committed as a
`capture` observation event (method, host, path and parameter names; no
values), so the follow-up planner validates and assigns it like any browser
capture. At most five leads per specialist are read. `wave_changes` lists
them and reports `leads_recorded`.

## Evidence search

`search_evidence(query, kind="http_exchange", limit=5)` searches the full text
of the session's recorded HTTP exchanges, newest first, for leaked paths,
internal hosts, stack traces, key names and error formats. Every term of three
or more characters must match, and at most ten hits are returned, each with a
400-character excerpt and the offset to pass to `read_evidence` for the full
context. Artifacts are redacted when recorded, so credential values do not
match. The tool sends no target traffic, is local-only for pilots, does not
record its own output as evidence, and its results go through the
target-content shield like `read_evidence`. Specialists receive it by default.

## Benchmarking bigger specialist budgets

`AGENT_SPECIALIST_TURN_MULTIPLIER` (default `1.0`, bounded to 0.5–4) scales
every specialist's turn limit, from its profile or directive. Scheduled runs
also cap tool calls and time per specialist through the schedule's
`max_specialist_tool_calls` (cap 40) and `max_specialist_seconds` (cap 600).
To test whether budget limits recall, run the same lab cases at `1.0` and at
`2.5` with matching schedule caps, then compare with
`python -m local_harness.ledger_compare`.

## Prompt caching

Anthropic models are called with automatic prompt caching
(`AGENT_PROMPT_CACHE`, default on), so each specialist or planner turn reads
the previous turn's system prompt and history at the cache-read rate. The
specialist system prompt puts its fixed part (role, tools, instructions, run
policy) above the line `=== ASSIGNMENT (everything below changes per task) ===`
and the directive, mission, targets, notes and iteration limit below it. The
Anthropic client adds a cache breakpoint at that line, so every lease a
specialist takes in a run reuses the fixed part. Keep per-assignment text below
the line: anything that varies above it stops the fixed part from being reused.
`token_usage` reports `cache_read_tokens` and `cache_creation_tokens`, and
spend caps price them at 0.1× and 1.25× the input rate.

## Rolling dispatch

With `FIRETEAM_ROLLING_DISPATCH=true` (default off), an attack-mode round no
longer waits for its slowest specialist before acting on results. As each
specialist finishes, `fireteam_dispatch` folds its report into the task graph
and fills the freed slot with work that report made ready:

1. a retry of that specialist (once per round, continuing from its progress
   note) when the auto-prompter would rewrite it, if at least 90 seconds of
   the round remain;
2. a hypothesis it spawned, or a chain step whose prerequisite it proved, one
   lease per specialist.

New work goes through the same lease claim, directive builder and
credential-testing permission as round-start work. At most
`FIRETEAM_MAX_MID_WAVE_STARTS` (default 6) members start mid-round, never with
less than 60 seconds of the round left, and they share the round's deadline.
Work that finds no free slot or time is left for the post-round retry wave or
the next dispatch, as before. `started_mid_wave` in the dispatch result lists
what started and why.

Out-of-lane leads and observation follow-ups are still applied after the
round. Assigning them mid-round needs the follow-up planner's coverage-cell
writes to merge with the cells specialists update while they run.

To compare, run the same lab cases with the flag off and on and compare with
`python -m local_harness.ledger_compare`. The follow-up chain timings in
`chain_report` (`accept_to_claim_ms`, `observation_to_verdict_ms`) show how
long found work waits before a specialist picks it up.

## Signed-in shell without credentials

Many single-page apps stop an anonymous browser at a client-side login gate,
so the APIs behind it never appear in the map. `scoped_browser_assessment`
with `operation="map"` or `"inspect_js"` and `unlock_shell=true` renders those
screens without a login:

- Before any page script runs, placeholder auth markers are put in local and
  session storage and a `token` cookie. The placeholder is JWT-shaped with an
  invalid HS256 signature (never `alg: none`), so no server accepts it.
- Same-origin XHR/fetch GETs go to the server as usual. When the server says
  "not signed in" (401/403/419/440, or a JSON body with a login error), the
  page receives a neutral success body instead, or a placeholder user for
  identity, permission and menu endpoints, so the app keeps rendering.
- XHR/fetch requests other than GET, HEAD and OPTIONS are never sent. Their
  method and path are recorded with `not_sent: true`, and the page receives a
  placeholder success.
- Client routes from the caller (`shell_routes`), a mounted Vue router, router
  tables in loaded scripts, and page links are visited with
  `history.pushState`, at most 12, skipping login and state-changing paths.

`shell_unlock.auth_gated` lists the requests the server refused without a
session, with their real status. Those surfaces are marked `auth_gated` in the
engagement brain, and withheld requests are marked `state_changing`. They are
authorization targets, not findings. Placeholder responses are never kept as
replayable captures.

The assessment pipeline runs this once after the anonymous JS inspection when
no login is configured (`AGENT_SHELL_UNLOCK`, default on).
