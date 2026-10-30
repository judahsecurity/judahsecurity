# Prowl autonomy upgrade sequence

1. **Normalize recon observations into hypotheses.** Add DNS/CNAME, live host,
   technology, JS endpoint and API observations to a shared event contract with
   target, source, timestamp, evidence reference, scope, and dedupe key. Adapt
   the existing takeover scanner and recon outputs to emit those events. Map
   CNAME/provider evidence to takeover hypotheses and JS-only API discoveries to
   relevant API and JS specialists.
   Acceptance:
   - A saved observation produces one ready, scoped hypothesis and one
     specialist dispatch, even when the same observation arrives twice.
   - A takeover hypothesis outside the run's origin is either dispatched in a
     host-scoped lane or explicitly skipped with a reason.

2. **Add a durable autonomy driver.** Store assessment run state and
   continuation revisions in Postgres, claim queued work atomically, heartbeat
   leases, and resume after worker restart. Reconcile expired leases against
   the action ledger before retrying; never blindly repeat a state-changing
   probe. Reuse Prowl's snapshots and task graph.
   Acceptance:
   - Interrupt a worker between observation and dispatch, restart it, and show
     exactly one completed or explicitly blocked work item.
   - Two workers racing for the same queued item produce one claim.

3. **Give each specialist a bounded contract.** Keep target and identity scope,
   allowed actions, request rate, time, spend, and per-specialist concurrency in
   the work item. Propagate limits to recon tools and child specialists; expose
   why a hypothesis was skipped, blocked, or exhausted.
   Acceptance:
   - A specialist cannot exceed its assigned budget or expand scope when it
     pivots.
   - A nested specialist's model spend appears in the run's total.

4. **Make outcomes visible.** Show the observation, hypothesis, specialist, tool
   attempts, evidence, verdict, stop reason, and cost in one run timeline. Keep
   potential leads separate from verified findings.
   Acceptance:
   - An operator can explain every finding and every stopped branch without
     reading raw logs.

5. **Benchmark before broad rollout.** Build sanitized fixtures from the
   successful NanoClaw cases and current Prowl regression cases. Track asset and
   endpoint recall, candidate recall, verified finding recall, false positives,
   requests, time, and spend. Release behind a feature flag: offline fixtures,
   then a controlled AWS pilot, then default-on only if the evidence supports
   it.
