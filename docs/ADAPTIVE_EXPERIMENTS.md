# Adaptive assessment experiments

Judah and PROWL can try a new hypothesis on a browser-observed GET query input
with `scoped_adaptive_experiment`. The agent supplies a short hypothesis, one
neutral control value, and one probe value. The executor chooses the URL from a
private browser capture, changes exactly one query field, and sends six GETs in
this order: baseline, control, probe, probe, control, baseline.

The operation rejects duplicate or missing parameter names, credential-bearing
query URLs, state-changing paths, cross-origin destinations, URL-shaped values,
and expired or mismatched coverage leases. It uses the existing scoped GET
budget and identity cookie transport. The result records bounded response
metadata and an evidence ID; a supplied coverage cell and lease attach that ID
to the assigned work item. A stable response difference or database-error label
is an exploratory lead. `finding` is always false. Existing XSS browser execution
and SQLi Boolean/error proof operations remain the path to a candidate and
independent verification.

The older `run_custom_probe` accepts only registered assessment hosts, disables
OOB callbacks and redirects, and caps its wrapped HTTPX requests at six. Its
AST checks and subprocess do **not** form a complete network isolation boundary.
Do not count its output as a scoped evidence receipt or confirmed finding. A
dedicated egress-controlled worker is required before making arbitrary Python
the default autonomous experiment path.

## Next implementation steps

1. Add a browser experiment variant that accepts a bounded, agent-chosen XSS
   payload template for an observed sink, records a fresh nonce execution result,
   and hands it to the existing independent verifier.
2. Add a POST variant only for operator-approved, synthetic-data paths. Require
   a cleanup action and record its outcome alongside the control and probe.
3. Persist an experiment decision (`hypothesis`, source capture, cell, control,
   mutation, outcome, follow-up) so specialists can choose the next check from
   observed results and stop when the request budget or coverage lease expires.
4. Put any arbitrary-code runner behind OS-level network egress policy and a
   per-request meter. Validate destination, redirect, method, and byte limits at
   the network boundary rather than relying on Python source validation.
5. Evaluate on seeded XSS and SQLi fixtures: measure confirmed findings,
   false positives, requests per confirmed finding, scope violations, and
   replay success. Promote only after the independent verifier reproduces the
   proof and the coverage report accounts for inconclusive cells.

The current implementation is a local code change. It has no deployed
assessment run attached to it.
