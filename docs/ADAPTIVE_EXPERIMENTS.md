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

1. Run the product-agent class lab's vulnerable and patched pairs with equal
   model and request budgets. Measure verified recall, false positives, request
   count, time, and spend before expanding mutation choices.
2. Main now has context-aware browser XSS variants and approved POST XSS/SQLi
   replay. If paired runs show a recall gap, extend those executors with a
   bounded agent-chosen variant on an observed sink or approved synthetic-data
   POST path. Preserve fresh nonce proof and cleanup requirements.
3. Persist an experiment decision (`hypothesis`, source capture, cell, control,
   mutation, outcome, follow-up) so specialists can choose the next check from
   observed results and stop when the request budget or coverage lease expires.
4. Enforce the scheduled assessment's actual HTTP request and rate limits at
   the shared network boundary. The current specialist limit counts tool starts;
   a browser or CLI tool may send several outbound requests per start.
5. Put any arbitrary-code runner behind OS-level network egress policy. Validate
   destination, redirect, method, and byte limits at the network boundary
   rather than relying on Python source validation.

The current implementation is in draft PR #96. It has no deployed assessment
run attached to it.
