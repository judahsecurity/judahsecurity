---
name: sqli
description: Test observed inputs, including search and filter fields, for SQLi with controlled differentials and independent proof.
---

# SQLi on observed inputs

Test every assigned SQLi coverage cell, including `search`, `query`, `filter`,
`category`, `sort`, and other fields that also reflect into a page. Reflection
does not exclude SQLi: the same input can have separate XSS and SQLi cells.
Preserve the captured request, identity, parameter location, and any observed
encoding when forming controls. Do not infer a database sink from a name alone.

## Injection points: find all of them first

The parameter inventory lists every place a request carries data the server
reads. Each row has a `location`; every testable row is SQLi work:

| location | Where the value lives | How to send a controlled value |
|---|---|---|
| `query` | URL query string | scoped probes, or `mutate_captured_request(location="query")` |
| `body_form` / `body_json` | request body | approved POST replay, `mutate_captured_request` |
| `cookie` | one cookie by name (e.g. `site_Language_Preference`) | `compare_requests` with `cookies: {name: value}` on baseline and mutant, or `mutate_captured_request(location="cookie", field=name)` |
| `header` | `User-Agent`, `Referer`, `X-Forwarded-For`, `Accept-Language`, custom `X-*` | `compare_requests` with that header changed |
| `path` | an ID-like path segment, named `path[N]` (`/item/42` → `path[2]`) | `mutate_captured_request(location="path", field="path[N]")` |

Cookies and headers ride on every page, so each name is listed once, on the
page where it was first seen. Session, auth, CSRF, and analytics cookies are
listed but marked untestable. Never inject into them. If the inventory has no
cookie rows, look at `Set-Cookie` on the entry page and add the
application-state cookies you see (language, country, region, branch,
currency, cart, view, sort).

## Determine the context before choosing a payload

Compare against the observed value (for example `1`) using
`generate_payloads("sqli", technique="context_probe")`:

* `2-1` and `1*1` behave like `1` while `1'` differs → **numeric** context. Use
  unquoted payloads: `1 AND 1=1` vs `1 AND 1=2`, `0 UNION SELECT <hex marker>-- -`.
* `1'` breaks and `1''` restores → single-quoted string: `' AND '1'='1`.
* `1"` breaks and `1""` restores → double-quoted string.
* `1)` breaks and `1)-- -` restores → inside parentheses.

A quote-led payload against a numeric sink fails silently: it is a wrong
guess, not a clean result. For an in-band UNION, use
`technique="union_based"`. The marker is hex-encoded, so seeing the decoded
plaintext in the response proves the database ran the query. Raise the NULL
column count (1–6) until it reflects.

## Procedure

1. Prioritize captured catalog search/filter/product inputs and real login/auth
   requests. Probe login POST form or JSON fields only with a valid captured
   session and CSRF workflow; do not guess a login request.
2. Use the assigned scoped probe for an observed GET query. Compare repeated
   baseline, true-condition, false-condition, and unrelated-invalid controls
   with the same request shape. The scoped string probe escalates on its own
   across one baseline: OR Boolean, then error / AND, then UNION (a server-owned
   encoded marker reflected into the response), then time-based (conditional
   sleep). Read `proof_confirmed` and the recipe name; do not hand-build these.
   For approved POST replay, keep the captured body and session context. A
   single quote error is only a lead.
3. If an observed value is encoded, test the actual decode path before selecting
   an SQLi payload. Compare the application response after decoding, not just
   the reflected text. Dynamic content and transient errors need repeated
   controls; a negative bounded recipe is inconclusive for other techniques.
4. If reflection, error, and timing all stay inconclusive on a value that still
   looks injectable and the run authorizes callbacks, try a blind out-of-band
   proof: `run_oob_callback_workflow(sql_family=<mysql|postgresql|oracle|
   sqlserver>, field=<parameter>)` on the same observed GET input. A correlated
   callback is the proof. Escalate to `execute_sqlmap --batch` only on a
   repeatable anomaly the scoped lanes could not close. Use `compare_requests`
   or `run_custom_probe` for a bounded rewrite if a WAF or timeout blocks the
   initial check. Do not use `--os-shell` or treat a scanner miss as proof of
   safety.
5. Submit a candidate only with a reliable differential and its evidence ID.
   The independent verifier must repeat the proof with a fresh control.

Command-looking fields belong to the command injection path; use `execute_commix`
only on a high-signal lead. A status code or template match alone is not SQLi.
