# Finding retest

`POST /api/vulnerabilities/{id}/retest` (the **Retest fix** button on a
finding) asks whether a finding is still there or fixed. It is different from
**Re-validate**, which asks whether a finding was ever real.

A retest replays the original proof and records one of three verdicts on the
finding's validation record (`purpose: "retest"`, `retest_verdict`):

| Verdict | Meaning | Finding status |
|---|---|---|
| `reproduced` (stored as `confirmed`) | This run observed the original vulnerable behavior again. | A resolved finding is reopened. |
| `fixed` | The original trigger ran under comparable conditions and failed, and a normal control request to the same origin succeeded. | An open or in-progress finding is resolved. |
| `inconclusive` | Anything short of that. | Unchanged. |

One failed request is never a fix. A retest is inconclusive when the proof
needed a signed-in identity or a session-only capture, the proof page or the
control request did not answer normally, the proof's requests were refused
(401, 403, 406, 407, 429 or 503, which a WAF or rate limit can cause), or the
replay errored.

What is replayed:

- **Agent findings:** the stored typed proof step, re-run anonymously with the
  same arguments, at most three steps: the bounded numeric and string SQLi
  controls, and the nonce-confirmed browser XSS and client-behavior checks.
  Each SQLi proof page is first re-observed with one anonymous GET, as a crawl
  would.
- **Template findings:** the same Nuclei template.
- **Port exposure:** the same Nmap state check; `closed` or `filtered` counts
  as fixed.

Other findings return `inconclusive` with `method: "no_replayable_proof"`.
The finding's `metadata.last_retest` records the verdict, method, and status
before and after.

Databases created by SQLAlchemy have a native `validationverdict` enum; the
backend adds the `FIXED` and `INCONCLUSIVE` labels at startup, and
`db/migrations/add_finding_retest_verdicts.sql` does the same by hand.
Databases built from `add_finding_validation.sql` store the verdict as text and
need nothing.
