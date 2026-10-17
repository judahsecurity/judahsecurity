# Manual testing and external finding validation

## Current implementation

The Agent page now shows persisted run counts near the top and lets an analyst
draft a focused hunt from an open input check or an external claim. The draft is
reviewed in the normal agent composer; it is not a durable import or a verified
case. The work record groups class coverage and pages recent actions. Generic
finding rechecks report endpoint reachability as inconclusive, and the Findings
page labels a reproduced Nuclei match as detector reproduction.

Agent assessments also run a bounded browser walkthrough after the first crawl,
even when that crawl found inputs. The built-in browser visits up to six linked
same-origin pages and clicks up to six safe tabs or disclosures across those
pages. It can open navigation menus and follows newly revealed links before
older queued links. Safe link query values stay inside the browser for
navigation; the agent sees paths and parameter names. It observes rendered forms, link parameter names,
first-party scripts, and XHR/fetch traffic after interactions. The Agent page
distinguishes browser-observed pages from pages mapped by other crawlers and
shows mapped form and link counts with recent browser actions. Failed
walkthroughs remain incomplete in the tester loop. Discovery does not submit
forms or perform state-changing actions.

The durable lead inbox, captured-request test workbench, new proof recipes, and
server-enforced publication flow below are the next implementation steps.
Deeper authenticated journeys and form submissions need explicit identities,
approved fixtures, readback, and cleanup before the agent can exercise them.

## Problem observed

The October 16 Gin & Juice assessment's narrative called two SQL injection leads
confirmed. Its persisted work record showed 8 input candidates, 0 verified input
candidates, 0 published findings, 99 open class checks, and 0 completed scanner
coverage actions. A reader cannot tell which claim has an independent proof.

The current Agent candidate workflow already separates discovery from independent
verification. The separate Findings recheck can re-run a Nuclei template or a
port check; for a generic manual or agent finding it only probes URLs found in
the writeup. Endpoint reachability is not evidence of SQLi, XSS, or authorization
bypass. The generic recheck must remain inconclusive until a class-specific test
has run.

## Operator experience

Put a **Testing** workspace at the top of the Agent page. Keep chat as a way to
direct work, not the source of truth for results.

1. **Lead inbox:** Paste a claim or import scanner output (start with Nuclei
   JSON and SARIF). Show its source, target, vulnerability class, exact observed
   request or detector, and any missing prerequisites. An imported pass is a
   *lead*, never a finding.
2. **Prepare test:** Select a captured first-party request, approved identities,
   a class-specific proof recipe, rate/budget, and any disposable fixture and
   cleanup. Show the exact mutations and expected controls before replay.
3. **Run manual test:** Expose baseline, negative control, candidate signal,
   browser or OAST observation, and side-by-side response differences. Let the
   analyst revise the hypothesis and rerun a bounded test.
4. **Verify:** A fresh verifier repeats the same recipe with a new nonce and
   separate execution artifacts. Show confirmed, refuted, inconclusive, or
   blocked with a reason. Only a current confirmed receipt may unlock Publish.
5. **Review:** The page shows published findings, verified but unpublished
   candidates, open leads, coverage by class, current action, failed/blocked
   work, and work skipped by budget. Every count links to its underlying cases.

The status language should distinguish **detector reproduced**, **mechanism
proved**, and **finding published**. Chat summaries may cite these records but
must not override them.

## Proposed service contract

Use the existing organization/session scope and execution-owned evidence store.
Add durable `ValidationCase` records with `source_type`, `source_tool`,
`source_fingerprint`, `target`, `vulnerability_class`, `claim`, `claimed_impact`,
`capture_id`, `identity_requirements`, `recipe_id`, `status`, and timestamps.
Imported text is untrusted source material and cannot create execution-owned
evidence. Deduplicate on source fingerprint, target, class, and affected input.

Add immutable `ValidationRun` records for the hunter and verifier. Each records
recipe version, nonce, scope/identity snapshot, redacted request and response
artifact IDs, control results, cleanup status, and verdict reason. Persist a
redacted proof bundle and digest long enough for review; the current short-lived
evidence ID alone is insufficient for a durable published finding.

Proposed API flow (names subject to repository conventions):

```text
POST /agent/validation-cases              import or enter a lead
GET  /agent/validation-cases               filtered inbox and counts
POST /agent/validation-cases/{id}/prepare  validate scope and recipe, no traffic
POST /agent/validation-cases/{id}/test     bounded hunter execution
POST /agent/validation-cases/{id}/verify   fresh independent execution
POST /agent/validation-cases/{id}/publish  consume current confirmed receipt
```

The server, not the model, enforces scope, identity, rate, replay method,
candidate revision, evidence provenance, and publication gates. A timed-out
write is not retried automatically. A case with incomplete cleanup remains
visible as `needs_follow_up`.

## Proof recipes

| Class | Minimum observable proof | Current state |
| --- | --- | --- |
| SQLi | Repeated baseline/true/false or error controls, then independent replay on the same input | Structured proof exists |
| XSS | Fresh browser nonce executes in the affected context | Structured proof exists |
| IDOR/authz | Known private fixture; owner and distinct verified attacker; read/write effect and readback | Structured proof exists |
| SSRF | Correlated callback from a fresh OAST registration and planting request | Structured proof exists |
| Exposure | Exact unintended content or directory listing, not HTTP 200 alone | Structured proof exists |
| CSRF | State change with and without the defense under a legitimate identity, followed by readback and cleanup | Recipe needed |
| XXE, command injection, traversal, SSTI, NoSQL | Class-specific harmless canary and negative controls; never infer from a generic 500 or reachable URL | Recipes needed |
| Race/business logic | Disposable fixture, expected invariant, bounded concurrent or sequenced actions, readback, cleanup | Recipe needed |
| CVE/misconfiguration | Verify product and preconditions, then the named mechanism or an explicit applicability-only verdict | Recipe needed |
| Other or unsupported | Analyst can record observations, but verdict stays inconclusive until a reviewable recipe exists | Manual review |

## Execution and page behavior

Reserve bounded time for manual replay and verification before broad scanning.
Do not let repeated model calls or a stalled specialist consume the whole run.
Show live action, elapsed/budget, queue position, blocked prerequisite, and the
reason a class has no proof. Once a case is verified, stop duplicate hunts for
the same input and publish or explicitly leave it pending review.

The Agent page should have four views: **Testing** (current action and control
results), **Leads** (imported and discovered claims), **Coverage** (per-class
attempted/probed/verified/published plus blocked and budget-skipped), and
**Activity** (paged receipts). A compact status strip should remain visible
above chat. The attack scenario map remains useful for navigation but cannot
stand in for proof status.

## Acceptance checks

- A reachable URL attached to a manual SQLi/XSS claim never produces a
  confirmed or false-positive verdict by itself.
- A Nuclei match is labeled as detector reproduction until a class-specific
  proof is attached; version-in-range stays applicability-only.
- Vulnerable and patched fixtures for every supported recipe produce distinct
  confirmed/refuted results; missing identity, scope, evidence, or cleanup is
  inconclusive or blocked.
- An imported claim cannot publish without a fresh independent receipt bound
  to the current candidate revision.
- The Agent page shows the persisted counts and reasons prominently, and a
  narrative cannot display a stronger verdict than the linked proof record.

Build the import inbox and SQLi/XSS/authz/SSRF/exposure workbench first. Add
new recipes one class at a time with vulnerable and patched fixtures. This
keeps the verifier's claims aligned with what it can actually demonstrate.
