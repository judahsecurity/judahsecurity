---
name: api_test
description: Recon a target's API surface — visit with interceptor, download lazy chunks, fingerprint captured traffic, then extract endpoints from JS. Use when the user says /api-test or wants SPA/API recon.
argument-hint: <target-url>
---

# /api-test (Judah)

Authorized API-recon pipeline. Not Codex, not Caido-required, not the operator's
signed-in Chrome.

**Target:** the URL/host in `$ARGUMENTS` / `target=`.

If the target is empty, ask for it before any tool. Only in-scope hosts.

Run these three steps in order. Report each result before moving on.

## Step 1 — Visit with interceptor

`execute_interceptor` on the target (`interact=true`). Fallback: `execute_deep_crawl`.

Goals:
- Confirm the page loads; capture origin / asset base URL for Step 2a.
- Note served JS (`js_files`) and `publicPath` hints.
- XHR/fetch → `api_samples` (live API calls + asset host). Script tags ≠ XHR.

## Step 2 — Download chunks AND fingerprint (concurrent)

Issue **both** tools in the same round — do not serialize:

**2a.** `fetch_lazy_chunks` — base URL from Step 1. Dry-run first (publicPath), then
download. Relay chunk count and ok/FAIL (404s expected).

**2b.** `fingerprint_api` — original target string (e.g. `tesla.com`). Sibling API
host discovery + coverage matrix from Judah samples, not Caido GraphQL. If no
captured traffic: blocked/no-data — relay and continue.

Wait for both before Step 3. 2b does not depend on 2a's files.

## Step 3 — Extract endpoints from the JS

`extract_js_endpoints` on the bundle plus fetched chunks. Triage `/api`, SSRF,
IDOR, open-redirect. `ingest_urls_into_map`. Return the list (do not write
`all_endpoints.txt`).

## Final report

Target visited, base URL, chunks downloaded, fingerprint (host candidates +
tech indicators + coverage), endpoint count, highest-value leads for manual
follow-up (`mutate_captured_request` / fireteam). This skill maps surface; it
does not prove vulnerabilities.
