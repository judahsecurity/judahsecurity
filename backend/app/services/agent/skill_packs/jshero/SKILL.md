---
name: jshero
description: Exhaustive first-party JavaScript collection and mining. Use when the user says /jshero or wants complete JS endpoints, lazy chunks, params, and DOM sinks. Not operator Chrome, not a VPS waymore hop.
---

# /jshero (Judah)

JShero's collection loop against Judah's Interceptor / capability map. Completeness
is the point: a JS file we never fetch is surface we never hunt.

## Not in this port

- Operator desktop Chrome / `interceptor.exe` / `INTERCEPTOR` profile
- SSH to someone else's VPS for waymore
- Three independent LLM crawls (timeout death). One deep interceptor + static
  chunks + extract/reseed is the Judah pass.
- 1600-pattern secrets regex DB — `scan_js_urls_for_secrets` / Gitleaks

## Loop

1. `execute_interceptor` (`interact=true`, depth≈3). Fallback `execute_deep_crawl`.
   XHR → `api_samples`; `<script>` → `js_files`. Not the operator's signed-in Chrome.
2. `fetch_lazy_chunks` (dry-run then download) — webpack/Vite/Next filenames the
   crawl never clicked. 404s expected.
3. Optional historical URLs: `execute_gau` / `execute_waybackurls`, keep `*.js`,
   fetch in-scope bodies into the map. Do not SSH off-box.
4. `extract_js_endpoints` — GAP/jsluice: paths, axios/XHR **methods**, config
   **params**, template ``EXPR`` routes. Auto-ingest in-scope hits (reseed).
5. `scan_js_sinks` — eval / innerHTML / postMessage / location (not fetch/cookie noise).
6. If `reseed_urls` or new chunks appeared, interceptor/chunks once more, then stop.
   Do not loop until 0 forever inside one turn.
7. `scan_js_urls_for_secrets` on the same bundles (Gitleaks + CWE-321 Object.keys HMAC /
   MQTT/RFID reconstruction). Then fireteam (`spa_client`, `js_secrets`, `injection`) —
   listing endpoints is not a vuln. If `client_signing_summary.submit_without_live_api`
   is true, submit immediately — public reconstruction is the finding.

## Done

Origin + chunk ok/FAIL + endpoint count + methods/params + sink types + whether
reseed ingested. Prove IDOR/SSRF/DOM XSS with a live request.
