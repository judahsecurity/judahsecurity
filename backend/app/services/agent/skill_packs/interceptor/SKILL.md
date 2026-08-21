---
name: interceptor
description: Browse the target in a real Chrome tab, capture XHR/fetch, and map functionality. Use when walking an app, capturing authenticated traffic, or enumerating loaded JS before lazy-chunk reconstruction.
---

# Interceptor (Judah)

Judah's `execute_interceptor` is a **Site Spider in a Chrome tab** (Mac worker →
Ubuntu worker → local CLI → Playwright `execute_deep_crawl`). It is **not** the
operator's signed-in Chrome, not macOS Accessibility, not a ChatGPT bridge.

## Always start here

`execute_interceptor` on the primary URL (`depth≈3`, `interact=true`). Attach to
the early-queued job if kickoff already started one. Fallback: `execute_deep_crawl`.

Compound analog of open / read / act / inspect:

- Walk: interceptor / deep_crawl (navigate + wait + interact).
- Re-read: capability map (`pages_visited`, `forms`, `api_samples`, `js_files`).
- Act: `execute_browser` click/fill/type on a concrete flow.
- Inspect: `list_captured_requests` + `fingerprint_api` + `inspect` via map.

## Network — three layers (least invasive first)

1. **Passive XHR/fetch** — `api_samples` from the crawl (Judah's `net log`).
   `list_captured_requests` → `mutate_captured_request` (one field) or
   `fingerprint_api`.
2. **Passive param mutate** — `mutate_captured_request` / `mutate_list`. Do not
   attach a debugger to rewrite bodies unless you must.
3. **Script tags ≠ XHR.** `net log` / `api_samples` do **not** list `<script>`
   loads. Judah records Playwright `resource_type=script` as `js_files`. If that
   list is thin: `execute_browser` `execute_js` with
   `performance.getEntriesByType('resource')` filtered to first-party `.js`, then
   `fetch_lazy_chunks` — crawl only saw what this page state loaded.

Code-split SPAs lazy-load on sign-in / opening tools. Interact, re-enumerate,
then `fetch_lazy_chunks` for the complete webpack/Vite manifest.

## Operating rules

- Prefer the capability map (tree/text analog) over screenshots.
- Stay in the engagement browser session (`auth_session` from interceptor).
  Do not drive the operator's desktop Chrome or native macOS apps.
- Cleanup: do not leave header overrides or interceptors attached.

## Next

`fetch_lazy_chunks` → `extract_js_endpoints` → `ingest_urls_into_map` → hunters.
