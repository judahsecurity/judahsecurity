# Interaction-first browser crawl (`agent/browser_crawl.py`)

The portable analog of Interceptor for a headless agent. Interceptor is a
browser-extension + native daemon that monkey-patches fetch/XHR to drive the
user's real Chrome; that substrate does not port to a headless Linux agent. We
get the capability that matters — **interaction-first crawling with full traffic
capture** — from Playwright, which sees all network at the browser level, with
no extension and no daemon.

## What it does

`browser_crawl(url)` drives real Chromium and, for each in-scope page:

- **captures every request/response** into the SessionStore via
  `page.on("response")` (XHR, fetch, API calls, documents — static assets like
  images/css/fonts are skipped);
- **exercises the page** so lazy content fires: scroll to exhaustion, click
  distinct safe controls once, expand menus/disclosures, fill the first text
  input (autocomplete/search XHR), then follow same-host links.

Destructive controls (delete / logout / pay / deactivate / …) are filtered by
`is_destructive`, so the crawl clicks aggressively without side effects. Scope
is the seed host only by default (no subdomains/third parties).

After it runs, `fingerprint_stack`, `authz_matrix`, `analyze_js`, and
`replay_request` all operate on the full captured surface — the recall the rest
of the pipeline needs.

## This is also how you make Caido realistic

Set `AEGIS_BROWSER_PROXY` to Caido's proxy listener and the whole crawl routes
through Caido, so Caido captures a realistic, interaction-driven surface (not
just a landing page). Then `ingest_caido` pulls Caido's history in. The crawl
records into the SessionStore directly *and* (when proxied) into Caido — belt
and suspenders.

## Testable core vs live driver

The decisions — safe-to-click, in-scope, capture filter, response→transaction —
are pure functions and unit-tested. The Playwright driver needs a live browser
and target; it degrades to a clean `{"error": ...}` when Playwright is absent.

## What we deliberately did NOT port from Interceptor

- The WebExtension + macOS Swift daemon + Unix-socket architecture.
- WebSocket/SSE/beacon deep capture and scene graphs (Google Docs/Canva).
- Driving the user's *real* logged-in Chrome profile.

These are valuable in Interceptor's interactive, human-in-the-loop context but
are the wrong shape for an autonomous headless fireteam. Playwright's
`page.on("websocket")` is the natural place to extend capture if WebSocket-heavy
targets need it.
