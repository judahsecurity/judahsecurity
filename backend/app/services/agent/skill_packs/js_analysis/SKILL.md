---
name: js_analysis
description: Extract API endpoints, paths, and URLs from JavaScript for recon and bug hunting. Use when hunting hidden APIs, IDOR, SSRF, or open-redirect leads in JS.
---

# JavaScript endpoint extraction (Judah)

Local analysis after an in-scope fetch. Not a secret scanner.

## Workflow

1. `extract_js_endpoints` on crawled `js_files` and/or URLs from `fetch_lazy_chunks`.
   Beautify is unnecessary — the extractor splits minified `;} )>` like the
   portable `extract_endpoints.sh` skill.
2. Triage groups in the tool output:
   - `/api/...` routes
   - absolute URLs (SSRF / open-redirect candidates)
   - `.get` / `.post` / `.ajax` / `.load` / `fetch` targets
   - paths with `?id=` / `?user_id=` (IDOR) or `?url=` / `?redirect=` / `requestUrl` (SSRF)
3. Filter `.css` / `.png` / `.woff` / third-party hosts. Keep in-scope API.
4. Reconstruct from `API_BASE` / `baseURL` constants. `ingest_urls_into_map`.
5. Prove: `mutate_captured_request` / `discover_parameters` on IDOR/SSRF leads.
   Then `scan_js_urls_for_secrets` on the same bundles (includes CWE-321 client HMAC /
   Object.keys-join signing keys and MQTT/RFID ICS creds — submit on reconstruction,
   do not wait for a live API).

Output is the triaged list (Judah does not write `all_endpoints.txt` to disk).
