---
name: lazy_chunk_downloader
description: Reconstruct webpack/Vite/Next lazy-chunk filenames from a first-party runtime and download in-scope chunks. Use when the crawl missed code-split bundles, or before JS endpoint/secret mining.
---

# Lazy chunk downloader (Judah)

Companion to `js_analysis`. Grab chunks first, then mine them.

Modern bundlers do not list chunk URLs. They build them at runtime from a
template plus a hash map. `fetch_lazy_chunks` reconstructs:

- **webpack 5** — `__webpack_require__.u` / `.miniCssF` string literals + chunkId +
  `{143:"a1b2c3"}` maps; reports `.p` publicPath.
- **Vite** — `__vite__mapDeps([...])`.
- **Fallback** — quoted `*.js` / `*.chunk.js` / `*.css`, including Next.js
  `_buildManifest.js` and bracketed route chunks (`[accountId]`, `[[...slug]]`).

## Workflow

1. `fetch_lazy_chunks(dry_run=true)` on a runtime bundle from the capability map
   (`js_files`, prefer `/_next/static` or `webpack`/`chunk` names).
2. Read `public_paths` + `in_scope_urls`. If publicPath is `/app/` or a CDN,
   pass `base_url` that already includes that prefix.
3. `fetch_lazy_chunks` (download). `FAIL HTTP 404` is expected — maps list ids
   that were never emitted.
4. Hand fetched URLs to `extract_js_endpoints`, then `ingest_urls_into_map`.

In-scope hosts only. Do not fetch `node_modules` or off-host CDNs unless that
host is in engagement scope.
