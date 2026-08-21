---
name: api_fingerprint
description: Fingerprint API hosts and technology from captured Judah traffic (Interceptor/crawl samples). Use when profiling an API stack, discovering sibling API hosts, or filling the HTTP fingerprinting coverage matrix. Caido is optional, not required.
---

# API fingerprint (Judah)

Port of api-fingerprint-caido against the capability map. Do **not** require
Caido on 127.0.0.1:8080. `mcp_connect` is optional if the operator already
runs Caido/Burp.

## Workflow

1. Normalize the target host. Do not assume it is the API host. Keep it in the report.
2. `execute_interceptor` / `execute_deep_crawl` if `api_samples` is empty.
   No traffic → blocked/no-data. Do not invent a stack. Do not ask follow-ups.
3. `fingerprint_api` — related-domain search (`api.target.com` from `target.com`),
   score every API candidate **and** the literal target host.
4. Fill the coverage matrix (covered / not-covered) for:
   header analysis, banners/proxy, header order, default error pages,
   malformed requests, default files, cookies. External corroboration
   (WhatWeb/Wappalyzer/Shodan) is **out of scope for this skill**.
5. Active probes stay a **plan** (`recommended_active_probes`). Do not run
   banner GET / random 404 / default-file HEAD / malformed HTTP unless the
   operator already authorized active testing. Never `nc` HTTP/4.4 by default.
6. Short evidence only. Redact Authorization / cookies / tokens.
   Separate facts from inferences. Confidence: High = explicit banner/cookie;
   Medium = repeated headers/paths; Low = header order or one weak clue.

## Next

Hunt from indicators (Appsmith actions → `mutate_captured_request` + Interactsh;
GraphQL → graphql specialist; Next.js → `fetch_lazy_chunks`). This skill maps
the stack; it does not prove vulns.
