# Caido integration — capture the full browse surface

The agent's tools only see the requests they make. Caido, as the proxy in front
of the browser, captures **everything** the page does — every XHR, fetch,
webpack chunk, and API call the crawl triggered. Pulling that into the session
store means `fingerprint_stack`, `authz_matrix`, `analyze_js`, and
`replay_request` all hunt the real, complete surface.

## Catch traffic as the agent browses

```
                    ┌── AEGIS_BROWSER_PROXY ──┐
  Playwright crawl ─┤  (Caido proxy listener) ├─► upstream target
  (crawl_urls_authenticated / test_dom_xss)   │
                    └──────── Caido ───────────┘ captures every request
                                   │
                    ingest_caido() │ pulls Caido history → SessionStore
                                   ▼
             fingerprint_stack / authz_matrix / analyze_js / replay_request
```

1. **Run Caido** (desktop or headless) with its proxy listener up, and its
   GraphQL API reachable.
2. **Point the browser at Caido:** set `AEGIS_BROWSER_PROXY` to the proxy
   listener (e.g. `http://127.0.0.1:8080`) before the crawl. Every Playwright
   context then routes through Caido (`_browser_proxy_kwargs` in scanners.py;
   TLS is accepted since Caido re-signs).
3. **Browse:** run `crawl_urls_authenticated` / `test_dom_xss` — Caido records
   all of it.
4. **Ingest:** `ingest_caido(host="example.com")` pulls Caido's captured
   requests+responses into the SessionStore (decoding the base64 raw messages).
5. **Hunt the full surface** with the existing tools.

## Config

| Env | Meaning |
|---|---|
| `AEGIS_BROWSER_PROXY` | Proxy the Playwright browser routes through (Caido's listener). |
| `AEGIS_CAIDO_API` | Caido GraphQL endpoint (default `http://127.0.0.1:8080/graphql`). |
| `AEGIS_CAIDO_TOKEN` | Bearer token for the GraphQL API. |
| `AEGIS_CAIDO_CLI` | Path to `caido-graphql` CLI (used instead of HTTP if set). |
| `AEGIS_CAIDO_PROXY` | Proxy listener for `CaidoBackend` replays (so replays are captured too). |
| `AEGIS_CAIDO_INSECURE` | Skip TLS verification against Caido's CA on replay (default true). |

## Replay through Caido

Select the replay backend with `AEGIS_PROXY_BACKEND=caido`. `CaidoBackend.send`
routes each request through `AEGIS_CAIDO_PROXY`, so `replay_request` /
`authz_matrix` replays appear in Caido's history like any browsed request, and
the real upstream response comes straight back. Unconfigured, it raises rather
than silently bypassing Caido.

## Notes

- `CaidoClient` speaks Caido's `requestsByOffset` GraphQL query (HTTP POST or the
  CLI); raw request/response bodies are base64 in the schema and decoded on
  ingest. The query shape follows the api-fingerprint-caido collector.
- No Caido? The session store still fills from `send_http_request` / replays;
  Caido just widens capture to everything the browser did. The lightweight
  alternative is instrumenting Playwright's own `page.on("response")` — a good
  future addition that needs no external proxy.
