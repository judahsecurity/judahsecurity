# HTTP session store & proxy backends

Stateful, evidence-bearing HTTP for authz / IDOR / CSRF / business-logic work.
A one-shot request can't prove broken access control; a captured request that
you **replay under a changed identity** and **diff** can — and the diff is the
auditable artifact (same principle as the flag oracle).

## Flow

1. Every `send_http_request` is recorded into the session store and returns a
   `transaction_id`. `session_transactions` lists recent ones.
2. `replay_request` re-sends a recorded (or inline) request under a mutation
   and returns the original response, the mutated response, and a structured
   diff whose `summary` flags a **possible broken access control** when a
   near-identical 200 comes back under a changed/absent identity.

```
replay_request(transaction_id="txn-0007",
               mutations_json='{"strip_auth": true}')                 # as nobody
replay_request(transaction_id="txn-0007",
               mutations_json='{"set_headers": {"Cookie": "session=<victim>"}}')  # as another user
replay_request(transaction_id="txn-0007",
               mutations_json='{"set_query": {"id": "1002"}}')         # object IDOR
```

## Backends (`agent/http_session.py`)

The proxy backend is pluggable via `ProxyBackend`; select with
`AEGIS_PROXY_BACKEND`:

| Backend | `AEGIS_PROXY_BACKEND` | Notes |
|---|---|---|
| `ScannersBackend` (default) | `scanners` | Reuses the existing send path (curl/httpx + private-range block). Works out of the box. |
| `CaidoBackend` | `caido` | Drives a running Caido instance for Strix-style interception. Requires `AEGIS_CAIDO_API` (base URL) and optional `AEGIS_CAIDO_TOKEN`. Unconfigured, it raises rather than silently falling back, so you always know which engine produced the evidence. |

## Persistence

Set `AEGIS_SESSION_LOG=/path/session.jsonl` to append every transaction to
disk **redacted** (cookies / bearer tokens stripped) for the audit trail. The
in-memory copy keeps full headers so replay carries real identity during the
run.

## Extending

Implement `ProxyBackend.send(HttpRequest) -> HttpResponse` and select it via
`set_backend(...)` (or add a name to `make_backend`). mitmproxy is the natural
next bundled backend for full transparent interception.
