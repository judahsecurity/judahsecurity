# Zscaler ZPA discovery evidence

Judah ingests **ZPA Log Streaming Service (LSS)** events from an existing log
collector. ZPA sends User Activity and, where licensed, Microsegmentation flow
logs to an LSS receiver. The collector forwards flat JSON or NDJSON to Judah.
This integration does not poll ZPA for arbitrary network traffic and does not
run a native LSS TCP receiver.

## Setup

1. In **Integrations → Zscaler ZPA**, create a connection and save the one-time
   ingest token. The connection shows its numeric ID and ingest path.
2. Configure a ZPA LSS receiver for **User Activity** and, if available,
   **Microsegmentation** flows. Use a JSON format containing the fields below.
3. Configure your existing collector to POST batches to
   `/api/v1/integrations/zpa/{id}/events` over HTTPS with
   `X-ZPA-Ingest-Token: <token>`. The API accepts a JSON object, a JSON array,
   `{ "events": [...] }`, or newline-delimited JSON with
   `Content-Type: application/x-ndjson`. Limit each request to 500 events and
   1 MiB. Rotate the token in Judah if compromised.

Minimal Microsegmentation event:

```json
{
  "ResourceID": "resource-123",
  "ResourceName": "payments",
  "AppZoneID": "zone-7",
  "MicroTenantID": "tenant-1",
  "ConnectionStartTime": "2025-01-21T17:32:33.463Z",
  "DestinationIP": "10.18.15.241",
  "DestinationPort": 1443,
  "Protocol": 6,
  "Direction": "OUTBOUND",
  "EnforcementAction": "ALLOW",
  "EnforcementDisposition": "CONNECTED"
}
```

Minimal User Activity event:

```json
{
  "Application": "Payroll",
  "ServerIP": "10.18.15.241",
  "ServerPort": 443,
  "TimestampConnectionStart": "2025-01-21T17:32:33Z",
  "ConnectionID": "connection-123",
  "ConnectionStatus": "CONNECTED"
}
```

The returned `accepted`, `duplicates`, and `ignored` counts let the collector
monitor parsing. Judah does not persist the raw event, username, or client IP.
Unknown event formats or records without a target, timestamp, or source context
are ignored. Events are deduplicated by a fingerprint of the connection fields.

## Graph meaning

- Destinations are **unverified candidate assets**. They are not automatically
  marked owned, live, public, or in scanning scope.
- A Microsegmentation `OUTBOUND` flow with `EnforcementDisposition=CONNECTED`
  becomes `ZpaSource -[:OBSERVED_OUTBOUND_TO]-> Asset`. Rejected or dropped
  flows become `ATTEMPTED_OUTBOUND_TO`; an allow policy without a connected
  disposition does not prove connectivity.
- User Activity reports access to a **private application**, not general
  Internet egress. An explicitly connected session becomes
  `OBSERVED_ACCESS_TO`; other statuses become `REPORTED_ACCESS_TO`.
- Each edge records destination port, protocol, event count, and first/last
  observation. ZPA edges are evidence, not inferred routing or attack paths.
- The destination's `network_scope_id` uses the integration, microtenant,
  application zone, or the narrowest known application/resource. Identical
  private IPs in distinct known scopes remain separate. When ZPA omits routing
  context, the association remains a best-effort candidate.

PostgreSQL holds observations. Neo4j projection runs after an accepted batch;
**Refresh graph** replays stored evidence if Neo4j was unavailable. ZPA
projection currently rebuilds a connection's edges from all stored events, so
high-volume feeds will need batched aggregation and retention controls before
large-scale production use.

For **general Internet egress** discovery, ingest the corresponding Zscaler
Internet Access (ZIA) NSS feed through a separate integration; ZPA LSS User
Activity does not provide that coverage.
