---
name: idor
description: IDOR / BOLA across REST, GraphQL, and nested IDs with two identities. Impact only via an authorization proof (owner_only or bounded state_change) replayed by the verifier.
---

# IDOR / BOLA

Object-level authorization failures: the route checks "logged in" but not "owns
this object". Look for IDs in paths (`/api/v1/orders/{id}`), query/body fields
(`id`, `user_id`, `account_id`, `org_id`, `tenant_id`, `invoice_id`), GraphQL
arguments and `node(id:)` global IDs, export/download links, and IDs that leak
from other responses (`Location` headers, lists, notifications, JS bundles).

## Proof rules (override everything below)

* A 200 instead of 403, a sequential-looking ID, or a UUID in a response is a
  lead. 200 with an empty array, redacted fields, or "access denied" in the body
  is not IDOR.
* Medium+ needs an authorization proof with distinct identities: `owner_only`
  (identity B retrieves an object only A owns; A's nonce/field values appear in
  B's response and are absent from B's own baseline and from an anonymous
  control) or `state_change` (B changes a bounded nonce canary on A's object,
  verified by readback, cleanup confirmed). The independent verifier replays it.
* Non-destructive: no DELETE of others' objects, no refunds/transfers, no
  membership or role changes, no bulk enumeration. One foreign object read or
  one restorable canary write is the whole proof.

## Variants to try (each is a lead until the receipt)

| Shape | Try |
|---|---|
| Direct reference | A's ID in B's request, same verb and body |
| Other verbs | GET guarded but PUT/PATCH/POST on the same path not (write = canary only) |
| Version drift | `/v1/` or legacy/mobile routes with weaker checks than `/v2/` |
| Body-trusted tenant | `org_id`/`account_id` in JSON taken without membership check |
| Parameter pollution | `?id=<B>&id=<A>`; nested `{"data":{"id":"<A>"}}`; name variants `userId`/`uid`/`account` |
| Encoded IDs | base64/hex-wrapped references decoded, A's value re-encoded |
| GraphQL | every query/mutation taking `id:`; nested relations under a node B can reach |
| Indirect | object B can read that embeds a reference to A's private object |
| Temporal | access still works after B is removed from the org (session lane) |

## Procedure

1. Use the run's identities: A owns a resource (prefer one A created with a
   nonce in a field), B is same-privilege, plus an anonymous control.
2. Baseline A reading its object and B reading B's own object.
3. Replay A's reference as B; diff bodies. On a hit, record evidence IDs for
   A-baseline, B-attempt, anonymous control.
4. For writes, change one restorable field on A's object to a nonce, read back
   as A, restore, read back again.

## Discipline

* Nonces ≥8 random characters, absent from B's baseline.
* A bypass needs a body difference (A's data), not a status change.
* A 400 on B's request may be schema validation of a malformed body; retest
  with a minimal well-formed body before concluding authorization held.
* Never submit alone: guessable IDs, UUID leakage without an access-control
  failure, 200-but-no-data. Chain-required: IDOR read of an ID + second IDOR
  write, or IDOR email change + password reset (report as chain only with both
  proofs, never execute the takeover).

Adapted from elementalsouls/Claude-BugHunter (skills/hunt-idor), CC BY 4.0; modified.
