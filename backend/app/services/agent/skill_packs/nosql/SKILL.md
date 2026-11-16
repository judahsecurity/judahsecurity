---
name: nosql
description: NoSQL (MongoDB-style) operator injection in JSON bodies and bracketed query/form params ($ne/$gt/$regex/$in), auth bypass and filter widening. No deterministic validator: leads unless an authorization proof shows impact.
---

# NoSQL injection

Likely when the stack is Node/Express + MongoDB/Mongoose (`X-Powered-By:
Express`, `mongoose` in bundles, `_id` 24-hex ObjectIds, `MongoError` /
`CastError` text), and on login, search, filter, and lookup endpoints that take
JSON or bracketed parameters. The bug is the server passing a user-supplied
object where it expected a string.

## Proof rules (override everything below)

* There is **no deterministic NoSQL validator yet.** A 500, a `CastError`, a
  changed result count, or a different status on `$ne` is a lead. Findings stay
  lead/inconclusive unless an authorization proof demonstrates impact: distinct
  identities with proof kind `owner_only` (identity B obtains an object or
  session that belongs only to A, absent from B's baseline) or `state_change`
  (bounded canary, readback, cleanup). The independent verifier replays it.
* Auth bypass must show a session for an identity you were not given
  credentials for, and that session must read A-only data. "Login returned 200"
  is not enough.
* Non-destructive: no `$where` JavaScript, no sleep loops, no mass enumeration
  or regex character-by-character extraction of other users' data, no Redis or
  database commands through SSRF.

## Operator shapes

JSON body:
```
{"username":"<A>","password":{"$ne":"<nonce>"}}
{"username":{"$in":["<A>"]},"password":{"$gt":""}}
{"q":{"$regex":"^<known-prefix>"}}
```
Query string / form (Express `qs`, PHP arrays):
```
username=<A>&password[$ne]=<nonce>
q[$regex]=^<known-prefix>&q[$options]=i
id[$gt]=
```
If JSON rejects objects, try the bracket form on the same endpoint (and vice
versa). Nested placement (`{"filter":{"owner":{"$ne":null}}}`) bypasses
top-level key filters. String-concatenated `$where` contexts (`'||'1'=='1`) are
a syntax-injection lead; report, do not exploit.

## Procedure

1. Baseline the endpoint with a legitimate value and a wrong value (e.g. wrong
   password) under identity B; record body and length.
2. Send one operator variant via `compare_requests` / `mutate_captured_request`
   with the same content type and session. Look for a body difference: more
   records, another identity's fields, a session token.
3. For login bypass, target a known test identity A supplied by the run, never
   "first user in the collection" or `admin` guesses.
4. Turn a lead into an `owner_only` authorization proof: as B, show one object
   only A owns. Stop there.

## Discipline

* Markers and nonces ≥8 random characters, absent from the baseline.
* A bypass needs a response-body difference, not just a status change.
* Timing claims (blind): ≥10 interleaved trials per group, mean ≥2σ above
  control; still only a lead.
* A 400 on an object-valued field is schema validation, not a bypass; retest
  with a minimal well-formed body so layer ordering is not misread.
* Never submit alone: MongoDB error text, `CastError` on `[$ne]`, result count
  change on a public search. Chain-required: username enumeration via `$regex`
  feeds a credential attack that is out of scope here.

Adapted from elementalsouls/Claude-BugHunter (skills/hunt-nosqli), CC BY 4.0; modified.
