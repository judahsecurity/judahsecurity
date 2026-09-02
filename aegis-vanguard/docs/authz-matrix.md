# Authorization matrix (`agent/authz_matrix.py`)

Automated **broken access control** detection — OWASP A01, the most prevalent
and most missed vuln class in real applications, and the one flags never test.
This is the Autorize technique, automated and wired to the proof gate.

## How it works

Take requests that were made **with credentials** (recorded in the session
store during an authenticated crawl), and replay each one:

```
authorized request (as A)  →  replay unauthenticated → same private 2xx body? → AUTH_BYPASS  (missing authorization)
                           →  replay as user B       → same private 2xx body? → BROKEN_ACCESS (horizontal IDOR)
```

Each hit registers a verified `response_diff` proof token (subject = the URL),
so the finding passes the [proof gate](proof-gate.md) automatically and is
documented as CONFIRMED.

## Tool

```
authz_matrix(
  transaction_ids="",                 # empty = all recorded authed requests
  identity_b_headers_json='{"Cookie":"session=<userB>"}',  # optional 2nd user
  include_unauth=true,                 # the missing-authorization column
)
```

The authz hunter runs this first (Phase 1.5) after an authenticated crawl, then
hand-tests object-id cases for anything the matrix missed.

## False-positive guard

Only requests whose baseline **carried an auth header** are tested — so a public
page that returns 200 to everyone is never even considered. Endpoints that
reject the changed identity (401/403) or return a diverged body are classified
`ENFORCED`, not flagged.

**Known limitation:** if a hunter sends credentials to a genuinely public page,
an identical unauthenticated response is classified `AUTH_BYPASS`. Keep the
authenticated crawl scoped to application endpoints; the proof token records the
exact request/response pair so the analyst can confirm. Horizontal IDOR
(user-B) is stronger evidence than the unauth column for exactly this reason —
prefer supplying a second account when you have one.
