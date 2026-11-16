---
name: csrf
description: CSRF on authenticated state-changing requests. Token removal/reuse/swap, method override, simple content types, JSON via text/plain; confirm via scoped_csrf_assigned (scoped_csrf_state_change).
---

# CSRF on state-changing requests

CSRF only matters for an authenticated action a victim's browser can be made to
send cross-site with ambient credentials (cookies). Targets in impact order:
email/password/phone change, MFA and recovery settings, OAuth/social account
linking, payment or payout settings, role/membership changes, API key creation,
then ordinary profile/content writes. Skip login (unless login CSRF is assigned),
logout, and read-only GETs. Bearer-token-only APIs (no cookie auth) are not
CSRF-able.

## Proof rules (override everything below)

* "No token field", `SameSite` missing, a 200 on replay, or a permissive CORS
  header are **leads**.
* Medium+ needs `scoped_csrf_assigned` with proof kind `scoped_csrf_state_change`:
  a cross-site replay using only a simple content type and no anti-CSRF token
  changes a nonce canary on the victim identity, verified by readback, with
  cleanup confirmed, while the anonymous control does not change it.
  The independent verifier replays it.
* A raw HTTP client that spoofs `Origin`/`Referer` is not cross-site delivery;
  it can find a weak header check (lead) but is not the proof.
* Bounded canaries only: change a field you can read back and restore (display
  name, bio, a preference) to a nonce value. Never change email, password, MFA,
  payout details, or delete anything to demonstrate CSRF.

## Bypass matrix (the tool's variants; leads until the receipt)

| Defense observed | Variant |
|---|---|
| Token field present | omit field; empty value; token from another session/user; static token reused across page loads |
| Token validated only on POST | same action via GET, or `_method=PUT/DELETE` / `X-HTTP-Method-Override` on a simple POST |
| JSON endpoint | `application/x-www-form-urlencoded` or `multipart/form-data` body; `text/plain` whose body parses as JSON: field name `{"k":"v","x":"` + value `"}` |
| `Content-Type` enforcement | the three CORS-simple types only; anything else forces preflight and is not CSRF |
| Origin/Referer check | missing header accepted (Referer stripped, sandboxed iframe `Origin: null`); suffix/prefix matching (`target.com.evil.tld`) |
| Custom header required | presence-only check vs value check (simple requests cannot set it) |
| Double-submit cookie | needs a cookie-setting primitive on a sibling (chain-required) |

## SameSite realities

* `Strict`: cross-site requests carry no cookie; CSRF needs a same-site gadget.
* `Lax` (and Chrome's default for unset): cookie sent on top-level GET
  navigations only, so GET-reachable state changes and method override matter;
  POST from another site does not carry it. "Same-site" includes sibling
  subdomains, so an attacker-controlled subdomain defeats Lax (chain-required).
* `None; Secure`: cookie sent cross-site; classic CSRF applies.
* Record the actual `Set-Cookie` attributes; do not assume the browser default.

## Procedure

1. From the authenticated capture, pick a state-changing request and a readable,
   restorable canary field. Record the original value.
2. Run `scoped_csrf_assigned`; read `proof_confirmed`, the variant, readback, and
   cleanup status. Confirm the anonymous control produced no change.
3. If cleanup did not confirm, restore the canary manually and note it.

## Discipline

* Canary values are random, ≥8 characters, absent from the baseline.
* Success means the readback changed, not that the response was 2xx.
* A 400 on a downgraded content type may be a parser rejecting a malformed
  body; retest with a minimal well-formed body in that type before concluding.
* Never submit alone: missing token on logout/login, missing `SameSite` with no
  state change shown, CORS headers without a credentialed read.
  Chain-required: open redirect + OAuth `redirect_uri`, sibling-subdomain
  takeover + Lax cookies, XSS that reads the token.

Adapted from elementalsouls/Claude-BugHunter (skills/hunt-csrf), CC BY 4.0; modified.
