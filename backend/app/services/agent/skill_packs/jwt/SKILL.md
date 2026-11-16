---
name: jwt
description: JWT / token-crypto weaknesses (alg none, RS256->HS256 confusion, kid/jku/x5u/jwk header injection, weak HMAC secret, unenforced exp). No deterministic validator: leads unless an authorization proof shows impact.
---

# JWT and token crypto

Applies when the app authenticates with a JSON Web Token: an `eyJ…` value in
`Authorization: Bearer`, a cookie, or a login/refresh response. Decode a real
token first (header + payload, base64url) and keep its exact claim names; a
forged payload the app cannot parse fails for the wrong reason.

## Proof rules (override everything below)

* There is **no deterministic JWT validator yet.** A forged token being
  "accepted" (200, no 401) is a lead. Findings stay lead/inconclusive unless an
  authorization proof demonstrates impact: distinct identities, with proof kind
  `owner_only` (identity B reads an object only identity A owns, absent from B's
  own baseline) or `state_change` (a bounded nonce canary on A's resource
  changes, verified by readback and cleaned up). The independent verifier
  replays it.
* A forged token that only returns your own data proves the forge mechanism,
  not impact. Keep at lead.
* Non-destructive: no admin actions (user deletion, role grants to others),
  no data dumps. Read one foreign object or change one restorable canary.
* Offline secret guessing must be bounded (small, known-weak wordlist) and
  stays local; never send cracking traffic at the target.

## Checks (in cost order)

| Weakness | Test | Signal (lead) |
|---|---|---|
| Signature not verified | flip one payload byte, keep signature | still accepted |
| `alg:none` | header `{"alg":"none"}` (and `None`, `NONE`, `nOnE`), empty signature, keep trailing `.` | accepted with edited claim |
| RS256 → HS256 confusion | sign HS256 using the server's RSA public key (PEM from `/.well-known/jwks.json`, `/jwks`, JS bundle) as the HMAC secret | accepted |
| `kid` injection | `kid` path traversal to a predictable file (`../../../../dev/null` → empty secret); `kid` reaching SQL/command/URL lookup is a separate injection lane | accepted |
| `jku` / `x5u` | key URL pointing at a host you control, or an open redirect on the target's allowed host | the verifier fetches it (OOB lead) and accepts |
| Embedded `jwk` | self-generated RSA key in the header, signed with its private key | accepted |
| Weak HMAC secret | offline guess against a small known-weak list | secret recovered |
| `exp` not enforced | expired token, or `exp` removed | still accepted |
| Claim trust | edit `sub`/`user_id`/`role`/`org_id`/`tenant` only, valid signature path | server trusts claim over session |
| Revocation | token still valid after logout / password change | accepted (lead; session lane) |

Use `execute_jwt` for forging and tampering so encoding and signing are correct;
do not hand-encode base64.

## Procedure

1. Capture two identities' tokens (A owner, B attacker) when the run provides
   them. Note a resource ID owned only by A.
2. Run the cheap checks first (signature-not-verified, `alg:none`), then
   key confusion only if a public key is reachable.
3. When a forge is accepted, aim it at A's object as identity B (`owner_only`)
   or at one restorable canary on A (`state_change`). Submit only that receipt.

## Discipline

* Decode the token you actually sent and confirm the edited claim is present.
* A bypass needs a body difference (foreign data or canary readback), not a
  status change; 200 with B's own data is not impact.
* A 400 on a malformed token is the parser, not auth; retest with a minimal
  well-formed token before concluding anything about the auth layer.
* Never submit alone: "uses HS256", long `exp`, token in localStorage, JWKS
  exposed (it is public by design). Chain-required: `jku` allowlist + open
  redirect on the target; `kid` → SQLi/command injection needs that lane's
  proof.

Adapted from elementalsouls/Claude-BugHunter (skills/hunt-jwt-crypto), CC BY 4.0; modified.
