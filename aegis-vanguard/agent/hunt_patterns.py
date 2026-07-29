"""
Disclosed-report pattern packs for Aegis Vanguard hunters.

Codifies high-signal detection patterns, kill signals, and chain templates
inspired by public bug-bounty skill packs (Claude-BugHunter / claude-bug-bounty),
adapted for validate-don't-destroy ROE.
"""

# =============================================================================
# Shared protocols
# =============================================================================

IDENTITY_PROTOCOL = """
## Identity Discipline (mandatory for authz / auth findings)
Before confirming IDOR, auth bypass, BFLA, or missing-auth:
1. Record which identity found it: anonymous / user_A / user_B / privileged.
2. Re-test anonymous (strip auth headers/cookies).
3. Re-test cross-identity (user A reading user B's object ID).
4. Classify correctly:
   - Works with NO auth → **missing authentication** (not IDOR)
   - User A reads user B data with A's token → **IDOR/BOLA**
   - Low-priv reaches admin function → **BFLA / vertical privilege escalation**
   - Only works for own data → **KILL** (not a vuln)
5. A 200 status alone is never enough — show other-user fields in the response body.
"""

SURFACE_RANK_PROTOCOL = """
## Rank-Then-Hunt (do this before spraying payloads)
Prioritize surfaces in this order — spend turns on top ranks first:
1. Auth / SSO / password-reset / MFA / session endpoints
2. Object-ID APIs (orders, users, docs, tenants) + GraphQL `node`/`viewer`
3. File upload, URL fetch/webhook/import, PDF/image renderers (SSRF)
4. Admin / internal / debug / actuator / swagger paths
5. Hidden params on state-changing POSTs (invite, export, role, payment)
6. Framework-specific hot paths (Next.js middleware, Spring actuators, Laravel telescope)
Skip low-value: marketing pages, static assets, third-party widgets, pure info disclosure.
"""

NEVER_SUBMIT_AND_CHAINS = """
## Never-submit without a working chain (instant kill)
- Missing CSP/HSTS/security headers alone
- GraphQL introspection alone (need authz bypass or IDOR on node())
- Banner/version disclosure without working exploit
- Self-XSS without CSRF delivery to victim
- Open redirect alone (need OAuth token theft or SSRF chain)
- CORS `*` without ACAC:true + credentialed data exfil
- SSRF DNS/OOB ping only (need internal HTTP data or metadata)
- Host header injection alone (need password-reset poisoning PoC)
- Clickjacking on non-sensitive pages
- Rate-limit missing on non-auth/non-OTP forms

## Conditionally valid — prove the chain end-to-end
| Standalone | Required chain | Valid impact |
|---|---|---|
| Open redirect | + OAuth redirect_uri → code theft | ATO |
| Host header | + reset email uses injected host | ATO |
| CORS wildcard | + credentialed PII read | High |
| CSRF | + sensitive state change | High |
| Subdomain takeover | + OAuth callback registered there | Critical |
| GraphQL introspection | + auth bypass or cross-user node() | High |
| Cache poison | + stored malicious response for other users | High |
"""

STACK_CONDITIONAL = """
## Tech-conditional checks (only if fingerprint matches)
**Next.js**: middleware auth bypass via static asset paths; `/_next/image` SSRF;
  Server Actions arbitrary invocation; ISR cache poisoning; RSC payload leakage.
**Spring Boot**: `/actuator/*` (env, heapdump, mappings, gateway); SpEL injection;
  H2 console; Jolokia; Spring4Shell-class RCE if version matches.
**Laravel**: APP_DEBUG stack traces; Telescope/Horizon unauth; Ignition RCE (CVE-2021-3129);
  signed URL tampering; `.env` exposure.
**ASP.NET**: ViewState deserialization (MAC/encryption); elmah.axd/trace.axd; NTLM info leak.
**SPA/JS**: extract hidden API base URLs from bundles; test those APIs for missing auth / IDOR.
If tech stack unknown, fingerprint first — do not burn turns on irrelevant framework paths.
"""

# =============================================================================
# Per-class pattern packs
# =============================================================================

AUTHZ_PATTERNS = """
## High-signal IDOR / BOLA patterns (from paid report shapes)
- Swap object IDs across: detail, list, export, download, share, invite, audit, attachment, preview
- GraphQL: `node(id:)`, `user(id:)`, aliased batch queries, persisted queries without authz
- Change numeric ID, UUID, base64({userId}), and hashed IDs independently
- Tenant headers: X-Tenant-Id, X-Org-Id, X-Workspace-Id, X-Account-Id
- Method confusion: GET denied but POST/PUT/PATCH/DELETE or HEAD/OPTIONS leaks
- Mass assignment on role/plan/verified/isAdmin/credits during signup or profile update
- Shadow APIs: /api/v1 vs /api/v2 vs /internal vs /legacy — older versions often weaker authz

## Kill signals
- Response body only contains YOUR user id/email → not IDOR
- Same data visible to both identities by design (public profile) → not IDOR
- Admin-only endpoint requiring admin session → not BFLA for low-priv
"""

AUTH_PATTERNS = """
## High-signal auth / ATO patterns
- Password reset Host / X-Forwarded-Host poisoning → link points to attacker
- Reset token in JSON body, Referer leak, or reusable/non-expiring
- OTP/2FA: code reuse, skip step (hit next URL after password), response manipulation
- JWT: alg:none, RS256→HS256, kid path traversal, missing exp validation
- Session fixation (pre-login cookie survives); logout does not invalidate server-side
- MFA bypass: disable 2FA without re-auth; backup codes predictable; SMS OTP brute without lockout
- Pre-account takeover: register victim email after invite without verification

## Kill signals
- "Admin can reset any password" (expected privilege) → kill
- Concurrent sessions alone → usually informational
- Missing HttpOnly alone without theft path → kill
"""

OAUTH_PATTERNS = """
## High-signal OAuth / OIDC patterns
- redirect_uri: path traversal, @, %, subdirectory, open-redirect chain, partial whitelist
- Missing/weak `state` → login CSRF / forced OAuth binding
- PKCE optional when confidential client expected; code replay accepted
- Token in URL → Referer exfil to third-party assets
- id_token aud/iss not validated; alg confusion on id_token
- Account linking without email verification → ATO via OAuth provider email claim

## Kill signals
- client_secret in mobile SPA alone (public clients) → usually expected
- Open redirect on non-OAuth page without token → hand to open_redirect_hunter / chain later
"""

SSRF_PATTERNS = """
## High-signal SSRF patterns
- Webhook/URL import/avatar/PDF/OCR/link-preview sinks
- Bypass: decimal/octal/IPv6/0.0.0.0/redirect-chain/DNS rebinding
- Cloud metadata only AFTER OOB confirms server-side fetch
- gopher/dict/file schemes if curl-backed fetchers suspected

## Kill signals
- DNS callback only with no HTTP body from internal → needs_more_evidence, not confirmed high
- Client-side fetch (browser) mislabeled as SSRF → kill
"""

GRAPHQL_PATTERNS = """
## GraphQL deep checks (when /graphql present)
- Introspection on + unauth mutations
- IDOR via node(id) / global IDs across users
- Batching / alias abuse for rate-limit bypass or mass data
- Nested query DoS (depth/cost) — report only with measured impact
- CSRF on GraphQL POST if cookie auth + missing Origin checks
Introspection alone is NEVER enough — pair with authz impact.
"""

HOST_HEADER_PATTERNS = """
## Host-header / password-reset poisoning
1. Find /forgot-password, /reset, /account/recover
2. Send Host: evil.com and X-Forwarded-Host: evil.com variants
3. Confirm absolute URL in email/response uses attacker host
4. Without poisoned reset link or cache key → informational only
Also test unkeyed Host for cache poisoning (hand off details to cache_poison_hunter).
"""

HTTP_SMUGGLING_PATTERNS = """
## HTTP request smuggling (timing + differential)
- Probe CL.TE, TE.CL, TE.TE with ambiguous Content-Length / Transfer-Encoding
- Confirm with timing desync or response desync affecting a second request
- H2 downgrade / H2.CL when HTTP/2 frontend present
- Do NOT claim smuggling from a single 400 — need differential proof
Safe validation only — no poisoning of shared infra beyond proof canary.
"""

CACHE_POISON_PATTERNS = """
## Web cache poisoning / deception
- Unkeyed headers: X-Forwarded-Host, X-Original-URL, X-Rewrite-URL, X-Host
- Inject canary, re-fetch without header — canary must persist for other clients
- Cache deception: static extension path that returns authenticated HTML
- Only report when cache stores attacker-controlled content for victims
"""

SAML_PATTERNS = """
## SAML / SSO patterns
- Discover /saml, /sso, /acs, metadata URLs
- Signature wrapping / comment injection in NameID if SAMLResponse obtainable
- Unsigned assertions accepted; XXE in metadata fetch
- Golden SAML only if signing key exposed (rare) — do not forge otherwise
Pair with OAuth/OIDC checks if hybrid SSO.
"""


def pack(*sections: str) -> str:
    """Join pattern sections for injection into hunter instructions."""
    return "\n".join(s.strip("\n") for s in sections if s)
