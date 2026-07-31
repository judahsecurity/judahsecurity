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

SQLI_PATTERNS = """
## High-signal SQLi patterns (BugHunter-aligned)
- Prefer endpoints that REFLECT rows (search/list/report) → UNION is fastest proof
- Establish column count with ORDER BY / UNION SELECT NULL… before dumping
- Crown params: id, q, search, sort, filter, page, order_id, user_id, report dates
- JSON APIs: also test body fields and NoSQL operators ($ne, $gt, $where)
- Second-order: store quote in profile/filename, trigger later in admin/search query

## Probe → confirm ladder
1. probe_sqli_params (error / boolean / time)
2. sql_injection_test(..., param=name, level=3)
3. confirm_vulnerability_poc with non-sensitive proof (version()/database())

## Kill signals
- WAF 403 on one payload with no bypass attempt → incomplete, not clean
- sqlmap on URL with zero parameters → wasted turn
- Time delay <3s over baseline → inconclusive
"""

XSS_PATTERNS = """
## High-signal XSS patterns (BugHunter-aligned)
- Map reflection FIRST with probe_xss_reflection canary — then context-correct payloads
- html_body → <img onerror=…> ; attr_double → "><img…> ; script_block → </script><img…>
- DOM: hash, postMessage, location sinks via test_dom_xss (Playwright marker)
- Stored: unique canary in comment/profile → re-fetch → execute
- alert(1) blocked ≠ safe — use window.__vanguard_xss marker

## Probe → confirm ladder
1. probe_xss_reflection
2. xss_test and/or test_dom_xss on reflected params
3. confirm_vulnerability_poc with execution evidence (not reflection alone)

## Kill signals
- Fully encoded reflection with no bypass after stacked encoding
- Self-XSS without delivery (CSRF/stored) path
- CSP reports without a working gadget — informational only
"""

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

# =============================================================================
# API depth + framework specialists
# =============================================================================

GRPC_PATTERNS = """
## gRPC / HTTP2 API patterns
- Server reflection enabled → enumerate services/methods without a .proto
- Missing auth metadata on internal methods; plaintext gRPC (h2c) on internet
- Proto / descriptor leakage via /grpc.reflection.v1alpha.ServerReflection
- Authz gaps: method-level ACL missing while HTTP gateway is locked down
- Do not DoS with unbounded streaming — prove with one unauthorized method call
"""

WEBSOCKET_PATTERNS = """
## WebSocket patterns
- Cross-Site WebSocket Hijacking (CSWSH): cookie auth + missing/weak Origin check
- No per-message auth after handshake; room/namespace join without membership check
- Message tampering / IDOR over WS channels (subscribe to other-user topics)
- socket.io: namespace ACL bypass; reconnect without re-auth
Confirm with Origin: evil.com handshake + sensitive subscription — not just open WS.
"""

NEXTJS_PATTERNS = """
## Next.js (only when fingerprint matches)
- Middleware auth bypass via static asset / `_next/static` / rewritten paths
- `/_next/image?url=` SSRF (internal + metadata) when remotePatterns loose
- Server Actions: invoke unexpected action IDs; mass-assignment on bound args
- ISR / cache key confusion; RSC flight payload leakage of secrets
- `x-middleware-subrequest` / historic CVE class — version-gate with nuclei
"""

SPRING_PATTERNS = """
## Spring Boot (only when fingerprint matches)
- `/actuator/*` unauth: env, heapdump, mappings, gateway, jolokia, shutdown
- SpEL injection in query/header-bound expressions
- H2 console / Spring4Shell-class RCE only when version evidence matches
- Prefer nuclei springboot/actuator tags before manual spray
"""

LARAVEL_PATTERNS = """
## Laravel (only when fingerprint matches)
- APP_DEBUG stack traces with env/secrets; Telescope/Horizon unauth
- Ignition RCE (CVE-2021-3129) only with version evidence
- Signed URL tampering; `.env` / storage exposure; debugbar
"""

ASPNET_PATTERNS = """
## ASP.NET / IIS (only when fingerprint matches)
- ViewState deserialization (MAC off / known machineKey) — validate carefully
- elmah.axd / trace.axd / ScriptResource disclosure
- NTLM Negotiate info leak on internet-facing IIS (hunt-ntlm-info class)
- Path: WebResource.axd, handler mappings, `__VIEWSTATE`
"""

NODEJS_PATTERNS = """
## Node.js / Express (only when fingerprint matches)
- Prototype pollution → gadget to RCE (lodash merge/defaultsDeep)
- `trust proxy` misconfig → IP spoof auth bypass
- child_process / eval / template SSTI (EJS/Pug/Handlebars)
- Path traversal in static file servers; Express open redirect helpers
"""

DESERIALIZATION_PATTERNS = """
## Insecure deserialization
- Java: ysoserial gadget hints only when ObjectInputStream / .ser upload present
- PHP: phpggc / phar:// when unserialize sinks found
- Python: pickle/yaml.load; .NET BinaryFormatter / LosFormatter (ViewState)
- JNDI/Log4Shell class: confirm with canary callback, no destructive payload
Never run OS-shell payloads — proof via controlled canary or safe property read.
"""

# =============================================================================
# Enterprise perimeter + cloud post-credential
# =============================================================================

M365_ENTRA_PATTERNS = """
## M365 / Entra ID (external-only)
- Tenant discovery: login.microsoftonline.com/{domain}, GetCompanyInformation, autodiscover
- User enumeration via GetCredentialType / Manage endpoints (rate-limit disciplined)
- Federation / STS endpoints; Seamless SSO hints; legacy auth surfaces
- Consent / OAuth app phishing preconditions (document only — no phishing victims)
- Device code / PTA / password-spray posture notes — spray ONLY if engagement ROE allows
- SharePoint Online / OneDrive anon sharing links if in scope
Do NOT attempt Golden SAML, token theft malware, or mailbox exfil.
"""

OKTA_PATTERNS = """
## Okta-as-IdP (external-only)
- Tenant discovery: *.okta.com, oktapreview, custom domains, /.well-known/okta-organization
- /api/v1/users/me, authn, factors enumeration without locking accounts
- Password spray with lockout discipline; MFA factor enumeration
- OIDC discovery + redirect_uri issues on Okta-hosted apps
- Admin console / agent endpoints exposure on internet
Coordinate with saml_sso_hunter / oauth_hunter for ACS and redirect issues.
"""

SHAREPOINT_PATTERNS = """
## SharePoint on-prem (ToolShell + legacy)
- Fingerprint /_layouts/, /_vti_bin/, Authentication.asmx, sites/default
- Version disclosure; anonymous list/library access
- Legacy SOAP auth bypass classes; ToolShell precondition chain (CVE-2025-53770 family)
  — fingerprint + nuclei only unless ROE explicitly allows exploit validation
- NTLM info disclosure on SharePoint/IIS fronts
Validate with non-destructive probes; no webshell drops.
"""

ENTERPRISE_VPN_PATTERNS = """
## SSL VPN / remote-access appliances
Fingerprint + version-gate high-impact CVE classes (nuclei tags preferred):
- Cisco ASA / AnyConnect
- Fortinet FortiGate / FortiOS
- Citrix NetScaler / ADC
- Palo Alto GlobalProtect
- Ivanti / Pulse Connect Secure
- SonicWall, F5 BIG-IP
Report: product, version/build evidence, relevant CVE/KEV, auth-bypass or RCE precondition.
No mass exploit; no credential stuffing beyond ROE-approved spray.
"""

VCENTER_PATTERNS = """
## VMware vCenter / Workspace ONE
- Fingerprint /ui, /vcsa, SOAP SDK, vRealize / Aria, Workspace ONE UEM
- High-impact CVE chains: unauth file upload, plugin RCE, SSTI classes (version-gate)
- Default/weak creds only if ROE allows; no datastore wipe or VM power actions
Prefer nuclei vmware/vcenter tags + version correlation over manual exploit kits.
"""

CLOUD_IAM_PATTERNS = """
## Cloud IAM / post-credential (external + found secrets)
When AWS/GCP/Azure keys, STS tokens, or SA JSONs appear in JS/repos/env:
1. Classify credential type (AKIA, ASIA, GCP SA, Azure client secret, etc.)
2. Estimate blast radius from key shape + any policy/resource hints in the leak
3. Check companion misconfigs: public S3/GCS listing, open Firebase, Azure blob SAS
4. SSRF→IMDS: document chain risk; do NOT fetch live IMDS from this agent
   (guardrails block metadata IPs — report as chained impact with evidence of SSRF)
5. Confused-deputy / cross-account AssumeRole only as analysis unless ROE grants a lab account
Never use discovered keys to modify customer resources or exfiltrate production data.
"""

SUPPLY_CHAIN_PATTERNS = """
## Supply-chain recon (external)
- Dependency confusion: internal package names in JS/source maps vs public registries
- Exposed .git / source maps / SBOM / package-lock with private registry URLs
- GitHub Actions workflow_dispatch / pull_request_target injection preconditions
- Container registry anon pull; CI artifact buckets
Report reachable supply-chain openings — do not publish malware packages.
"""

PERIMETER_RANK_PROTOCOL = """
## Perimeter rank-then-hunt
1. Internet-facing IdP (Entra/Okta/SAML ACS) before marketing sites
2. SSL VPN / remote access appliances
3. Collaboration (SharePoint/Exchange/on-prem)
4. Virtualization mgmt (vCenter / Aria / Workspace ONE)
5. Cloud control-plane exposures + leaked cloud credentials
6. CI/CD + package supply-chain
Skip: pure SaaS marketing CDNs, third-party widgets, out-of-scope subsidiaries.
"""


def pack(*sections: str) -> str:
    """Join pattern sections for injection into hunter instructions."""
    return "\n".join(s.strip("\n") for s in sections if s)
