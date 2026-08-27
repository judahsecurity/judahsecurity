# Curiosity: observe → hypothesis → signal

Shared reference for `/threat-model` (URL branch) and `/pentest` (Observe).
Read this before turning a page into a hunt. Full autonomous packs live in
`agent/hunt_patterns.py`; this is the session-mode distillation.

**Curiosity is not "look harder."** It is a loop where every observation
spawns a *hypothesis* (a bug class this page plausibly has) paired with the
*one signal* that would confirm or kill it. Random poking is not curiosity.
A hypothesis with no confirming signal is a guess — drop it.

```
observe a surface → name the bug-class hypothesis → state the confirming
signal → rank → test top-N → record finding | clean | skipped+reason
```

## Page-type / component → bug-class hypothesis map

Each row: what you see → what to suspect → the signal that proves it (not a
200 status, not reflection alone).

| Observed on the page | Hypothesis (bug class) | Confirming signal |
|---|---|---|
| `?next=`, `redirect_uri`, `returnUrl`, `callback` | Open redirect → OAuth code theft | injected host appears in `Location` / token sent off-host |
| Numeric or UUID object id in URL/API (`/orders/1043`, `?user_id=`) | IDOR / BOLA | other user's fields in *your* session's response body |
| Role/plan/`isAdmin`/`verified`/`credits` in signup or profile POST | Mass assignment / BFLA | privileged field persists after you set it |
| `<img>`/PDF/preview proxy, "import from URL", webhook, avatar-by-URL | SSRF | internal-only or metadata response differential |
| `/graphql`, `__typename`/`node(` in JS bundles | Introspection → `node()` authz bypass | cross-tenant object fetched via `node(id:)` |
| Search / list / report / sortable table | SQLi (reflects rows → UNION is fastest) | `version()`/`database()` in a reflected row |
| Any reflected input (search box, error page, param echo) | XSS (map reflection context first) | `window.__vanguard_xss` marker executes |
| File upload (name, type, path, content) | Path traversal / stored XSS / SSRF via parser | traversal write, stored canary executes, or parser SSRF |
| Login / SSO / password-reset / MFA / session cookie | Auth bypass, reset poisoning, weak session | reset link uses injected `Host`; session fixation; MFA skip |
| Framework banner (see stack quick-hits below) | Version-specific hot path | framework-specific 200 (actuator, telescope, `/_next/image`…) |
| `X-Tenant-Id` / `X-Org-Id` / `X-Workspace-Id` headers | Tenant confusion | swap header → other tenant's data |
| `/api/v1` vs `/v2` vs `/internal` vs `/legacy` | Shadow API weaker authz | older version answers what newer one denies |
| GET denied on an object | Method confusion | POST/PUT/PATCH/DELETE/HEAD/OPTIONS leaks it |

## Rank-then-hunt (spend turns top-first)

1. Auth / SSO / password-reset / MFA / session endpoints
2. Object-id APIs (orders, users, docs, tenants) + GraphQL `node`/`viewer`
3. File upload, URL fetch / webhook / import, PDF / image renderers (SSRF)
4. Admin / internal / debug / actuator / swagger paths
5. Hidden params on state-changing POSTs (invite, export, role, payment)
6. Framework hot paths (Next.js middleware, Spring actuators, Laravel telescope)

Skip low-value: marketing pages, static assets, third-party widgets, pure
banner/version disclosure.

## Stack-conditional quick-hits (only if fingerprint matches)

- **Next.js**: middleware auth bypass via static-asset paths; `/_next/image`
  SSRF; Server Actions arbitrary invocation; RSC payload leakage.
- **Spring Boot**: `/actuator/*` (env, heapdump, mappings); SpEL injection;
  H2 console; version-matched RCE.
- **Laravel**: `APP_DEBUG` stack traces; Telescope/Horizon unauth; Ignition
  RCE (CVE-2021-3129); `.env` exposure.
- **ASP.NET**: ViewState deserialization; `elmah.axd`/`trace.axd`.
- **SPA/JS**: extract hidden API base URLs from bundles → test those APIs for
  missing auth / IDOR.

If the stack is unknown, fingerprint first. Do not burn turns on irrelevant
framework paths.

## Never submit alone — chain it or kill it

These are footholds, not findings, until chained end-to-end:

| Standalone observation | Required chain | Valid impact |
|---|---|---|
| Open redirect | + OAuth `redirect_uri` → code theft | ATO |
| Host header injection | + reset email uses injected host | ATO |
| CORS wildcard | + ACAC:true + credentialed PII read | High |
| CSRF | + sensitive state change | High |
| Subdomain takeover | + OAuth callback registered there | Critical |
| GraphQL introspection | + auth bypass or cross-user `node()` | High |
| Cache poison | + stored malicious response for other users | High |

Instant kill (do not file): missing CSP/HSTS alone; banner/version alone;
self-XSS without delivery; SSRF DNS-ping only (need internal HTTP/metadata);
clickjacking on non-sensitive pages; rate-limit on non-auth forms.

## Identity discipline (authz findings only)

Before calling IDOR/BOLA/auth-bypass, record which identity found it and
re-test: strip auth (→ *missing authentication*, not IDOR); cross-identity A
reads B (→ IDOR/BOLA); low-priv reaches admin (→ BFLA). Own data only → kill.
A 200 is never enough — show the *other* user's fields in the body.

## Coverage discipline

Every ranked hypothesis ends the run as one of:
`finding` | `clean` (tested, killed) | `skipped` (+ reason). Write these to
`coverage.json`. Untested top-rank hypotheses mean the hunt is incomplete,
not that the target is safe.
