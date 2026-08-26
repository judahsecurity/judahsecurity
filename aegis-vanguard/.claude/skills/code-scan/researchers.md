# Researcher protocol (code-scan)

Copy the relevant block into each Task prompt. Researchers **read source only**.
Do not build, test, or hit the network.

## Shared rules

- Scope: files the orchestrator listed. Ignore `node_modules`, `.venv`, `dist`.
- Report a candidate only with: file:line, data flow (source → sink), exploit
  scenario, why existing checks fail, threat_id from `THREAT_MODEL.md`.
- Drop: theoretical CWE, framework noise, dead code, findings that need runtime.
- Output JSON list. Empty list is valid.

## Lanes (pick from threat-model focus areas)

**authz** — IDOR / BOLA / missing object checks. Look for identifiers in
routes/body used as authz. PASS shape: same session, other object's id, extra
fields or 200 with foreign data.

**auth** — session, JWT, password reset, SSO. Default creds only on known
product lists (tiny). Forced browse of admin routes. Client-side-only flags.

**injection** — untrusted input into SQL / template / shell / LDAP. Prefer
parameterized vs concatenated. SSTI: user string into template engine.

**xss** — sinks (`innerHTML`, unescaped templates, Markdown). Note encoding
and CSP. DOM XSS: location/hash into sink.

**ssrf** — server fetch of attacker URL (webhooks, previews, imports, PDF).
Cloud metadata and localhost are out of scope unless the engagement says so.

**secrets** — keys in source, `.env` committed, public JS bundles, source maps.

**upload / path** — filename join, archive extract, content-type vs magic.

**business-logic** — price/qty, state skips, race on redeem/transfer.

## Exclusion (do not report)

Docs and comments; test-only fixtures; findings whose only proof is a linter
rule; "missing security header" with no impact story; duplicate of another
candidate (same sink + same source).
