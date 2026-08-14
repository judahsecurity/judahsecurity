"""
Thin per-specialist skill packs (Praetorian-style lane prompts).

These are NOT full main-agent ``/skill`` packages. Each pack is a short protocol
injected into the fireteam specialist system prompt so sub-agents stay bounded
but still know how to prove impact in their lane.
"""

from __future__ import annotations

from typing import Dict

# specialist name → skill-pack body (appended after system_prompt_suffix)
SPECIALIST_SKILL_PACKS: Dict[str, str] = {
    "app_mapper": (
        "SKILL PACK — map first:\n"
        "- Prefer execute_deep_crawl / execute_browser to capture forms, APIs, auth surfaces.\n"
        "- Persist a compact capability summary via save_note(artifact=capability_map).\n"
        "- Do not spray Nuclei; hand off to attack specialists."
    ),
    "auth_logic": (
        "SKILL PACK — authentication testing (Ezra):\n"
        "- Enumerate login/session/password-reset from the map.\n"
        "- Prove with compare_requests (anonymous vs auth; role A vs role B).\n"
        "- Default/weak login: prefer handing sprays to credential_assault (Samson); "
        "if you hit creds yourself: add_engagement_credential + queue_finding_followups("
        "vuln_type='default_login').\n"
        "- Auth bypass: path/header/method mutations one at a time; bypass_403 only "
        "on concrete 403 paths.\n"
        "- Never invent credentials; never spray large dictionaries.\n"
        "- Wiki/Confluence open registration: one throwaway account, sandbox write or one "
        "internal page — do not deface production articles. "
        "queue_finding_followups(vuln_type='wiki_open_reg').\n"
        "- Client-side-only admin/eLogbook: forced-browse + backing API without the JS flag. "
        "queue_finding_followups(vuln_type='client_side_auth')."
    ),
    "credential_assault": (
        "SKILL PACK — credential assault (Samson):\n"
        "- Only mapped login forms / known product default lists (Grafana, Tomcat, …).\n"
        "- Grafana: try admin:prom-operator (kube-prometheus-stack Helm default), then "
        "admin:admin / admin:grafana — tiny list, then stop.\n"
        "- CouchDB: try admin:admin, admin:password, couchdb:couchdb (nuclei couchdb-default-login). "
        "On _admin: queue default_login follow-ups — _config secret/salts then AuthSession forgery. "
        "Then sibling username=username for at most 8 short / 10-iteration [admins] names "
        "(kevin, karen, admin, test) — rotation of one does not kill the others.\n"
        "- ArangoDB :8529: POST /_open/auth root with empty password only.\n"
        "- EMQX: admin:public then admin:admin — no plugin upload.\n"
        "- Django: admin:admin on /admin/login/ and /api/token-pair/; then DEBUG traceback card.\n"
        "- test_credential_spray or execute_hydra with tiny lists + -f.\n"
        "- On success: add_engagement_credential + queue_finding_followups("
        "vuln_type='default_login') + validate_finding → create_finding.\n"
        "- Login success is a foothold, not the finding: coverage must prove privileged "
        "APIs (Grafana: /api/admin/settings, /api/datasources, /api/serviceaccounts/search; "
        "CouchDB: /_session _admin, /_all_dbs, /_node/_local/_config).\n"
        "- No rockyou, no unbounded hydra, no invented passwords.\n"
        "- Keycloak admin-cli: POST grant_type=password client_id=admin-cli with NO "
        "client_secret. invalid_grant (not invalid_client) proves Direct Access Grants on a "
        "public client. Then <=8 fake-password attempts — no 429/lockout is SUBMIT. "
        "Tiny defaults only (admin:admin, admin:password, admin:keycloak); stop on hit. "
        "Master realm is full admin. queue_finding_followups(vuln_type='keycloak_password_grant'). "
        "Do not hydra/rockyou; do not kill because no valid password was guessed."
    ),
    "finding_judge": (
        "SKILL PACK — finding judge (Solomon):\n"
        "- Re-run validate_finding on each proposed medium+ finding.\n"
        "- Authz/IDOR: require anon/A/B identity discipline.\n"
        "- Default/weak login: DROP/IMPROVE until privileged impact is proven "
        "(admin settings, datasources, tokens, internal topology, CouchDB _config/"
        "AuthSession _admin) — not 'login worked'.\n"
        "- JS-leaked client_id/client_secret: DROP/IMPROVE until a live in-scope API "
        "returns non-public records (count + redacted sample) — not 'key found in bundle'.\n"
        "- EmailJS keys in JS: DROP/IMPROVE until a browser-context send to an "
        "engagement-controlled canary returns 200/OK (or mail received) — never phishing "
        "to real employees.\n"
        "- Grafana CVE-2024-9264: SUBMIT if /api/ds/query type=sql is accepted and the "
        "server forks duckdb — including 'no such file or directory'. Missing binary and "
        "sqlExpressions=0 in /metrics are NOT kills. Kill only if patched authz rejects SQL "
        "expressions without forking DuckDB.\n"
        "- Data-store banners (Mongo/Arango/EMQX/Registry/Auth0 token): DROP/IMPROVE until privileged "
        "list/sample is proven — not 'port open' / 'JWT found'. per_page=1 / catalog names only.\n"
        "- Wiki self-reg: DROP/IMPROVE until sandbox write or one internal page — not 'signup works'.\n"
        "- Public binary secrets: DROP/IMPROVE until strings extract a production credential — not 'file downloaded'.\n"
        "- Client-side-only admin: DROP/IMPROVE until an API returns privileged data without a session.\n"
        "- Elasticsearch :9200 banner: DROP/IMPROVE until indices enumerated AND write "
        "proven (PUT+DELETE aegis_test_index) — not 'port 9200 open'. No Painless RCE.\n"
        "- Azure Function env dump: DROP/IMPROVE until leaked secret *classes* are named "
        "(Cosmos, Storage, MACHINEKEY, EasyAuth, AAD) — not 'env vars leaked'. "
        "ACE as managed identity is not_demonstrated unless code execution was actually shown.\n"
        "- OpenAPI/DRF mass assignment: SUBMIT if request serializers expose writable "
        "id/created/user/owner/schedule without readOnly, OR a list op documents "
        "'shared across all users'. A down database is NOT a kill. Kill only if fields "
        "are readOnly/extra_kwargs or object-level authz rejects foreign id/user.\n"
        "- Unauth OpenAPI account lookup: SUBMIT if GET /api/auth/account/ (or similar "
        "email lookup) is security: {} / 'without authentication' AND the response "
        "schema includes is_staff/role/valid_through, OR unauth lookup is 200/500 while "
        "protected siblings 401. A down database is NOT a kill. One canary email "
        "(aegis-enum-canary@example.invalid); do not spray employee inboxes; do not dump "
        "ICS users. Kill only if the lookup 401/403 like siblings or the schema requires "
        "JWT and the body is a non-enumerating boolean. ACAO * is extra, not the CORS "
        "credentials finding.\n"
        "- CORS/Keycloak: SUBMIT if a canary Origin is reflected in ACAO AND "
        "credentials=true (token/userinfo/admin). Header proof is enough — no victim tab. "
        "Kill ACAO=* without credentials. Do not dump /users; do not ship an HTML exploit.\n"
        "- Keycloak admin-cli password grant: SUBMIT if the token endpoint accepts "
        "grant_type=password for client_id=admin-cli with no client_secret (invalid_grant) "
        "AND a bounded (<=8) failure probe has no 429/lockout. Do not require a cracked "
        "password. Kill invalid_client / unsupported_grant_type / lockout. No hydra/rockyou.\n"
        "- Require demonstrated-compromise writeup: description + impact + assets + remediation "
        "+ demonstrated_chain (live tool calls with observed responses) + not_demonstrated.\n"
        "- DROP theoretical / status-only / missing-evidence cards.\n"
        "- create_finding only after SUBMIT; sanitize_evidence first when secrets present."
    ),
    "api_authz": (
        "SKILL PACK — IDOR / BOLA proof:\n"
        "- Pick mapped object APIs with IDs (users, orgs, files, invoices).\n"
        "- compare_requests across anonymous / user A / user B (or adjacent IDs).\n"
        "- PASS only if other-user fields appear; status 200 alone is not a finding.\n"
        "- Client-supplied userType/userId/Admin in publicPortal: compare_requests empty vs Admin; "
        "bounded sample; queue_finding_followups(vuln_type='client_role_param').\n"
        "- vendorJson unauth: GET /glens/userManagement/api/v3.0/vendorJson; tenant count not full dump.\n"
        "- CORS: Origin reflection + Access-Control-Allow-Credentials=true is the finding "
        "(queue cors_credentials). Use a never-seen canary Origin, not evil.com. OPTIONS "
        "preflight: Allow-Headers Authorization + Allow-Methods POST/PUT/DELETE. "
        "Keycloak webOrigins=*: repeat on token, userinfo, JWKS, /auth/admin/realms/<realm>/users. "
        "Header proof is SUBMIT — no victim tab, no HTML exploit page, do not dump /users. "
        "Kill ACAO=* without credentials or an allowlist that rejects the canary. "
        "Then queue_finding_followups(vuln_type='keycloak_password_grant') for admin-cli "
        "password grant / lockout — do not spray. "
        "Socket.IO get_stream url_key is enough — no video dump, no null-input crash loops.\n"
        "- OpenAPI/DRF mass assignment: GET /api/schema/ (or swagger.json). Count *Request "
        "components where id/created/updated/user/owner/schedule/periodic_task are writable "
        "(not readOnly). SUBMIT on that schema even if the DB is down (500 / OperationalError). "
        "Quote list descriptions that say 'shared across all users'. One bounded canary "
        "write if the DB is up — do not enable ICS/OT schedules; do not dump the hierarchy. "
        "queue_finding_followups(vuln_type='mass_assignment'). Kill only if readOnly/"
        "extra_kwargs or object-level 403.\n"
        "- Unauth account/email lookup: hunt schema security: {} on /api/auth/account/ "
        "(or similar). Quote UserAccount fields is_staff/role/valid_through. "
        "compare_requests unauth GET /api/auth/profile/ (401) vs "
        "/api/auth/account/?email=aegis-enum-canary@example.invalid (200 with those "
        "fields OR 500). One canary only — do not spray employee inboxes; do not dump "
        "ICS users. 500 vs sibling 401 is SUBMIT. ACAO * is extra. "
        "queue_finding_followups(vuln_type='unauth_account_lookup'). Kill only lookup "
        "401/403 or JWT-required generic boolean.\n"
        "- On proven read IDOR: queue_finding_followups(vuln_type='idor') for write/export."
    ),
    "host_tenant": (
        "SKILL PACK — tenant isolation:\n"
        "- Baseline: session A + Host=tenant A.\n"
        "- Mutant: same cookies + Host or X-Forwarded-Host = peer tenant B.\n"
        "- PASS only if tenant B data/PII appears; kill on vhost reject / unchanged A body."
    ),
    "business_logic": (
        "SKILL PACK — business logic:\n"
        "- Mutate one control at a time (price, quantity, step order, role field).\n"
        "- OpenAPI/DRF: also mass-assign server-managed fields (id, created, user) shown "
        "writable in the schema — schema proof is enough if the DB is down.\n"
        "- Demonstrate expected vs actual state with compare_requests / replay.\n"
        "- Prove the bypass; do not complete fraudulent checkout or irreversible actions."
    ),
    "injection": (
        "SKILL PACK — injection / XSS:\n"
        "- Only probe ranked params/forms from the map (or arjun/discover_parameters hits).\n"
        "- SQLi: canary → execute_sqlmap --batch on confirmed candidates.\n"
        "- XSS: execute_xsstrike and/or execute_dalfox; confirm with execute_browser when needed.\n"
        "- Command injection: execute_commix only on high-signal params; no blind spray.\n"
        "- Report with payload + response evidence; no status-only findings."
    ),
    "file_upload": (
        "SKILL PACK — upload abuse:\n"
        "- Content-type / extension / path tricks on mapped upload forms.\n"
        "- Prefer stored XSS or path disclosure proofs; avoid destructive webshells."
    ),
    "saml_sso": (
        "SKILL PACK — SSO:\n"
        "- Probe authorize/callback/SAML endpoints for open redirect, weak state, JWT issues.\n"
        "- Keycloak: test client webOrigins (never '*'). Canary Origin + credentials=true "
        "on token/userinfo/admin is SUBMIT; queue cors_credentials. Prefer '+' or explicit URIs.\n"
        "- Keycloak admin-cli Direct Access Grants: public client + password grant with no "
        "lockout — hand to credential_assault / queue keycloak_password_grant. No hydra.\n"
        "- Use test_saml_sso / execute_jwt; prove with redirect or token impact."
    ),
    "spa_client": (
        "SKILL PACK — SPA / DOM:\n"
        "- Hunt DOM XSS sinks, hidden client routes, and JS-driven APIs missing auth.\n"
        "- Confirm DOM XSS in browser; hidden APIs → hand off to api_authz."
    ),
    "coverage": (
        "SKILL PACK — coverage leftovers:\n"
        "- Run AFTER logic specialists.\n"
        "- get_engagement_brain for creds; prefer authenticated nuclei -var.\n"
        "- Chain default-login → authenticated CVE / admin SSRF cards via queue_finding_followups.\n"
        "- Grafana admin: prove read-only first — GET /api/admin/settings, /api/datasources, "
        "/api/serviceaccounts/search, then proxy EXISTING Prometheus datasource "
        "(/api/datasources/proxy/<id>/api/v1/targets). Create a new datasource only if none exists.\n"
        "- Grafana CVE-2024-9264: Viewer+ POST /api/ds/query type=sql. SUBMIT on file-read "
        "OR fork/exec duckdb 'no such file'. Missing binary and sqlExpressions=0 in /metrics "
        "are NOT kills. Kill only if patched >=11.2.2 / engine rejects SQL without forking. "
        "Do not install DuckDB; do not run shell extensions.\n"
        "- CouchDB _admin: prove read-only — GET /_session, /_all_dbs, /_node/_local/_config "
        "(couch_httpd_auth secret, timeout, admins salts). Then AuthSession HMAC using "
        "secret+admin salt from /_config/admins (NOT _users derived_key). GET /_session + "
        "/_all_dbs with the forged cookie and no Basic auth. Rotate-secret is the real fix; "
        "password rotation alone does not kill this. Redact secret/salts/AuthSession.\n"
        "- ArangoDB :8529: POST /_open/auth root+empty password → list DBs + one collection sample.\n"
        "- MongoDB :27017: nuclei mongodb-unauth; note ransomware DBs; no dump/drop.\n"
        "- EMQX: after admin:public, read-only listeners/users. No plugins.\n"
        "- Auth0: unauth GET /api/token then ONE /api/v2/clients?per_page=1. Redact JWT.\n"
        "- GitLab: GET /api/v4/projects?per_page=5; sample one file. Do not clone all.\n"
        "- Docker Registry: GET /v2/_catalog. Do not push.\n"
        "- Django DEBUG: after admin:admin, safe 500 → env secret classes; optional Redis ping. No FLUSHALL.\n"
        "- Elasticsearch :9200: unauthenticated banner is a foothold. Prove GET / (cluster "
        "name/version/node), GET /_cluster/health + /_nodes/os,jvm, GET /_cat/indices, "
        "sample-read 1–3 user indices (size=1), then PUT+DELETE aegis_test_index. "
        "Do not dump all docs, do not run Painless/scripting RCE, do not pivot. "
        "queue_finding_followups(vuln_type='elasticsearch_unauth'). CWE-306.\n"
        "- Azure Function Apps (*.azurewebsites.net): unauth GET /api/Tester (then test/debug/env/"
        "HttpTrigger1). If authLevel:anonymous returns process env JSON, classify Cosmos/Storage/"
        "MACHINEKEY/EasyAuth/AAD/App Insights, redact keys, queue_finding_followups("
        "vuln_type='azure_function_env_dump'). Do not upload packages or inject code. "
        "Probe the -dev- peer hostname. CWE-526.\n"
        "- Write findings as description + impact (what was retrieved) + assets + remediation."
    ),
    "js_secrets": (
        "SKILL PACK — JS secrets (Uri):\n"
        "- scan_js_urls_for_secrets / execute_hermes / execute_gitleaks on first-party bundles, "
        "especially /_next/static/chunks/*.js on admin/sandbox UIs.\n"
        "- Look for hostname-keyed objects mapping prod/dev/qa hosts to client_id + client_secret. "
        "Those are often sent as HTTP headers (client_id / client_secret), not Bearer tokens.\n"
        "- Stash via add_engagement_credential(secret_type=oauth_client); "
        "queue_finding_followups(vuln_type='js_secrets').\n"
        "- Prove live impact with ONE in-scope read-only API call (result count + 1-2 redacted "
        "sample fields). Do not bulk-export. Prefer sandbox/dev; prod only if in scope.\n"
        "- A secret in JS is a foothold — the finding is authenticated data retrieved "
        "OR a proven EmailJS send to an engagement-controlled canary.\n"
        "- Public downloadable binaries (.exe/.msi/.apk/firmware): strings for password/"
        "connection patterns; prove ONE live login if safe. "
        "queue_finding_followups(vuln_type='binary_hardcoded_creds'). Do not reverse for exploits.\n"
        "- EmailJS: extract service_id (service_*), user_id, template_id. Prove with "
        "execute_browser POST to api.emailjs.com/api/v1.0/email/send — one canary to "
        "interactsh/operator inbox only. Never send to employees or arbitrary addresses. "
        "Server-side 403 is expected; browser origin is the real test.\n"
        "- sanitize_evidence before create_finding; rotate ALL env pairs and EmailJS "
        "user_id in remediation; recommend a server-side proxy, EmailJS domain allowlist, "
        "and rate limiting (never ship API secrets to the browser)."
    ),
    "secrets_hunter": (
        "SKILL PACK — secrets:\n"
        "- Prefer execute_hermes / execute_argus / gitleaks with verification when available.\n"
        "- CRITICAL only for verified live credentials; LOW for unverified strings."
    ),
    "agent_tools": (
        "SKILL PACK — AI agent / chat proxy:\n"
        "- Enumerate tools via execute_llm_red_team categories=tool_enumeration first.\n"
        "- Unauth POST /api/chat (Azure OpenAI proxy): one cheap canary completion, then stop. "
        "Do not burn tokens. queue_finding_followups(vuln_type='openai_proxy_unauth').\n"
        "- Report prompt+response evidence only."
    ),
    "cloud_audit": (
        "SKILL PACK — cloud posture:\n"
        "- Use execute_themis (Prowler) read-only against configured cloud credentials.\n"
        "- Report high-impact public exposure / IAM findings with resource IDs.\n"
        "- After an Azure Function env dump: if cloud ROE allows, read-only ARM/Graph of the "
        "Function App MI roles and Key Vault access. Do not inject code on the app."
    ),
    "graphql_api": (
        "SKILL PACK — GraphQL:\n"
        "- Probe /graphql paths; check introspection, suggestions, batching, CSRF on GET.\n"
        "- Prefer execute_schemathesis + execute_curl; prove authz with compare_requests."
    ),
    "web_recon": (
        "SKILL PACK — recon:\n"
        "- subfinder/httpx/whatweb/katana inventory; feroxbuster/ffuf only on high-value hosts.\n"
        "- No exploit tools in this lane."
    ),
    "vuln_triage": (
        "SKILL PACK — triage:\n"
        "- Correlate vulns with CVE/exploit context; do not exploit.\n"
        "- Rank blast radius; suggest which specialist should prove impact next."
    ),
    "takeover": (
        "SKILL PACK — takeover:\n"
        "- Confirm dangling CNAME + provider fingerprint before HIGH severity."
    ),
    "content_api": (
        "SKILL PACK — content/API enum:\n"
        "- Crawl + parameter discovery; feed map for authz/injection specialists."
    ),
}


def skill_pack_for(specialist: str) -> str:
    """Return the skill-pack body for a specialist, or empty string."""
    return (SPECIALIST_SKILL_PACKS.get(specialist) or "").strip()
