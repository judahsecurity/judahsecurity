"""
Fireteam / Scatter-Gather ReAct pattern.

Joshua (orchestrator) only *schedules*. This module runs N short-lived
specialist executors in parallel. Each gets:

    * A tightly-scoped role and allowlist
    * An operation directive + brain slice (not the full engagement dump)
    * A fresh context window

Each specialist returns an ``ExecutorSummary`` contract (verdict / evidence /
spawn). The Penetration Task Graph is the planner; auto-prompter rewrites a
failed hunter instead of looping the same prompt.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, Iterable, Optional

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Built-in specialist profiles
# ---------------------------------------------------------------------------


@dataclass
class SpecialistProfile:
    name: str
    role: str
    allowed_tools: list[str]
    max_iterations: int = 6
    max_tools_per_iteration: int = 4
    system_prompt_suffix: str = ""
    epithet: str = ""  # Aegis pantheon display name (Samson, Daniel, …)
    # model_router task: recon (cheap) vs offensive (flagship proof)
    llm_task: str = "offensive"

    def __post_init__(self) -> None:
        if not self.epithet:
            try:
                from app.services.agent.aegis_pantheon import epithet_for

                self.epithet = epithet_for(self.name)
            except Exception:
                self.epithet = self.name.replace("_", " ").title()


DEFAULT_SPECIALISTS: list[SpecialistProfile] = [
    SpecialistProfile(
        name="web_recon",
        role=(
            "Passive web reconnaissance specialist. Enumerate assets, "
            "technologies, exposed ports and HTTP surface."
        ),
        allowed_tools=[
            "query_assets",
            "query_ports",
            "query_technologies",
            "analyze_attack_surface",
            "execute_httpx",
            "execute_naabu",
            "execute_subfinder",
            "execute_subfaster",
            "execute_crtsh",
            "execute_dnsx",
            "execute_uncover",
            "execute_whatweb",
            "execute_wappalyzer",
            "execute_katana",
            "execute_gau",
            "execute_feroxbuster",
        ],
        max_iterations=8,
        llm_task="recon",
    ),
    SpecialistProfile(
        name="content_api",
        role=(
            "Content and API discovery specialist. When the page is 404, login-only, "
            "or thin: directory brute-force, crawl JS, mine parameters, find undocumented "
            "APIs. A 404 is not 'nothing else is available'."
        ),
        allowed_tools=[
            "query_assets",
            "execute_katana",
            "execute_gau",
            "execute_waybackurls",
            "execute_deep_crawl",
            "execute_interceptor",
            "execute_ffuf",
            "execute_feroxbuster",
            "execute_kiterunner",
            "execute_arjun",
            "discover_parameters",
            "ingest_urls_into_map",
            "create_scan",
            "mutate_list",
            "list_captured_requests",
            "mutate_captured_request",
            "fingerprint_api",
            "extract_js_endpoints",
            "fetch_lazy_chunks",
            "scan_js_sinks",
        ],
        max_iterations=12,
        llm_task="recon",
    ),
    SpecialistProfile(
        name="js_secrets",
        role=(
            "JavaScript recon specialist. Extract endpoints from bundles, "
            "find secrets (hostname-keyed OAuth maps, CWE-321 client HMAC via "
            "Object.keys join, MQTT/RFID ICS creds), then prove impact."
        ),
        allowed_tools=[
            "query_assets",
            "scan_js_urls_for_secrets",
            "fetch_lazy_chunks",
            "extract_js_endpoints",
            "scan_js_sinks",
            "ingest_urls_into_map",
            "execute_retirejs",
            "execute_gitleaks",
            "execute_hermes",
            "execute_curl",
            "execute_httpx",
            "execute_browser",
            "execute_interactsh",
            "run_custom_probe",
            "mutate_list",
            "get_engagement_brain",
            "add_engagement_credential",
            "queue_finding_followups",
            "update_hypothesis",
            "sanitize_evidence",
            "validate_finding",
            "submit_finding_candidate",
            "save_note",
            "create_scan",
        ],
        max_iterations=12,
        llm_task="recon",
        system_prompt_suffix=(
            "First fetch_lazy_chunks (dry_run then download) on webpack/Vite/Next/Angular "
            "runtime bundles, then extract_js_endpoints, ingest_urls_into_map, then secrets. "
            "Hunt first-party /_next/static/chunks/*.js, Angular main-es2015.*.js, and "
            "main.*.js (often 5–10MB — do not skip). "
            "CWE-321: scan_js_urls_for_secrets client_signing_findings reconstructs "
            "Object.keys(obj).join('') / for-in HMAC-SHA256 keys (iLens this.waste) and "
            "MQTT/RFID creds. SUBMIT on public reconstruction + HmacSHA256/HS256 in the "
            "same unauth bundle. Live token accept is extra; backend timeout is NOT a kill. "
            "Stash hmac_key / mqtt / rfid via add_engagement_credential. Do not brute brokers. "
            "Also hunt hostname-keyed config objects (prod/dev/qa → client_id + client_secret). "
            "OAuth credentials are often sent as client_id/client_secret HTTP headers, not Bearer. "
            "Sandbox/admin UIs commonly ship PRODUCTION pairs — stash all envs, redact in evidence. "
            "For OAuth: prove impact with ONE read-only API call (count + 1-2 redacted sample fields). "
            "Do not paginate or bulk-export. Call prod APIs only if in scope. "
            "On hit: add_engagement_credential + "
            "queue_finding_followups(vuln_type='js_secrets'). "
            "Also hunt EmailJS: emailjs_userid / emailjs_serviceid / emailjs_templateid "
            "(or service_id: service_*). Prove with ONE browser-context POST to "
            "https://api.emailjs.com/api/v1.0/email/send using execute_interactsh "
            "payload_email (aegis@<payload_domain>) — never Canarytokens, never customer "
            "employees or arbitrary recipients. curl 403 from missing Origin is NOT a kill; retry execute_browser. "
            "Max one canary per template (cap two). "
            "Write description + impact + assets + remediation (rotate HMAC key, MQTT/RFID, "
            "ALL env pairs, EmailJS user_id, and any client encryption_key — file encryption_key "
            "as its own Critical CWE-321 card, not an EmailJS footnote; never ship secrets to "
            "the browser — server-side signing/proxy; EmailJS origin allowlist + rate limit). "
            "CWE-321 / CWE-798 / CWE-312 / CWE-540."
        ),
    ),
    SpecialistProfile(
        name="vuln_triage",
        role=(
            "Vulnerability triage specialist. Correlate findings with CVEs, "
            "exploit availability and blast radius. Never exploits anything."
        ),
        allowed_tools=[
            "query_vulnerabilities",
            "get_asset_details",
            "search_cve",
            "search_vulnx",
            "vulnx_query",
            "check_cve_applicability",
            "fingerprint_passive_stack",
            "analyze_attack_surface",
            "rank_attack_surface",
        ],
        llm_task="recon",
    ),
    SpecialistProfile(
        name="secrets_hunter",
        role=(
            "Secrets & credential exposure specialist. Focus on leaked keys, "
            "exposed source maps, github secrets, and dependency-confusion."
        ),
        allowed_tools=[
            "execute_hermes",
            "execute_argus",
            "scan_js_urls_for_secrets",
            "execute_gitleaks",
            "query_assets",
        ],
    ),
    SpecialistProfile(
        name="cloud_audit",
        role=(
            "Cloud / CSPM specialist. Look for AWS/Azure/GCP misconfig, "
            "exposed buckets, IAM issues."
        ),
        allowed_tools=[
            "query_assets",
            "execute_themis",
            "execute_curl",
            "probe_registry_anonymous",
            "validate_finding",
            "submit_finding_candidate",
            "queue_finding_followups",
            "search_cve",
            "analyze_attack_surface",
        ],
    ),
    SpecialistProfile(
        name="graphql_api",
        role=(
            "GraphQL / API specialist. Find GraphQL endpoints, probe them "
            "for introspection, verbose errors, CSRF, batching DoS."
        ),
        allowed_tools=[
            "execute_schemathesis",
            "execute_astf",
            "execute_kiterunner",
            "execute_curl",
            "compare_requests",
            "create_scan",
            "query_assets",
            "update_hypothesis",
            "validate_finding",
            "submit_finding_candidate",
        ],
    ),
    SpecialistProfile(
        name="takeover",
        role=(
            "Subdomain takeover specialist. Hunt dangling CNAMEs and "
            "provider fingerprints; only report confirmed/likely takeovers."
        ),
        allowed_tools=[
            "query_assets",
            "execute_dnsx",
            "execute_subfinder",
            "create_scan",
            "execute_nuclei",
        ],
    ),
    # ── Attack specialists (spawned from capability map after browser walkthrough) ──
    SpecialistProfile(
        name="app_mapper",
        role=(
            "Application mapper. You already have a browser capability map. "
            "Summarize features, trust boundaries, and the highest-value hunt "
            "queue. Do not spray scanners — reason about what a tester would try next."
        ),
        allowed_tools=[
            "query_assets",
            "analyze_attack_surface",
            "rank_attack_surface",
            "save_note",
            "execute_curl",
            "list_captured_requests",
            "fingerprint_api",
            "mutate_list",
        ],
        max_iterations=4,
        llm_task="recon",
        system_prompt_suffix=(
            "Output a ranked hunt queue with concrete URLs/forms/APIs from the mission. "
            "Call save_note(category='artifact') with the map summary."
        ),
    ),
    SpecialistProfile(
        name="auth_logic",
        role=(
            "Auth / session / access-control specialist. Probe login, session cookies, "
            "forced browsing, and horizontal/vertical authz using concrete endpoints "
            "from the capability map and open engagement hypotheses."
        ),
        allowed_tools=[
            "execute_curl",
            "execute_browser",
            "execute_httpx",
            "bypass_403",
            "test_saml_sso",
            "test_credential_spray",
            "execute_hydra",
            "execute_jwt",
            "compare_requests",
            "mutate_captured_request",
            "run_custom_probe",
            "add_engagement_credential",
            "queue_finding_followups",
            "update_hypothesis",
            "log_engagement_approach",
            "save_note",
            "validate_finding",
            "submit_finding_candidate",
        ],
        max_iterations=12,
        system_prompt_suffix=(
            "Prefer compare_requests (anonymous vs auth). On default/weak login success: "
            "add_engagement_credential + queue_finding_followups(vuln_type='default_login'). "
            "Login username/password (or JSON /login body) is also an injection surface — "
            "spawn sqli for error/boolean/time canaries; do not treat login as creds-only. "
            "Never invent credentials. Hand large sprays to credential_assault (Samson). "
            "ASP.NET SaveSettings: missing [Authorize] is sibling 401 vs unauth 200 void — "
            "hand to api_authz; queue_finding_followups(vuln_type='unauth_settings_write'). "
            "djoser reset_email: unauth 204 vs set_password 401 — hand to auth_logic; "
            "queue_finding_followups(vuln_type='email_change_ato'). One canary; do not "
            "complete ATO on a real mailbox."
        ),
    ),
    SpecialistProfile(
        name="credential_assault",
        role=(
            "Credential assault specialist (Samson). Prove default/weak/known credentials on "
            "mapped login forms with tiny lists; stash working creds and enqueue post-auth chains."
        ),
        allowed_tools=[
            "execute_httpx",
            "execute_curl",
            "execute_browser",
            "test_credential_spray",
            "execute_hydra",
            "add_engagement_credential",
            "queue_finding_followups",
            "update_hypothesis",
            "log_engagement_approach",
            "validate_finding",
            "submit_finding_candidate",
            "save_note",
        ],
        max_iterations=8,
        system_prompt_suffix=(
            "Tiny lists only (defaults / known product creds). Grafana: admin:prom-operator "
            "(kube-prometheus-stack), then admin:admin / admin:grafana. CouchDB: admin:admin, "
            "admin:password, couchdb:couchdb (nuclei couchdb-default-login). Always hydra -f / "
            "exit on success. "
            "On hit: add_engagement_credential + queue_finding_followups(vuln_type='default_login') "
            "+ validate_finding before submit_finding_candidate. Login is a foothold — coverage proves "
            "privileged APIs. Never invent credentials; no rockyou. "
            "Keycloak: POST /auth/realms/master/protocol/openid-connect/token "
            "grant_type=password client_id=admin-cli with NO client_secret. invalid_grant "
            "proves the public password grant. At most 8 fake-password attempts for lockout/"
            "429 — then stop. Tiny defaults only (admin:admin, admin:password, admin:keycloak). "
            "queue_finding_followups(vuln_type='keycloak_password_grant'). Master is highest impact."
        ),
    ),
    SpecialistProfile(
        name="api_authz",
        role=(
            "API authorization specialist. Test captured first-party APIs for IDOR, "
            "verb tampering, missing auth, and mass assignment on concrete paths."
        ),
        allowed_tools=[
            "execute_curl",
            "execute_httpx",
            "execute_kiterunner",
            "execute_schemathesis",
            "execute_astf",
            "discover_parameters",
            "execute_arjun",
            "compare_requests",
            "mutate_captured_request",
            "list_captured_requests",
            "run_custom_probe",
            "update_hypothesis",
            "queue_finding_followups",
            "log_engagement_approach",
            "validate_finding",
            "submit_finding_candidate",
            "save_note",
        ],
        max_iterations=12,
        system_prompt_suffix=(
            "Prove with compare_requests across identities/object IDs. "
            "Status 200 alone is not a finding — show other-user fields. "
            "OpenAPI/DRF (GET /api/schema/ or swagger.json): count request serializers "
            "where id, created, updated, user, owner, schedule, periodic_task are writable "
            "(not readOnly). SUBMIT on that schema even if writes 500 / DB down. "
            "List descriptions that say 'all users' / 'shared across' are missing isolation. "
            "One bounded canary write if the DB is up — do not enable ICS schedules or dump "
            "OT/ICS asset trees. queue_finding_followups(vuln_type='mass_assignment'). "
            "Kill only if fields are readOnly / extra_kwargs or object-level 403. "
            "Unauth account lookup: schema security: {} on /api/auth/account/?email= "
            "plus is_staff/role, or compare_requests sibling 401 vs lookup 200/404/500. "
            "One canary email (aegis-enum-canary@example.invalid) — do not spray. "
            "DB down or 404 existence oracle is SUBMIT Critical. Do not claim a 200 "
            "role body unless stdout has it. "
            "queue_finding_followups(vuln_type='unauth_account_lookup'). "
            "Unauth settings write: compare_requests protected write 401 vs POST "
            "/api/Settings/SaveSettings 200 Content-Length: 0 (void) with "
            "use_auth_session=false. GET 500 is SUBMIT. "
            "One canary key (aegis-verify-*); do not replace production settings. "
            "queue_finding_followups(vuln_type='unauth_settings_write'). "
            "Auth header bypass: no Authorization vs Bearer aegis-invalid — SUBMIT if "
            "no-header is 200/400 AND invalid-bearer is 401. 400 missing-params is a bypass. "
            "queue_finding_followups(vuln_type='auth_header_bypass'). "
            "Socket.IO get_stream: Engine.IO polling + fabricated siteId → url_key. "
            "Do not fetch video; do not send null crash loops. "
            "queue_finding_followups(vuln_type='socketio_idor'). "
            "ML train/delete: self-reg JWT often has no RBAC. Do not delete production models. "
            "queue_finding_followups(vuln_type='ml_pipeline_rbac'). "
            "CORS: canary Origin (not evil.com) vs none. SUBMIT if ACAO echoes AND "
            "credentials=true. OPTIONS preflight Authorization+POST. Keycloak: repeat on "
            "token, userinfo, /auth/admin/realms/<realm>/users — header proof is enough; "
            "do not dump users; webOrigins explicit or '+', never '*'. "
            "queue_finding_followups(vuln_type='cors_credentials'). "
            "Keycloak admin-cli: if CORS is proven, queue_finding_followups("
            "vuln_type='keycloak_password_grant') — do not spray passwords."
        ),
    ),
    SpecialistProfile(
        name="host_tenant",
        role=(
            "Host-header / tenant-isolation specialist. Keep the same session and mutate "
            "Host or X-Forwarded-Host toward a peer tenant to prove cross-tenant access."
        ),
        allowed_tools=[
            "compare_requests",
            "execute_curl",
            "replay_http_request",
            "mutate_captured_request",
            "update_hypothesis",
            "queue_finding_followups",
            "log_engagement_approach",
            "validate_finding",
            "submit_finding_candidate",
            "save_note",
        ],
        max_iterations=8,
        system_prompt_suffix=(
            "Baseline = tenant A host + session A. Mutant = peer tenant Host/X-Forwarded-Host "
            "with the SAME cookies. PASS only if tenant B data appears. "
            "Kill on vhost reject or unchanged tenant A body. "
            "On proven: queue_finding_followups(vuln_type='host_header')."
        ),
    ),
    SpecialistProfile(
        name="business_logic",
        role=(
            "Business-logic specialist. Abuse workflows: step skipping, price/quantity "
            "tamper, mass assignment, insecure state transitions on mapped forms/APIs."
        ),
        allowed_tools=[
            "compare_requests",
            "replay_http_request",
            "mutate_captured_request",
            "run_custom_probe",
            "execute_curl",
            "execute_browser",
            "update_hypothesis",
            "log_engagement_approach",
            "validate_finding",
            "submit_finding_candidate",
            "save_note",
        ],
        max_iterations=8,
        system_prompt_suffix=(
            "Mutate one control at a time. Demonstrate expected vs actual state; "
            "do not complete fraudulent transactions — prove the bypass."
        ),
    ),
    SpecialistProfile(
        name="injection",
        role=(
            "Injection and input-abuse specialist. Hunt UNKNOWN bugs on discovered "
            "and hidden parameters: SQLi/XSS/SSTI/command AND SSRF/URL-fetch "
            "(webhook, proxy, execute, datasource, url/uri fields). Do not wait for "
            "a named CVE. If the map is thin, run discover_parameters + arjun first."
        ),
        allowed_tools=[
            "discover_parameters",
            "execute_arjun",
            "execute_sqlmap",
            "execute_xsstrike",
            "execute_dalfox",
            "execute_commix",
            "execute_browser",
            "execute_interactsh",
            "generate_injection_payloads",
            "execute_curl",
            "compare_requests",
            "mutate_list",
            "list_captured_requests",
            "mutate_captured_request",
            "run_custom_probe",
            "update_hypothesis",
            "log_engagement_approach",
            "validate_finding",
            "submit_finding_candidate",
        ],
        max_iterations=12,
        system_prompt_suffix=(
            "Start with discover_parameters + arjun on live paths if params are unknown. "
            "SQLi/XSS/SSTI/cmd as usual. Also treat url/uri/request/datasource/execute/"
            "query fields as SSRF: execute_interactsh register → plant payload_url → poll, "
            "then compare benign vs internal canary (do not use cloud-metadata/loopback if Lictor blocks). "
            "Do not use Canarytokens. Status 200 is not a finding. Unknown-bug hunting beats Nuclei templates."
        ),
    ),
    SpecialistProfile(
        name="xss",
        role=(
            "XSS specialist. Hunt reflected/stored/DOM XSS on search and reflect "
            "params the map actually showed — not a generic injection dump."
        ),
        allowed_tools=[
            "execute_xsstrike",
            "execute_dalfox",
            "execute_browser",
            "execute_curl",
            "compare_requests",
            "mutate_list",
            "list_captured_requests",
            "mutate_captured_request",
            "run_custom_probe",
            "update_hypothesis",
            "log_engagement_approach",
            "validate_finding",
            "submit_finding_candidate",
        ],
        max_iterations=10,
        system_prompt_suffix=(
            "Only params that reflect or render (q, search, name, message, comment, "
            "redirect). Canary first, then browser confirm. Status 200 is not XSS."
        ),
    ),
    SpecialistProfile(
        name="sqli",
        role=(
            "SQL / template / command injection specialist. Probe mapped non-reflect "
            "params with canaries; escalate to sqlmap/commix only on hits."
        ),
        allowed_tools=[
            "discover_parameters",
            "execute_arjun",
            "execute_sqlmap",
            "execute_commix",
            "execute_interactsh",
            "generate_injection_payloads",
            "execute_curl",
            "compare_requests",
            "mutate_captured_request",
            "run_custom_probe",
            "update_hypothesis",
            "log_engagement_approach",
            "validate_finding",
            "submit_finding_candidate",
        ],
        max_iterations=10,
        system_prompt_suffix=(
            "Login/auth fields are rank-1 even with no query params. "
            "compare_requests error/boolean/time on username then password "
            "(or JSON /login body). Timing that scales with SLEEP is SUBMIT. "
            "Canary → differential. sqlmap --batch only on confirmed candidates. "
            "Blind OOB SQLi/XXE: execute_interactsh register → plant payload_url → poll. "
            "If WAF/403: run_custom_probe / encoding, then prove or kill. "
            "No os-shell. Status 200 is not SQLi."
        ),
    ),
    SpecialistProfile(
        name="ssrf",
        role=(
            "SSRF / URL-fetch specialist. Webhooks, proxies, imports, preview, "
            "datasource, requestUrl fields from the map."
        ),
        allowed_tools=[
            "execute_interactsh",
            "execute_curl",
            "compare_requests",
            "list_captured_requests",
            "mutate_captured_request",
            "run_custom_probe",
            "update_hypothesis",
            "log_engagement_approach",
            "validate_finding",
            "submit_finding_candidate",
        ],
        max_iterations=10,
        system_prompt_suffix=(
            "OOB is Interactsh only: execute_interactsh register → plant payload_url → poll. "
            "Do not use Canarytokens. Compare benign vs in-scope canary. "
            "Never metadata/localhost if Lictor blocks. OOB-only without an "
            "internal body is incomplete for Critical."
        ),
    ),
    SpecialistProfile(
        name="file_upload",
        role=(
            "File upload specialist. Abuse upload forms/APIs from the map for "
            "content-type bypass, path issues, and stored XSS via uploaded content."
        ),
        allowed_tools=[
            "execute_curl",
            "execute_browser",
            "execute_httpx",
            "update_hypothesis",
            "validate_finding",
            "submit_finding_candidate",
            "save_note",
        ],
        max_iterations=6,
    ),
    SpecialistProfile(
        name="saml_sso",
        role=(
            "SSO / SAML / OAuth specialist. Probe authorize/callback/SAML endpoints "
            "for open redirects, signature issues, and OIDC misconfig."
        ),
        allowed_tools=[
            "test_saml_sso",
            "execute_jwt",
            "execute_curl",
            "execute_browser",
            "compare_requests",
            "update_hypothesis",
            "validate_finding",
            "submit_finding_candidate",
        ],
        max_iterations=6,
    ),
    SpecialistProfile(
        name="spa_client",
        role=(
            "SPA / client-side specialist. DOM XSS, hidden client routes, and "
            "JS-driven API abuse using the browsed pages and bundles."
        ),
        allowed_tools=[
            "execute_browser",
            "execute_deep_crawl",
            "execute_interceptor",
            "scan_js_urls_for_secrets",
            "fetch_lazy_chunks",
            "extract_js_endpoints",
            "scan_js_sinks",
            "execute_retirejs",
            "execute_curl",
            "compare_requests",
            "mutate_list",
            "mutate_captured_request",
            "run_custom_probe",
            "update_hypothesis",
            "validate_finding",
            "submit_finding_candidate",
        ],
        max_iterations=12,
    ),
    SpecialistProfile(
        name="agent_tools",
        role=(
            "AI agent / chatbot tool-surface specialist. Treat agent tools as the "
            "attack surface (email→phishing, refund→fraud, DB→exfil). Enumerate "
            "tools first, then abuse parameters (user_id→IDOR, send_now→immediate action)."
        ),
        allowed_tools=[
            "execute_llm_red_team",
            "execute_garak",
            "execute_curl",
            "execute_browser",
            "execute_nuclei",
            "create_scan",
            "compare_requests",
            "update_hypothesis",
            "validate_finding",
            "submit_finding_candidate",
            "save_note",
        ],
        max_iterations=8,
        system_prompt_suffix=(
            "Methodology: (1) Confirm chat/agent endpoint. (2) Run "
            "execute_llm_red_team with categories including tool_enumeration — "
            "tool names = what it can do; parameters = how to exploit. "
            "(3) Prioritize email/notify, refund/payment, query/DB tools and "
            "identity/side-effect params. (4) Broaden with other LLM categories "
            "and optional execute_garak. Report only with prompt+response evidence."
        ),
    ),
    SpecialistProfile(
        name="coverage",
        role=(
            "Coverage / known-vuln specialist. Run Nuclei and related scanners AFTER "
            "logic hunts. If engagement credentials exist, prefer authenticated templates "
            "(-var username/password) for default-login and post-auth CVEs."
        ),
        allowed_tools=[
            "execute_nuclei",
            "execute_nikto",
            "execute_httpx",
            "execute_curl",
            "execute_gitleaks",
            "probe_registry_anonymous",
            "get_engagement_brain",
            "queue_finding_followups",
            "update_hypothesis",
            "add_engagement_credential",
            "validate_finding",
            "submit_finding_candidate",
            "save_note",
        ],
        max_iterations=8,
        llm_task="recon",
        system_prompt_suffix=(
            "Check get_engagement_brain for credentials before nuclei. "
            "Grafana default-login: execute_nuclei args='-u https://host -id grafana-default-login "
            "-var username=admin -var password=prom-operator -jsonl'. "
            "On default-login hits: add_engagement_credential + queue_finding_followups. "
            "For Grafana admin sessions, prove demonstrated compromise read-only first: "
            "(1) GET /api/admin/settings — pod identity, grafana.ini, DB config; "
            "(2) GET /api/datasources — existing Prometheus/Loki URLs; "
            "(3) GET /api/serviceaccounts/search — SA names, roles, token counts (do not create tokens); "
            "(4) Proxy EXISTING prometheus datasource: GET /api/datasources/proxy/<id>/api/v1/targets "
            "or /api/v1/query?query=up — enumerate in-cluster exporters. "
            "(5) Only if no usable existing DS: create a temporary prometheus datasource to "
            "kubernetes.default.svc / metadata, then GET /api/datasources/proxy/... "
            "CouchDB _admin: (1) GET /_session — roles _admin; (2) GET /_all_dbs — db count; "
            "(3) GET /_node/_local/_config/couch_httpd_auth/secret and /admins — secret + salts; "
            "(4) Forge AuthSession with HMAC-SHA1(secret+admin_salt, user:hex_ts) — NOT _users "
            "derived_key — then GET /_session and /_all_dbs with Cookie only. Password rotation "
            "does not kill this; rotating the secret does. Redact secret/salts/AuthSession. "
            "Elasticsearch :9200 (xpack.security off): unauth GET / is a foothold. Prove: "
            "(1) GET / — cluster name, version, node, tagline; "
            "(2) GET /_cluster/health and GET /_nodes/os,jvm — hostname/OS/kernel; "
            "(3) GET /_cat/indices?v then GET /<user-index>/_search?size=1 on 1–3 user "
            "indices (do not scroll/dump); "
            "(4) PUT /aegis_test_index then immediately DELETE /aegis_test_index. "
            "Do not run Painless/scripting RCE. Do not pivot. "
            "queue_finding_followups(vuln_type='elasticsearch_unauth'). CWE-306. "
            "Write the finding as Vulnerability Description, Impact (what was retrieved), "
            "Assets Affected, Recommendation (rotate admin + SA tokens, metrics_require_auth, "
            "upgrade, network ACL). CWE-1393. Prefer read-only canaries; do not mutate cluster state. "
            "Azure Function Apps (*.azurewebsites.net): unauthenticated GET /api/Tester then "
            "/api/test,/api/debug,/api/env,/api/HttpTrigger1. If the body is process env JSON "
            "(AzureWebJobsStorage, Cosmos keys, MACHINEKEY, WEBSITE_AUTH_*), classify secret "
            "classes, redact keys, queue_finding_followups(vuln_type='azure_function_env_dump'). "
            "Do not upload function packages or inject code. Probe the -dev- / production peer hostname. "
            "ACR / Docker Registry (*.azurecr.io or /v2/_catalog): unauth GET "
            "/oauth2/token?service=<host>&scope=registry:catalog:* then GET /v2/_catalog "
            "with the bearer. Catalog names = SUBMIT High. Then tags/list + config/history "
            "on at most 1–3 first-party repos. Do not pull the whole catalog; do not push; "
            "do not authenticate recovered PATs. queue_finding_followups("
            "vuln_type='docker_registry'). CWE-306. "
            "CVE-2024-9264 (Grafana): ANY authenticated session (Viewer / SA token is enough). "
            "POST /api/ds/query with type=sql. SUBMIT if the server forks /usr/local/bin/duckdb "
            "— including 'no such file or directory'. Missing DuckDB is NOT a kill. "
            "sqlExpressions=0 in /metrics is NOT a kill (UI toggle ≠ backend in 11.0.x). "
            "Kill only if patched >=11.2.2 or the engine rejects SQL expressions without "
            "forking DuckDB. Use direct curl plus nuclei CVE-2024-9264; do not install DuckDB; "
            "do not run shell extensions."
        ),
    ),
    SpecialistProfile(
        name="code_sast",
        role=(
            "White-box / SAST specialist (Huldah). Threat-model the checkout, then "
            "instantiate ranked threat shapes with Semgrep/Gitleaks/Trivy. Never execute "
            "target code."
        ),
        allowed_tools=[
            "build_threat_model",
            "get_threat_model",
            "get_engagement_brain",
            "execute_semgrep",
            "execute_gitleaks",
            "execute_trivy",
            "update_hypothesis",
            "validate_finding",
            "submit_finding_candidate",
            "save_note",
        ],
        max_iterations=8,
        epithet="Huldah",
        system_prompt_suffix=(
            "get_threat_model first; hunt shapes from ranked threats. "
            "A Semgrep hit is a lead — require a reachable exploit scenario that "
            "instantiates a threat row before submit_finding_candidate. "
            "Mitigated one layer up → kill. Never execute target binaries."
        ),
    ),
    SpecialistProfile(
        name="finding_judge",
        role=(
            "Finding judge (Solomon). Adversarial review of proposed findings — "
            "require demonstrated impact, identity discipline for authz, and SUBMIT "
            "verdicts. Does not exploit; improves or kills weak cards."
        ),
        allowed_tools=[
            "validate_finding",
            "sanitize_evidence",
            "compare_requests",
            "get_engagement_brain",
            "update_hypothesis",
            "log_engagement_approach",
            "get_notes",
            "save_note",
        ],
        max_iterations=6,
        system_prompt_suffix=(
            "Re-score each proposed finding with validate_finding. Do NOT create_finding "
            "or submit_finding_candidate — hunters submit candidates; Deborah verifies; "
            "Joshua publishes. Kill theoretical / status-only / identity-less IDOR claims. "
            "Prefer sanitize_evidence before publish. "
            "Grafana CVE-2024-9264: SUBMIT if /api/ds/query type=sql forks duckdb — "
            "including 'no such file or directory'. Missing binary and sqlExpressions=0 "
            "in /metrics are NOT kills. "
            "OpenAPI/DRF mass assignment: SUBMIT on writable id/created/user without "
            "readOnly, or a list that documents 'all users' — even if the DB is down. "
            "Unauth account lookup: SUBMIT Critical on security: {} + is_staff/role, or "
            "200/404/500 vs sibling 401. Do not kill because the DB is down or the "
            "lookup is 404. One canary email; do not spray. Do not claim a 200 role "
            "body unless stdout has it. "
            "Unauth settings write: SUBMIT on sibling write 401 vs SaveSettings 200 "
            "void (Content-Length: 0). GET GetSettings 500 is not a kill. One canary "
            "key; do not replace production settings. "
            "CORS/Keycloak: SUBMIT if a canary Origin is reflected with credentials=true "
            "on token/userinfo/admin. Header proof is enough; do not dump /users. "
            "Keycloak admin-cli: SUBMIT if password grant works without client_secret and "
            "<=8 failures have no 429/lockout — do not require a guessed password; no hydra."
        ),
    ),
    SpecialistProfile(
        name="risk_assessor",
        role=(
            "Risk assessor (Marcus). Writes demonstrated-only risk assessments "
            "on published findings — confirm/downgrade/upgrade severity, CVSS, "
            "control failures, remediation with close criteria. Does not exploit "
            "and does not live-retest."
        ),
        allowed_tools=[
            "assess_finding_risk",
            "query_vulnerabilities",
            "get_notes",
            "save_note",
            "sanitize_evidence",
            "get_engagement_brain",
        ],
        max_iterations=6,
        epithet="Marcus",
        llm_task="recon",
        system_prompt_suffix=(
            "You are Marcus. Score the published packet only. Call "
            "assess_finding_risk(finding_id, assessment JSON). Do NOT "
            "execute_curl, execute_browser, or create_finding. Critical "
            "requires demonstrated write/RCE/cloud credentials — except unauth "
            "/api/auth/account/ (schema security: {} + is_staff/role, or sibling "
            "401 vs 200/404/500) which is Critical. Do not invent a 200 UserAccount "
            "body. Non-blind SSRF with IMDS blocked is High. If RA IMPROVE, fix gaps once."
        ),
    ),
    SpecialistProfile(
        name="independent_verifier",
        role=(
            "Independent verifier (Deborah). Fresh session — re-derive the claimed "
            "proof without the hunter transcript. Issues verify receipts only."
        ),
        allowed_tools=[
            "compare_requests",
            "execute_curl",
            "execute_httpx",
            "scan_js_urls_for_secrets",
            "replay_http_request",
            "record_verify_verdict",
            "sanitize_evidence",
            "save_note",
            "get_notes",
        ],
        max_iterations=6,
        system_prompt_suffix=(
            "You did not see the hunter's chain. Re-derive with your own requests. "
            "CWE-321 HMAC/ICS in JS: re-run scan_js_urls_for_secrets on the cited bundle; "
            "confirmed if client_signing_findings reconstructs the signing key or MQTT/RFID "
            "creds. Do not require JWT mint or broker login. "
            "Unauth account lookup: confirmed on schema security: {} + is_staff/role OR "
            "sibling 401 vs lookup 200/404/500 with aegis-enum-canary@example.invalid. "
            "404/500 is confirmed, not refuted. Do not spray emails. "
            "Call record_verify_verdict only. Never create_finding or "
            "submit_finding_candidate. Never call get_engagement_brain."
        ),
    ),
]

_SPECIALISTS_BY_NAME: dict[str, SpecialistProfile] = {s.name: s for s in DEFAULT_SPECIALISTS}


def get_specialist(name: str) -> Optional[SpecialistProfile]:
    return _SPECIALISTS_BY_NAME.get(name)


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


@dataclass
class ToolInvocation:
    tool: str
    args: dict
    success: bool
    summary: str
    error: Optional[str] = None


@dataclass
class SpecialistReport:
    specialist: str
    role: str
    mission: str
    summary: str                          # LLM-written narrative
    key_findings: list[str] = field(default_factory=list)
    tool_calls: list[ToolInvocation] = field(default_factory=list)
    duration_seconds: float = 0.0
    error: Optional[str] = None
    verdict: str = ""                     # proven | killed | blocked | retry | inconclusive
    hypothesis_ids: list[str] = field(default_factory=list)
    evidence: str = ""
    spawn: list[str] = field(default_factory=list)
    rewrite_hint: str = ""


@dataclass
class FireteamResult:
    mission: str
    specialists_run: list[str]
    reports: list[SpecialistReport]
    merged_summary: str = ""
    duration_seconds: float = 0.0
    total_tool_calls: int = 0


def _fill_summary_contract(report: SpecialistReport, payload: dict) -> None:
    """Copy executor summary-contract fields off a done JSON payload."""
    verdict = str(payload.get("verdict") or "").strip().lower()
    if verdict:
        report.verdict = verdict
    hyps = payload.get("hypothesis_ids") or payload.get("hypothesis_id") or []
    if isinstance(hyps, str):
        hyps = [hyps]
    if isinstance(hyps, list) and hyps:
        report.hypothesis_ids = [str(x) for x in hyps if x][:12]
    evidence = payload.get("evidence")
    if evidence:
        report.evidence = str(evidence)[:2000]
    spawn = payload.get("spawn") or payload.get("spawn_specialists") or []
    if isinstance(spawn, str):
        spawn = [spawn]
    if isinstance(spawn, list):
        report.spawn = [str(x).strip() for x in spawn if str(x).strip()][:8]
    hint = payload.get("rewrite_hint") or payload.get("next_attempt")
    if hint:
        report.rewrite_hint = str(hint)[:500]


# ---------------------------------------------------------------------------
# Mini ReAct loop per specialist
# ---------------------------------------------------------------------------


_SPECIALIST_SYSTEM_PROMPT = """\
You are {epithet}, a specialist sub-agent in Judah Security's Aegis fireteam.
Other specialists run in parallel. Stay strictly in your lane.
You MUST NOT call fireteam_dispatch or spawn sub-agents.

EPITHET / ROLE: {epithet} — {role}

OPERATION DIRECTIVE:
{directive}

SHARED MISSION CONTEXT:
{mission}

TARGETS: {targets}

AVAILABLE TOOLS (allowlist -- you MAY NOT call anything else):
{tool_list}

PALACE / HUNT NOTES (compact — URL, param, hypothesis, next mutation):
{memory}

INSTRUCTIONS:
1. Obey the operation directive (goal, PASS/KILL, hypothesis ids).
2. Code-first: list_captured_requests → mutate_captured_request (one field) or run_custom_probe.
   JS: fetch_lazy_chunks → extract_js_endpoints → ingest_urls_into_map. API profile: fingerprint_api.
   For lists (paths/params/xss) call mutate_list once — do not ReAct them.
3. Blind SSRF/XXE: execute_interactsh register, plant payload_url. Never 169.254.169.254 or localhost.
4. Think briefly about which tool(s) will most quickly prove or kill the hypothesis.
5. Respond ONLY with a JSON object of this shape:

   {{
     "tool_calls": [
       {{"tool": "<tool_name>", "args": {{...}}}}
     ],
     "done": false,
     "reasoning": "one-line rationale"
   }}

6. When you have enough evidence, respond with:

   {{
     "done": true,
     "summary": "1-3 paragraph narrative of what you found",
     "key_findings": ["bullet", "bullet", "bullet"],
     "verdict": "proven|killed|blocked|retry|inconclusive",
     "hypothesis_ids": ["id from the directive"],
     "evidence": "tool-backed proof only — quote tool output, never imagined",
     "spawn": ["optional specialist names to enqueue, e.g. graphql_api"],
     "rewrite_hint": "if retry: what to try differently"
   }}

6. Medium+ findings: call validate_finding first; submit_finding_candidate only on SUBMIT.
   Write demonstrated-compromise reports (description + impact + assets + remediation),
   not 'login worked' or template-match-only.
7. Do not exceed {max_iter} iterations. If unsure, finish with done=true.
8. Imagining tool output is a failure (soliloquy). If you did not call a tool, verdict=retry.
9. save_note(category='hunt') with URL/param/hypothesis/next mutation — not raw httpx.

{suffix}
"""


async def _run_specialist(
    profile: SpecialistProfile,
    mission: str,
    targets: Iterable[str],
    llm: Any,
    tools_manager: Any,
    directive: Any = None,
) -> SpecialistReport:
    start = datetime.utcnow()
    target_list = list(targets) if targets else []
    report = SpecialistReport(
        specialist=profile.name,
        role=f"{profile.epithet}: {profile.role}",
        mission=mission,
        summary="",
    )

    from app.services.agent.operation_directive import (
        OperationDirective,
        merge_directive_into_mission,
    )
    from app.services.agent.specialist_skills import skill_pack_for

    skill_pack = skill_pack_for(profile.name)
    suffix_parts = [profile.system_prompt_suffix.strip()] if profile.system_prompt_suffix else []
    if skill_pack:
        suffix_parts.append(skill_pack)
    suffix = "\n\n".join(suffix_parts)

    if isinstance(directive, OperationDirective):
        directive_block = directive.to_prompt_block()
        mission_for_prompt = merge_directive_into_mission(mission, None)  # directive shown separately
        max_iter = directive.max_iterations or profile.max_iterations
        if directive.hypothesis_ids and not report.hypothesis_ids:
            report.hypothesis_ids = list(directive.hypothesis_ids)
    else:
        directive_block = (
            f"Goal: execute your role ({profile.epithet}) against the shared mission.\n"
            f"PASS: demonstrated impact with evidence.\n"
            f"KILL: no impact after disciplined probes."
        )
        mission_for_prompt = mission
        max_iter = profile.max_iterations

    allowed_tools = list(profile.allowed_tools)
    if "search_memory" not in allowed_tools:
        allowed_tools.append("search_memory")

    memory_block = "None."
    org_id = None
    session_id = None
    try:
        from app.services.agent.tools import current_session_id, get_tenant_context
        from app.services.agent.palace_memory import wake_up as palace_wake_up
        from app.services.agent.hunter_brief import OOB_SPECIALISTS, format_hunter_brief

        _uid, org_id = get_tenant_context()
        session_id = current_session_id.get() or None
        palace_snippet = ""
        if org_id:
            seed = target_list[0] if target_list else ""
            palace_snippet = palace_wake_up(
                org_id,
                target=str(seed) or None,
                specialist=profile.name,
            )
        cmap = getattr(tools_manager, "_capability_map", None) or {}
        memory_block = format_hunter_brief(
            specialist=profile.name,
            directive=directive if isinstance(directive, OperationDirective) else None,
            cmap=cmap if isinstance(cmap, dict) else {},
            palace_snippet=palace_snippet,
            provision_oob=profile.name in OOB_SPECIALISTS,
        )
    except Exception:
        logger.debug("specialist hunt-brief skipped", exc_info=True)

    sys_prompt = _SPECIALIST_SYSTEM_PROMPT.format(
        epithet=profile.epithet or profile.name,
        role=profile.role,
        directive=directive_block,
        mission=mission_for_prompt,
        targets=", ".join(target_list) or "<see analyze_attack_surface output>",
        tool_list="\n".join(f"  - {t}" for t in allowed_tools),
        memory=memory_block,
        max_iter=max_iter,
        suffix=suffix,
    )

    messages: list = [SystemMessage(content=sys_prompt)]
    messages.append(HumanMessage(content="Begin."))

    iteration = 0
    while iteration < profile.max_iterations:
        iteration += 1
        try:
            response = await llm.ainvoke(messages)
        except Exception as exc:
            logger.warning("fireteam %s: LLM failure: %s", profile.name, exc)
            report.error = f"LLM error: {exc}"
            break

        text = getattr(response, "content", "") or ""
        messages.append(AIMessage(content=text))

        payload = _extract_json(text)
        if not payload:
            report.summary = text[:2000]
            break

        if payload.get("done"):
            report.summary = (payload.get("summary") or "").strip()
            kf = payload.get("key_findings") or []
            if isinstance(kf, list):
                report.key_findings = [str(x) for x in kf][:20]
            _fill_summary_contract(report, payload)
            break

        tool_calls = payload.get("tool_calls") or []
        if not tool_calls:
            report.summary = payload.get("reasoning") or text[:2000]
            break

        # Enforce allowlist + max parallelism per turn.
        tool_calls = [tc for tc in tool_calls if tc.get("tool") in allowed_tools][: profile.max_tools_per_iteration]

        if not tool_calls:
            messages.append(HumanMessage(
                content="None of the tools you requested are allowed. "
                        "Pick from the allowlist or finish with done=true."
            ))
            continue

        tool_results = await asyncio.gather(*(
            _safe_invoke(tools_manager, tc.get("tool", ""), tc.get("args") or {})
            for tc in tool_calls
        ))

        for tc, tr in zip(tool_calls, tool_results):
            report.tool_calls.append(tr)

        feedback = {
            "tool_results": [
                {
                    "tool": tr.tool,
                    "success": tr.success,
                    "summary": tr.summary[:1500],
                    "error": tr.error,
                }
                for tr in tool_results
            ],
        }
        messages.append(HumanMessage(content=json.dumps(feedback)))

    report.duration_seconds = (datetime.utcnow() - start).total_seconds()
    if not report.summary and not report.error:
        report.summary = (
            f"{profile.name} exhausted {profile.max_iterations} iterations without "
            f"concluding. Last tool calls: "
            f"{[t.tool for t in report.tool_calls[-3:]]}"
        )
    if org_id and (report.summary or report.key_findings):
        try:
            from app.services.agent.palace_memory import store_specialist_diary

            seed = target_list[0] if target_list else ""
            store_specialist_diary(
                organization_id=org_id,
                specialist=profile.name,
                summary=report.summary or "",
                key_findings=report.key_findings,
                session_id=session_id,
                target=str(seed) or None,
            )
        except Exception:
            logger.debug("specialist diary store skipped", exc_info=True)
    return report


async def _safe_invoke(tools_manager: Any, tool_name: str, args: dict) -> ToolInvocation:
    try:
        result = await tools_manager.execute(tool_name, args or {})
        success = bool(result.get("success"))
        summary = _stringify_tool_result(result)
        return ToolInvocation(
            tool=tool_name,
            args=args or {},
            success=success,
            summary=summary,
            error=result.get("error") if not success else None,
        )
    except Exception as exc:
        return ToolInvocation(
            tool=tool_name,
            args=args or {},
            success=False,
            summary=f"invocation raised {type(exc).__name__}: {exc}",
            error=str(exc),
        )


def _stringify_tool_result(result: Any) -> str:
    if isinstance(result, dict):
        out = result.get("output")
        if isinstance(out, str):
            return out
        return json.dumps(result)[:3000]
    return str(result)[:3000]


def _extract_json(text: str) -> Optional[dict]:
    """Parse the first top-level JSON object from ``text``, tolerating code fences."""
    if not text:
        return None
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        newline = text.find("\n")
        if newline >= 0:
            text = text[newline + 1:]
        if text.endswith("```"):
            text = text[:-3]
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        return json.loads(text[start: end + 1])
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def run_fireteam(
    mission: str,
    targets: Iterable[str],
    specialists: Iterable[str | SpecialistProfile],
    llm: Any,
    tools_manager: Any,
    max_parallel: int = 4,
    progress_callback: Optional[Callable[[str, str], Awaitable[None]]] = None,
    directives: Optional[Dict[str, Any]] = None,
    llm_for_specialist: Optional[Callable[[SpecialistProfile], Any]] = None,
) -> FireteamResult:
    """Run a fireteam in parallel and return the merged result.

    ``specialists`` may contain either string names from :data:`DEFAULT_SPECIALISTS`
    or fully custom :class:`SpecialistProfile` instances (for ad-hoc missions).
    ``directives`` maps specialist name → OperationDirective (optional).
    """
    start = datetime.utcnow()
    directives = directives or {}

    resolved: list[SpecialistProfile] = []
    for s in specialists:
        if isinstance(s, SpecialistProfile):
            resolved.append(s)
        elif isinstance(s, str):
            prof = get_specialist(s)
            if prof:
                resolved.append(prof)
            else:
                logger.warning("Fireteam: unknown specialist '%s' -- skipping", s)

    if not resolved:
        return FireteamResult(mission=mission, specialists_run=[], reports=[])

    targets_list = [t for t in targets if t]
    sem = asyncio.Semaphore(max(1, max_parallel))

    async def _run(p: SpecialistProfile) -> SpecialistReport:
        async with sem:
            label = f"{p.epithet} ({p.name})" if p.epithet else p.name
            if progress_callback:
                try:
                    await progress_callback(label, "started")
                except Exception:
                    pass
            spec_llm = llm
            if llm_for_specialist is not None:
                try:
                    spec_llm = llm_for_specialist(p) or llm
                except Exception:
                    logger.warning("llm_for_specialist failed for %s; using default", p.name, exc_info=True)
                    spec_llm = llm
            rep = await _run_specialist(
                p,
                mission,
                targets_list,
                spec_llm,
                tools_manager,
                directive=directives.get(p.name),
            )
            if progress_callback:
                try:
                    await progress_callback(label, "done")
                except Exception:
                    pass
            return rep

    reports = await asyncio.gather(*( _run(p) for p in resolved ))

    merged = _merge_reports(mission, reports)

    result = FireteamResult(
        mission=mission,
        specialists_run=[r.specialist for r in reports],
        reports=list(reports),
        merged_summary=merged,
        duration_seconds=(datetime.utcnow() - start).total_seconds(),
        total_tool_calls=sum(len(r.tool_calls) for r in reports),
    )
    logger.info(
        "Fireteam complete: %d specialists, %d tool calls, %.2fs",
        len(result.specialists_run), result.total_tool_calls, result.duration_seconds,
    )
    return result


def _merge_reports(mission: str, reports: list[SpecialistReport]) -> str:
    lines: list[str] = [f"# Aegis fireteam debrief (Joshua) — {mission}\n"]
    for r in reports:
        lines.append(f"## {r.specialist} ({r.role})")
        if r.error:
            lines.append(f"- status: **error** -- {r.error}")
        lines.append(f"- tool calls: {len(r.tool_calls)}  duration: {r.duration_seconds:.1f}s")
        if r.key_findings:
            lines.append("- key findings:")
            for kf in r.key_findings:
                lines.append(f"  * {kf}")
        if r.summary:
            lines.append(r.summary.strip())
        lines.append("")
    return "\n".join(lines)
