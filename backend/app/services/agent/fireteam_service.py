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
import inspect
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, Iterable, Optional
from urllib.parse import urlsplit

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

if TYPE_CHECKING:
    from app.services.agent.operation_directive import OperationDirective

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
            "get_api_operation_inventory",
            "execute_katana",
            "execute_gau",
            "execute_waybackurls",
            "execute_deep_crawl",
            "execute_interceptor",
            "execute_ffuf",
            "execute_feroxbuster",
            "execute_kiterunner",
            "execute_arjun",
            "spawn_recon_workers",
            "list_recon_workers",
            "discover_parameters",
            "ingest_urls_into_map",
            "create_scan",
            "mutate_list",
            "list_captured_requests",
            "plan_intruder_mutations",
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
            "scan_assigned_js",
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
            "When an observed script is assigned, call scan_assigned_js with its coverage "
            "cell and lease first; then inspect its endpoints and sinks. Fetch lazy chunks (dry_run then "
            "download) on webpack/Vite/Next/Angular "
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
        name="cms_followup",
        role=(
            "CMS follow-up specialist. Investigate fingerprinted core, plugin, theme, "
            "and configuration leads while application-input hunters run."
        ),
        allowed_tools=[
            "fingerprint_passive_stack",
            "check_cve_applicability",
            "execute_cmseek",
            "execute_wpscan",
            "search_cve",
            "search_vulnx",
            "vulnx_query",
            "execute_curl",
            "execute_browser",
            "compare_requests",
            "get_engagement_brain",
            "submit_finding_candidate",
            "update_hypothesis",
            "queue_finding_followups",
            "save_note",
        ],
        max_iterations=8,
        llm_task="recon",
        system_prompt_suffix=(
            "Use the observed CMS fingerprint and exact scoped host. Research only "
            "components and versions supported by response evidence; an unversioned "
            "label is a lead, not a finding. Investigate public plugin/theme files and "
            "CMS configuration exposures with bounded requests. On WordPress, Joshua "
            "separately runs the passive CVE map, REST user enumeration, and admin-ajax "
            "checks; focus on distinct plugin/theme/configuration follow-ups. "
            "Submit a candidate only with a matched affected range or reproduced "
            "configuration impact, including URL and evidence. Independent verification "
            "will confirm or refute it. Record uncertain leads as notes."
        ),
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
            "get_api_operation_inventory",
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
            "get_api_operation_inventory",
            "execute_browser",
            "execute_httpx",
            "bypass_403",
            "test_saml_sso",
            "execute_jwt",
            "scoped_race_assigned",
            "scoped_csrf_assigned",
            "scoped_jwt_probe",
            "scoped_jwt_key_url_probe",
            "scoped_jwt_key_url_probe",
            "compare_requests",
            "list_captured_requests",
            "mutate_captured_request",
            "run_custom_probe",
            "record_surface_coverage",
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
            "Prefer compare_requests (anonymous vs supplied test identities). "
            "Login username/password (or JSON /login body) is also an injection surface — "
            "spawn sqli for error/boolean/time canaries; do not treat login as creds-only. "
            "Never invent credentials. Credential testing needs explicit operator authorization "
            "and belongs to credential_assault (Samson), not this specialist. "
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
            "execute_brutus",
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
            "admin:password, couchdb:couchdb (nuclei couchdb-default-login). Prefer "
            "execute_brutus validation; use hydra -f only as a fallback. Never select mass "
            "mode unless the user explicitly requested mass brute forcing. "
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
            "get_api_operation_inventory",
            "fingerprint_api",
            "execute_httpx",
            "execute_kiterunner",
            "execute_schemathesis",
            "execute_astf",
            "discover_parameters",
            "execute_arjun",
            "scoped_jwt_probe",
            "compare_requests",
            "mutate_captured_request",
            "list_captured_requests",
            "plan_intruder_mutations",
            "run_intruder_batch",
            "run_custom_probe",
            "record_surface_coverage",
            "update_hypothesis",
            "queue_finding_followups",
            "log_engagement_approach",
            "validate_finding",
            "submit_finding_candidate",
            "save_note",
        ],
        max_iterations=12,
        system_prompt_suffix=(
            "Start with get_api_operation_inventory and fingerprint_api; prioritize browser-captured "
            "operations, then validate static JavaScript leads. Use capture references and "
            "parameter names to plan bounded authorization and input checks. "
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
            "get_parameter_inventory",
            "discover_parameters",
            "execute_arjun",
            "execute_sqlmap",
            "execute_xsstrike",
            "execute_dalfox",
            "execute_commix",
            "execute_browser",
            "execute_interactsh",
            "generate_injection_payloads",
            "scoped_xml_entity_assigned",
            "scoped_response_probe_assigned",
            "scoped_cors_probe_assigned",
            "scoped_injection_probe_assigned",
            "compare_requests",
            "mutate_list",
            "list_captured_requests",
            "plan_intruder_mutations",
            "run_intruder_batch",
            "mutate_captured_request",
            "run_custom_probe",
            "record_surface_coverage",
            "update_hypothesis",
            "log_engagement_approach",
            "validate_finding",
            "submit_finding_candidate",
        ],
        max_iterations=12,
        system_prompt_suffix=(
            "Start with get_parameter_inventory; use discover_parameters + arjun on live paths if params are unknown. "
            "SQLi/XSS/SSTI/cmd as usual. Use structured request tools for payloads. "
            "Also treat url/uri/request/datasource/execute/"
            "query fields as SSRF: if this run authorizes OOB, register a callback, plant "
            "a unique payload URL, and poll; otherwise keep checks local and read-only. "
            "then compare benign vs internal canary (do not use cloud-metadata/loopback if Lictor blocks). "
            "Do not use Canarytokens. Status 200 is not a finding. Unknown-bug hunting beats Nuclei templates. "
            "Run execute_ffuf with -of json so discovered paths auto-seed in-scope coverage cells; "
            "an execute_sqlmap or execute_ffuf hit is a lead that seeds a cell, not a finding — "
            "confirm it with the scoped probes and independent verifier before submitting a candidate."
        ),
    ),
    SpecialistProfile(
        name="server_injection",
        role=(
            "Server-side injection specialist for SSTI, OS command injection, path "
            "traversal, and NoSQL operator injection on observed inputs. Prove with "
            "computed output or a known-file signature, never with errors or reflection."
        ),
        allowed_tools=[
            "get_parameter_inventory",
            "scoped_injection_probe_assigned",
            "scoped_response_probe_assigned",
            "execute_interactsh",
            "execute_commix",
            "compare_requests",
            "list_captured_requests",
            "mutate_captured_request",
            "generate_injection_payloads",
            "record_surface_coverage",
            "update_hypothesis",
            "log_engagement_approach",
            "validate_finding",
            "submit_finding_candidate",
        ],
        max_iterations=10,
        system_prompt_suffix=(
            "For each leased ssti, command_injection, or path_traversal cell call "
            "scoped_injection_probe_assigned first; it is the only way to a medium+ "
            "proof. Submit a candidate only from a positive receipt, with the exact "
            "vulnerability_class and evidence_id. Never send destructive commands, "
            "write files, open shells, or read secrets; arithmetic and world-readable "
            "file signatures are the whole proof. NoSQL GET inputs use the operator "
            "differential in the same tool. For blind command injection with OOB "
            "authorized, call run_oob_callback_workflow with cmdi_shell set "
            "(posix_subshell|posix_separator|windows_separator) and field=<parameter>."
        ),
    ),
    SpecialistProfile(
        name="http_protocol",
        role=(
            "HTTP protocol specialist for request smuggling and web cache poisoning. "
            "Records leads for operator follow-up; these classes have no automated proof "
            "because a positive test can affect other users."
        ),
        allowed_tools=[
            "test_request_smuggling",
            "test_cache_poisoning",
            "compare_requests",
            "list_captured_requests",
            "record_surface_coverage",
            "update_hypothesis",
            "log_engagement_approach",
            "save_note",
        ],
        max_iterations=6,
        system_prompt_suffix=(
            "Use test_request_smuggling in timing-detection mode only and "
            "test_cache_poisoning (it adds a unique cache-buster to every probe). "
            "Never send a poisoning request on a shared cache key and never chain a "
            "desync into another user's request. Record results as leads with "
            "save_note and update_hypothesis; do not submit finding candidates."
        ),
    ),
    SpecialistProfile(
        name="xss",
        role=(
            "XSS specialist. Hunt reflected/stored/DOM XSS on observed inputs, "
            "prioritizing search and reflect params — not a generic injection dump."
        ),
        allowed_tools=[
            "get_parameter_inventory",
            "scoped_input_probe_assigned",
            "scoped_dom_xss_assigned",
            "scoped_stored_xss_assigned",
            "scoped_assessment_probe_assigned",
            "scoped_assessment_candidate",
            "execute_xsstrike",
            "execute_dalfox",
            "execute_browser",
            "scan_js_sinks",
            "compare_requests",
            "mutate_list",
            "list_captured_requests",
            "plan_intruder_mutations",
            "run_intruder_batch",
            "mutate_captured_request",
            "run_custom_probe",
            "record_surface_coverage",
            "update_hypothesis",
            "log_engagement_approach",
            "validate_finding",
            "submit_finding_candidate",
        ],
        max_iterations=14,
        system_prompt_suffix=(
            "Work the assigned observed input first. Use a harmless unique canary to check "
            "reflection or rendering; if it is absent, record an evidence-backed negative for "
            "that input. Use structured request tools for special characters; do not "
            "pass raw injection strings through a shell command. If the directive has "
            "an observed GET query input without a private browser capture, call "
            "scoped_input_probe_assigned with its coverage cell and lease IDs. "
            "This records an execution-owned browser receipt on the exact cell. "
            "Choose html_body, html_attribute, js_single, or js_double from the observed reflection context. "
            "After a negative probe, follow an applicable xss_trace.next_tests before closing. "
            "Then call record_surface_coverage with this cell, its lease, "
            "and the evidence ID only when the browser completed a context-appropriate check; "
            "otherwise record inconclusive so the input remains open. "
            "When it confirms execution, submit_finding_candidate with the receipt and coverage cell; "
            "an independent verifier must repeat the proof. "
            "If the directive has "
            "a PROWL private browser capture, call "
            "scoped_assessment_probe_assigned with the coverage cell and lease IDs; "
            "For a captured GET query, inspect the canary reflection context first. "
            "Use technique='xss_browser' for HTML body/DOM insertion, "
            "'xss_browser_attribute' for a double-quoted HTML attribute, or "
            "'xss_browser_js_single'/'xss_browser_js_double' for the corresponding "
            "JavaScript string. Each runs a fresh nonce-backed browser proof. "
            "Submit a local candidate with the execution receipt and exact cell; the independent "
            "verifier repeats it. "
            "A quote differential alone is not XSS. Status 200 is not XSS."
            " For a leased dom_xss cell with an observed rendering page, call "
            "scoped_dom_xss_assigned with the cell and lease IDs. Choose html_body, "
            "html_body_svg, html_attribute, html_attribute_single, js_single, or js_double "
            "from the observed context. A negative result is inconclusive; use the returned "
            "reflection_contexts to select a different technique on the same lease. "
            "Read xss_trace after each scoped XSS probe: it separates the observed source, "
            "static sink leads, rendered context, render representation, and next_tests. "
            "Choose at most one of the suggested next_tests at a time; technique and "
            "variant are backend allowlisted and the eight-attempt cap is shared across "
            "the cell. Use mixed_case only for HTML contexts and url_double only when "
            "a decode lead and rendered encoding make it plausible. Keep unsupported URL/CSS sinks "
            "inconclusive instead of calling reflection an XSS proof. "
            "Submit a candidate only "
            "when its fresh nonce executes; static source and sink patterns remain leads. "
            "For a leased stored_xss form cell, call scoped_stored_xss_assigned only with "
            "an observed readback page and an operator-approved nonce-addressed cleanup URL. "
            "It submits through the observed form, checks execution on a separate read, and "
            "requires successful cleanup. Cite its receipt for independent verification."
        ),
    ),
    SpecialistProfile(
        name="sqli",
        role=(
            "SQL / template / command injection specialist. Probe assigned observed "
            "params, including search and filter inputs, with controlled canaries; "
            "escalate to sqlmap/commix only on hits."
        ),
        allowed_tools=[
            "get_parameter_inventory",
            "scoped_input_probe_assigned",
            "scoped_string_sqli",
            "scoped_numeric_sqli",
            "scoped_assessment_probe_assigned",
            "scoped_assessment_candidate",
            "discover_parameters",
            "execute_arjun",
            "execute_sqlmap",
            "execute_commix",
            "execute_interactsh",
            "generate_injection_payloads",
            "compare_requests",
            "plan_intruder_mutations",
            "run_intruder_batch",
            "mutate_captured_request",
            "run_custom_probe",
            "record_surface_coverage",
            "update_hypothesis",
            "log_engagement_approach",
            "validate_finding",
            "submit_finding_candidate",
        ],
        max_iterations=10,
        system_prompt_suffix=(
            "Work the assigned observed input first. Prioritize captured catalog "
            "category/filter/search/product inputs before blind login guesses; test login "
            "only with a valid captured CSRF workflow. If baseline and mutants all "
            "return the same CSRF 400, mark that input blocked and move on. "
            "Use structured request tools for SQL syntax; do not pass raw injection "
            "strings through a shell command. If the directive has a PROWL private "
            "browser capture, call scoped_assessment_probe_assigned "
            "with the coverage cell and lease IDs. Numeric GET inputs use the scoped boolean "
            "proof; a single quote differential is only a lead. Submit a scoped candidate "
            "only on proof_confirmed=true and cite its service artifact ID. "
            "For an assigned string GET query without a private browser capture, call "
            "scoped_input_probe_assigned with its coverage cell and lease IDs; it preflights "
            "an ordinary baseline when the browser disclosed only parameter names and "
            "links the result to the exact coverage cell. A numeric input can use an "
            "observed positive browser link or captured GET value for its Boolean proof. "
            "For a confirmed local receipt, "
            "submit_finding_candidate with its evidence ID and coverage cell so an independent "
            "verifier can repeat it. "
            "Use scoped_string_sqli directly only for exploratory mapped inputs without "
            "an assigned coverage lease; it does not attach evidence to a coverage cell. "
            "For an assigned string GET input, use scoped_input_probe_assigned instead. "
            "The string proof can recover a private same-origin browser link "
            "or preflight a one-field observed GET form; if neither exists, mark "
            "the cell inconclusive and request more capture. It also checks small JSON "
            "result arrays with exact repeated true/false controls. Its Boolean and repeated "
            "database-error controls produce an execution-owned proof receipt. Submit a candidate "
            "only when proof_confirmed=true and cite that receipt. A negative result "
            "remains inconclusive for this class; a killed summary is not a test receipt. For other text "
            "inputs, compare baseline, true-condition, false-condition, and unrelated "
            "invalid controls with the same request shape. Repeat any candidate "
            "differential and account for dynamic content. "
            "For time-based probes, alternate multiple baseline and delay requests "
            "and require a repeatable gap beyond normal latency before submission. "
            "Canary → differential. sqlmap --batch only on confirmed candidates. "
            "Blind OOB SQLi/XXE requires explicit callback permission for this run; "
            "otherwise use local, bounded controls and record an untested proof path. "
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
            "plan_intruder_mutations",
            "run_intruder_batch",
            "mutate_captured_request",
            "run_custom_probe",
            "record_surface_coverage",
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
            "list_captured_requests",
            "mutate_captured_request",
            "record_surface_coverage",
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
            "scan_assigned_js_dependency",
            "scoped_client_probe_assigned",
            "execute_curl",
            "compare_requests",
            "mutate_list",
            "mutate_captured_request",
            "run_custom_probe",
            "record_surface_coverage",
            "update_hypothesis",
            "validate_finding",
            "submit_finding_candidate",
        ],
        max_iterations=12,
    ),
    # ── Surface-triggered stack / perimeter specialists ──
    # Ported from the Vanguard framework and enterprise hunters. Each activates
    # only on its fingerprint (surface_hunters.py). A class without a proof kind
    # in proof_policy.PROOFS_BY_CLASS stays a lead: recorded, never published.
    SpecialistProfile(
        name="grpc_api",
        role=(
            "gRPC / gRPC-Web specialist. Check server reflection, methods callable "
            "without auth metadata, and HTTP/JSON gateway twins that are weaker than "
            "the gRPC front."
        ),
        allowed_tools=[
            "get_api_operation_inventory",
            "fingerprint_api",
            "list_captured_requests",
            "execute_httpx",
            "execute_curl",
            "execute_nuclei",
            "compare_requests",
            "replay_http_request",
            "record_surface_coverage",
            "update_hypothesis",
            "log_engagement_approach",
            "validate_finding",
            "submit_finding_candidate",
            "save_note",
        ],
        max_iterations=8,
        system_prompt_suffix=(
            "Confirm gRPC first: application/grpc or grpc-web content types, "
            "/package.Service/Method paths, Envoy gRPC-Web. execute_nuclei -tags grpc. "
            "Reflection: one ServerReflectionInfo list_services request with execute_curl "
            "--http2 (gRPC-Web framing if that is all the edge accepts). An enabled "
            "reflection listing has no proof kind: record it as a lead with save_note "
            "and update_hypothesis. Unauthenticated methods: call at most one read-only "
            "method per service; never streaming or mutating methods, never loops. For "
            "a JSON gateway twin, compare_requests with two verified test identities on "
            "the same object and submit_finding_candidate(vulnerability_class="
            "'authorization') only with the authorization proof; otherwise it is a lead."
        ),
    ),
    SpecialistProfile(
        name="nodejs_express",
        role=(
            "Node.js / Express specialist. Server-side prototype pollution, trust-proxy "
            "IP spoofing, and template/static-path bugs on a fingerprinted Node stack."
        ),
        allowed_tools=[
            "get_parameter_inventory",
            "list_captured_requests",
            "execute_curl",
            "execute_nuclei",
            "compare_requests",
            "mutate_captured_request",
            "replay_http_request",
            "scoped_injection_probe_assigned",
            "record_surface_coverage",
            "update_hypothesis",
            "log_engagement_approach",
            "validate_finding",
            "submit_finding_candidate",
            "save_note",
        ],
        max_iterations=8,
        system_prompt_suffix=(
            "Confirm Node/Express (X-Powered-By: Express, connect.sid, Express error "
            "pages). Server-side prototype pollution has no proof kind: it is a lead. "
            "Detect it only with non-persistent reflection: send a JSON body with a "
            "unique __proto__ / constructor.prototype key to a captured merge endpoint "
            "and look for the key inherited in that same response. Never send payloads "
            "that change process-wide behaviour (status, json spaces, exposedHeaders, "
            "shell or env options) and never try a gadget chain; other users share the "
            "process. Trust proxy: compare a protected or IP-restricted path with and "
            "without X-Forwarded-For: 127.0.0.1; a difference is a lead. EJS/Pug/"
            "Handlebars SSTI and static-path traversal go through "
            "scoped_injection_probe_assigned on a leased cell; submit only on its "
            "receipt (vulnerability_class='ssti' or 'path_traversal')."
        ),
    ),
    SpecialistProfile(
        name="deserialization",
        role=(
            "Insecure deserialization specialist. Java/PHP/Python/.NET serialized-object "
            "sinks and JNDI lookups, proven only with a correlated canary callback."
        ),
        allowed_tools=[
            "get_parameter_inventory",
            "list_captured_requests",
            "execute_curl",
            "execute_nuclei",
            "execute_interactsh",
            "compare_requests",
            "record_surface_coverage",
            "update_hypothesis",
            "log_engagement_approach",
            "validate_finding",
            "submit_finding_candidate",
            "save_note",
        ],
        max_iterations=8,
        system_prompt_suffix=(
            "Look for serialized data in observed traffic: rO0AB / aced0005 (Java), "
            "O:<n>:\" or phar:// (PHP), pickle/yaml.load hints (Python), "
            "javax.faces.ViewState, application/x-java-serialized-object. A sink is a "
            "lead; gadget-chain deserialization has no proof kind, so never send "
            "ysoserial/phpggc/pickle gadget payloads. JNDI/Log4Shell class: only when "
            "this run authorizes OOB, call run_oob_callback_workflow with "
            "location='query_template' (or 'raw') and a body such as "
            "${jndi:dns://{{callback_host}}/a} on one observed field. A correlated "
            "callback proves a server-side outbound lookup: "
            "submit_finding_candidate(vulnerability_class='ssrf') with its oob_callback "
            "proof, titled as a JNDI lookup, without claiming code execution. Without "
            "OOB authorization record the sink as a lead. execute_nuclei only with "
            "-etags intrusive,dos, and -ni unless OOB is authorized."
        ),
    ),
    SpecialistProfile(
        name="m365_entra",
        role=(
            "Microsoft 365 / Entra ID external IdP specialist. Tenant discovery, "
            "federation and legacy-auth posture, and user-enumeration oracles for the "
            "in-scope domain only."
        ),
        allowed_tools=[
            "execute_curl",
            "execute_httpx",
            "execute_nuclei",
            "test_saml_sso",
            "compare_requests",
            "update_hypothesis",
            "log_engagement_approach",
            "submit_finding_candidate",
            "save_note",
        ],
        max_iterations=6,
        llm_task="recon",
        system_prompt_suffix=(
            "Requests stay subject to scope enforcement; if a Microsoft endpoint is "
            "blocked, record the lead and stop. Tenant: GET the domain's "
            "/.well-known/openid-configuration on login.microsoftonline.com and "
            "getuserrealm.srf (Managed vs Federated, federation endpoint/ADFS). Probe an "
            "exposed ADFS with test_saml_sso. Tenant metadata is informational: "
            "save_note. User enumeration (GetCredentialType): one nonexistent canary and "
            "one address observed on the target, nothing more. A repeatable difference "
            "here stays a lead: account_enumeration confirms only through "
            "scoped_account_enum_assigned on an operator-captured test account, which "
            "this lane does not run. No password spraying, device-code or consent "
            "phishing, token theft or mailbox access; spraying belongs to "
            "credential_assault and only when the run grants credential testing."
        ),
    ),
    SpecialistProfile(
        name="okta_idp",
        role=(
            "Okta IdP specialist. Tenant discovery, OIDC metadata, authn/factor "
            "enumeration posture and exposed admin surfaces for in-scope Okta tenants."
        ),
        allowed_tools=[
            "execute_curl",
            "execute_httpx",
            "execute_nuclei",
            "test_saml_sso",
            "compare_requests",
            "update_hypothesis",
            "log_engagement_approach",
            "submit_finding_candidate",
            "save_note",
        ],
        max_iterations=6,
        llm_task="recon",
        system_prompt_suffix=(
            "Confirm the tenant (*.okta.com, oktapreview, or a custom domain via "
            "/.well-known/okta-organization). GET /.well-known/openid-configuration and "
            "/oauth2/default/.well-known/oauth-authorization-server; note self-service "
            "registration and exposed client ids. POST /api/v1/authn with one "
            "nonexistent canary and one observed username only to read the enumeration "
            "posture; never a real password, never more than these two. "
            "A repeatable difference here is a lead: account_enumeration confirms only "
            "through scoped_account_enum_assigned on an operator-captured test account. "
            "Hand redirect_uri / SAML ACS issues to saml_sso via "
            "update_hypothesis. No password spraying, MFA fatigue or lockout testing; "
            "spraying belongs to credential_assault and only when the run grants "
            "credential testing."
        ),
    ),
    SpecialistProfile(
        name="sharepoint",
        role=(
            "SharePoint on-prem specialist. Fingerprint the farm build, anonymous "
            "_api/_vti_bin access, and ToolShell-class preconditions without exploit "
            "payloads."
        ),
        allowed_tools=[
            "execute_httpx",
            "execute_curl",
            "execute_nuclei",
            "fingerprint_passive_stack",
            "check_cve_applicability",
            "search_vulnx",
            "vulnx_query",
            "compare_requests",
            "update_hypothesis",
            "queue_finding_followups",
            "log_engagement_approach",
            "validate_finding",
            "submit_finding_candidate",
            "save_note",
        ],
        max_iterations=8,
        system_prompt_suffix=(
            "On-prem only: *.sharepoint.com is Microsoft SaaS, not this lane. Read the "
            "build from MicrosoftSharePointTeamServices / X-SharePointHealthScore "
            "headers and /_vti_pvt/service.cnf. Anonymous GET /_api/web, "
            "/_vti_bin/listdata.svc and /_layouts/15/viewlsts.aspx: list data returned "
            "to an anonymous GET is exposure (submit_finding_candidate("
            "vulnerability_class='exposure') with a response_match proof quoting the "
            "data; describe what is exposed, no CVE in the title). ToolShell "
            "(CVE-2025-53770/53771, CVE-2025-49704/49706): version-gate with "
            "check_cve_applicability and search_vulnx for KEV status; never POST to "
            "ToolPane.aspx, never send a spoofed SignOut Referer, no webshells. A build "
            "in range is a known_cve lead with no proof kind, capped low: "
            "submit_finding_candidate(vulnerability_class='known_cve') with the build "
            "evidence, or save_note."
        ),
    ),
    SpecialistProfile(
        name="enterprise_vpn",
        role=(
            "SSL VPN / remote-access appliance specialist (Cisco ASA, FortiGate, "
            "NetScaler, GlobalProtect, Ivanti, F5 BIG-IP, SonicWall). Fingerprint "
            "product and build, then gate on KEV-listed CVEs."
        ),
        allowed_tools=[
            "execute_httpx",
            "execute_curl",
            "execute_nuclei",
            "fingerprint_passive_stack",
            "check_cve_applicability",
            "lookup_component_vulns",
            "search_cve",
            "search_vulnx",
            "vulnx_query",
            "update_hypothesis",
            "queue_finding_followups",
            "log_engagement_approach",
            "submit_finding_candidate",
            "save_note",
        ],
        max_iterations=8,
        system_prompt_suffix=(
            "Fingerprint from portal paths and static assets: /+CSCOE+/logon.html "
            "(ASA), /remote/login (FortiGate), /vpn/index.html or /logon/LogonPoint "
            "(NetScaler), /global-protect/login.esp (GlobalProtect), /dana-na/ "
            "(Ivanti/Pulse), /my.policy or /tmui/ (F5), /cgi-bin/welcome (SonicWall). "
            "Get a build from version endpoints or asset hashes, not a guess. Only "
            "then check_cve_applicability and search_vulnx; prioritize CVEs that are "
            "KEV-listed and whose affected range includes the evidenced build. "
            "execute_nuclei -tags <product> -etags intrusive,dos, with -ni unless OOB "
            "is authorized. Never run exploit payloads (file read, auth bypass, RCE), "
            "never touch firmware or sessions, no credential attempts. A build in "
            "range is a known_cve lead with no proof kind, capped low: "
            "submit_finding_candidate(vulnerability_class='known_cve') with product, "
            "build evidence, CVE and KEV status, or save_note when no build is evidenced."
        ),
    ),
    SpecialistProfile(
        name="vcenter",
        role=(
            "VMware vCenter / Aria / Workspace ONE specialist. Fingerprint the "
            "management plane build and version-gate known unauthenticated CVE classes."
        ),
        allowed_tools=[
            "execute_httpx",
            "execute_curl",
            "execute_nuclei",
            "fingerprint_passive_stack",
            "check_cve_applicability",
            "lookup_component_vulns",
            "search_vulnx",
            "vulnx_query",
            "update_hypothesis",
            "queue_finding_followups",
            "log_engagement_approach",
            "submit_finding_candidate",
            "save_note",
        ],
        max_iterations=6,
        system_prompt_suffix=(
            "Build evidence: POST /sdk RetrieveServiceContent (read-only AboutInfo "
            "version and build), /ui and /websso banners, Workspace ONE /catalog-portal "
            "and /SAAS/auth. Then check_cve_applicability and search_vulnx for KEV "
            "status on the evidenced build. execute_nuclei -tags vmware,vcenter "
            "-etags intrusive,dos, with -ni unless OOB is authorized. Never upload "
            "files, never call plugin endpoints with payloads, never power, snapshot "
            "or migrate VMs, no default-credential attempts. A build in range is a "
            "known_cve lead with no proof kind, capped low: submit_finding_candidate("
            "vulnerability_class='known_cve') with the build evidence, or save_note."
        ),
    ),
    SpecialistProfile(
        name="spring_boot",
        role=(
            "Spring Boot specialist. Unauthenticated actuator/jolokia exposure and SpEL "
            "evaluation on a fingerprinted Spring stack."
        ),
        allowed_tools=[
            "get_parameter_inventory",
            "execute_httpx",
            "execute_curl",
            "execute_ffuf",
            "execute_nuclei",
            "scoped_injection_probe_assigned",
            "compare_requests",
            "sanitize_evidence",
            "record_surface_coverage",
            "update_hypothesis",
            "queue_finding_followups",
            "log_engagement_approach",
            "validate_finding",
            "submit_finding_candidate",
            "save_note",
        ],
        max_iterations=8,
        system_prompt_suffix=(
            "Confirm Spring (Whitelabel Error Page, X-Application-Context, /actuator). "
            "Anonymous GET /actuator, then env, configprops, mappings, beans, "
            "gateway/routes and jolokia (also under /manage or the context path). "
            "Sensitive data returned to an anonymous GET is exposure: "
            "submit_finding_candidate(vulnerability_class='exposure') with a "
            "response_match proof quoting a non-secret literal (a property name or "
            "route id); redact secret values. heapdump/threaddump: HEAD only, never "
            "download. Never POST shutdown, refresh, env, loggers or restart, never "
            "jolokia exec. SpEL: on leased ssti cells call "
            "scoped_injection_probe_assigned (dollar_brace / hash_brace recipes) and "
            "submit only on its receipt (vulnerability_class='ssti'). Spring4Shell and "
            "H2 console RCE are version-gated leads; do not exploit."
        ),
    ),
    SpecialistProfile(
        name="laravel",
        role=(
            "Laravel specialist. APP_DEBUG leakage, Telescope/Horizon/debugbar exposure "
            "and Ignition version gating on a fingerprinted Laravel stack."
        ),
        allowed_tools=[
            "execute_httpx",
            "execute_curl",
            "execute_ffuf",
            "execute_nuclei",
            "check_cve_applicability",
            "compare_requests",
            "sanitize_evidence",
            "record_surface_coverage",
            "update_hypothesis",
            "queue_finding_followups",
            "log_engagement_approach",
            "validate_finding",
            "submit_finding_candidate",
            "save_note",
        ],
        max_iterations=8,
        system_prompt_suffix=(
            "Confirm Laravel (laravel_session cookie, Ignition/Whoops error page, "
            "/_ignition/health-check). Anonymous GET /telescope/requests, "
            "/horizon/api/stats, /_debugbar/open, /.env and storage/logs: data returned "
            "to an anonymous GET is exposure (submit_finding_candidate("
            "vulnerability_class='exposure') with a response_match proof quoting a "
            "non-secret literal; redact APP_KEY, DB and mail secrets). APP_DEBUG: "
            "trigger one ordinary 404/405 and read the stack trace; env values in it "
            "are exposure under the same rule. Ignition CVE-2021-3129: version-gate "
            "only; never call /_ignition/execute-solution and never write to logs or "
            "phar files. Signed URL tampering is a lead unless a distinct-identity "
            "authorization proof exists."
        ),
    ),
    SpecialistProfile(
        name="nextjs",
        role=(
            "Next.js specialist. Middleware auth bypass, /_next/image SSRF, Server "
            "Action exposure and RSC/ISR leakage on a fingerprinted Next.js app."
        ),
        allowed_tools=[
            "list_captured_requests",
            "get_api_operation_inventory",
            "execute_httpx",
            "execute_curl",
            "execute_nuclei",
            "execute_interactsh",
            "compare_requests",
            "mutate_captured_request",
            "replay_http_request",
            "record_surface_coverage",
            "update_hypothesis",
            "log_engagement_approach",
            "validate_finding",
            "submit_finding_candidate",
            "save_note",
        ],
        max_iterations=8,
        system_prompt_suffix=(
            "Confirm Next.js (/_next/static, __NEXT_DATA__, x-nextjs-* headers) and "
            "read the version from the build manifest or nuclei -tags nextjs. "
            "Middleware bypass (CVE-2025-29927 class, version-gated): for a path that "
            "redirects anonymous users, compare_requests with x-middleware-subrequest "
            "set; submit (vulnerability_class='authorization') only with the "
            "authorization proof (verified identity baseline vs anonymous mutant on "
            "the same URL returning the owner's field); otherwise it is a lead. "
            "/_next/image?url=: only when this run authorizes OOB, "
            "run_oob_callback_workflow location='query' field='url'; a correlated "
            "callback is vulnerability_class='ssrf' with its oob_callback proof. "
            "Never point it at metadata or loopback. Server Actions: note Next-Action "
            "ids from captures and replay them without the UI's preconditions; a state "
            "change needs the state_change proof. RSC/__NEXT_DATA__ secrets are "
            "exposure only with a response_match proof."
        ),
    ),
    SpecialistProfile(
        name="aspnet_iis",
        role=(
            "ASP.NET / IIS specialist. elmah.axd/trace.axd exposure, ViewState MAC "
            "posture and NTLM challenge information leaks."
        ),
        allowed_tools=[
            "execute_httpx",
            "execute_curl",
            "execute_ffuf",
            "execute_nuclei",
            "compare_requests",
            "sanitize_evidence",
            "record_surface_coverage",
            "update_hypothesis",
            "queue_finding_followups",
            "log_engagement_approach",
            "validate_finding",
            "submit_finding_candidate",
            "save_note",
        ],
        max_iterations=6,
        system_prompt_suffix=(
            "Confirm ASP.NET/IIS (X-AspNet-Version, X-Powered-By: ASP.NET, .aspx/.axd, "
            "__VIEWSTATE). Anonymous GET /elmah.axd and /trace.axd (also under app "
            "virtual directories): logged requests or error details returned to an "
            "anonymous GET are exposure (submit_finding_candidate(vulnerability_class="
            "'exposure') with a response_match proof; redact cookies and auth headers). "
            "ViewState: decode __VIEWSTATE locally; an unsigned or unencrypted "
            "ViewState is a lead, never send a crafted ViewState or gadget. NTLM: one "
            "request with Authorization: NTLM and a Type 1 message to an auth endpoint "
            "(/autodiscover, /ews, /rpc, /_windows) and decode the Type 2 for NetBIOS/DNS "
            "domain and host; this is informational and goes in save_note. SharePoint "
            "farms belong to sharepoint; /api/Settings/SaveSettings belongs to api_authz."
        ),
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
            "record_surface_coverage",
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
            "Coverage / known-vuln specialist. Run bounded Nuclei coverage on the "
            "mapped live surface alongside logic hunts. If engagement credentials exist, prefer authenticated templates "
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
            "Source-only findings are not runtime-exploited: set "
            "verification_level='source_verified' (capped at medium until a runtime "
            "proof upgrades them). "
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
            "Risk assessor (Leo). Writes demonstrated-only risk assessments "
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
        epithet="Leo",
        llm_task="recon",
        system_prompt_suffix=(
            "You are Leo. Score the published packet only. Call "
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
            "scoped_string_sqli",
            "scoped_numeric_sqli",
            "compare_requests",
            "execute_curl",
            "execute_browser",
            "execute_interactsh",
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
            "Re-derive with your own recorded requests. Schema hints and errors are candidates only. "
            "Use fresh evidence_ids and structured proof; do not trust scanner labels. "
            "Call record_verify_verdict only; never create_finding or submit_finding_candidate."
        ),
    ),
    # Deep mode only (needs the explorer sandbox): open-ended testing with a
    # real shell for bugs the fixed-payload probes cannot reach.
    SpecialistProfile(
        name="explorer",
        role="Open-ended application tester with the isolated probe sandbox shell",
        allowed_tools=[
            "sandbox_shell",
            "read_evidence", "search_evidence", "list_test_identities",
            "submit_finding_candidate", "record_surface_coverage", "update_hypothesis",
        ],
        max_iterations=12,
        max_tools_per_iteration=3,
        system_prompt_suffix=(
            "You have sandbox_shell: bash with curl, python (requests/httpx/pyjwt), sqlmap, "
            "ffuf and nmap in an isolated runner. Its traffic reaches only this assessment's "
            "scoped hosts and every exchange is recorded as evidence. Work one hypothesis at "
            "a time: script the requests, vary the technique when one fails (encoding, content "
            "type, parameter location, method, identity, ordering), and chain what you learn. "
            "Prefer reproducible scripts over one-off commands. Submit a candidate only with "
            "cited exchange evidence_ids and a clear reproduction; verification decides what is "
            "published. Record coverage for what you ruled out, with evidence. If sandbox_shell "
            "is disabled, fall back to the scoped probe and replay tools."
        ),
    ),
]

# Lead-only probe and recon tools ported from Vanguard (tools_ported_probes.py),
# granted to the lanes that hunt their surface. The tools enforce scope, method
# policy and the active-testing gate themselves.
_PORTED_TOOL_GRANTS: dict[str, tuple[str, ...]] = {
    "grpc_api": ("probe_grpc_reflection",),
    "nodejs_express": ("probe_server_prototype_pollution",),
    "api_authz": ("probe_websocket_origin",),
    "graphql_api": ("probe_graphql",),
    "content_api": ("probe_vcs_exposure",),
    "secrets_hunter": ("probe_vcs_exposure",),
    "web_recon": ("fingerprint_gitlab", "detect_third_party_vendors", "query_mail_security"),
    "m365_entra": ("query_mail_security",),
    "okta_idp": ("query_mail_security",),
}
# Receipt-backed class proofs (tools_class_proofs.py), granted to the lanes the
# coverage catalog routes those cells to. Approvals and scope are enforced by
# the tools; a positive receipt is a candidate the verifier repeats.
_CLASS_PROOF_TOOL_GRANTS: dict[str, tuple[str, ...]] = {
    "file_upload": ("scoped_upload_probe_assigned",),
    "auth_logic": ("scoped_account_enum_assigned", "scoped_oauth_redirect_assigned"),
    "saml_sso": ("scoped_oauth_redirect_assigned",),
    "injection": ("scoped_server_pp_assigned",),
    "nodejs_express": ("scoped_server_pp_assigned",),
    "api_authz": ("scoped_cswsh_probe",),
    "agent_tools": ("scoped_llm_canary_assigned",),
}
for _profile in DEFAULT_SPECIALISTS:
    _extra = list(_PORTED_TOOL_GRANTS.get(_profile.name, ()))
    _extra.extend(_CLASS_PROOF_TOOL_GRANTS.get(_profile.name, ()))
    # Specialists that log approaches can also record what the WAF blocked.
    if "log_engagement_approach" in _profile.allowed_tools:
        _extra.append("record_defense_profile")
    # Workers claim and complete planned intents; only the main agent adds them.
    if "submit_finding_candidate" in _profile.allowed_tools:
        _extra.extend(("graph_overview", "record_fact", "claim_intent", "complete_intent"))
    # Lanes that compare live requests can also diff stored exchanges for free.
    if "compare_requests" in _profile.allowed_tools:
        _extra.append("diff_stored_exchanges")
    _profile.allowed_tools.extend(t for t in _extra if t not in _profile.allowed_tools)

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
    evidence_ids: list[str] = field(default_factory=list)
    started_at: float = 0.0  # wall clock when the tool was sent (after budget gates)


@dataclass
class SpecialistReport:
    specialist: str
    role: str
    mission: str
    summary: str                          # LLM-written narrative
    key_findings: list[str] = field(default_factory=list)
    tool_calls: list[ToolInvocation] = field(default_factory=list)
    duration_seconds: float = 0.0
    reported_spend_usd: float = 0.0
    error: Optional[str] = None
    verdict: str = ""                     # proven | killed | blocked | retry | inconclusive
    hypothesis_ids: list[str] = field(default_factory=list)
    evidence: str = ""
    spawn: list[str] = field(default_factory=list)
    rewrite_hint: str = ""
    hypothesis_results: list[dict] = field(default_factory=list)
    assigned_hypothesis_id: str = ""
    lease_id: str = ""
    coverage_cell_id: str = ""
    coverage_lease_id: str = ""
    # How the run ended: done (concluded on its own), exhausted (a turn, tool,
    # spend or time budget cut it off) or blocked (model or execution failure).
    stop_reason: str = ""
    # Where an exhausted run stopped and the next step, written during wrap-up
    # so a retry can continue instead of starting over.
    progress: str = ""
    # Out-of-lane endpoints a specialist saw but did not test (raw, unvalidated).
    leads: list[dict] = field(default_factory=list)


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
    report.hypothesis_results = [r for r in payload.get("hypothesis_results", []) if isinstance(r, dict)][:24]
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
    progress = payload.get("progress")
    if progress:
        report.progress = str(progress)[:800]
    leads = payload.get("leads") or []
    if isinstance(leads, list):
        report.leads = [
            {
                "method": str(row.get("method") or "GET")[:8].upper(),
                "url": str(row.get("url") or "")[:2048],
                "why": str(row.get("why") or "")[:300],
                "evidence_ids": [str(e) for e in (row.get("evidence_ids") or [])][:8],
            }
            for row in leads[:_MAX_LEADS]
            if isinstance(row, dict) and row.get("url")
        ]


_MAX_LEADS = 5


def _scaled_turns(turns: int) -> int:
    """Apply AGENT_SPECIALIST_TURN_MULTIPLIER and the assessment depth to a turn limit."""
    from app.core.config import settings

    from app.services.agent.assessment_depth import assessment_depth

    try:
        factor = float(getattr(settings, "AGENT_SPECIALIST_TURN_MULTIPLIER", 1.0) or 1.0)
    except (TypeError, ValueError):
        factor = 1.0
    depth = assessment_depth()
    factor = min(depth.specialist_turn_cap, max(0.5, factor * depth.specialist_turn_factor))
    return max(1, round(int(turns or 1) * factor))


_OPENING_BRAIN_CHARS = 6000
_OPENING_PEER_ROWS = 12


def _specialist_opening(tools_manager: Any, specialist: str) -> str:
    """First user turn for a specialist.

    Standard mode keeps the bare "Begin." so runs stay comparable. Deep mode
    hands the specialist what the team already knows (hypotheses, coverage,
    candidates, and recent peer results) so it does not rediscover the
    surface with a fraction of its budget. The text comes from the same
    engagement brain and peer board the orchestrator already trusts.
    """
    from app.services.agent.assessment_depth import assessment_depth

    if not assessment_depth().seed_specialist_context:
        return "Begin."
    parts: list[str] = []
    try:
        from app.services.agent.engagement_brain import format_engagement_brain_for_prompt

        brain = getattr(tools_manager, "_engagement_brain", None)
        if isinstance(brain, dict) and brain:
            text = format_engagement_brain_for_prompt(brain) or ""
            if text.strip():
                parts.append("## Shared engagement state\n" + text[:_OPENING_BRAIN_CHARS])
    except Exception:
        logger.debug("specialist brain seed skipped", exc_info=True)
    try:
        board = _peer_board(tools_manager)
        if board is not None:
            rows = board.recent(limit=_OPENING_PEER_ROWS, exclude=specialist)
            if rows:
                parts.append("## Recent teammate results (search_peer_traces for detail)\n"
                             + "\n".join(f"- {row}" for row in rows))
    except Exception:
        logger.debug("specialist peer seed skipped", exc_info=True)
    if not parts:
        return "Begin."
    return (
        "\n\n".join(parts)
        + "\n\nThis is a deep assessment: you have a large budget. Build on what the team "
        "already learned rather than repeating it. When a technique fails, vary it "
        "(encoding, content type, parameter location, HTTP method, identity) before "
        "concluding. Begin."
    )


def validated_leads(report: "SpecialistReport", scope_hosts: Iterable[str]) -> list[dict]:
    """Leads a specialist may hand off: in-scope and backed by its own evidence.

    A lead must cite evidence IDs from one of the specialist's own successful
    tool calls, so a model cannot invent an endpoint it never observed.
    """
    hosts = {str(h).lower().rstrip(".") for h in scope_hosts if h}
    owned = {
        eid for call in (report.tool_calls or []) if call.success
        for eid in (call.evidence_ids or [])
    }
    out = []
    for lead in report.leads or []:
        parsed = urlsplit(lead.get("url") or "")
        host = (parsed.hostname or "").lower().rstrip(".")
        evidence = [e for e in lead.get("evidence_ids") or [] if e in owned]
        if parsed.scheme not in ("http", "https") or host not in hosts or not evidence:
            continue
        if lead.get("method") not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            continue
        out.append({**lead, "evidence_ids": evidence})
    return out


# ---------------------------------------------------------------------------
# Mini ReAct loop per specialist
# ---------------------------------------------------------------------------


_STRICT_FINISH_RULE = "If unsure, finish with done=true."
_HUNT_FINISH_RULE = (
    "Before finishing with verdict=killed, try the bypasses that fit what you "
    "observed; one failed technique is inconclusive, not killed. Finish with "
    "done=true once the lead is proven, killed with evidence, or you are within "
    "two iterations of the limit."
)


def _specialist_finish_rule() -> str:
    from app.services.agent.prompts import hunt_discipline_enabled

    return _HUNT_FINISH_RULE if hunt_discipline_enabled() else _STRICT_FINISH_RULE


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
Use only the argument names shown above. Names with ? are optional. For execute_* tools that take args, pass one CLI argument string in {{"args": "..."}}.

PALACE / HUNT NOTES (compact — URL, param, hypothesis, next mutation):
{memory}

INSTRUCTIONS:
1. Obey the operation directive (goal, PASS/KILL, hypothesis ids).
2. Code-first: list_captured_requests → mutate_captured_request using sample_ref (one field) or run_custom_probe.
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
     "hypothesis_results": [{{"hypothesis_id": "one id", "verdict": "killed|blocked|inconclusive|retry", "evidence_ids": ["execution-owned evidence_id"], "evidence": "what this specific test established"}}],
     "evidence": "tool-backed proof only — quote tool output, never imagined",
     "spawn": ["optional specialist names to enqueue, e.g. graphql_api"],
     "rewrite_hint": "if retry: what to try differently",
     "leads": [{{"method": "GET", "url": "in-scope URL a tool result revealed", "why": "one line", "evidence_ids": ["evidence_id of that tool result"]}}]
   }}

   leads: endpoints outside your lane that a tool result revealed (a path in an
   error, a hidden API, a linked admin route). Do not test them; hand them off.
   A lead without your own evidence_id is dropped.

6. Medium+ findings: call validate_finding first; submit_finding_candidate only on SUBMIT.
   Write demonstrated-compromise reports (description + impact + assets + remediation),
   not 'login worked' or template-match-only.
7. Do not exceed {max_iter} iterations. {finish_rule}
8. Work only on the single leased hypothesis or exact parameter coverage cell in the directive. Return one hypothesis_results entry when a hypothesis ID is leased; sibling tests stay open. Pass hypothesis_id and coverage_cell_id to replay_http_request/compare_requests when available. A scoped_input_probe_assigned receipt belongs to its exact coverage cell and lease; a negative receipt for one technique is inconclusive for the whole input. Only independent verification marks proven.
9. Imagining tool output is a failure (soliloquy). If you did not call a tool, verdict=retry.
9. save_note(category='hunt') with URL/param/hypothesis/next mutation — not raw httpx.

{suffix}
"""


def _tool_contract(tools_manager: Any, tool_name: str) -> str:
    """Show specialists the actual registered argument names for a tool."""
    registry = getattr(tools_manager, "tools", None)
    tool = registry.get(tool_name) if isinstance(registry, dict) else None
    if not callable(tool):
        return f"  - {tool_name}"
    if tool_name == "execute_browser":
        # The adapter accepts an actions object and serializes it to the MCP
        # string itself. Asking the model to hand-escape JSON caused invalid
        # browser calls that never reached an assessment request.
        return (
            '  - execute_browser(actions=[{"action":"navigate","url":"..."},'
            '{"action":"get_source"}])'
        )
    if tool_name == "execute_curl":
        from aegis_praetorium.censor import curl_arg_contract

        return f"  - execute_curl(args: {curl_arg_contract()})"
    if getattr(tool, "__name__", "") == "execute_mcp_tool":
        return f"  - {tool_name}(args?)"
    try:
        parameters = inspect.signature(tool).parameters.values()
    except (TypeError, ValueError):
        return f"  - {tool_name}"
    names = []
    for parameter in parameters:
        if parameter.name == "self" or parameter.kind in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        ):
            continue
        optional = "?" if parameter.default is not inspect.Parameter.empty else ""
        names.append(f"{parameter.name}{optional}")
    return f"  - {tool_name}({', '.join(names)})"


# Peer trace search: specialists in one session can read what other specialists'
# tool calls returned (an error body, a hidden parameter, a token format) before
# re-probing. It is answered from memory here, never sent to the target, and is
# scoped to the session's tools manager so it cannot cross tenants.
PEER_SEARCH_TOOL = "search_peer_traces"
_PEER_SEARCH_MAX = 4
_PEER_BOARD_MAX = 400
_PEER_SUMMARY_CHARS = 1500
_PEER_RESULTS = 6
_PEER_CONTRACT = (
    f"  - {PEER_SEARCH_TOOL}(q?) — read-only search of other specialists' tool "
    "results in this engagement (keywords, all must match; empty q lists the "
    f"newest). No target traffic; at most {_PEER_SEARCH_MAX} per run and it does "
    "not use your tool budget. Use it before re-probing something a peer may "
    "already have seen."
)


class PeerTraceBoard:
    """Bounded, session-scoped record of specialist tool results."""

    def __init__(self) -> None:
        self._entries: list[dict] = []

    def record(self, run_key: str, specialist: str, results: Iterable[ToolInvocation]) -> None:
        for r in results:
            self._entries.append({
                "run": run_key,
                "specialist": specialist,
                "tool": r.tool,
                "args": json.dumps(r.args or {}, default=str)[:300],
                "success": bool(r.success),
                "summary": (r.summary or "")[:_PEER_SUMMARY_CHARS],
                "error": (r.error or "")[:300],
                "evidence_ids": list(r.evidence_ids or [])[:8],
            })
        if len(self._entries) > _PEER_BOARD_MAX:
            del self._entries[: len(self._entries) - _PEER_BOARD_MAX]

    def recent(self, *, limit: int, exclude: str = "") -> list[str]:
        """One-line summaries of the newest successful results from other specialists."""
        rows: list[str] = []
        for entry in reversed(self._entries):
            if len(rows) >= limit:
                break
            if entry["specialist"] == exclude or not entry["success"]:
                continue
            summary = " ".join((entry["summary"] or "").split())[:200]
            if summary:
                rows.append(f"{entry['specialist']} {entry['tool']}: {summary}")
        return rows

    def search(self, query: str, *, exclude_run: str) -> list[dict]:
        terms = [t for t in str(query or "").lower().split() if t][:8]
        hits = []
        for entry in reversed(self._entries):
            if entry["run"] == exclude_run:
                continue
            hay = " ".join((entry["tool"], entry["args"], entry["summary"], entry["error"])).lower()
            if terms and not all(t in hay for t in terms):
                continue
            text = entry["summary"] or entry["error"]
            at = text.lower().find(terms[0]) if terms else 0
            start = max(0, at - 200) if at >= 0 else 0
            hits.append({
                "specialist": entry["specialist"],
                "tool": entry["tool"],
                "args": entry["args"],
                "success": entry["success"],
                "excerpt": text[start:start + 600],
                "evidence_ids": entry["evidence_ids"],
            })
            if len(hits) >= _PEER_RESULTS:
                break
        return hits


def _peer_board(tools_manager: Any) -> Optional[PeerTraceBoard]:
    board = getattr(tools_manager, "_peer_trace_board", None)
    if isinstance(board, PeerTraceBoard):
        return board
    board = PeerTraceBoard()
    try:
        setattr(tools_manager, "_peer_trace_board", board)
    except Exception:
        return None
    return board


# Wrap-up after a budget stop: a few model turns with only write-back tools so a
# specialist cut off mid-hunt still records what it evidenced and where it
# stopped. Network probing tools are never offered here.
_WRAPUP_TOOLS = (
    "submit_finding_candidate",
    "record_surface_coverage",
    "save_note",
    "store_memory",
)
_WRAPUP_TURNS = 2
_WRAPUP_MAX_TOOL_CALLS = 3
_WRAPUP_RESERVE_SECONDS = 45.0

_WRAPUP_PROMPT = """\
BUDGET STOP ({reason}). Do not probe the target again.
Write back only what earlier tool results already evidence. Allowed now: {tools}.
Then respond with done=true and the usual summary contract, plus:
  "progress": "what you tested, where you stopped, and the exact next step to try"
Never claim a result that a tool output above does not show."""


async def _wrap_up_specialist(
    profile: SpecialistProfile,
    report: SpecialistReport,
    messages: list,
    *,
    llm: Any,
    tools_manager: Any,
    allowed_tools: list,
    exhausted_by: str,
    target_list: list,
    scope_target: str,
    budget: Optional["_SpecialistBudget"],
    directive: Optional[OperationDirective],
) -> None:
    """Give a budget-stopped specialist a bounded turn to save its leads."""
    write_back = [name for name in _WRAPUP_TOOLS if name in allowed_tools]
    stop_summary = report.summary
    calls_left = _WRAPUP_MAX_TOOL_CALLS
    messages.append(HumanMessage(content=_WRAPUP_PROMPT.format(
        reason=exhausted_by.replace("_", " "),
        tools=", ".join(write_back) or "none (summary only)",
    )))
    from app.services.agent.orchestrator import _ledger_llm_call

    for _turn in range(_WRAPUP_TURNS):
        try:
            response = await _ledger_llm_call(
                llm, messages, kind="agent_specialist_wrapup",
                target=target_list[0] if target_list else "",
                phase=profile.name,
            )
        except Exception as exc:
            logger.warning("fireteam %s: wrap-up LLM failure: %s", profile.name, exc)
            break
        if directive is not None and directive.max_spend_usd:
            from app.services.agent.observability import estimate_cost_usd, usage_from_llm_response

            usage = usage_from_llm_response(response)
            model = str(getattr(llm, "model_name", "") or getattr(llm, "model", "") or "")
            report.reported_spend_usd += estimate_cost_usd(
                model, usage["input_tokens"], usage["output_tokens"],
                usage.get("cache_read_tokens", 0), usage.get("cache_write_tokens", 0),
            )
        text = getattr(response, "content", "") or ""
        messages.append(AIMessage(content=text))
        payload = _extract_json(text)
        if not payload:
            break
        if payload.get("done"):
            summary = (payload.get("summary") or "").strip()
            if summary:
                report.summary = f"{stop_summary} {summary}".strip()
            kf = payload.get("key_findings") or []
            if isinstance(kf, list):
                report.key_findings = [str(x) for x in kf][:20]
            _fill_summary_contract(report, payload)
            break
        calls = [
            tc for tc in (payload.get("tool_calls") or [])
            if isinstance(tc, dict) and tc.get("tool") in write_back
        ][:calls_left]
        if not calls:
            messages.append(HumanMessage(
                content="Only the write-back tools listed above are allowed. Finish with done=true.",
            ))
            continue
        calls_left -= len(calls)
        results = await asyncio.gather(*(
            _safe_invoke(
                tools_manager, tc.get("tool", ""), tc.get("args") or {},
                scope_target=scope_target, budget=budget,
            )
            for tc in calls
        ))
        report.tool_calls.extend(results)
        messages.append(HumanMessage(content=json.dumps({
            "tool_results": [
                {"tool": r.tool, "success": r.success, "summary": r.summary[:2000], "error": r.error}
                for r in results
            ],
        })))
    # The wrap-up may restate a verdict, but a budget stop is never "done".
    if not report.verdict:
        report.verdict = "inconclusive"
    if not report.progress:
        last = [t.tool for t in report.tool_calls[-3:]]
        report.progress = f"Stopped by {exhausted_by.replace('_', ' ')}; last tools: {last}"


async def _run_specialist(
    profile: SpecialistProfile,
    mission: str,
    targets: Iterable[str],
    llm: Any,
    tools_manager: Any,
    directive: Any = None,
    execution_progress: Optional[Dict[str, Any]] = None,
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
    from app.services.agent.proof_policy import PROOF_GUIDANCE
    suffix_parts.append(PROOF_GUIDANCE)
    from app.services.agent.prompts import APPLICATION_ASSESSMENT_GUIDANCE
    suffix_parts.append(APPLICATION_ASSESSMENT_GUIDANCE)
    from app.services.agent.prompts import HUNT_DISCIPLINE_GUIDANCE, hunt_discipline_enabled
    if hunt_discipline_enabled():
        suffix_parts.append(HUNT_DISCIPLINE_GUIDANCE)
    from app.services.agent.prompts import self_challenge_guidance

    if self_challenge_guidance():
        suffix_parts.append(self_challenge_guidance())
    if not getattr(tools_manager, "_credential_testing_allowed", False):
        suffix_parts.append(
            "This run has no operator authorization for credential guessing, default "
            "login attempts, password spraying, or brute force. Use only supplied "
            "test identities for auth comparisons."
        )
    if not getattr(tools_manager, "_oob_callbacks_allowed", False):
        suffix_parts.append(
            "This run has no operator authorization for out-of-band or third-party "
            "callbacks. Do not register callback services or embed callback URLs."
        )
    suffix = "\n\n".join(suffix_parts)

    if isinstance(directive, OperationDirective):
        directive_block = directive.to_prompt_block()
        mission_for_prompt = merge_directive_into_mission(mission, None)  # directive shown separately
        max_iter = directive.max_iterations or profile.max_iterations
        if directive.hypothesis_ids and not report.hypothesis_ids:
            report.hypothesis_ids = list(directive.hypothesis_ids)
        if len(directive.hypothesis_ids) == 1:
            report.assigned_hypothesis_id = directive.hypothesis_ids[0]
        report.lease_id = directive.lease_id
        report.coverage_cell_id = directive.coverage_cell_id
        report.coverage_lease_id = directive.coverage_lease_id
    else:
        directive_block = (
            f"Goal: execute your role ({profile.epithet}) against the shared mission.\n"
            f"PASS: demonstrated impact with evidence.\n"
            f"KILL: no impact after disciplined probes."
        )
        mission_for_prompt = mission
        max_iter = profile.max_iterations
    max_iter = _scaled_turns(max_iter)

    allowed_tools = list(profile.allowed_tools)
    if not getattr(tools_manager, "_oob_callbacks_allowed", False):
        allowed_tools = [
            tool for tool in allowed_tools
            if tool not in {"execute_interactsh", "run_oob_callback_workflow"}
        ]
    if (isinstance(directive, OperationDirective)
            and directive.parameter_work
            and not directive.parameter_work.get("scoped_capture_id")):
        allowed_tools = [
            tool for tool in allowed_tools
            if tool not in {"scoped_assessment_probe_assigned", "scoped_assessment_candidate"}
        ]
    allowed_tools.extend(
        t for t in ("read_evidence", "search_evidence", "list_test_identities") if t not in allowed_tools
    )
    if profile.name in ("auth_logic", "independent_verifier", "api_logic", "coverage"):
        allowed_tools.extend(
            t
            for t in (
                "generate_authorization_matrix",
                "run_authorization_proof",
                "get_assessment_coverage",
                "map_application_traffic",
                "list_proof_captures",
                "list_authorization_leads",
                "prepare_captured_authorization_proof",
            )
            if t not in allowed_tools
        )
    if "execute_interactsh" in allowed_tools and "run_oob_callback_workflow" not in allowed_tools:
        allowed_tools.append("run_oob_callback_workflow")
    if "compare_requests" in allowed_tools:
        allowed_tools.extend(t for t in ("check_test_identity", "test_authorization_boundary", "run_assessment_workflow") if t not in allowed_tools)
    if "search_memory" not in allowed_tools:
        allowed_tools.append("search_memory")
    from app.services.agent.custom_probe import custom_probe_mode

    if custom_probe_mode() == "off":
        # Model-written Python only runs in the isolated probe runner; keep
        # specialists from spending turns on a disabled tool.
        allowed_tools = [name for name in allowed_tools
                         if name not in ("run_custom_probe", "run_poc_python")]
    from app.core.config import settings as _settings

    if (custom_probe_mode() == "isolated" and getattr(_settings, "AGENT_SANDBOX_SHELL", False)
            and "run_custom_probe" in allowed_tools and "sandbox_shell" not in allowed_tools):
        allowed_tools.append("sandbox_shell")
    from app.services.agent.pilot_policy import current_pilot

    pilot = current_pilot()
    if pilot is not None:
        # A verifier spawned by a pilot must inherit the same tool boundary.
        # The manager also enforces this at execution time, but filtering here
        # keeps the fresh verifier from wasting turns on denied tools.
        allowed_tools = [name for name in allowed_tools if name in pilot.allowed_tools]
        suffix += (
            "\n\nBounded pilot: only anonymous GET/HEAD on the exact HTTPS origin "
            "and port. Every network request needs analyst approval and uses "
            "the shared request budget. Use only the listed tools."
        )

    memory_block = "None."
    org_id = None
    session_id = None
    try:
        from app.services.agent.hunter_brief import OOB_SPECIALISTS, format_hunter_brief
        from app.services.agent.palace_memory import wake_up as palace_wake_up
        from app.services.agent.tools import current_session_id, get_tenant_context

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
            provision_oob=(profile.name in OOB_SPECIALISTS
                           and bool(getattr(tools_manager, "_oob_callbacks_allowed", False))),
        )
    except Exception:
        logger.debug("specialist hunt-brief skipped", exc_info=True)

    # Bounded pilots keep their exact tool list; everyone else may read peers.
    peer_board = _peer_board(tools_manager) if pilot is None else None
    run_key = uuid.uuid4().hex
    peer_searches_left = _PEER_SEARCH_MAX

    sys_prompt = _SPECIALIST_SYSTEM_PROMPT.format(
        epithet=profile.epithet or profile.name,
        role=profile.role,
        directive=directive_block,
        mission=mission_for_prompt,
        targets=", ".join(target_list) or "<see analyze_attack_surface output>",
        tool_list="\n".join(
            [_tool_contract(tools_manager, t) for t in allowed_tools]
            + ([_PEER_CONTRACT] if peer_board is not None else [])
        ),
        memory=memory_block,
        max_iter=max_iter,
        finish_rule=_specialist_finish_rule(),
        suffix=suffix,
    )

    messages: list = [SystemMessage(content=sys_prompt)]
    messages.append(HumanMessage(content=_specialist_opening(tools_manager, profile.name)))

    iteration = 0
    max_tool_calls = directive.max_tool_calls if isinstance(directive, OperationDirective) else 0
    budget = _SpecialistBudget(directive) if isinstance(directive, OperationDirective) else None
    from app.services.agent.autonomy_limits import current_autonomy_limits
    strict_scope = bool(current_autonomy_limits.get())
    scope_target = (
        directive.target if isinstance(directive, OperationDirective) else
        target_list[0] if target_list else ""
    ) if strict_scope else ""
    # Stop exploring early enough that the wrap-up turn finishes before the
    # caller's hard timeout cancels this task and discards its leads.
    soft_deadline = 0.0
    if isinstance(directive, OperationDirective) and directive.max_seconds:
        seconds = float(directive.max_seconds)
        soft_deadline = time.monotonic() + seconds - min(_WRAPUP_RESERVE_SECONDS, seconds * 0.2)
    exhausted_by = ""
    while iteration < max_iter:
        if budget and directive.max_spend_usd and report.reported_spend_usd >= directive.max_spend_usd:
            report.verdict = "inconclusive"
            report.rewrite_hint = "specialist reported spend budget exhausted"
            report.summary = "Stopped at the specialist reported spend threshold."
            exhausted_by = "spend"
            break
        if max_tool_calls and len(report.tool_calls) >= max_tool_calls:
            report.verdict = "inconclusive"
            report.rewrite_hint = "specialist tool budget exhausted"
            report.summary = f"Stopped after {max_tool_calls} tool calls; remaining checks are open."
            exhausted_by = "tool_budget"
            break
        if soft_deadline and iteration and time.monotonic() >= soft_deadline:
            report.verdict = "inconclusive"
            report.rewrite_hint = "specialist time budget exhausted"
            report.summary = "Stopped near the specialist time limit; remaining checks are open."
            exhausted_by = "time"
            break
        iteration += 1
        try:
            from app.services.agent.orchestrator import _ledger_llm_call

            response = await _ledger_llm_call(
                llm, messages, kind="agent_specialist_model",
                target=target_list[0] if target_list else "",
                phase=profile.name,
            )
            if budget and directive.max_spend_usd:
                from app.services.agent.observability import estimate_cost_usd, usage_from_llm_response
                usage = usage_from_llm_response(response)
                model = str(getattr(llm, "model_name", "") or getattr(llm, "model", "") or "")
                report.reported_spend_usd += estimate_cost_usd(
                    model, usage["input_tokens"], usage["output_tokens"],
                usage.get("cache_read_tokens", 0), usage.get("cache_write_tokens", 0),
                )
                if report.reported_spend_usd >= directive.max_spend_usd:
                    report.verdict = "inconclusive"
                    report.rewrite_hint = "specialist reported spend budget exhausted"
                    report.summary = "Stopped after the model call reached the reported spend threshold."
                    exhausted_by = "spend"
                    break
        except Exception as exc:
            logger.warning("fireteam %s: LLM failure: %s", profile.name, exc)
            report.error = f"LLM error: {exc}"
            report.stop_reason = "blocked"
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

        # Peer searches are answered locally and do not use the tool budget.
        peer_results = []
        if peer_board is not None:
            for tc in tool_calls:
                if not isinstance(tc, dict) or tc.get("tool") != PEER_SEARCH_TOOL:
                    continue
                if peer_searches_left <= 0:
                    peer_results.append({"tool": PEER_SEARCH_TOOL, "error": "peer search limit reached"})
                    continue
                peer_searches_left -= 1
                query = str((tc.get("args") or {}).get("q") or "")[:200]
                peer_results.append({
                    "tool": PEER_SEARCH_TOOL, "q": query,
                    "matches": peer_board.search(query, exclude_run=run_key),
                })

        # Enforce allowlist + max parallelism per turn.
        tool_calls = [tc for tc in tool_calls if tc.get("tool") in allowed_tools][: profile.max_tools_per_iteration]
        if budget and directive.max_parallel_tool_calls:
            tool_calls = tool_calls[:directive.max_parallel_tool_calls]
        if max_tool_calls:
            tool_calls = tool_calls[:max_tool_calls - len(report.tool_calls)]

        if not tool_calls:
            if peer_results:
                messages.append(HumanMessage(content=json.dumps({"peer_results": peer_results})))
                continue
            messages.append(HumanMessage(
                content="None of the tools you requested are allowed. "
                        "Pick from the allowlist or finish with done=true."
            ))
            continue

        if execution_progress is not None:
            # Cancellation while a tool is in flight may leave an unknown
            # effect. Completed batches are safe to resume from the ledger.
            execution_progress["tool_inflight"] = True
        tool_results = await asyncio.gather(*(
            _safe_invoke(
                tools_manager, tc.get("tool", ""), tc.get("args") or {},
                scope_target=scope_target,
                budget=budget,
            )
            for tc in tool_calls
        ))
        if execution_progress is not None:
            execution_progress["tool_inflight"] = False
            execution_progress["completed_calls"].extend(tool_results)

        for tc, tr in zip(tool_calls, tool_results):
            report.tool_calls.append(tr)
        if peer_board is not None:
            peer_board.record(run_key, profile.name, tool_results)

        feedback = {
            "tool_results": [
                {
                    "tool": tr.tool,
                    "success": tr.success,
                    "summary": tr.summary[:6000],
                    "evidence_ids": tr.evidence_ids,
                    "error": tr.error,
                }
                for tr in tool_results
            ],
        }
        if peer_results:
            feedback["peer_results"] = peer_results
        messages.append(HumanMessage(content=json.dumps(feedback)))
    else:
        # The loop condition ended the run: the turn budget ran out.
        exhausted_by = "iterations"

    if exhausted_by:
        report.stop_reason = "exhausted"
        if exhausted_by != "spend":
            # A spend stop gets no further model call; every other budget stop
            # gets a bounded wrap-up so evidenced leads are written back.
            await _wrap_up_specialist(
                profile, report, messages, llm=llm, tools_manager=tools_manager,
                allowed_tools=allowed_tools, exhausted_by=exhausted_by,
                target_list=target_list, scope_target=scope_target, budget=budget,
                directive=directive if isinstance(directive, OperationDirective) else None,
            )
    elif not report.stop_reason:
        report.stop_reason = "done"

    report.duration_seconds = (datetime.utcnow() - start).total_seconds()
    if not report.summary and not report.error:
        report.summary = (
            f"{profile.name} exhausted {max_iter} iterations without "
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


def _out_of_scope_url(args: dict, target: str) -> str:
    """Reject an explicit cross-host URL before a scheduled specialist tool call."""
    allowed = urlsplit(target if "://" in target else f"https://{target}").hostname
    if not allowed:
        return "invalid specialist target"
    # The existing assessment scope checks resolved destinations; this catches
    # a specialist's explicit URL argument before any tool is invoked.
    for candidate in re.findall(r'https?://[^\s"\'<>},]+', json.dumps(args or {})):
        host = urlsplit(candidate.rstrip(".)")).hostname
        if host and host.lower().rstrip(".") != allowed.lower().rstrip("."):
            return host
    return ""


def _requested_identities(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"identity", "identity_a", "identity_b", "requester_identity", "actor_identity"} and isinstance(item, str):
                found.add(item)
            else:
                found.update(_requested_identities(item))
    elif isinstance(value, list):
        for item in value:
            found.update(_requested_identities(item))
    return found


def _action_kind(tool_name: str, args: dict) -> str:
    if (tool_name.startswith(("get_", "list_", "query_", "read_", "search_"))
            or tool_name in {"execute_dnsx", "execute_httpx", "execute_whatweb", "execute_wafw00f"}):
        return "read"
    if tool_name in {"mutate_captured_request", "run_intruder_batch", "execute_hydra", "execute_brutus", "test_credential_spray"}:
        return "state_change"
    if tool_name in {"execute_browser", "execute_curl", "replay_http_request", "run_assessment_workflow"}:
        blob = json.dumps(args or {}).lower()
        if any(token in blob for token in ('"post"', '"put"', '"patch"', '"delete"', "-x post", "-x put", "-x delete", '"click"', '"fill"', '"submit"')):
            return "state_change"
    return "probe"


class _SpecialistBudget:
    def __init__(self, directive: OperationDirective):
        self.directive = directive
        self.count = 0
        self.next_at = 0.0
        self.lock = asyncio.Lock()

    async def acquire(self, tool_name: str, args: dict) -> str:
        directive = self.directive
        # An empty directive means the ordinary engagement policy applies.
        # Scheduled limits fill this list explicitly; without them, read and
        # probe calls must remain available while state changes stay gated.
        allowed_actions = set(directive.allowed_actions or ("read", "probe"))
        if _action_kind(tool_name, args) not in allowed_actions:
            return "specialist_action_denied"
        if (directive.allowed_identities
                and _requested_identities(args) - set(directive.allowed_identities)):
            return "specialist_identity_denied"
        if directive.allowed_hosts:
            for host in re.findall(r'https?://[^\s"\'<>},]+', json.dumps(args or {})):
                parsed = urlsplit(host.rstrip(".)"))
                if parsed.hostname and not any(
                    parsed.hostname.lower().rstrip(".") == allowed.lower().rstrip(".")
                    or (allowed.startswith("*.") and parsed.hostname.lower().rstrip(".").endswith(allowed[1:].lower()))
                    for allowed in directive.allowed_hosts
                ):
                    return "specialist_scope_denied"
        async with self.lock:
            if directive.max_requests and self.count >= directive.max_requests:
                return "specialist_request_budget_exhausted"
            delay = self.next_at - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)
            self.count += 1
            self.next_at = time.monotonic() + max(0, directive.interval_ms) / 1000
        return ""


async def _safe_invoke(
    tools_manager: Any, tool_name: str, args: dict, *, scope_target: str = "",
    budget: _SpecialistBudget | None = None,
) -> ToolInvocation:
    def denied_receipt(code: str) -> ToolInvocation:
        from app.services.agent.action_ledger import active_run_id, append_action

        append_action(
            active_run_id.get(), uuid.uuid4().hex, "skipped", tool_name,
            target=scope_target or (budget.directive.target if budget else ""),
            phase=budget.directive.specialist if budget else "specialist",
            detail=code,
        )
        return ToolInvocation(
            tool=tool_name, args=args or {}, success=False,
            summary=f"Specialist contract denied: {code}", error=code,
        )

    if scope_target:
        denied = _out_of_scope_url(args, scope_target)
        if denied:
            return denied_receipt("specialist_scope_denied")
    if budget:
        denied = await budget.acquire(tool_name, args)
        if denied:
            return denied_receipt(denied)
    started_at = time.time()
    try:
        result = await tools_manager.execute(tool_name, args or {})
        success = bool(result.get("success"))
        summary = _stringify_tool_result(result)
        if result.get("evidence_ids"):
            summary = json.dumps({"evidence_ids": result["evidence_ids"]}) + "\n" + summary
        import re

        from app.services.agent.evidence_store import evidence_store
        # Only transport-owned records for this invocation's explicit hypothesis.
        ids = re.findall(r'"evidence_id"\s*:\s*"([a-f0-9]+)"', summary)
        store = evidence_store(tools_manager)
        ids = [i for i in ids if i in store.records and store.records[i]["kind"] == "http_exchange"
               and store.records[i]["hypothesis_id"] == (args or {}).get("hypothesis_id", "")
               and store.records[i]["payload"].get("response", {}).get("status", 500) < 500]
        if success and tool_name == "scoped_input_probe_assigned":
            # This tool receives a leased coverage cell, rather than a
            # hypothesis ID. Its proof artifact is attached to that cell by
            # the executor. Keep the receipt available to the specialist only
            # when the returned cell and lease match this invocation.
            output = result.get("output")
            if (isinstance(output, dict) and output.get("success") is True
                    and output.get("coverage_cell_id") == args.get("coverage_cell_id")
                    and output.get("coverage_lease_id") == args.get("coverage_lease_id")
                    and args.get("coverage_cell_id") and args.get("coverage_lease_id")):
                receipt_id = str(output.get("evidence_id") or "")
                record = store.records.get(receipt_id)
                from app.services.agent.engagement_brain import engagement_brain_from_dict

                brain = engagement_brain_from_dict(getattr(tools_manager, "_engagement_brain", None))
                cell = next((row for row in brain.coverage_cells
                             if row.get("id") == args["coverage_cell_id"]), None)
                if (record and record.get("kind") in {
                        "scoped_numeric_sqli", "scoped_string_sqli", "scoped_browser_check_xss",
                        "scoped_browser_check_form_xss",
                    } and cell and cell.get("lease_id") == args["coverage_lease_id"]
                        and receipt_id in (cell.get("probe_artifact_ids") or [])):
                    ids = list(dict.fromkeys([*ids, receipt_id]))
        if result.get("artifact_id"):
            summary = f"artifact_id={result['artifact_id']} (read_evidence for full output)\n" + summary
        # Specialist LLMs read the same redacted/fenced view as the lead agent.
        from app.services.agent.content_shield import shield_tool_output

        summary, _shield = shield_tool_output(tool_name, summary)
        return ToolInvocation(
            tool=tool_name,
            args=args or {},
            success=success,
            summary=summary,
            error=result.get("error") if not success else None,
            evidence_ids=ids,
            started_at=started_at,
        )
    except Exception as exc:
        return ToolInvocation(
            tool=tool_name,
            args=args or {},
            success=False,
            summary=f"invocation raised {type(exc).__name__}: {exc}",
            error=str(exc),
            started_at=started_at,
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
    report_callback: Optional[Callable[[SpecialistReport], Awaitable[None]]] = None,
    directives: Optional[Dict[str, Any]] = None,
    llm_for_specialist: Optional[Callable[[SpecialistProfile], Any]] = None,
    member_timeout_sec: float = 600.0,
    wave_timeout_sec: float = 1200.0,
) -> FireteamResult:
    """Run a bounded fireteam and return completed and interrupted receipts.

    ``specialists`` may contain either string names from :data:`DEFAULT_SPECIALISTS`
    or fully custom :class:`SpecialistProfile` instances (for ad-hoc missions).
    ``directives`` maps specialist name → OperationDirective (optional).
    ``report_callback`` receives each completed member before the whole wave ends.
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

    def _interrupted_report(
        p: SpecialistProfile, reason: str, *, execution_progress: Dict[str, Any]
    ) -> SpecialistReport:
        directive = directives.get(p.name)
        hypothesis_ids = list(getattr(directive, "hypothesis_ids", None) or [])
        return SpecialistReport(
            specialist=p.name,
            role=f"{p.epithet}: {p.role}",
            mission=mission,
            summary=(f"Execution interrupted: {reason}. "
                     + ("Reconcile the in-flight tool before retrying."
                        if execution_progress["tool_inflight"] else
                        "No tool call is in flight; the task can be retried.")),
            error=reason,
            verdict="blocked" if execution_progress["tool_inflight"] else "retry",
            rewrite_hint=("execution_timeout" if execution_progress["tool_inflight"]
                          else "execution_timeout_no_inflight_tool"),
            tool_calls=list(execution_progress["completed_calls"]),
            # A cancelled in-flight tool has an unknown effect; otherwise the
            # run simply ran out of wall-clock time.
            stop_reason="blocked" if execution_progress["tool_inflight"] else "exhausted",
            hypothesis_ids=hypothesis_ids,
            assigned_hypothesis_id=hypothesis_ids[0] if len(hypothesis_ids) == 1 else "",
            lease_id=str(getattr(directive, "lease_id", "") or ""),
        )

    async def _run(p: SpecialistProfile, execution_progress: Dict[str, Any]) -> SpecialistReport:
        async with sem:
            from app.services.agent.action_ledger import active_run_id, append_action

            action_id = uuid.uuid4().hex
            run_id = active_run_id.get()
            append_action(run_id, action_id, "started", f"specialist:{p.name}",
                          target=targets_list[0] if targets_list else "")
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
            member_task = asyncio.create_task(_run_specialist(
                p,
                mission,
                targets_list,
                spec_llm,
                tools_manager,
                directive=directives.get(p.name),
                execution_progress=execution_progress,
            ))
            try:
                directive = directives.get(p.name)
                member_cap = min(
                    member_timeout_sec,
                    float(getattr(directive, "max_seconds", 0) or member_timeout_sec),
                )
                done, _ = await asyncio.wait(
                    {member_task}, timeout=max(0.01, member_cap)
                )
                if done:
                    rep = member_task.result()
                else:
                    member_task.cancel()
                    member_task.add_done_callback(_log_late_failure)
                    rep = _interrupted_report(
                        p, f"specialist timed out after {member_cap:g}s",
                        execution_progress=execution_progress,
                    )
            except asyncio.CancelledError:
                member_task.cancel()
                member_task.add_done_callback(_log_late_failure)
                append_action(run_id, action_id, "interrupted", f"specialist:{p.name}",
                              target=targets_list[0] if targets_list else "",
                              detail="specialist cancelled")
                raise
            except Exception as exc:
                logger.exception("Fireteam specialist %s failed", p.name)
                rep = _interrupted_report(
                    p, f"specialist failed: {exc}",
                    execution_progress=execution_progress,
                )
            if progress_callback:
                try:
                    await progress_callback(label, "error" if rep.error else "done")
                except Exception:
                    pass
            append_action(
                run_id, action_id,
                "interrupted" if rep.rewrite_hint.startswith("execution_timeout") else
                "failed" if rep.error else "completed",
                f"specialist:{p.name}", target=targets_list[0] if targets_list else "",
                detail=rep.error or rep.verdict or "",
            )
            if report_callback and not rep.error:
                try:
                    await report_callback(rep)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception("Fireteam report callback failed for %s", p.name)
            return rep

    def _log_late_failure(task: asyncio.Task) -> None:
        if task.cancelled():
            return
        try:
            task.result()
        except Exception:
            logger.exception("Fireteam task failed after its deadline")

    execution_progress = [{"tool_inflight": False, "completed_calls": []}
                          for _ in resolved]
    tasks = [asyncio.create_task(_run(p, progress))
             for p, progress in zip(resolved, execution_progress)]
    try:
        _, pending = await asyncio.wait(
            tasks, timeout=max(0.01, wave_timeout_sec)
        )
    except BaseException:
        for task in tasks:
            task.cancel()
            task.add_done_callback(_log_late_failure)
        raise
    for task in pending:
        task.cancel()
        task.add_done_callback(_log_late_failure)

    reports = []
    for profile, task, progress in zip(resolved, tasks, execution_progress):
        if task in pending:
            reports.append(_interrupted_report(
                profile, f"fireteam wave timed out after {wave_timeout_sec:g}s",
                execution_progress=progress,
            ))
            if progress_callback:
                try:
                    label = f"{profile.epithet} ({profile.name})" if profile.epithet else profile.name
                    await progress_callback(label, "timeout")
                except Exception:
                    pass
        else:
            try:
                reports.append(task.result())
            except BaseException as exc:
                reports.append(_interrupted_report(
                    profile, f"specialist failed: {exc}",
                    execution_progress=progress,
                ))

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
