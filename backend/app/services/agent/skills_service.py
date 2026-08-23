"""
Agent Skills + ``/skill`` chat prefix routing.

A "skill" is a named, bounded workflow the agent knows how to run:

    * ``threat-model`` - Durable threat model from a URL crawl or local checkout
    * ``code-scan``    - White-box: threat-model the checkout then SAST
    * ``external-assessment`` - Full tester-methodology external engagement
    * ``tester-process`` - Hypothesis queue + compare_requests + specialist fireteam
    * ``web-recon``    - subdomain + HTTP + tech fingerprint
    * ``vuln-scan``    - Nuclei critical/high on known assets
    * ``js-recon``     - JS bundle deep dive for secrets / maps / DOM sinks
    * ``graphql``      - Discover & audit GraphQL endpoints
    * ``takeover``     - Subdomain takeover sweep
    * ``secrets``      - TruffleHog verified secret scan
    * ``llm-redteam``  - LLM / chatbot red-team
    * ``surface-ranking`` - Rank recon results by testing value
    * ``api-authz-validation`` - Prove API authz gaps with minimal requests
    * ``idor-validation`` - Validate BOLA / IDOR with response comparison
    * ``dual-identity-authz`` - Anonymous / A / B authz matrix
    * ``host-tenant-bypass`` - Host-header tenant isolation differentials
    * ``nextjs-stack`` / ``springboot-stack`` / ``laravel-stack`` - Tech-conditional hunts
    * ``spa-api-discovery`` - Hidden APIs from JS bundles
    * ``api-test``     - Interceptor → lazy chunks ∥ fingerprint → JS endpoints
    * ``jshero``       - Exhaustive first-party JS collection + extract + sinks
    * ``wordpress``    - REST user enum + admin-ajax tax_query timing (WPScan optional)
    * ``evidence-hygiene`` - Redact sensitive evidence before reporting

In chat, the user can invoke any skill with::

    /skill external-assessment target=acme.com

If no ``/skill`` prefix is used, :func:`route_by_intent` asks a small LLM
to pick the most relevant skill from the registry.
"""

from __future__ import annotations

import json
import logging
import re
import shlex
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

logger = logging.getLogger(__name__)


@dataclass
class Skill:
    id: str
    aliases: list[str]
    title: str
    description: str
    scan_type: Optional[str] = None
    playbook_id: Optional[str] = None
    default_args: dict = field(default_factory=dict)
    system_context: str = ""
    required_inputs: list[str] = field(default_factory=lambda: ["target"])


SKILLS: list[Skill] = [
    Skill(
        id="threat-model",
        aliases=["threatmodel", "threat_model", "tm", "aim"],
        title="Threat model",
        description=(
            "Build a durable threat model from a URL (after crawl) or a local checkout. "
            "Aims hunters and calibrates severity; does not itself prove bugs."
        ),
        playbook_id="threat_model",
        system_context=(
            "You are running the THREAT-MODEL skill. Produce the map, not findings. "
            "URL: observe (interceptor/deep_crawl) then build_threat_model(source='map' or 'url'). "
            "Code: build_threat_model(source='code', repo_path=...) — do not execute target code. "
            "Describe shapes, not CWE checklists. If an owner is in the session, ask what "
            "assets/actors matter and update_threat_model. sync_engagement_brain so later "
            "fireteams consume ranked threats + focus areas. save_note the markdown artifact. "
            "Do not spray Nuclei."
        ),
    ),
    Skill(
        id="code-scan",
        aliases=["code-assessment", "sast", "whitebox", "source-scan", "ccsec"],
        title="Code assessment (threat-model → SAST)",
        description=(
            "White-box scan: threat-model the checkout, hunt instantiations of those "
            "threats with Semgrep/Gitleaks/Trivy, verify adversarially."
        ),
        playbook_id="code_assessment",
        required_inputs=["repo_path"],
        system_context=(
            "You are running the CODE-SCAN skill. "
            "1) build_threat_model(source='code', repo_path=...). "
            "2) Hunt shapes from the model with execute_semgrep / execute_gitleaks / "
            "execute_trivy — not a named-bug checklist. "
            "3) fireteam_dispatch(specialists='auto') so code_sast hunts (independent_verify is the second wave). "
            "4) submit_finding_candidate then independent_verify; create_finding only when a threat row is instantiated "
            "and reachable. Do not execute target binaries."
        ),
    ),
    Skill(
        id="external-assessment",
        aliases=["external", "pentest-recon", "full-assessment", "tester", "engagement"],
        title="External assessment (tester methodology)",
        description=(
            "Coordinated external engagement: passive recon → ports/TLS → content/API/JS "
            "enum → ranked targeted testing → evidence-backed findings."
        ),
        playbook_id="external_assessment",
        system_context=(
            "You are running the EXTERNAL-ASSESSMENT skill — behave like an experienced "
            "external penetration tester, not a tool sprayer. Work in phases (scope → "
            "passive discovery → ports/TLS → crawl/API/JS → rank → targeted tests → "
            "confirm/report). Call auto_select_tools after each discovery wave. Use "
            "create_scan for bulk platform work (graphql_scan, subdomain_takeover, "
            "js_recon, jsluice_scan, vulnerability, katana, waybackurls, paramspider) and "
            "execute_* for interactive follow-up. Branch on evidence (GraphQL, SPA, CMS, "
            "chatbot, dangling DNS). Every create_finding needs concrete evidence and "
            "validate_finding first for medium+. Do not complete after Nuclei alone."
        ),
    ),
    Skill(
        id="tester-process",
        aliases=[
            "tester",
            "hypothesis",
            "engagement-brain",
            "logic-bugs",
            "compare-requests",
        ],
        title="Tester process (hypotheses + differentials)",
        description=(
            "Orchestrator loop: crawl observations → methodology cards (CWE/CAPEC) → "
            "specialist fireteam → compare_requests proof → chain follow-ups → coverage."
        ),
        playbook_id="tester_process",
        system_context=(
            "You are running the TESTER-PROCESS skill. "
            "1) execute_deep_crawl on the primary web target. "
            "2) sync_engagement_brain to seed a threat model + observation→methodology cards "
            "(CWE/CAPEC-tagged tests from forms/APIs/auth/params seen). "
            "3) fireteam_dispatch(specialists='auto') — specialists receive methodology "
            "directives and must prove/kill each card. "
            "4) Prove logic/authz with compare_requests (baseline vs one mutation). "
            "5) update_hypothesis(proven|killed); on confirm queue_finding_followups "
            "(default_login→authenticated CVE; host_header→tenant bypass). "
            "6) Only then run nuclei coverage; use add_engagement_credential + -var when creds exist. "
            "Do not spray scanners before methodology cards exist."
        ),
    ),
    Skill(
        id="host-tenant-bypass",
        aliases=[
            "host-tenant",
            "tenant-isolation",
            "host-header-tenant",
            "tenant-bypass",
        ],
        title="Host-header tenant isolation bypass",
        description=(
            "Prove cross-tenant access by keeping session A and mutating Host / "
            "X-Forwarded-Host to peer tenant B."
        ),
        playbook_id="host_tenant_bypass",
        system_context=(
            "You are running the HOST-TENANT-BYPASS skill. "
            "1) Identify tenant-routing hosts (tenant-a.app / tenant-b.app). "
            "2) Authenticate as tenant A (or use auth_session). "
            "3) compare_requests: baseline Host=A vs mutant Host=B (same cookies); "
            "also try X-Forwarded-Host. "
            "4) PASS only if response contains tenant B objects/PII. "
            "5) update_hypothesis + validate_finding + create_finding; "
            "queue_finding_followups(vuln_type='host_header'). "
            "Kill on vhost reject or unchanged tenant A body."
        ),
    ),
    Skill(
        id="web-recon",
        aliases=["webrecon", "recon", "web"],
        title="Web reconnaissance",
        description="Subdomain enumeration, HTTP probing, tech fingerprinting.",
        scan_type="discovery",
        playbook_id="quick_recon",
        system_context=(
            "You are running the WEB-RECON skill. Prefer subfinder/httpx/wappalyzer "
            "and finish with a compact inventory. Do NOT launch active exploit tools."
        ),
    ),
    Skill(
        id="vuln-scan",
        aliases=["vuln", "nuclei", "scan-vuln"],
        title="Vulnerability scan",
        description="Run Nuclei with severity critical,high against in-scope URLs.",
        scan_type="vulnerability",
        playbook_id="vuln_scan",
        default_args={"severity": "critical,high"},
        system_context=(
            "You are running the VULN-SCAN skill. Query existing assets/vulns first "
            "to avoid duplicate work, then run execute_nuclei -severity critical,high."
        ),
    ),
    Skill(
        id="js-recon",
        aliases=["jsrecon", "js"],
        title="JavaScript reconnaissance",
        description="JS secrets, endpoint extraction, source-map / dep-confusion / DOM-sink analysis.",
        scan_type="js_recon",
        system_context=(
            "You are running the JS-RECON skill. "
            "1) execute_interceptor / crawl so js_files exist. "
            "2) fetch_lazy_chunks(dry_run then download) — webpack/Vite/Next code-split "
            "chunks the crawl never loaded. "
            "3) extract_js_endpoints (IDOR/SSRF/redirect triage) then ingest_urls_into_map. "
            "4) scan_js_urls_for_secrets / gitleaks on the same bundles. "
            "5) scan_js_sinks for eval/innerHTML/postMessage (prove, don't just list). "
            "api_samples are XHR only; script tags live in js_files."
        ),
    ),
    Skill(
        id="graphql",
        aliases=["gql", "graphql-audit"],
        title="GraphQL audit",
        description="Discover GraphQL endpoints and audit for introspection / CSRF / DoS.",
        scan_type="graphql_scan",
        system_context=(
            "You are running the GRAPHQL skill. Probe /graphql, /api/graphql and "
            "common IDE paths. Check introspection, field suggestions, GET/CSRF, "
            "and query batching limits."
        ),
    ),
    Skill(
        id="takeover",
        aliases=["subtakeover", "subdomain-takeover"],
        title="Subdomain takeover",
        description="CNAME-fingerprint + Nuclei takeover templates + optional Subjack.",
        scan_type="subdomain_takeover",
        system_context=(
            "You are running the TAKEOVER skill. Only subdomains with dangling "
            "CNAMEs / 404 fingerprints warrant HIGH severity findings."
        ),
    ),
    Skill(
        id="secrets",
        aliases=["trufflehog", "secret-scan"],
        title="Deep secret scan",
        description="TruffleHog with active verification across git repos, orgs, buckets.",
        scan_type="trufflehog_scan",
        system_context=(
            "You are running the SECRETS skill. Prefer ``--only-verified`` findings; "
            "raise LOW for unverified matches and CRITICAL for verified ones."
        ),
        required_inputs=["source"],
    ),
    Skill(
        id="llm-redteam",
        aliases=["llmredteam", "ai-redteam", "chatbot", "agent-tools", "mcp-tools"],
        title="LLM / chatbot red team",
        description=(
            "OWASP LLM Top-10 evaluation against chatbot/agent endpoints, including "
            "tool enumeration (AI port scan) and parameter abuse."
        ),
        scan_type="llm_red_team",
        playbook_id="llm_red_team",
        system_context=(
            "You are running the LLM-REDTEAM skill. Discover chat/agent endpoints, "
            "confirm with a benign message, then call execute_llm_red_team. "
            "For tool-using agents: enumerate tools/schemas first (tool_enumeration) — "
            "tools define the attack surface; each parameter is an injection point "
            "(user_id→IDOR, email→phishing/PII, refund→fraud, send_now→immediate action). "
            "Then run remaining categories."
        ),
    ),
    Skill(
        id="garak-scan",
        aliases=["garak", "llm-vuln-scan", "llm-deeptest", "ai-vuln"],
        title="Garak LLM vulnerability scan",
        description=(
            "Deep LLM vulnerability scan using NVIDIA garak: jailbreaks, DAN attacks, "
            "prompt injection, encoding exploits, data leakage, package hallucination, "
            "toxicity, malware generation, and 200+ additional probe classes."
        ),
        scan_type="garak_scan",
        playbook_id="garak_scan",
        system_context=(
            "You are running the GARAK-SCAN skill. "
            "Use execute_garak to run NVIDIA's garak LLM vulnerability scanner against "
            "the target model or endpoint. "
            "1) If target_type is unknown, check with the user or run garak_help to list options. "
            "2) Set --report_prefix /tmp/garak_<target> so results are retrievable. "
            "3) After the scan completes, read the JSONL report with execute_curl or list its "
            "FAIL lines; for each failing probe create_finding with the garak probe name, "
            "the triggering prompt, and the detected response as evidence. "
            "4) Map findings to OWASP LLM Top-10 categories where applicable."
        ),
    ),
    Skill(
        id="surface-ranking",
        aliases=["surface", "rank-surface", "attack-surface-ranking", "rank"],
        title="Surface ranking",
        description="Rank discovered assets and endpoints by likely testing value and impact.",
        scan_type="surface_ranking",
        playbook_id="surface_ranking",
        system_context=(
            "You are running the SURFACE-RANKING skill. Build a prioritized target "
            "queue BEFORE deep hunting. Hard priority order: "
            "(1) auth/SSO/reset/MFA, (2) object-ID APIs + GraphQL, "
            "(3) upload/webhook/URL-fetch/PDF, (4) admin/actuator/swagger/debug, "
            "(5) framework hot paths if fingerprint matches (Next.js/Spring/Laravel), "
            "(6) everything else. Favor assets with authentication, APIs, Swagger/OpenAPI, "
            "GraphQL, file upload, admin routes, sensitive tech, risky ports, known vulns, "
            "JS secrets, or cloud/identity integrations. Do not perform destructive "
            "validation; finish with ranked targets, why each matters, suggested skill "
            "(dual-identity-authz, nextjs-stack, etc.), and the next safe proof step. "
            "save_note the ranked queue as category=artifact."
        ),
    ),
    Skill(
        id="api-authz-validation",
        aliases=["api-authz", "api-authorization", "swagger-authz", "api-validation"],
        title="API authorization validation",
        description="Validate unauthenticated or under-authorized API exposure from discovered API specs and endpoints.",
        scan_type="api_authz_validation",
        playbook_id="api_authz_validation",
        system_context=(
            "You are running the API-AUTHZ-VALIDATION skill. Start from discovered "
            "OpenAPI/Swagger, GraphQL, or REST endpoints. Prove exposure with minimal "
            "GET/HEAD requests first, then compare unauthenticated and authorized "
            "responses when credentials are available. On /api/schema/: hunt security: {} "
            "on /api/auth/account/?email= (is_staff/role). compare_requests unauth "
            "/api/auth/profile/ (401) vs the lookup with aegis-enum-canary@example.invalid "
            "(200 or 500 or 404 existence oracle). A down database is still SUBMIT Critical. "
            "One canary; do not spray. Do not claim a 200 role body unless stdout has it. "
            "On ASP.NET / Settings: compare_requests unauth POST a 401 sibling write vs "
            "POST /api/Settings/SaveSettings with one canary key and use_auth_session=false. "
            "200 Content-Length: 0 is void success. GET 500 is still SUBMIT. Do not replace "
            "production settings. Look for sensitive data, PII, bulk records, secrets, and "
            "missing 401/403 controls. Do not replace production data. The SaveSettings "
            "canary POST (one aegis-verify-* key, no session cookies) is in-scope for "
            "missing-[Authorize] proof."
        ),
    ),
    Skill(
        id="idor-validation",
        aliases=["idor", "bola", "authz-validation", "object-authz"],
        title="IDOR / BOLA validation",
        description="Validate object-level authorization flaws with safe response comparison.",
        scan_type="idor_validation",
        playbook_id="idor_validation",
        system_context=(
            "You are running the IDOR-VALIDATION skill. Identify endpoints with object "
            "IDs, account IDs, document IDs, tenant IDs, or predictable UUIDs. Compare "
            "responses across unauthenticated, user A, and user B contexts when test "
            "credentials are available. A finding needs concrete cross-user or cross-"
            "tenant data access, not just a 200 response. Use read-only requests unless "
            "the engagement explicitly authorizes mutation. "
            "Classify carefully: no-auth success = missing authentication; "
            "user A reading user B = IDOR/BOLA; low-priv hitting admin function = BFLA."
        ),
    ),
    Skill(
        id="dual-identity-authz",
        aliases=["dual-identity", "two-user-authz", "cross-identity", "authz-matrix"],
        title="Dual-identity authorization matrix",
        description=(
            "Prove authz bugs with an anonymous / user-A / user-B matrix. Distinguishes "
            "missing auth, IDOR/BOLA, and BFLA before reporting."
        ),
        scan_type="dual_identity_authz",
        playbook_id="dual_identity_authz",
        system_context=(
            "You are running the DUAL-IDENTITY-AUTHZ skill. "
            "1) Collect candidate object-ID and privileged endpoints from recon/notes. "
            "2) For each candidate, send the SAME request under: anonymous, user A, user B "
            "(use provided auth headers/cookies; ask if missing). "
            "3) Compare status, length, owner fields, and sensitive data. "
            "4) Classify: missing_auth | idor_bola | bfla | no_issue. ASP.NET writes: "
            "missing_auth = sibling 401 vs SaveSettings 200 void (one canary key). "
            "5) Only create_finding when cross-identity or unauth impact is proven with "
            "response evidence. Call sanitize_evidence, then validate_finding, then "
            "detect_bug_chains for confirmed authz bugs."
        ),
        required_inputs=["target"],
    ),
    Skill(
        id="nextjs-stack",
        aliases=["nextjs", "next-js", "vercel-next"],
        title="Next.js stack hunt",
        description="Tech-conditional checks for Next.js: middleware bypass, image SSRF, Server Actions, ISR cache.",
        scan_type="nextjs_stack",
        playbook_id="nextjs_stack",
        system_context=(
            "You are running the NEXTJS-STACK skill. Only proceed if fingerprinting shows "
            "Next.js (/_next/, x-nextjs, or Vercel). Check: middleware auth bypass via "
            "static asset paths; /_next/image URL SSRF; Server Actions invocation; "
            "ISR/cache poisoning via unkeyed headers; RSC payload leakage. "
            "Prove impact with execute_curl; do not claim CVE names without live proof."
        ),
    ),
    Skill(
        id="springboot-stack",
        aliases=["spring", "springboot", "actuator"],
        title="Spring Boot stack hunt",
        description="Tech-conditional checks for Spring Boot actuators, SpEL, H2, Jolokia.",
        scan_type="springboot_stack",
        playbook_id="springboot_stack",
        system_context=(
            "You are running the SPRINGBOOT-STACK skill. Only if Spring/actuator signals "
            "exist. Probe /actuator, /actuator/env, heapdump, mappings, gateway, jolokia, "
            "h2-console. Prefer GET/HEAD. Escalate only with demonstrated data exposure "
            "or RCE preconditions — never dump full heapdump into findings (sanitize)."
        ),
    ),
    Skill(
        id="laravel-stack",
        aliases=["laravel", "ignition", "telescope"],
        title="Laravel stack hunt",
        description="Tech-conditional checks for Laravel debug, Telescope/Horizon, Ignition, signed URLs.",
        scan_type="laravel_stack",
        playbook_id="laravel_stack",
        system_context=(
            "You are running the LARAVEL-STACK skill. Only if Laravel/_ignition/telescope "
            "signals exist. Check APP_DEBUG stack traces, Telescope/Horizon auth, "
            "Ignition RCE preconditions (version-gated), signed URL tampering, .env leak. "
            "Validate live; create_finding only with concrete evidence."
        ),
    ),
    Skill(
        id="spa-api-discovery",
        aliases=["spa-api", "hidden-api", "js-api-map", "shadow-api"],
        title="SPA → hidden API discovery",
        description="Extract backend API routes from JS bundles and test them for missing auth / IDOR.",
        scan_type="spa_api_discovery",
        playbook_id="spa_api_discovery",
        system_context=(
            "You are running the SPA-API-DISCOVERY skill. "
            "1) execute_interceptor (interact=true). XHR → api_samples; <script> → js_files. "
            "2) fetch_lazy_chunks then extract_js_endpoints — code-split routes the crawl missed. "
            "3) ingest_urls_into_map; probe unauthenticated then low-priv. "
            "4) Feed object routes into dual-identity-authz or idor-validation. "
            "Route listing alone is not a finding — need authz impact."
        ),
    ),
    Skill(
        id="api-test",
        aliases=["api_test", "apitest", "api-recon", "api_recon"],
        title="API test (interceptor → chunks ∥ fingerprint → endpoints)",
        description=(
            "Recon an API surface: visit with interceptor, download lazy JS chunks and "
            "fingerprint captured traffic in parallel, then extract endpoints from JS."
        ),
        playbook_id="api_test",
        required_inputs=["target"],
        system_context=(
            "You are running the /api-test skill (Judah, not Codex/Caido).\n"
            "If target is missing, ask for the URL and stop.\n"
            "Step 1: execute_interceptor (interact=true) on the target. Fallback "
            "execute_deep_crawl. Capture origin, js_files, api_samples. Report before Step 2. "
            "Not the operator's desktop Chrome.\n"
            "Step 2: SAME tool round — fetch_lazy_chunks(dry_run then download) using "
            "Step 1 base URL/publicPath, AND fingerprint_api on the original target string. "
            "Fingerprint is independent of chunk files. If fingerprint is blocked/no-data, "
            "relay it and continue. Do not require Caido.\n"
            "Step 3: extract_js_endpoints on js_files + fetched chunks, ingest_urls_into_map. "
            "Triage /api, IDOR, SSRF/redirect. Do not write all_endpoints.txt.\n"
            "Final report: origin, chunk ok/FAIL, fingerprint hosts+tech+coverage, "
            "endpoint count, highest-value leads. Map surface; do not claim vulns yet."
        ),
    ),
    Skill(
        id="jshero",
        aliases=["js-hero", "js_hero", "js-collect"],
        title="JShero (collect + extract + sinks)",
        description=(
            "Exhaustive first-party JS: interceptor, lazy chunks, endpoint/method/param "
            "extract, DOM sinks. Optional gau/wayback JS URLs. Not operator Chrome."
        ),
        playbook_id="jshero",
        required_inputs=["target"],
        system_context=(
            "You are running /jshero (Judah). Not Codex, not operator Chrome, not a VPS waymore hop.\n"
            "If target is missing, ask for the URL and stop.\n"
            "1) execute_interceptor (interact=true). Fallback execute_deep_crawl.\n"
            "2) fetch_lazy_chunks (dry_run then download).\n"
            "3) Optional: execute_gau / execute_waybackurls, keep in-scope *.js, fetch into the map.\n"
            "4) extract_js_endpoints (methods + params + reseed ingest).\n"
            "5) scan_js_sinks on the same bundles.\n"
            "6) One reseed pass if new URLs/chunks appeared. Then secrets + fireteam.\n"
            "Listing endpoints/sinks is not a finding."
        ),
    ),
    Skill(
        id="wordpress",
        aliases=["wordpress-stack", "wp", "wpscan", "wp-json"],
        title="WordPress stack hunt",
        description=(
            "Mandatory WordPress probes: unauth REST user enum and admin-ajax "
            "tax_query timing. WPScan is optional and must never block those."
        ),
        playbook_id="wordpress_stack",
        required_inputs=["target"],
        system_context=(
            "You are running the WORDPRESS skill. WordPress fingerprint is enough "
            "even on a thin marketing site — do not wait for a rich map or WPScan.\n"
            "1) execute_curl GET {target}/wp-json/wp/v2/users?per_page=100. "
            "200 + slug/name → create_finding (CWE-200). 401/403/empty → kill with evidence.\n"
            "2) compare_requests POST {target}/wp-admin/admin-ajax.php loadmore tax_query "
            "SLEEP(0) vs SLEEP(2), timeout=20. Delta ≥1.5s → SLEEP(4) then sqlmap --technique=BT. "
            "Timing table is the finding. Status 200 is not.\n"
            "3) Login oracle: ONE POST /wp-login.php per discovered username. No hydra.\n"
            "4) If a probe is WAF/403/timeout blocked: compare_requests or run_custom_probe "
            "with one mutation, then prove or kill. Do not return empty.\n"
            "5) OPTIONAL execute_wpscan. Skip on quota abort. Never block steps 1–2 on WPScan."
        ),
    ),
    Skill(
        id="evidence-hygiene",
        aliases=["evidence", "redact", "sanitize-evidence", "report-hygiene"],
        title="Evidence hygiene",
        description="Redact cookies, tokens, secrets, and PII before findings or reports are submitted.",
        scan_type="evidence_hygiene",
        playbook_id="evidence_hygiene",
        system_context=(
            "You are running the EVIDENCE-HYGIENE skill. Review evidence before it is "
            "saved or reported. Redact session cookies, bearer tokens, API keys, private "
            "keys, authorization codes, passwords, emails beyond the minimum needed, "
            "phone numbers, SSNs, payment data, and unnecessary response bodies. Preserve "
            "enough structure to prove impact: endpoint, status, field names, data type, "
            "and a short redacted snippet."
        ),
        required_inputs=["finding"],
    ),
    Skill(
        id="fireteam",
        aliases=["scatter", "parallel-agents", "subagents", "capability-hunt"],
        title="Fireteam (parallel specialists)",
        description=(
            "Scatter-gather: after browser deep_crawl, spawn map-matched attack specialists "
            "(auth, API authz, injection, GraphQL, uploads, JS secrets) in parallel."
        ),
        system_context=(
            "You are the fireteam coordinator for tester-style engagements. "
            "Prefer execute_deep_crawl → sync_engagement_brain so hypotheses exist, then call "
            "fireteam_dispatch with specialists=\"auto\" (selected from open hypothesis cards). "
            "Do not default to the old recon-only triad when attacking a web app."
        ),
        required_inputs=["mission"],
    ),
    Skill(
        id="finding-validation",
        aliases=["validate", "gate", "7q", "triage", "validate-finding"],
        title="Finding validation (8-Question Gate)",
        description=(
            "Score a proposed finding before reporting: impact, reachability, reproducibility, "
            "boundary, evidence, severity, N/A risk, and identity discipline for authz."
        ),
        scan_type="finding_validation",
        playbook_id="finding_validation",
        system_context=(
            "You are running the FINDING-VALIDATION skill. Call validate_finding with "
            "the title, description, severity, and any evidence. Use the score and "
            "verdict to decide: SUBMIT (pass nearly all), IMPROVE, or DROP. "
            "For authz findings, require anonymous/user-A/user-B identity context. "
            "For IMPROVE, explain each failing question to the user. "
            "After validation, call detect_bug_chains to surface follow-on test opportunities."
        ),
        required_inputs=["finding"],
    ),
    Skill(
        id="chain-detection",
        aliases=["chain", "bug-chain", "vuln-chain", "chains"],
        title="Bug chain detection",
        description="Given a confirmed vulnerability, surface follow-on bug classes that commonly chain with it and rank them by impact.",
        scan_type="chain_detection",
        playbook_id="chain_detection",
        system_context=(
            "You are running the CHAIN-DETECTION skill. Call detect_bug_chains with the "
            "confirmed vuln_type and target. Then for each CRITICAL/HIGH chain candidate, "
            "use the appropriate tool or skill to validate the chain. "
            "Document chain findings with create_finding referencing the original bug."
        ),
        required_inputs=["vuln_type"],
    ),
    Skill(
        id="403-bypass",
        aliases=["bypass", "bypass403", "access-bypass", "forbidden-bypass"],
        title="403 / 401 access bypass",
        description="Test header tricks, path normalization, and method overrides to bypass 403/401 access restrictions.",
        scan_type="bypass_403",
        playbook_id="bypass_403",
        system_context=(
            "You are running the 403-BYPASS skill. "
            "1) Identify all 403/401/302 restricted endpoints using execute_katana or execute_ffuf. "
            "2) Call bypass_403(url=<restricted_url>) for each candidate. "
            "3) If bypasses are found, call create_finding with the successful technique as evidence. "
            "4) Call detect_bug_chains(vuln_type='broken_auth') to surface follow-on tests."
        ),
    ),
    Skill(
        id="request-smuggling",
        aliases=["smuggling", "http-smuggling", "req-smuggling", "cl-te", "te-cl"],
        title="HTTP request smuggling",
        description="Detect CL.TE, TE.CL, and TE.TE HTTP/1.1 request desync via timing-based probes.",
        scan_type="request_smuggling",
        playbook_id="request_smuggling",
        system_context=(
            "You are running the REQUEST-SMUGGLING skill. "
            "1) Call test_request_smuggling(url=target, technique='all'). "
            "2) If timing-based indicators are found, use execute_curl with crafted CL/TE payloads "
            "to attempt differential confirmation. "
            "3) Call detect_bug_chains(vuln_type='request_smuggling') for downstream impact. "
            "4) Document confirmed findings with create_finding citing the timed-out probe."
        ),
    ),
    Skill(
        id="cache-poisoning",
        aliases=["cache", "web-cache", "cache-poison", "cache-deception"],
        title="Web cache poisoning",
        description="Probe for unkeyed header injection and cache poisoning via canary-value reflection tests.",
        scan_type="cache_poisoning",
        playbook_id="cache_poisoning",
        system_context=(
            "You are running the CACHE-POISONING skill. "
            "1) Call test_cache_poisoning(url=target) with default probe headers. "
            "2) For any confirmed or candidate unkeyed headers, craft manual payloads "
            "with execute_curl to confirm cache storage. "
            "3) Call detect_bug_chains(vuln_type='cache_poisoning') for downstream impact. "
            "4) Create findings only for confirmed cache storage of injected values."
        ),
    ),
    Skill(
        id="race-conditions",
        aliases=["race", "concurrent", "toctou", "race-condition"],
        title="Race condition testing",
        description="Fire concurrent requests to detect TOCTOU flaws in transactions, coupons, balances, and rate limits.",
        scan_type="race_conditions",
        playbook_id="race_conditions",
        system_context=(
            "You are running the RACE-CONDITIONS skill. "
            "1) Identify state-changing endpoints: balance/credits, coupon/voucher redemption, "
            "invite/role changes, file operations, or any 'one-time' actions. "
            "2) Call test_race_condition(url=endpoint, method='POST', concurrency=20) with "
            "the appropriate body/auth_headers. "
            "3) Look for multiple success responses or duplicate unique field values. "
            "4) Create a finding with evidence showing the race (number of successes, duplicated IDs)."
        ),
    ),
    Skill(
        id="saml-sso",
        aliases=["saml", "sso", "oauth-bypass", "oidc", "jwt-confusion", "saml-attack"],
        title="SAML / SSO / OAuth attack surface",
        description="Discover SAML/OAuth/OIDC endpoints and probe for signature wrapping, algorithm confusion, open redirect, and OIDC misconfiguration.",
        scan_type="saml_sso",
        playbook_id="saml_sso",
        system_context=(
            "You are running the SAML-SSO skill. "
            "1) Call test_saml_sso(url=target) to discover endpoints and run all category probes. "
            "2) For OAuth open redirect findings, test token theft with execute_curl. "
            "3) For OIDC alg=none or HS256 findings, attempt JWT forging manually. "
            "4) If a SAMLResponse is captured, re-run with saml_response_b64=<base64> for "
            "XML Signature Wrapping analysis. "
            "5) Create findings for any confirmed bypasses."
        ),
    ),
    Skill(
        id="credential-spray",
        aliases=["spray", "cred-spray", "password-spray", "bruteforce"],
        title="Credential spray (authorized)",
        description="Spray a small, targeted credential set against a login endpoint with lockout detection and rate-limit awareness. Requires explicit authorization.",
        scan_type="credential_spray",
        playbook_id="credential_spray",
        system_context=(
            "You are running the CREDENTIAL-SPRAY skill. "
            "LEGAL REQUIREMENT: Confirm with the user that they have written authorization "
            "to test credentials against the target before proceeding. "
            "1) Identify the login endpoint URL and confirm the username/password field names. "
            "2) Call test_credential_spray(login_url=..., usernames=[...], passwords=[...], "
            "authorized=True, max_attempts=10, delay_seconds=3.0). "
            "3) If lockout is detected, stop immediately and report the lockout as a positive "
            "finding (lockout policy exists). "
            "4) If hits are found, create_finding with severity=critical and REDACTED evidence."
        ),
        required_inputs=["login_url", "credentials"],
    ),
]


_BY_ID: dict[str, Skill] = {s.id: s for s in SKILLS}
_BY_ALIAS: dict[str, Skill] = {
    **_BY_ID,
    **{alias.lower(): s for s in SKILLS for alias in s.aliases},
}


def list_skills() -> list[dict]:
    return [
        {
            "id": s.id,
            "aliases": s.aliases,
            "title": s.title,
            "description": s.description,
            "scan_type": s.scan_type,
            "playbook_id": s.playbook_id,
            "required_inputs": s.required_inputs,
        }
        for s in SKILLS
    ]


def get_skill(name: str) -> Optional[Skill]:
    return _BY_ALIAS.get((name or "").strip().lower().lstrip("/"))


# ---------------------------------------------------------------------------
# /skill prefix parsing
# ---------------------------------------------------------------------------


_SKILL_PREFIX_RE = re.compile(r"^\s*/skill\s+([a-zA-Z0-9_\-]+)\b(.*)$", re.DOTALL)
_SHORT_PREFIX_RE = re.compile(r"^\s*/([a-zA-Z0-9_\-]+)\b(.*)$", re.DOTALL)


def parse_skill_prefix(message: str) -> tuple[Optional[Skill], dict, str]:
    """
    Return ``(skill, parsed_args, stripped_message)``.

    Accepts both ``/skill <name> key=val ...`` and the shorter ``/<alias>
    key=val ...``. If no prefix matches the registered skills, returns
    ``(None, {}, message)`` unchanged.
    """
    if not message:
        return None, {}, message

    m = _SKILL_PREFIX_RE.match(message)
    if not m:
        m = _SHORT_PREFIX_RE.match(message)
        if not m:
            return None, {}, message
        name = m.group(1)
        if name.lower() not in _BY_ALIAS:
            return None, {}, message

    name = m.group(1)
    rest = (m.group(2) or "").strip()

    skill = get_skill(name)
    if not skill:
        return None, {}, message

    args: dict[str, Any] = dict(skill.default_args)
    free_text_parts: list[str] = []
    try:
        tokens = shlex.split(rest) if rest else []
    except ValueError:
        tokens = rest.split() if rest else []

    for tok in tokens:
        if "=" in tok:
            k, _, v = tok.partition("=")
            k = k.strip()
            v = v.strip()
            if not k:
                continue
            if "," in v:
                args[k] = [x.strip() for x in v.split(",") if x.strip()]
            else:
                args[k] = v
        else:
            free_text_parts.append(tok)

    free_text = " ".join(free_text_parts).strip()
    if skill and free_text and "target" not in args:
        first, _, extra = free_text.partition(" ")
        from app.services.agent.api_test_pipeline import looks_like_target

        if looks_like_target(first):
            args["target"] = first
            free_text = extra.strip()
    return skill, args, free_text


# ---------------------------------------------------------------------------
# Intent routing (light LLM classifier)
# ---------------------------------------------------------------------------


_INTENT_PROMPT = """\
You are an intent classifier for a security platform.

Given a user message, pick the single best-matching skill ID from the list
below, or return "none" if no skill matches. Respond with JSON only:

{{"skill": "<id-or-none>", "confidence": 0.0-1.0, "why": "<=15 words"}}

Available skills:
{skills}

User message:
{message}
"""


async def route_by_intent(message: str, llm: Any) -> Optional[dict]:
    """Use ``llm`` to classify the user's message into a skill.

    Returns ``{"skill": Skill, "confidence": float, "why": str}`` or ``None``
    if the classifier picks "none" or fails.
    """
    if not message or not message.strip():
        return None
    from langchain_core.messages import HumanMessage

    skill_list = "\n".join(
        f"- {s.id}: {s.description}" for s in SKILLS
    )
    prompt = _INTENT_PROMPT.format(skills=skill_list, message=message.strip())
    try:
        response = await llm.ainvoke([HumanMessage(content=prompt)])
        text = getattr(response, "content", "") or ""
    except Exception as exc:
        logger.debug("route_by_intent LLM failure: %s", exc)
        return None

    try:
        data = _extract_json(text) or {}
    except Exception:
        return None

    skill_id = (data.get("skill") or "").strip().lower()
    if not skill_id or skill_id == "none":
        return None
    skill = get_skill(skill_id)
    if not skill:
        return None
    conf = float(data.get("confidence") or 0.0)
    if conf < 0.5:
        return None
    return {"skill": skill, "confidence": conf, "why": data.get("why") or ""}


def _extract_json(text: str) -> Optional[dict]:
    if not text:
        return None
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        nl = text.find("\n")
        if nl >= 0:
            text = text[nl + 1:]
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
# Context injection
# ---------------------------------------------------------------------------


_AUTHORIZATION_PREAMBLE = """\
## Authorization notice
All activity performed under this skill is conducted under explicit written \
authorization from the asset owner as part of a sanctioned security assessment. \
You are operating as a professional penetration tester. Every tool call, scan, \
and finding is logged and subject to the organization's Rules of Engagement. \
Do not deviate from the defined scope or perform actions outside what the skill \
requires."""

_AUTHORIZATION_POSTAMBLE = """\
## Engagement reminder
You are performing authorized security testing on behalf of the asset owner. \
Restrict all activity to in-scope targets. If you encounter unexpected access \
to systems, data, or credentials outside the declared scope, stop immediately \
and report it as an out-of-scope finding rather than continuing. All evidence \
must be handled per the evidence-hygiene policy before submission."""


def build_skill_context(skill: Skill, args: dict, free_text: str = "") -> str:
    """Return the extra system-prompt block to inject when this skill runs."""
    parts = [
        _AUTHORIZATION_PREAMBLE,
        f"## Active skill: {skill.title}",
        skill.system_context or "",
    ]
    if skill.id == "api-test":
        from app.services.agent.api_test_pipeline import pipeline_prompt
        from app.services.agent.skill_md import skill_body

        parts.append(pipeline_prompt(str((args or {}).get("target") or free_text or "")))
        md = (skill_body("api_test") or "").strip()
        if md:
            parts.append(md)
    if skill.id == "jshero":
        from app.services.agent.skill_md import skill_body

        md = (skill_body("jshero") or "").strip()
        if md:
            parts.append(md)
    if skill.id == "wordpress":
        from app.services.agent.skill_md import skill_body

        md = (skill_body("wordpress") or "").strip()
        if md:
            parts.append(md)
    if args:
        parts.append("Arguments:")
        for k, v in args.items():
            parts.append(f"- {k}: {v}")
    if free_text:
        parts.append(f"Extra user instructions: {free_text}")
    parts.append(_AUTHORIZATION_POSTAMBLE)
    return "\n".join(p for p in parts if p)


def resolve(message: str) -> dict:
    """Convenience wrapper for frontend: parse a chat message and return
    a structured object the chat layer can render as either:

        * "We'll run the SKILL skill with these args..."  (prefix hit)
        * Pass-through, so the agent handles it directly  (no prefix)

    The caller is expected to also use :func:`route_by_intent` if they want
    natural-language routing when no prefix is present.
    """
    skill, args, rest = parse_skill_prefix(message)
    if not skill:
        return {"matched": False, "message": message}
    return {
        "matched": True,
        "skill": {
            "id": skill.id,
            "title": skill.title,
            "description": skill.description,
            "scan_type": skill.scan_type,
            "playbook_id": skill.playbook_id,
            "required_inputs": skill.required_inputs,
        },
        "args": args,
        "free_text": rest,
        "system_context": build_skill_context(skill, args, rest),
    }
