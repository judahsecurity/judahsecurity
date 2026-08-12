"""Preset playbook objectives for the agent. No full playbook engine; just rich initial objectives and optional todos."""

from typing import List, Dict, Any, Optional

PLAYBOOKS: List[Dict[str, Any]] = [
    {
        "id": "tester_process",
        "name": "Tester Process (Hypotheses + Differentials)",
        "description": (
            "Engagement-brain orchestrator loop: map → hypotheses → specialist fireteam → "
            "compare_requests proof → chain follow-ups → coverage."
        ),
        "objective": (
            "Run a tester-process engagement (not a scanner spray).\n\n"
            "CONTROL LOOP (mandatory methodology):\n"
            "1) Observe — execute_deep_crawl on the primary web target.\n"
            "2) Enrich — execute_katana/gau then ingest_urls_into_map so passive URLs "
            "update methodologies.\n"
            "3) Hypothesize — sync_engagement_brain seeds observation→methodology cards "
            "(CWE/CAPEC/OWASP-tagged: login→creds, search→XSS, APIs→IDOR, …).\n"
            "4) Dispatch — fireteam_dispatch(specialists='auto') from open methodology cards.\n"
            "5) Mutate one variable — compare_requests(baseline, mutant) for logic proofs.\n"
            "6) Prove or kill — update_hypothesis(status=proven|killed); check "
            "get_methodology_progress until high-priority cards are resolved.\n"
            "7) Chain — queue_finding_followups on confirmed hits "
            "(default_login → authenticated CVE; host_header → tenant bypass; pass cve_id for CWE loop-back).\n"
            "8) Coverage leftovers — execute_nuclei only after methodology progress allows "
            "(use -var username/password from engagement credentials when present).\n\n"
            "RULES:\n"
            "- Status 200 alone is never a finding — show field/body differentials.\n"
            "- Prefer 3–6 specialists, not every hunter.\n"
            "- validate_finding before create_finding for medium+.\n"
            "- Do NOT complete while high-priority methodology cards are open "
            "(unless completion_reason includes 'defer methodologies').\n"
            "- Complete with proven/killed methodologies + coverage summary, not Nuclei-only.\n"
        ),
        "initial_todos": [
            {"description": "Deep crawl primary app → capability map + methodologies", "status": "pending", "priority": "high"},
            {"description": "ingest_urls_into_map from katana/gau; sync_engagement_brain", "status": "pending", "priority": "high"},
            {"description": "fireteam_dispatch(specialists=auto) from methodology cards", "status": "pending", "priority": "high"},
            {"description": "compare_requests proofs; update_hypothesis proven/killed", "status": "pending", "priority": "high"},
            {"description": "get_methodology_progress — clear high-priority blockers", "status": "pending", "priority": "high"},
            {"description": "queue_finding_followups + authenticated coverage", "status": "pending", "priority": "high"},
            {"description": "validate_finding → create_finding → report", "status": "pending", "priority": "medium"},
        ],
    },
    {
        "id": "host_tenant_bypass",
        "name": "Host-Header Tenant Isolation Bypass",
        "description": (
            "Prove cross-tenant access via Host / X-Forwarded-Host mutation under a fixed session."
        ),
        "objective": (
            "Test host-header tenant isolation bypass like a human tester.\n\n"
            "1) Identify peer tenant hosts (from map, DNS, or user).\n"
            "2) Obtain/reuse session for tenant A (deep_crawl login or provided cookies).\n"
            "3) compare_requests: baseline Host=tenant-A vs mutant Host=tenant-B (same Cookie); "
            "repeat with X-Forwarded-Host.\n"
            "4) PASS only if tenant B data/fields appear under session A.\n"
            "5) update_hypothesis + validate_finding + create_finding; "
            "queue_finding_followups(vuln_type='host_header').\n"
            "Kill on connection/vhost reject or unchanged tenant A body.\n"
        ),
        "initial_todos": [
            {"description": "Identify tenant A/B hostnames", "status": "pending", "priority": "high"},
            {"description": "Establish tenant A session", "status": "pending", "priority": "high"},
            {"description": "compare_requests Host / X-Forwarded-Host differentials", "status": "pending", "priority": "high"},
            {"description": "Validate, record finding, queue follow-ups", "status": "pending", "priority": "medium"},
        ],
    },
    {
        "id": "external_assessment",
        "name": "External Assessment (Tester Methodology)",
        "description": (
            "Full external engagement workflow: coordinated recon → enumeration → "
            "surface ranking → targeted testing → evidence-backed findings. "
            "Behaves like a real tester — branches on discoveries, does not spray tools blindly."
        ),
        "objective": (
            "Conduct a thorough external security assessment like an experienced penetration tester.\n\n"
            "OPERATING RULES (non-negotiable):\n"
            "- Work like a human tester: browse and click the app before spraying scanners.\n"
            "- Early on the primary web target, run execute_deep_crawl to build an Application "
            "Capability Map (pages, forms, APIs, auth, uploads). Then sync_engagement_brain and "
            "fireteam_dispatch with specialists=\"auto\" so attack sub-agents match open hypotheses.\n"
            "- Work in phases. Finish the purpose of a phase before moving on, but branch early when "
            "a high-value lead appears (login, API, GraphQL, chatbot, admin, upload, dangling DNS).\n"
            "- Call auto_select_tools after every major discovery wave so recommendations stay current.\n"
            "- Prefer evidence over volume: reproduce interesting findings with a second tool or "
            "targeted curl before create_finding. Call validate_finding first for medium+.\n"
            "- Use create_scan for bulk / long-running platform work (subdomain_enum, graphql_scan, "
            "subdomain_takeover, js_recon, jsluice_scan, vulnerability, waybackurls, katana, "
            "paramspider, technology). Use execute_* for interactive, targeted follow-up.\n"
            "- Stay in scope. Ask the user before destructive or authenticated testing if ROE is unclear.\n"
            "- Do NOT complete after Nuclei alone. Coverage must include browser capability map (or "
            "explicit non-browser justification), fireteam/mapped attacks, and tech-specific testing.\n\n"
            "**PHASE 0 — Scope & existing intel**\n"
            "1) query_assets / query_ports / query_technologies / query_vulnerabilities / get_notes "
            "for the target org. Note what is already known so you do not re-do work blindly.\n"
            "2) add_asset for any seed hostname/URL/IP the user gave that is missing.\n"
            "3) save_note(category='artifact') with engagement scope, seed targets, and plan.\n\n"
            "**PHASE 1 — Passive discovery (fan-out)**\n"
            "4) Subdomain / asset discovery in parallel where useful:\n"
            "   - execute_subfinder + execute_subfaster + execute_crtsh (+ execute_crt_name / execute_amass if needed)\n"
            "   - execute_uncover with ssl:\"<root>\" / hostname queries (persist=True) for internet-DB hits\n"
            "   - create_scan(scan_type='subdomain_enum' or 'discovery') for bulk worker coverage\n"
            "5) execute_dnsx on discovered hosts. Flag interesting CNAMEs for takeover later.\n"
            "6) execute_httpx on live candidates (-tech-detect -status-code -title -follow-redirects).\n"
            "7) execute_wafw00f + execute_wappalyzer/whatweb on primary live hosts.\n"
            "8) auto_select_tools(target=...) — follow priority order.\n\n"
            "**PHASE 2 — Ports, TLS, and service surface**\n"
            "9) Request exploitation phase, then execute_naabu (top ports) on key hosts/IPs.\n"
            "10) execute_nmap -sV on interesting non-HTTP ports; execute_testssl/sslyze on HTTPS hosts.\n"
            "11) create_scan(scan_type='port_scan') for large IP/CIDR sets instead of looping execute_*.\n\n"
            "**PHASE 3 — Browser walkthrough & capability map (tester eyes-on)**\n"
            "12) On each primary live web app: execute_deep_crawl (interact=true; auth session if available). "
            "This is mandatory before broad exploitation — click menus/tabs/links and learn the app.\n"
            "13) Supplement with execute_katana / execute_gau / waybackurls, then "
            "ingest_urls_into_map so passive URLs refresh methodologies. "
            "Treat the capability map + methodology checklist as the source of truth.\n"
            "14) sync_engagement_brain then fireteam_dispatch(specialists=\"auto\") to spawn "
            "specialists from open methodology cards (CWE/CAPEC-tagged). Prove with "
            "compare_requests; queue_finding_followups on hits (include cve_id when known).\n"
            "15) JS recon: scan_js_urls_for_secrets + execute_retirejs on crawled bundles; "
            "create_scan(js_recon/jsluice_scan) for bulk JS analysis when many hosts.\n"
            "16) If GraphQL/chatbot/takeover signals appear outside the fireteam: create_scan or "
            "targeted execute_* follow-ups.\n"
            "17) get_methodology_progress — do not finish Phase 3 until high-priority cards are "
            "proven/killed (coverage card may remain open). save_note with checklist. "
            "auto_select_tools.\n\n"
            "**PHASE 4 — Targeted testing (tester branching from methodologies)**\n"
            "18) Work open methodology cards / ranked hunt queue, highest proof-value first. Examples:\n"
            "   - WordPress → wpscan; other CMS → cmseek\n"
            "   - OpenAPI/Swagger → schemathesis; REST APIs → authz checks + kiterunner leftovers\n"
            "   - Injection candidates → sqlmap / xsstrike / browser check_xss with real params\n"
            "   - Auth/SSO/admin → careful curl/browser proofs; dual-identity only if creds provided\n"
            "   - Unkeyed cache / Host header leads → test_cache_poisoning\n"
            "   - Next.js / Spring / Laravel fingerprints → corresponding stack skills/playbooks\n"
            "19) execute_nuclei without -severity on primary live URLs only after "
            "get_methodology_progress.ready_for_coverage_spray (or force=true). "
            "Follow with create_scan(vulnerability) for remaining host inventory.\n"
            "20) execute_nikto on key web servers when still within iteration budget.\n\n"
            "**PHASE 5 — Confirm, record, report**\n"
            "21) For each solid lead: sanitize_evidence → validate_finding → create_finding "
            "(concrete request/response, impact, remediation; include cve_id). detect_bug_chains.\n"
            "22) Queue any remaining bulk gaps with create_scan before completing.\n"
            "23) Complete only when high-priority methodologies are resolved (or completion_reason "
            "includes 'defer methodologies'): scope covered, checklist status, confirmed findings, "
            "and recommended next steps.\n\n"
            "Think like a tester: every tool call should answer a question raised by prior evidence."
        ),
        "initial_todos": [
            {"description": "Phase 0: Review existing assets/vulns/notes; register seed targets", "status": "pending", "priority": "high"},
            {"description": "Phase 1: Passive discovery (subfinder/crt/uncover) + httpx + WAF/tech", "status": "pending", "priority": "high"},
            {"description": "Phase 1b: auto_select_tools and adjust plan from discoveries", "status": "pending", "priority": "high"},
            {"description": "Phase 2: Ports (naabu/nmap) + TLS on key hosts", "status": "pending", "priority": "high"},
            {"description": "Phase 3: Browser deep_crawl → methodologies on primary apps", "status": "pending", "priority": "high"},
            {"description": "Phase 3b: ingest_urls_into_map + fireteam from methodology cards", "status": "pending", "priority": "high"},
            {"description": "Phase 4: Prove/kill methodologies; Nuclei only after checklist allows", "status": "pending", "priority": "high"},
            {"description": "Phase 5: Validate, findings, methodology checklist clear, report", "status": "pending", "priority": "medium"},
        ],
    },
    {
        "id": "web_app_assessment",
        "name": "Web App Assessment (Auto-Select)",
        "description": "Comprehensive web application vulnerability assessment with automatic tool selection based on discovered technologies.",
        "objective": (
            "Perform a comprehensive web application vulnerability assessment using automatic tool selection.\n\n"
            "**Phase 1 — Initial Reconnaissance**\n"
            "1) add_asset if the target is not in the database.\n"
            "2) execute_httpx — probe for HTTP status, tech stack, redirects.\n"
            "3) execute_dnsx — DNS resolution (IPs, MX, NS, CNAME).\n"
            "4) execute_wafw00f — detect WAF protections before injection testing.\n"
            "5) execute_wappalyzer — fingerprint technologies (CMS, frameworks, servers).\n\n"
            "**Phase 2 — Browser walkthrough & specialists**\n"
            "6) execute_deep_crawl on the primary URL — click around like a tester and build a capability map.\n"
            "7) fireteam_dispatch(specialists=\"auto\") to spawn attack sub-agents matched to the map.\n"
            "8) Call auto_select_tools; follow recommendations that still apply (WordPress→wpscan, "
            "API→schemathesis, chatbot→llm_red_team).\n\n"
            "**Phase 3 — Parameter Discovery & Injection Testing**\n"
            "8) discover_parameters + execute_arjun — find all injectable params.\n"
            "9) For SQLi-prone params: execute_sqlmap with --batch --dbs.\n"
            "10) For XSS-prone params: execute_xsstrike, execute_browser check_xss.\n"
            "11) generate_injection_payloads for manual payload crafting if automated tools miss.\n\n"
            "**Phase 4 — Active Vulnerability Scanning** (requires exploitation phase)\n"
            "12) execute_nuclei — comprehensive scan (NO severity filter).\n"
            "13) execute_naabu — port scan beyond 80/443.\n"
            "14) execute_nikto — web server vuln scan (6,700+ checks).\n"
            "15) execute_testssl — TLS/SSL vulnerability testing.\n"
            "16) execute_browser — headless browser for XSS verification and JS analysis.\n\n"
            "**Phase 5 — Findings & Reporting**\n"
            "17) create_finding for each confirmed vulnerability with evidence.\n"
            "18) save_note for important discoveries.\n"
            "19) Complete with a summary of findings, scan coverage, and remediation.\n\n"
            "IMPORTANT: Call auto_select_tools after initial recon (step 6) AND after parameter discovery (before step 9) to get updated recommendations."
        ),
        "initial_todos": [
            {"description": "Initial recon: httpx, dnsx, wafw00f, wappalyzer", "status": "pending", "priority": "high"},
            {"description": "Call auto_select_tools for context-aware recommendations", "status": "pending", "priority": "high"},
            {"description": "Parameter discovery: discover_parameters + arjun", "status": "pending", "priority": "high"},
            {"description": "Injection testing: sqlmap, xsstrike, browser for identified params", "status": "pending", "priority": "high"},
            {"description": "Active scanning: nuclei, naabu, nikto, testssl", "status": "pending", "priority": "high"},
            {"description": "Record findings and generate final report", "status": "pending", "priority": "medium"},
        ],
    },
    {
        "id": "web_assessment",
        "name": "Web assessment",
        "description": "Structured web application assessment: discovery then vulnerability scanning.",
        "objective": (
            "Perform a structured web application assessment. "
            "1) Discovery: identify technologies, endpoints, and authentication mechanisms using query_assets, query_technologies, execute_httpx, execute_katana. "
            "2) Vulnerability scanning: run Nuclei with severity critical,high on discovered URLs. "
            "3) Summarize findings and recommend remediation. Stay within the organization's scope."
        ),
        "initial_todos": [
            {"description": "Enumerate technologies and endpoints", "status": "pending", "priority": "high"},
            {"description": "Run Nuclei with severity critical,high", "status": "pending", "priority": "high"},
            {"description": "Summarize findings and remediation", "status": "pending", "priority": "medium"},
        ],
    },
    {
        "id": "quick_recon",
        "name": "Quick recon",
        "description": "Fast reconnaissance: subdomains, DNS, and HTTP probing.",
        "objective": (
            "Perform quick reconnaissance on the target. "
            "1) Discover subdomains (execute_subfinder, execute_dnsx). "
            "2) Probe HTTP with execute_httpx. "
            "3) Report open ports and live hosts. Use query_assets first to see existing scope."
        ),
        "initial_todos": [
            {"description": "Subdomain and DNS discovery", "status": "pending", "priority": "high"},
            {"description": "HTTP probing and live host list", "status": "pending", "priority": "high"},
            {"description": "Brief recon summary", "status": "pending", "priority": "medium"},
        ],
    },
    {
        "id": "vuln_scan",
        "name": "Vuln scan",
        "description": "Vulnerability scan with Nuclei on in-scope assets.",
        "objective": (
            "Run a vulnerability scan focused on critical and high severity. "
            "1) Use query_assets and query_vulnerabilities to see current scope and existing findings. "
            "2) Run Nuclei (execute_nuclei) on in-scope web URLs with -severity critical,high. "
            "3) Summarize new and existing critical/high findings and remediation steps."
        ),
        "initial_todos": [
            {"description": "Review scope and existing vulns", "status": "pending", "priority": "high"},
            {"description": "Run Nuclei critical,high on targets", "status": "pending", "priority": "high"},
            {"description": "Summarize findings", "status": "pending", "priority": "medium"},
        ],
    },
    {
        "id": "surface_ranking",
        "name": "Surface ranking",
        "description": "Prioritize discovered assets and endpoints by likely exploitability, impact, and proof value.",
        "objective": (
            "Rank the target's attack surface by testing value and likely impact.\n\n"
            "**Phase 1 - Gather existing context**\n"
            "1) Use query_assets, query_vulnerabilities, query_ports, query_technologies, "
            "analyze_attack_surface, rank_attack_surface, and get_notes to understand what is already known.\n"
            "2) Use query_prior_sessions if available to pull prior findings, failed attempts, "
            "and lessons for this organization.\n\n"
            "**Phase 2 - Light enrichment**\n"
            "3) For the requested target or top candidates, run lightweight checks such as "
            "execute_httpx, execute_wappalyzer or execute_whatweb, execute_wafw00f, and "
            "execute_katana only when needed to fill gaps.\n"
            "4) Look for high-value surfaces: login/admin flows, APIs, Swagger/OpenAPI, "
            "GraphQL, file upload, payment/export/webhook flows, exposed JS bundles, "
            "cloud/identity integrations, risky ports, known vulnerable tech, or existing "
            "critical/high findings.\n\n"
            "**Phase 3 - Rank and route**\n"
            "5) Produce a ranked queue with each target's evidence, why it matters, likely "
            "vulnerability classes, and the next safest validation skill/tool.\n"
            "6) Save the ranked queue with save_note(category='artifact') so later skills "
            "can pick up from it.\n\n"
            "Do not perform destructive validation in this playbook. The deliverable is a "
            "prioritized target queue and a concise next-step plan."
        ),
        "initial_todos": [
            {"description": "Review existing assets, vulns, ports, technologies, and notes", "status": "pending", "priority": "high"},
            {"description": "Run light enrichment on the requested target or top candidates", "status": "pending", "priority": "medium"},
            {"description": "Rank surfaces by proof value and likely impact", "status": "pending", "priority": "high"},
            {"description": "Save the ranked target queue as an artifact note", "status": "pending", "priority": "medium"},
        ],
    },
    {
        "id": "api_authz_validation",
        "name": "API authorization validation",
        "description": "Validate unauthenticated or under-authorized API access with minimal safe requests.",
        "objective": (
            "Validate API authorization exposure using the least intrusive proof possible.\n\n"
            "**Phase 1 - Identify API surface**\n"
            "1) Review existing assets, notes, and recon. Use execute_katana, execute_kiterunner, "
            "discover_parameters, and execute_curl for focused discovery when needed.\n"
            "2) Look for OpenAPI/Swagger specs, GraphQL endpoints, REST route patterns, "
            "JSON responses, WebSocket hints, and JS-discovered endpoints.\n\n"
            "**Phase 2 - Safe authorization checks**\n"
            "3) For each candidate endpoint, send minimal GET or HEAD requests first with "
            "execute_curl. Compare unauthenticated vs authenticated responses when provided "
            "credentials or headers are available.\n"
            "4) If an OpenAPI/Swagger spec exists and active testing is approved, request "
            "the exploitation phase and use execute_schemathesis or targeted curl requests "
            "to validate documented endpoints. Avoid POST/PUT/PATCH/DELETE unless explicitly "
            "authorized.\n\n"
            "**Phase 3 - Evidence and reporting**\n"
            "5) A valid finding needs proof of meaningful impact: missing 401/403, sensitive "
            "data, PII, secrets, bulk records, tenant data, or privileged operations exposed.\n"
            "6) Call sanitize_evidence to redact credentials, cookies, PII, and response "
            "bodies before create_finding. "
            "Store only the endpoint, status codes, request context, and short redacted snippets.\n"
            "7) Save non-findings and exhausted endpoints with save_note so future runs skip them."
        ),
        "initial_todos": [
            {"description": "Map candidate API endpoints and any API specs", "status": "pending", "priority": "high"},
            {"description": "Compare unauthenticated and authorized responses with safe methods", "status": "pending", "priority": "high"},
            {"description": "Confirm meaningful exposed data or access-control impact", "status": "pending", "priority": "high"},
            {"description": "Create redacted findings or save exhausted endpoint notes", "status": "pending", "priority": "medium"},
        ],
    },
    {
        "id": "idor_validation",
        "name": "IDOR / BOLA validation",
        "description": "Validate object-level authorization flaws by comparing read-only responses across identities.",
        "objective": (
            "Validate IDOR/BOLA candidates with safe response comparison.\n\n"
            "**Phase 1 - Find object access patterns**\n"
            "1) Review recon, notes, Katana output, API routes, and JS bundles for endpoints "
            "with object IDs: user_id, account_id, org_id, tenant_id, document IDs, order IDs, "
            "numeric paths, predictable UUIDs, or GraphQL node IDs.\n"
            "2) Use discover_parameters and execute_arjun on high-value endpoints when needed.\n\n"
            "**Phase 2 - Compare access contexts**\n"
            "3) Prefer read-only GET requests. Compare unauthenticated, user A, and user B "
            "responses when the engagement provides test credentials or headers.\n"
            "4) Vary one object identifier at a time. Record status code, content length, "
            "stable identifiers, owner fields, and sensitive data type.\n"
            "5) Do not create, update, delete, purchase, invite, export, or trigger workflows "
            "unless explicitly authorized.\n\n"
            "**Phase 3 - Confirm and document**\n"
            "6) A valid finding requires demonstrated cross-user, cross-tenant, or privilege "
            "boundary impact. A 200 response alone is not enough.\n"
            "7) Call sanitize_evidence to redact PII and tokens, then create_finding with the compared requests, "
            "responses, and impact. Save false positives as exhausted notes."
        ),
        "initial_todos": [
            {"description": "Identify endpoints with object IDs or tenant/user identifiers", "status": "pending", "priority": "high"},
            {"description": "Compare read-only responses across available auth contexts", "status": "pending", "priority": "high"},
            {"description": "Confirm cross-user or cross-tenant data access impact", "status": "pending", "priority": "high"},
            {"description": "Create redacted findings or save false-positive notes", "status": "pending", "priority": "medium"},
        ],
    },
    {
        "id": "evidence_hygiene",
        "name": "Evidence hygiene",
        "description": "Redact sensitive evidence while preserving enough proof for triage.",
        "objective": (
            "Review and sanitize finding evidence before it is submitted or reported.\n\n"
            "**Phase 1 - Identify sensitive material**\n"
            "1) Inspect the provided finding/evidence and any related notes. Identify session "
            "cookies, bearer tokens, API keys, auth codes, passwords, private keys, emails, "
            "phone numbers, SSNs, payment data, full database rows, and unnecessary response bodies.\n\n"
            "**Phase 2 - Redact safely**\n"
            "2) Replace secrets with stable placeholders such as [REDACTED_TOKEN], "
            "[REDACTED_COOKIE], [REDACTED_EMAIL], or partial fingerprints like akia...last4 "
            "when needed to show credential type without exposing value.\n"
            "3) Preserve proof structure: endpoint, method, status code, affected field names, "
            "data type, tenant/user boundary, short snippet, and reproduction steps.\n\n"
            "**Phase 3 - Save clean evidence**\n"
            "4) Call sanitize_evidence on raw evidence. If a finding already exists, summarize "
            "the sanitized evidence for the user. If creating a new finding, use create_finding "
            "only with redacted evidence.\n"
            "5) Save the redaction rationale with save_note(category='artifact') when useful."
        ),
        "initial_todos": [
            {"description": "Inspect evidence for cookies, tokens, secrets, and PII", "status": "pending", "priority": "high"},
            {"description": "Redact sensitive values while preserving proof structure", "status": "pending", "priority": "high"},
            {"description": "Prepare sanitized evidence for finding/report use", "status": "pending", "priority": "medium"},
        ],
    },
    {
        "id": "llm_red_team",
        "name": "AI/LLM Red Team Assessment",
        "description": "Security assessment of chatbots and AI-powered endpoints: discover, test, and report AI-specific vulnerabilities.",
        "objective": (
            "Perform an AI/LLM red team security assessment against the target application. "
            "Follow the OWASP Top 10 for LLM Applications methodology:\n\n"
            "**Phase 1 — Reconnaissance & Endpoint Discovery**\n"
            "1) Use execute_httpx to probe the target for live web services and technologies.\n"
            "2) Use execute_katana to crawl the target and discover API endpoints, chat widgets, and JavaScript references to AI/chatbot functionality.\n"
            "3) Look for indicators of chatbot presence: /api/chat, /api/message, /api/ask, /api/completions, WebSocket upgrade headers, "
            "references to OpenAI/Anthropic/LangChain in JavaScript, chat widget iframes, or Intercom/Drift/Zendesk AI integrations.\n\n"
            "**Phase 2 — Chatbot Endpoint Validation**\n"
            "4) If chat endpoints are found, use execute_curl to send a test message ('Hello') and confirm the endpoint responds like an AI chatbot.\n"
            "5) Identify the API contract: request format (JSON field name for messages), authentication requirements, response structure.\n\n"
            "**Phase 3 — Automated Red Team Testing**\n"
            "6) Run execute_llm_red_team against confirmed chatbot/agent endpoints. "
            "For tool-using agents, start with tool_enumeration (AI port scan), then other categories:\n"
            "   - tool_enumeration: List tools/schemas; abuse email→phishing, refund→fraud, "
            "DB→exfil; parameter abuse (user_id→IDOR, send_now→immediate action)\n"
            "   - prompt_injection: Can the system prompt be overridden?\n"
            "   - system_prompt_leakage: Can hidden instructions be extracted?\n"
            "   - data_exfiltration: Can PII or internal data be leaked?\n"
            "   - jailbreak: Can safety filters be bypassed?\n"
            "   - ssrf_tool_abuse: Can the chatbot be used for SSRF (cloud metadata, localhost)?\n"
            "   - excessive_agency: Will it perform unauthorized actions?\n"
            "   - hallucination: Does it fabricate security-relevant information?\n"
            "   - harmful_content: Will it generate malicious code or phishing content?\n\n"
            "**Phase 4 — Analysis & Reporting**\n"
            "7) Review results. For each failed test (vulnerability found), create_finding with:\n"
            "   - Title referencing the OWASP LLM category\n"
            "   - CWE ID from the test payload\n"
            "   - Evidence showing the prompt sent and response received\n"
            "   - Specific remediation steps\n"
            "8) Summarize: total endpoints tested, test categories, pass/fail rates, risk score, and prioritized remediation.\n\n"
            "IMPORTANT: execute_llm_red_team auto-creates findings, so don't duplicate them with create_finding unless you have additional manual observations.\n\n"
            "**Phase 5 — Deep Probe with Garak (optional)**\n"
            "9) If execute_llm_red_team finds confirmed chatbot endpoints, run execute_garak for a broader sweep:\n"
            "   - Use --target_type rest with the confirmed API endpoint URL.\n"
            "   - Recommended probes: 'dan,promptinject,encoding,jailbreak,malwaregen,leakreplay,packagehallucination,xss'.\n"
            "   - Set --report_prefix /tmp/garak_<target> to retrieve the JSONL output.\n"
            "10) Parse FAIL lines from the garak report and create_finding for any new vulnerabilities not already captured.\n"
            "11) Cross-reference garak probe names with OWASP LLM Top 10 categories in your final summary."
        ),
        "initial_todos": [
            {"description": "Probe target with HTTPX and crawl with Katana to find chat/AI endpoints", "status": "pending", "priority": "high"},
            {"description": "Validate discovered endpoints with curl test messages", "status": "pending", "priority": "high"},
            {"description": "Run execute_llm_red_team against confirmed chatbot endpoints", "status": "pending", "priority": "high"},
            {"description": "Review results and create findings for any manual observations", "status": "pending", "priority": "medium"},
            {"description": "Run execute_garak for deep probe sweep (dan, promptinject, encoding, jailbreak probes)", "status": "pending", "priority": "medium"},
            {"description": "Generate final report with OWASP LLM Top 10 mapping and remediation", "status": "pending", "priority": "medium"},
        ],
    },
    {
        "id": "finding_validation",
        "name": "Finding validation (7-Question Gate)",
        "description": "Score a proposed finding through 7 criteria before reporting to eliminate weak, theoretical, and duplicate submissions.",
        "objective": (
            "Validate one or more proposed findings using the 7-Question Gate.\n\n"
            "**Phase 1 — Score the finding**\n"
            "1) Call validate_finding(title, description, severity, target, evidence) for each finding.\n"
            "2) Report the score and verdict: SUBMIT (6-7/7), IMPROVE (3-5/7), DROP (0-2/7).\n\n"
            "**Phase 2 — Address gaps (IMPROVE verdict)**\n"
            "3) For each failing question, explain to the user what evidence or language is missing.\n"
            "4) If evidence is missing: use execute_curl, execute_browser, or the appropriate injection "
            "tool to generate a concrete PoC request/response.\n"
            "5) Re-run validate_finding once the gaps are addressed.\n\n"
            "**Phase 3 — Surface follow-on opportunities**\n"
            "6) For any SUBMIT finding, call detect_bug_chains(vuln_type=<confirmed_type>) to "
            "identify what else to test that commonly chains with this vulnerability.\n"
            "7) Save chain recommendations with save_note(category='artifact').\n\n"
            "IMPORTANT: Never create_finding for a DROP verdict. Only create_finding after SUBMIT."
        ),
        "initial_todos": [
            {"description": "Run validate_finding on the proposed finding(s)", "status": "pending", "priority": "high"},
            {"description": "Address failing questions if IMPROVE verdict", "status": "pending", "priority": "high"},
            {"description": "Run detect_bug_chains on confirmed findings", "status": "pending", "priority": "medium"},
            {"description": "Create findings only for SUBMIT verdicts", "status": "pending", "priority": "high"},
        ],
    },
    {
        "id": "chain_detection",
        "name": "Bug chain detection",
        "description": "Given a confirmed vulnerability, surface follow-on bug classes that commonly chain with it and attempt to validate the highest-impact chains.",
        "objective": (
            "Discover and validate vulnerability chains from a confirmed finding.\n\n"
            "**Phase 1 — Map chain candidates**\n"
            "1) Call detect_bug_chains(vuln_type=<confirmed_type>, target=<target>) to get "
            "ranked chain candidates with severity and attack path explanations.\n"
            "2) Review the CRITICAL and HIGH chain candidates first.\n\n"
            "**Phase 2 — Validate top chains**\n"
            "3) For SSRF chains: test cloud metadata access (169.254.169.254), internal ports.\n"
            "4) For XSS chains: check for missing HttpOnly, test cookie exfiltration path.\n"
            "5) For SQLi chains: test authentication bypass, attempt data extraction.\n"
            "6) For IDOR chains: vary object IDs, compare cross-user responses.\n"
            "7) Use the tool most appropriate for each chain (execute_curl, execute_browser, "
            "execute_sqlmap, execute_nuclei, etc.).\n\n"
            "**Phase 3 — Document chains**\n"
            "8) For each confirmed chain, call create_finding with evidence and reference to "
            "the original finding.\n"
            "9) Save the chain map with save_note(category='artifact') for the report."
        ),
        "initial_todos": [
            {"description": "Call detect_bug_chains for the confirmed vulnerability", "status": "pending", "priority": "high"},
            {"description": "Validate CRITICAL chain candidates", "status": "pending", "priority": "high"},
            {"description": "Validate HIGH chain candidates", "status": "pending", "priority": "medium"},
            {"description": "Create findings for confirmed chains", "status": "pending", "priority": "high"},
        ],
    },
    {
        "id": "bypass_403",
        "name": "403 / 401 access bypass",
        "description": "Enumerate restricted endpoints and test header tricks, path normalization, and method overrides to bypass access controls.",
        "objective": (
            "Find and bypass access-restricted endpoints.\n\n"
            "**Phase 1 — Find restricted endpoints**\n"
            "1) Use execute_katana to crawl the target and identify endpoints.\n"
            "2) Use execute_ffuf with a common paths wordlist to discover hidden endpoints.\n"
            "3) Review responses — collect all URLs returning 403, 401, or 302.\n\n"
            "**Phase 2 — Attempt bypasses**\n"
            "4) For each 403/401 URL, call bypass_403(url=<restricted_url>).\n"
            "5) Bypass categories tested: IP override headers, path normalization tricks, "
            "HTTP method overrides, and protocol/scheme headers.\n\n"
            "**Phase 3 — Validate and report**\n"
            "6) For any bypass, use execute_curl to confirm the response contents are "
            "sensitive or privileged (not just a 200 with empty body).\n"
            "7) Call detect_bug_chains(vuln_type='broken_auth') for follow-on opportunities.\n"
            "8) Create findings with the bypass header/path as evidence."
        ),
        "initial_todos": [
            {"description": "Enumerate 403/401/302 restricted endpoints via katana + ffuf", "status": "pending", "priority": "high"},
            {"description": "Run bypass_403 on each restricted URL", "status": "pending", "priority": "high"},
            {"description": "Confirm bypass contents are sensitive or privileged", "status": "pending", "priority": "high"},
            {"description": "Create findings for confirmed bypasses", "status": "pending", "priority": "high"},
        ],
    },
    {
        "id": "request_smuggling",
        "name": "HTTP request smuggling",
        "description": "Detect CL.TE, TE.CL, and TE.TE desync vulnerabilities via timing-based probes and differential response analysis.",
        "objective": (
            "Detect and confirm HTTP request smuggling vulnerabilities.\n\n"
            "**Phase 1 — Timing-based detection**\n"
            "1) Call test_request_smuggling(url=target, technique='all').\n"
            "2) A probe that times out (>10 s) indicates a desync condition.\n"
            "3) Note which technique (CL.TE, TE.CL, or TE.TE variant) triggered the timeout.\n\n"
            "**Phase 2 — Differential confirmation**\n"
            "4) Use execute_curl with a crafted request matching the vulnerable technique to "
            "confirm via a differential response (poison the next request).\n"
            "5) If HTTP/2 is supported, test H2.CL and H2.TE downgrade variants manually.\n\n"
            "**Phase 3 — Impact assessment**\n"
            "6) Call detect_bug_chains(vuln_type='request_smuggling') to understand downstream "
            "impact (cache poisoning, auth bypass, XSS).\n"
            "7) Create a HIGH/CRITICAL finding with the timing evidence and technique used.\n\n"
            "CAUTION: Do not attempt to poison real user traffic. Use timing detection only."
        ),
        "initial_todos": [
            {"description": "Run timing-based smuggling probes (CL.TE, TE.CL, TE.TE)", "status": "pending", "priority": "high"},
            {"description": "Confirm with differential curl probe if timing indicates vulnerability", "status": "pending", "priority": "high"},
            {"description": "Run detect_bug_chains for downstream impact mapping", "status": "pending", "priority": "medium"},
            {"description": "Create finding with technique and timing evidence", "status": "pending", "priority": "high"},
        ],
    },
    {
        "id": "cache_poisoning",
        "name": "Web cache poisoning",
        "description": "Probe for unkeyed HTTP headers that are reflected in cached responses, enabling persistent XSS, open redirect, or DoS via cache corruption.",
        "objective": (
            "Detect and confirm web cache poisoning vulnerabilities.\n\n"
            "**Phase 1 — Unkeyed header discovery**\n"
            "1) Call test_cache_poisoning(url=target) to probe all common unkeyed headers with "
            "a canary value and check for reflection in clean (un-poisoned) fetches.\n"
            "2) Review results for 'potentially_poisoned' and 'unkeyed_header_candidates'.\n\n"
            "**Phase 2 — Manual confirmation**\n"
            "3) For confirmed or candidate headers, use execute_curl to manually send the "
            "injected header and then fetch without it — confirm canary appears in cached response.\n"
            "4) Check the Cache-Control, X-Cache, Age, and Vary response headers to understand "
            "the caching behavior and cache TTL.\n\n"
            "**Phase 3 — Impact escalation**\n"
            "5) Escalate: if X-Forwarded-Host is unkeyed, inject a malicious host to test for "
            "open redirect or XSS via poisoned resource URLs.\n"
            "6) Call detect_bug_chains(vuln_type='cache_poisoning') for downstream impact.\n"
            "7) Create a finding with the unkeyed header, canary evidence, and cache headers."
        ),
        "initial_todos": [
            {"description": "Run test_cache_poisoning to find unkeyed headers", "status": "pending", "priority": "high"},
            {"description": "Confirm cache storage of injected values via manual curl", "status": "pending", "priority": "high"},
            {"description": "Escalate impact (XSS, redirect) via poisoned resource injection", "status": "pending", "priority": "medium"},
            {"description": "Create finding with header, evidence, and cache headers", "status": "pending", "priority": "high"},
        ],
    },
    {
        "id": "race_conditions",
        "name": "Race condition testing",
        "description": "Identify TOCTOU flaws in transactions, coupons, balances, and rate limits by firing concurrent requests and observing inconsistent state.",
        "objective": (
            "Detect race conditions in state-changing endpoints.\n\n"
            "**Phase 1 — Identify candidate endpoints**\n"
            "1) Use execute_katana or query_assets to enumerate endpoints.\n"
            "2) Target: coupon/voucher redemption, balance deductions, vote/like counters, "
            "invite/role changes, referral bonuses, order creation, file deduplication.\n\n"
            "**Phase 2 — Concurrent request test**\n"
            "3) Call test_race_condition(url=endpoint, method='POST', concurrency=20, "
            "body={<request_body>}, auth_headers={<auth>}).\n"
            "4) Increase concurrency to 30-50 if initial tests show no effect.\n"
            "5) If a unique field (transaction_id, reference_code) is in the response, "
            "pass it as expected_unique_field to detect duplicate values.\n\n"
            "**Phase 3 — Confirm and document**\n"
            "6) A race condition is confirmed when: multiple success responses are returned, "
            "or a unique field has duplicate values, or state changes exceed expected limits.\n"
            "7) Document with success_count, duplicate field values, and response samples.\n"
            "8) Create a HIGH finding — recommend atomic DB operations or distributed locks."
        ),
        "initial_todos": [
            {"description": "Identify single-use or state-changing endpoints", "status": "pending", "priority": "high"},
            {"description": "Run test_race_condition with concurrency=20", "status": "pending", "priority": "high"},
            {"description": "Confirm state inconsistency (duplicate IDs or multiple successes)", "status": "pending", "priority": "high"},
            {"description": "Create finding with success_count and duplicate value evidence", "status": "pending", "priority": "high"},
        ],
    },
    {
        "id": "saml_sso",
        "name": "SAML / SSO / OAuth attack surface",
        "description": "Discover and probe SAML, OAuth, and OIDC endpoints for signature wrapping, algorithm confusion, open redirect, and misconfiguration.",
        "objective": (
            "Assess the SAML/SSO/OAuth attack surface.\n\n"
            "**Phase 1 — Endpoint discovery and probing**\n"
            "1) Call test_saml_sso(url=target) to run all categories: saml_endpoints, "
            "oauth_bypass, oidc_misconfig, jwt_confusion.\n"
            "2) Review discovered endpoints and any high/critical findings.\n\n"
            "**Phase 2 — Follow up on findings**\n"
            "3) OAuth open redirect: use execute_curl to craft a redirect_uri=https://evil.example.com "
            "and confirm the redirect occurs.\n"
            "4) OIDC alg=none or HS256: manually forge a JWT using the public key as HMAC secret "
            "and test acceptance (use save_note to guide manual test steps).\n"
            "5) If a SAMLResponse is captured from Burp/browser: re-run "
            "test_saml_sso(saml_response_b64=<base64>) to check for signature wrapping.\n\n"
            "**Phase 3 — Document**\n"
            "6) Create findings for: open OAuth redirect, alg=none acceptance, "
            "missing NotOnOrAfter, or multiple Assertion elements.\n"
            "7) Provide platform-specific remediation (strict redirect_uri allowlist, "
            "algorithm enforcement, assertion expiry)."
        ),
        "initial_todos": [
            {"description": "Run test_saml_sso for endpoint discovery and all categories", "status": "pending", "priority": "high"},
            {"description": "Confirm OAuth open redirect with manual curl", "status": "pending", "priority": "high"},
            {"description": "Test JWT algorithm confusion if HS256/alg=none found", "status": "pending", "priority": "high"},
            {"description": "Analyze SAMLResponse if captured (signature wrapping)", "status": "pending", "priority": "medium"},
            {"description": "Create findings with evidence and remediation guidance", "status": "pending", "priority": "high"},
        ],
    },
    {
        "id": "credential_spray",
        "name": "Credential spray (authorized)",
        "description": "Spray targeted credentials against a login endpoint with lockout detection. Requires explicit written authorization.",
        "objective": (
            "Conduct an authorized credential spray test.\n\n"
            "**PRE-FLIGHT: Confirm Authorization**\n"
            "REQUIRED: Ask the user to explicitly confirm they have written permission to test "
            "credentials against this target before proceeding. If not confirmed, stop here.\n\n"
            "**Phase 1 — Identify login endpoint**\n"
            "1) Use execute_httpx, execute_katana, or execute_browser to locate the login form.\n"
            "2) Confirm the HTTP method (POST), endpoint path, username/password field names, "
            "and any CSRF token requirements.\n\n"
            "**Phase 2 — Credential spray**\n"
            "3) Call test_credential_spray(login_url=..., usernames=[...], passwords=[...], "
            "authorized=True, max_attempts=10, delay_seconds=3.0).\n"
            "4) Use a password spray strategy: 1-2 passwords × many usernames (avoids lockout).\n\n"
            "**Phase 3 — Document results**\n"
            "5) If lockout is detected: create a MEDIUM finding — account lockout policy exists "
            "(positive finding) or confirm rate limiting is effective.\n"
            "6) If no lockout detected: create a MEDIUM finding — missing account lockout / "
            "rate limiting on authentication endpoint.\n"
            "7) If hits are found: create CRITICAL finding — valid credentials found. "
            "NEVER log the actual password in the finding; use sanitize_evidence first."
        ),
        "initial_todos": [
            {"description": "Confirm written authorization from user before proceeding", "status": "pending", "priority": "high"},
            {"description": "Locate and confirm login endpoint, field names", "status": "pending", "priority": "high"},
            {"description": "Run test_credential_spray with authorized=True, max_attempts=10", "status": "pending", "priority": "high"},
            {"description": "Document lockout behavior (finding regardless of hits)", "status": "pending", "priority": "medium"},
            {"description": "Create critical finding if valid credentials found (sanitize password)", "status": "pending", "priority": "high"},
        ],
    },
    {
        "id": "dual_identity_authz",
        "name": "Dual-identity authorization matrix",
        "description": (
            "Compare anonymous / user-A / user-B access on object and privileged endpoints "
            "to prove missing auth, IDOR/BOLA, or BFLA with evidence."
        ),
        "objective": (
            "Run a dual-identity authorization matrix on the target.\n\n"
            "**Phase 1 — Collect candidates**\n"
            "1) From recon/notes/Katana/JS, list endpoints with object IDs, tenant IDs, "
            "exports, admin/staff paths, and GraphQL node queries.\n"
            "2) Confirm you have (or request) two distinct low-priv sessions plus ability "
            "to send anonymous requests.\n\n"
            "**Phase 2 — Matrix**\n"
            "3) For each candidate, send the same read-only request as: anonymous, user A, user B.\n"
            "4) Record status, length, owner identifiers, and whether foreign PII/objects appear.\n"
            "5) Classify each row: missing_auth | idor_bola | bfla | no_issue.\n\n"
            "**Phase 3 — Report**\n"
            "6) create_finding only for proven cross-identity or unauth impact.\n"
            "7) sanitize_evidence → validate_finding → detect_bug_chains(vuln_type='idor').\n"
            "8) save_note exhausted endpoints that showed no_issue."
        ),
        "initial_todos": [
            {"description": "Collect object-ID and privileged endpoint candidates", "status": "pending", "priority": "high"},
            {"description": "Obtain or confirm user A / user B auth contexts", "status": "pending", "priority": "high"},
            {"description": "Run anonymous/A/B matrix on each candidate (read-only)", "status": "pending", "priority": "high"},
            {"description": "Create findings for proven missing_auth/IDOR/BFLA only", "status": "pending", "priority": "high"},
        ],
    },
    {
        "id": "nextjs_stack",
        "name": "Next.js stack hunt",
        "description": "Conditional Next.js checks: middleware bypass, image SSRF, Server Actions, ISR cache.",
        "objective": (
            "Hunt Next.js-specific issues only if the target fingerprints as Next.js.\n"
            "1) Confirm /_next/ static assets or Next headers.\n"
            "2) Test middleware auth bypass via static/asset path quirks.\n"
            "3) Probe /_next/image with internal URLs for SSRF (safe canaries).\n"
            "4) Review Server Actions / RSC exposure; ISR cache via unkeyed headers.\n"
            "5) create_finding only with live proof; otherwise save_note no Next.js surface."
        ),
        "initial_todos": [
            {"description": "Confirm Next.js fingerprint", "status": "pending", "priority": "high"},
            {"description": "Test middleware / image / Server Action / cache vectors", "status": "pending", "priority": "high"},
            {"description": "Create findings or note clean Next.js surface", "status": "pending", "priority": "medium"},
        ],
    },
    {
        "id": "springboot_stack",
        "name": "Spring Boot stack hunt",
        "description": "Conditional Spring Boot actuator and related exposure checks.",
        "objective": (
            "Hunt Spring Boot exposures if actuator/Spring signals exist.\n"
            "1) Probe /actuator and common subpaths with GET/HEAD.\n"
            "2) Check env/mappings/gateway/jolokia/h2-console exposure.\n"
            "3) Sanitize any sensitive samples; never attach full heap dumps.\n"
            "4) create_finding for confirmed unauthenticated sensitive exposure."
        ),
        "initial_todos": [
            {"description": "Confirm Spring/actuator signals", "status": "pending", "priority": "high"},
            {"description": "Probe actuator and related consoles safely", "status": "pending", "priority": "high"},
            {"description": "Create redacted findings for confirmed exposures", "status": "pending", "priority": "medium"},
        ],
    },
    {
        "id": "laravel_stack",
        "name": "Laravel stack hunt",
        "description": "Conditional Laravel debug/Telescope/Ignition/signed-URL checks.",
        "objective": (
            "Hunt Laravel-specific issues if Laravel/_ignition/telescope signals exist.\n"
            "1) Check debug mode leakage and Telescope/Horizon auth.\n"
            "2) Version-gate Ignition RCE checks — prove safely or skip.\n"
            "3) Test signed URL tampering and .env exposure paths.\n"
            "4) create_finding only with live evidence."
        ),
        "initial_todos": [
            {"description": "Confirm Laravel fingerprint", "status": "pending", "priority": "high"},
            {"description": "Check debug/Telescope/Ignition/signed URL/.env", "status": "pending", "priority": "high"},
            {"description": "Create findings or note clean Laravel surface", "status": "pending", "priority": "medium"},
        ],
    },
    {
        "id": "spa_api_discovery",
        "name": "SPA → hidden API discovery",
        "description": "Map APIs from JS bundles and validate authz on discovered routes.",
        "objective": (
            "Discover hidden backend APIs from SPA JavaScript and test authorization.\n"
            "1) Gather first-party JS bundles.\n"
            "2) Extract API bases, GraphQL endpoints, and object routes.\n"
            "3) Probe unauthenticated then low-priv.\n"
            "4) Hand object routes to dual-identity matrix / idor-validation.\n"
            "5) Do not report route listing alone — require authz impact."
        ),
        "initial_todos": [
            {"description": "Collect and parse first-party JS for API routes", "status": "pending", "priority": "high"},
            {"description": "Probe discovered APIs unauth and low-priv", "status": "pending", "priority": "high"},
            {"description": "Run dual-identity checks on object routes; create findings", "status": "pending", "priority": "high"},
        ],
    },
    {
        "id": "garak_scan",
        "name": "Garak LLM Vulnerability Scan (NVIDIA)",
        "description": (
            "Deep LLM vulnerability assessment using NVIDIA garak — probes jailbreaks, DAN attacks, "
            "prompt injection, encoding exploits, data leakage, package hallucination, toxicity, "
            "malware generation, and 200+ vulnerability classes across OpenAI, REST, Bedrock, and HF endpoints."
        ),
        "objective": (
            "Perform a deep LLM vulnerability scan using NVIDIA's garak framework.\n\n"
            "**Phase 1 — Pre-flight**\n"
            "1) Run garak_help(topic='probes') to list all available probe modules and confirm garak is installed.\n"
            "2) Determine the target_type:\n"
            "   - REST/HTTP chatbot endpoint → --target_type rest --target_name <full_url>\n"
            "   - OpenAI-compatible API → --target_type openai --target_name <model_name> (set OPENAI_API_KEY)\n"
            "   - AWS Bedrock → --target_type bedrock --target_name <model_id> (set BEDROCK_API_KEY)\n"
            "   - Hugging Face Hub → --target_type huggingface --target_name <model_id>\n"
            "3) Confirm the target responds with a benign 'Hello' message using execute_curl or execute_browser.\n\n"
            "**Phase 2 — Targeted Probe Selection**\n"
            "4) Choose probes based on the threat model. Recommended starting set:\n"
            "   - 'dan' — DAN (Do Anything Now) jailbreak variants\n"
            "   - 'promptinject' — PromptInject framework attacks\n"
            "   - 'encoding' — Base64, rot13, MIME, quoted-printable injection bypasses\n"
            "   - 'jailbreak' — Role-play and context-confusion jailbreaks\n"
            "   - 'malwaregen' — Attempts to generate malware or weaponizable code\n"
            "   - 'leakreplay' — Training data replay / memorization detection\n"
            "   - 'packagehallucination' — Hallucinated npm/PyPI package names (supply-chain risk)\n"
            "   - 'xss' — XSS payload generation via the LLM\n"
            "   - 'lmrc' — Language Model Risk Cards subsample (broad safety)\n"
            "   For a full sweep, omit --probes to run all probes (slow; allow 30+ min).\n\n"
            "**Phase 3 — Run Scan**\n"
            "5) Execute:\n"
            "   execute_garak(args='--target_type <type> --target_name <name> "
            "--probes dan,promptinject,encoding,jailbreak,malwaregen,leakreplay,packagehallucination,xss "
            "--report_prefix /tmp/garak_<target>')\n"
            "6) Monitor stdout progress. garak prints per-probe PASS/FAIL rows with failure rates.\n\n"
            "**Phase 4 — Report Parsing & Findings**\n"
            "7) After the scan completes, read the JSONL report at /tmp/garak_<target>.report.jsonl.\n"
            "   - Lines with 'status': 2 are FAIL (vulnerability confirmed).\n"
            "   - Each entry contains: probe, detector, prompt, response, and hit details.\n"
            "8) For each FAIL entry, call create_finding with:\n"
            "   - Title: 'LLM: <probe_name> — <short description>' (e.g. 'LLM: DAN.Dan_11_0 — Jailbreak via DAN prompt')\n"
            "   - Severity: CRITICAL for jailbreak/malwaregen/data leakage; HIGH for encoding/promptinject; MEDIUM for hallucination\n"
            "   - OWASP LLM mapping:\n"
            "     * dan/jailbreak → LLM01: Prompt Injection\n"
            "     * promptinject → LLM01: Prompt Injection\n"
            "     * encoding → LLM01: Prompt Injection (obfuscated)\n"
            "     * leakreplay → LLM06: Sensitive Information Disclosure\n"
            "     * packagehallucination → LLM09: Misinformation / Supply-Chain Risk\n"
            "     * malwaregen → LLM02: Insecure Output Handling\n"
            "     * xss → LLM02: Insecure Output Handling\n"
            "     * lmrc → LLM08: Excessive Agency / Safety Bypass\n"
            "   - Evidence: the triggering prompt and model response (redacted per evidence-hygiene policy)\n"
            "   - Remediation: output filtering, system prompt hardening, input validation, RLHF/guardrails\n"
            "9) De-duplicate: if execute_llm_red_team was already run, only create findings for probe classes "
            "not already captured (encoding, DAN, leakreplay, packagehallucination are typically garak-unique).\n\n"
            "**Phase 5 — Summary**\n"
            "10) Output a table: probe module | total attempts | failures | failure rate | OWASP category.\n"
            "11) Prioritize remediations by severity and include garak probe references for the development team."
        ),
        "initial_todos": [
            {"description": "Run garak_help to confirm installation and list available probes", "status": "pending", "priority": "high"},
            {"description": "Confirm target type (rest/openai/bedrock/huggingface) and validate connectivity", "status": "pending", "priority": "high"},
            {"description": "Run execute_garak with targeted probe set (dan, promptinject, encoding, jailbreak, malwaregen, leakreplay, packagehallucination, xss)", "status": "pending", "priority": "high"},
            {"description": "Parse JSONL report for FAIL entries and map to OWASP LLM Top 10", "status": "pending", "priority": "high"},
            {"description": "Create findings for each confirmed vulnerability class", "status": "pending", "priority": "high"},
            {"description": "Generate final summary table with probe results and prioritized remediations", "status": "pending", "priority": "medium"},
        ],
    },
]


def get_playbook(playbook_id: str) -> Optional[Dict[str, Any]]:
    """Return preset by id or None."""
    for p in PLAYBOOKS:
        if p["id"] == playbook_id:
            return p
    return None


def list_playbooks() -> List[Dict[str, Any]]:
    """Return list of { id, name, description } for UI."""
    return [
        {"id": p["id"], "name": p["name"], "description": p["description"]}
        for p in PLAYBOOKS
    ]


def build_initial_objective(playbook_id: str, target: Optional[str] = None) -> tuple:
    """
    Build (objective_string, initial_todos) for the given preset and optional target.
    Returns (objective, initial_todos); objective includes target line if target is set.
    """
    p = get_playbook(playbook_id)
    if not p:
        return ("", [])
    objective = p["objective"]
    if target and target.strip():
        objective = f"{objective}\n\nTarget: {target.strip()}"
    return (objective, p.get("initial_todos", []))
