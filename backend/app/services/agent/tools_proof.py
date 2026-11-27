"""Finding validation gate, bug chains, evidence, candidates and independent verify.

Mixin for ASMToolsManager; methods moved verbatim from tools.py.
"""

from app.services.agent.tools_common import (
    Any,
    Dict,
    List,
    Optional,
    _tool_output_max_chars,
    json,
)


class ProofToolsMixin:
    """Finding validation gate, bug chains, evidence, candidates and independent verify."""

    # ──────────────────────────────────────────────────────────────────────
    # Bug chain lookup table: confirmed_vuln → likely follow-on vulns
    # ──────────────────────────────────────────────────────────────────────
    _BUG_CHAINS: Dict[str, List[Dict[str, str]]] = {
        "ssrf": [
            {"vuln": "Cloud Metadata Exfiltration", "severity": "critical", "why": "SSRF reaches AWS/GCP/Azure metadata endpoints exposing IAM credentials."},
            {"vuln": "Internal Network Pivot (Redis, Elasticsearch, Jenkins)", "severity": "high", "why": "SSRF pivots to unauthenticated internal services."},
            {"vuln": "SSRF → RCE via internal Consul/Kubernetes API", "severity": "critical", "why": "Internal orchestration APIs often have no auth."},
            {"vuln": "SSRF via PDF/Image renderer → LFI (file:// scheme)", "severity": "high", "why": "wkhtmltopdf / Headless Chrome server-side renderers follow file:// URIs."},
        ],
        "xss": [
            {"vuln": "Account Takeover via Cookie Theft", "severity": "high", "why": "Stored XSS + document.cookie exfil = ATO when HttpOnly is absent."},
            {"vuln": "CSRF via XSS (SameSite bypass)", "severity": "high", "why": "In-browser execution bypasses SameSite cookie restrictions for CSRF."},
            {"vuln": "Admin Privilege Escalation via Admin-visible XSS", "severity": "critical", "why": "XSS in admin panel can create new admins or dump secrets."},
            {"vuln": "postMessage Hijacking (DOM XSS)", "severity": "medium", "why": "Insecure postMessage listeners amplify DOM XSS to cross-origin data theft."},
        ],
        "sqli": [
            {"vuln": "Authentication Bypass", "severity": "critical", "why": "OR-based SQLi in login forms defeats authentication entirely."},
            {"vuln": "PII / Credential Exfiltration", "severity": "critical", "why": "UNION or error-based SQLi dumps user tables and password hashes."},
            {"vuln": "File Read/Write → RCE (MySQL LOAD/INTO OUTFILE)", "severity": "critical", "why": "MySQL FILE privilege with misconfigured secure_file_priv allows shell upload."},
            {"vuln": "Second-Order SQLi", "severity": "high", "why": "Payload stored in DB, triggered on a later query — bypasses most scanners."},
        ],
        "idor": [
            {"vuln": "Mass Account Enumeration", "severity": "high", "why": "Sequential/predictable IDs allow scraping all user records."},
            {"vuln": "Privilege Escalation to Admin", "severity": "critical", "why": "Accessing admin-role object IDs or manipulating role fields."},
            {"vuln": "Private File / Document Disclosure", "severity": "high", "why": "IDOR on file IDs leaks contracts, PII, medical records."},
            {"vuln": "IDOR + Mass Assignment → Account Takeover", "severity": "critical", "why": "Combining writable user fields with IDOR enables full ATO."},
        ],
        "open_redirect": [
            {"vuln": "OAuth Access Token Theft via redirect_uri", "severity": "high", "why": "Open redirect in redirect_uri leaks OAuth tokens to attacker."},
            {"vuln": "Phishing / Credential Harvesting", "severity": "medium", "why": "Trusted-domain redirect enables convincing phishing pages."},
            {"vuln": "SSRF via server-side redirect following", "severity": "high", "why": "If the server follows the redirect, it becomes an SSRF pivot."},
        ],
        "xxe": [
            {"vuln": "LFI via XXE (file:// entity)", "severity": "high", "why": "XXE reads /etc/passwd, ~/.aws/credentials, app config files."},
            {"vuln": "SSRF via XXE (http:// entity)", "severity": "high", "why": "XXE forces internal HTTP requests — same impact as SSRF."},
            {"vuln": "Blind XXE via OOB DNS / HTTP callback", "severity": "high", "why": "Error-blind XXE exfiltrates data through DNS or HTTP callbacks."},
            {"vuln": "XXE → RCE via PHP expect:// or phar:// wrapper", "severity": "critical", "why": "PHP stream wrappers convert XXE into code execution on legacy stacks."},
        ],
        "lfi": [
            {"vuln": "Log Poisoning → RCE", "severity": "critical", "why": "Include access.log after injecting PHP into User-Agent → RCE."},
            {"vuln": "SSH Key / Credential Disclosure", "severity": "high", "why": "LFI of ~/.ssh/id_rsa or /etc/shadow leaks credentials."},
            {"vuln": "PHP Session File Disclosure", "severity": "high", "why": "LFI of /tmp/sess_<token> discloses active PHP sessions."},
            {"vuln": "LFI → RCE via phar:// / zip:// wrapper", "severity": "critical", "why": "PHP stream wrappers escalate file inclusion to code execution."},
        ],
        "csrf": [
            {"vuln": "Account Takeover via Password/Email Change", "severity": "high", "why": "CSRF on password-change or email-update = ATO."},
            {"vuln": "Admin Action Execution", "severity": "high", "why": "CSRF on admin-only actions when admin visits attacker-controlled page."},
            {"vuln": "SSRF via CSRF (server-side request forgery chain)", "severity": "high", "why": "CSRF on an SSRF-prone action chains into SSRF impact."},
        ],
        "broken_auth": [
            {"vuln": "Account Takeover via Password Reset Flaw", "severity": "critical", "why": "Weak tokens, host-header injection in reset link, or token reuse."},
            {"vuln": "MFA Bypass", "severity": "high", "why": "Missing MFA on API endpoints or OTP brute-force with no rate limiting."},
            {"vuln": "Session Fixation", "severity": "high", "why": "Token not rotated on login/logout allows session fixation attack."},
            {"vuln": "JWT Algorithm Confusion (RS256 → HS256)", "severity": "critical", "why": "RS256 public key used as HS256 HMAC secret forges arbitrary tokens."},
        ],
        "rce": [
            {"vuln": "Reverse Shell / C2 Persistence", "severity": "critical", "why": "RCE enables persistent foothold and lateral movement."},
            {"vuln": "Credential Harvesting from Config / Env Vars", "severity": "critical", "why": "DB credentials, API keys, k8s secrets are trivially readable."},
            {"vuln": "Cloud Metadata → IAM Privilege Escalation", "severity": "critical", "why": "EC2/GCP instance metadata provides IAM role credentials."},
            {"vuln": "Container Escape (privileged / CAP_SYS_ADMIN)", "severity": "critical", "why": "Privileged Docker container or host-mounted socket → host escape."},
        ],
        "mass_assignment": [
            {"vuln": "Privilege Escalation (role = admin)", "severity": "critical", "why": "Mass-assigning the role field promotes any user to admin."},
            {"vuln": "Account Balance / Credits Manipulation", "severity": "critical", "why": "Assigning balance/credits field bypasses payment logic."},
            {"vuln": "Email Takeover via email field assignment", "severity": "high", "why": "Overwriting email field hijacks the account without a reset flow."},
            {"vuln": "DRF/OpenAPI writable id/created across CRUD serializers", "severity": "high", "why": "Request schemas without readOnly on id/created enable resource overwrite via ID collision. Schema proof is enough if the DB is down."},
            {"vuln": "Writable user/owner on group/asset create", "severity": "critical", "why": "Any authenticated user can assign ownership to an arbitrary user (cross-user mass assignment)."},
            {"vuln": "List endpoints with no tenant isolation", "severity": "critical", "why": "Operation text like 'shared across all users' means every registrant sees the same object hierarchy."},
            {"vuln": "Writable schedule/periodic_task on monitoring assets", "severity": "high", "why": "Unauthorized task scheduling on ICS/OT monitoring assets. Prove via schema; do not enable production schedules."},
            {"vuln": "Unauth GET /api/auth/account/?email= (security: {} + role leak)", "severity": "critical", "why": "Same schema often marks account lookup public. 500 vs sibling 401 proves JWT was skipped. One canary email; do not spray."},
        ],
        "unauth_account_lookup": [
            {"vuln": "Schema-documented public account lookup (security: {} + is_staff/role)", "severity": "critical", "why": "OpenAPI marks GET /api/auth/account/ unauthenticated and the UserAccount model returns email, is_active, valid_through, is_staff, role."},
            {"vuln": "JWT bypass proven by 401 siblings vs 500/200 lookup", "severity": "critical", "why": "Protected /api/auth/profile/ and /users/me/ return 401 without a token. The lookup reaches app code (200 or 500). A down database is not a kill."},
            {"vuln": "Privilege-targeted credential attacks", "severity": "high", "why": "Enumerating is_staff/role lets an attacker aim password attacks at admin/maintainer accounts. One canary email only — do not spray employee inboxes or dump ICS users."},
        ],
        "unauth_settings_write": [
            {"vuln": "Unauth POST /api/Settings/SaveSettings accepted (ASP.NET void 200)", "severity": "high", "why": "Missing [Authorize] on SettingsController. Paired proof: sibling write (TaskAdmin/UpdateTask) returns 401 without a token; SaveSettings returns 200 Content-Length: 0. Any internet user can overwrite org-wide config."},
            {"vuln": "Sibling controllers also skip auth middleware", "severity": "high", "why": "The same missing-attribute pattern usually hits LogQuery, Audit, ReadTasks, OpenDocument, Metadata. Probe unauth; file separately if they process without 401. Empty arrays and Graph-downstream 500s are missing-auth, not this write."},
            {"vuln": "Authenticated non-admin can still SaveSettings (BFLA)", "severity": "high", "why": "Class-level [Authorize] without Roles=Admin still lets any logged-in user change notifications, Planner flags, PowerBI report IDs, and arbitrary key/value settings."},
            {"vuln": "Canary key persisted / production flags mutated", "severity": "high", "why": "If SaveSettings replaces the collection, a one-item canary body can wipe production settings. Confirm merge vs replace; restore if needed. Do not flip enableNotifications/createPlannerTasks/powerBIReportId."},
        ],
        "email_change_ato": [
            {"vuln": "Unauth POST reset_email 204 while set_password 401s", "severity": "high", "why": "djoser reset_email skips JWT. The remaining control is a token mailed to the attacker-controlled address. One canary; do not complete ATO on a real mailbox."},
            {"vuln": "reset_email_confirm uid enumeration (MQ = user 1)", "severity": "high", "why": "Confirm locates the user without a session. Existing ids return 'Invalid token for given user'; missing ids return 'Invalid user id'. 2–4 uids max."},
            {"vuln": "No rate-limit / lockout on email-change", "severity": "medium", "why": "Bounded 8 unauth reset_email posts with no 429 lets an attacker spray mailbox changes. Do not hydra; do not hit employee inboxes."},
        ],
        "auth_header_bypass": [
            {"vuln": "OIDC/JWT middleware skipped when Authorization is absent", "severity": "high", "why": "ByPassAuthorization / fail-open: no-header reaches the controller (200/400) while invalid Bearer is 401. 400 missing-params is still a bypass."},
            {"vuln": "Always-open mutating sibling (Notes / UpdateNote)", "severity": "high", "why": "Some controllers skip auth even with an invalid Bearer. Empty/canary body only; do not mutate production rows."},
        ],
        "socketio_idor": [
            {"vuln": "Anonymous get_stream returns url_key for fabricated siteId", "severity": "high", "why": "No server-side authz on siteId/analyzerId. Do not fetch the video stream. Do not send null crash loops against ICS."},
            {"vuln": "Socket.IO CORS + hardcoded Admin params in client JS", "severity": "high", "why": "ACAO+credentials on /socket.io/ plus hardcoded siteId/userType=Admin. Queue cors_credentials and js_secrets. Do not dump footage."},
        ],
        "ml_pipeline_rbac": [
            {"vuln": "Self-reg JWT can POST train or DELETE celery-task", "severity": "high", "why": "Authentication without authorization. Do not delete production models; one canary train or OPTIONS/authz probe."},
            {"vuln": "Celery / optimize queue injection as any registrant", "severity": "high", "why": "BFLA after open signup. Do not inject pickle/code. Record 202 vs 403."},
        ],
        "business_logic": [
            {"vuln": "Race Condition on Transaction / Balance", "severity": "high", "why": "Concurrent requests exploit TOCTOU in balance/inventory checks."},
            {"vuln": "Negative Price / Discount Stacking", "severity": "high", "why": "Missing input validation on price/discount fields."},
            {"vuln": "Order State Skip (unpaid → shipped)", "severity": "medium", "why": "Manipulating workflow state variables skips payment enforcement."},
        ],
        "subdomain_takeover": [
            {"vuln": "Cookie Tossing / Session Hijacking", "severity": "high", "why": "Taken-over subdomain sets cookies for the parent domain."},
            {"vuln": "Phishing via Trusted Company Subdomain", "severity": "medium", "why": "Company subdomain used for convincing phishing campaigns."},
            {"vuln": "CSP Whitelist Bypass", "severity": "medium", "why": "Subdomain in CSP whitelist — takeover bypasses Content Security Policy."},
        ],
        "cache_poisoning": [
            {"vuln": "Stored XSS via Cached Response", "severity": "high", "why": "Poisoned cache serves malicious payload to all visitors of the page."},
            {"vuln": "Denial of Service via Cache Corruption", "severity": "medium", "why": "Injecting error responses into cache causes widespread availability issues."},
            {"vuln": "Open Redirect via X-Forwarded-Host", "severity": "medium", "why": "Poisoned redirect target serves attacker-controlled redirect to all users."},
        ],
        "request_smuggling": [
            {"vuln": "Cache Poisoning via Smuggled Poison", "severity": "high", "why": "Smuggled poison request poisons the cache for subsequent victims."},
            {"vuln": "Authentication Bypass via Smuggled Prefix", "severity": "critical", "why": "Prefix injected by smuggling rewrites the next victim's request."},
            {"vuln": "XSS via Smuggled Reflected Content", "severity": "high", "why": "Reflected content from smuggled request executes in victim's browser."},
            {"vuln": "Internal Service Access via Smuggling", "severity": "high", "why": "Smuggled request routes to internal endpoints not exposed externally."},
        ],
        "host_header": [
            {"vuln": "Password Reset Poisoning → ATO", "severity": "critical", "why": "Reset email absolute URL uses attacker Host / X-Forwarded-Host."},
            {"vuln": "Host-Header Tenant Isolation Bypass", "severity": "critical", "why": "Same session + peer-tenant Host/X-Forwarded-Host returns other tenant data."},
            {"vuln": "Web Cache Poisoning via Unkeyed Host", "severity": "high", "why": "Host influences cache key inconsistently across layers."},
            {"vuln": "Routing SSRF", "severity": "high", "why": "Host selects upstream → internal service or metadata access."},
        ],
        "default_login": [
            {"vuln": "Grafana Admin Settings / Service-Account Enum", "severity": "critical", "why": "Server Admin GET /api/admin/settings and /api/serviceaccounts/search disclose pod identity, DB config, and API token inventory."},
            {"vuln": "Grafana Existing Prometheus Datasource Proxy → Cluster Topology", "severity": "critical", "why": "Relay PromQL via the existing kube-prometheus-stack datasource (/api/datasources/proxy) to enumerate in-cluster exporters and kubelets — no new datasource required."},
            {"vuln": "CouchDB _config Secret + Admin Salt Exposure", "severity": "critical", "why": "GET /_node/_local/_config returns couch_httpd_auth.secret, timeout, and [admins] salts — the HMAC inputs for AuthSession. Survives password rotation."},
            {"vuln": "CouchDB AuthSession Cookie Forgery", "severity": "critical", "why": "HMAC-SHA1(secret+admin_salt) forges a valid AuthSession for any server admin without their password; prove via /_session _admin + /_all_dbs."},
            {"vuln": "Grafana CVE-2024-9264 SQL expressions (Viewer+)", "severity": "critical", "why": "POST /api/ds/query type=sql forks DuckDB. Missing binary still confirms the vulnerable path; sqlExpressions=0 in /metrics does not disable the backend. Patch is 11.2.2+."},
            {"vuln": "Grafana Datasource-Proxy SSRF → Internal AKS/K8s", "severity": "critical", "why": "If no existing Prometheus DS: Server Admin can create one pointing at kubernetes.default.svc / metadata when whitelist is empty."},
            {"vuln": "Admin API / Config Abuse", "severity": "critical", "why": "Admin session can change auth, datasources, or exfil secrets."},
            {"vuln": "Privilege Persistence", "severity": "high", "why": "Create backdoor users/tokens before password change."},
        ],
        "elasticsearch_unauth": [
            {"vuln": "Cluster/node metadata disclosure", "severity": "critical", "why": "Unauth GET /_cluster/health and /_nodes/os,jvm disclose hostname, OS, kernel, JVM."},
            {"vuln": "Index enumeration + sample read", "severity": "critical", "why": "Unauth GET /_cat/indices plus size=1 sample of user indices (prompts, chat, ransomware notes). Do not dump all docs."},
            {"vuln": "Arbitrary write via test index", "severity": "critical", "why": "PUT then DELETE aegis_test_index proves create/delete without credentials. Do not write into customer indices."},
            {"vuln": "Prior compromise / ransomware note", "severity": "high", "why": "User indices named read_me often contain extortion notes — evidence the cluster was already hit."},
        ],
        "arangodb_default": [
            {"vuln": "ArangoDB collection sample / PII", "severity": "critical", "why": "root JWT lists databases; one collection sample proves read of registration/Cookie_Data without dumping PII."},
        ],
        "mongodb_unauth": [
            {"vuln": "MongoDB listDatabases + ransomware-note integrity", "severity": "critical", "why": "Anonymous listDatabases; READ_ME_TO_RECOVER_YOUR_DATA means prior compromise."},
        ],
        "emqx_default": [
            {"vuln": "EMQX authn/plugin admin", "severity": "critical", "why": "admin:public unlocks listeners, users, and plugin upload — do not upload plugins."},
        ],
        "cors_credentials": [
            {"vuln": "CORS ACAO reflection + credentials=true", "severity": "critical", "why": "Arbitrary Origin echoed with Access-Control-Allow-Credentials: true lets attacker JS read cookie-authenticated responses. Header proof is enough; no victim tab required."},
            {"vuln": "Keycloak webOrigins=* on token/userinfo/admin", "severity": "critical", "why": "IdP CORS on /auth/realms/*/protocol/openid-connect/* and /auth/admin/realms/* exposes userinfo claims and admin user/client APIs to any website. Fix: webOrigins explicit or '+', never '*'."},
            {"vuln": "Preflight allows Authorization + POST/PUT/DELETE from any origin", "severity": "high", "why": "OPTIONS from a canary origin is approved with Authorization in Allow-Headers."},
            {"vuln": "Socket.IO unauth get_stream IDOR", "severity": "high", "why": "After ACAO+credentials, get_stream accepts empty userType and arbitrary siteId."},
        ],
        "keycloak_password_grant": [
            {"vuln": "admin-cli public client + password grant", "severity": "critical", "why": "grant_type=password with client_id=admin-cli and no client_secret returns invalid_grant, not invalid_client. Master tokens are full realm-admin."},
            {"vuln": "No brute-force detection on the token endpoint", "severity": "critical", "why": "Bounded failed password-grant attempts are all processed with no 429 or lockout. Do not hydra; 8 attempts is enough proof."},
            {"vuln": "CORS compounds browser credential stuffing", "severity": "high", "why": "Filed separately: ACAO+credentials on the token endpoint lets a malicious page submit password grants."},
        ],
        "client_role_param": [
            {"vuln": "Cross-tenant inventory via userType=Admin", "severity": "critical", "why": "publicPortal trusts client userType; Admin returns the full site list."},
        ],
        "vendorjson_unauth": [
            {"vuln": "Internal IP / SuperRegulator map", "severity": "high", "why": "vendorJson discloses userId, roles, and RFC1918 addresses for every tenant."},
        ],
        "auth0_mgmt_token": [
            {"vuln": "Auth0 user/client directory read", "severity": "critical", "why": "Unauth token is accepted by /api/v2 with read:users/read:clients — prove with per_page=1."},
        ],
        "gitlab_unauth": [
            {"vuln": "Hardcoded secrets in public GitLab files", "severity": "critical", "why": "Unauth /api/v4/projects then one-file sample for passwords/keys."},
        ],
        "docker_registry": [
            {"vuln": "ACR/Docker anonymous catalog listing", "severity": "high", "why": "Anonymous oauth2 token (registry:catalog:*) plus /v2/_catalog returns first-party repository names. Do not push."},
            {"vuln": "Secrets in anonymously pullable images (lockfile PAT / history)", "severity": "critical", "why": "Bounded 1–3 tag config/history or package-lock.json git+https PATs. ghp_* with repo/workflow/admin is Critical. Do not pull the whole catalog; do not authenticate recovered tokens."},
            {"vuln": "Recurring ghs_* leak from copying .git into the image", "severity": "high", "why": "Expired GitHub App installation tokens in extraheader prove every new build ships a fresh short-TTL token."},
            {"vuln": "Internal-only Artifactory/NATS/Keycloak strings in image history", "severity": "high", "why": "Rotate even if the host does not resolve on the public internet. Do not hunt internal services from outside."},
        ],
        "django_debug": [
            {"vuln": "Leaked Redis key from DEBUG traceback", "severity": "critical", "why": "admin:admin + DEBUG=True 500 dumps Azure Redis and env; ping only, no FLUSHALL."},
        ],
        "openai_proxy_unauth": [
            {"vuln": "Unauth model spend / tool execution", "severity": "high", "why": "POST /api/chat proxies to Azure OpenAI with no session — one canary then stop."},
        ],
        "wiki_open_reg": [
            {"vuln": "Self-registered wiki write / internal PII", "severity": "high", "why": "Open CreateAccount grants sandbox write or internal page read — do not deface production."},
        ],
        "binary_hardcoded_creds": [
            {"vuln": "Production password in public installer/firmware", "severity": "critical", "why": "strings extracts live creds; prove one in-scope login. Do not reverse for exploits."},
        ],
        "client_side_auth": [
            {"vuln": "Admin/eLogbook API without server session", "severity": "critical", "why": "JS-only isAdmin/userType gate; backing API returns privileged records anonymously."},
        ],
        "saml": [
            {"vuln": "Account Takeover via Assertion Tampering", "severity": "critical", "why": "Unsigned or wrapped assertions change NameID to victim."},
            {"vuln": "SSO Privilege Escalation", "severity": "critical", "why": "Group/role attributes accepted without signature validation."},
            {"vuln": "Metadata XXE / SSRF", "severity": "high", "why": "IdP metadata fetch parses attacker XML or URLs."},
        ],
        "graphql": [
            {"vuln": "BOLA via node(id) / global IDs", "severity": "high", "why": "GraphQL object IDs lack field-level authz."},
            {"vuln": "Auth Bypass Mutation", "severity": "critical", "why": "Unauth mutations change email/password/role."},
            {"vuln": "Batching / Alias Rate-Limit Bypass", "severity": "medium", "why": "Aliased queries evade per-request throttles."},
        ],
        "js_secrets": [
            {"vuln": "Hostname-keyed client_id/client_secret in Next.js chunks", "severity": "critical", "why": "Admin/sandbox /_next/static/chunks often embed prod/dev/qa OAuth client secrets keyed by hostname."},
            {"vuln": "Live IAM/API gateway access with leaked headers", "severity": "critical", "why": "client_id/client_secret HTTP headers authenticate to locations/account APIs and return non-public records."},
            {"vuln": "Cross-environment secret reuse (sandbox ships prod)", "severity": "critical", "why": "A sandbox UI bundle that contains production client_secret requires rotating ALL env pairs, not just sandbox."},
            {"vuln": "Bulk enumeration via search/queryText", "severity": "high", "why": "Authenticated search parameters enable targeted or bulk record retrieval — prove with a bounded sample, then recommend rate limits."},
            {"vuln": "EmailJS unauthorized send (phishing via authorized ESP)", "severity": "critical", "why": "Hardcoded EmailJS user_id/service_id/template_id in JS lets any site send mail as the app from a visitor's browser; template_params set the recipient. File Critical, not High."},
            {"vuln": "Client encryption_key in public JS env object", "severity": "critical", "why": "Symmetric encryption_key/encryptionKey next to EmailJS ids in a public bundle. Separate CWE-321 card from EmailJS; rotate and keep crypto server-side."},
            {"vuln": "CWE-321 client HMAC-SHA256 signing key in public JS", "severity": "critical", "why": "Object.keys(obj).join('') reconstructs an HS256 key the backend trusts; Gitleaks misses it because the secret is property names. Public bundle is enough — API timeout is not a kill."},
            {"vuln": "ICS MQTT / RFID credentials in the same bundle", "severity": "critical", "why": "MQTT username/password reconstructed the same way, plus plaintext RFID, let an attacker reach SCADA/digital-twin brokers. Rotate and keep creds off the client."},
        ],
        "azure_function_env_dump": [
            {"vuln": "Classify runtime secret classes", "severity": "critical", "why": "Anonymous Tester/debug HTTP trigger returns process env: Cosmos master keys, Storage account keys, MACHINEKEY, EasyAuth WEBSITE_AUTH_*, AAD client secrets, App Insights, Key Vault URIs."},
            {"vuln": "Cosmos master key → internet-accessible DB", "severity": "critical", "why": "Master key grants read/write/delete on employee identity and project records. Prove with one read-only list of databases/containers; no item dumps or writes."},
            {"vuln": "Storage account key inventory", "severity": "critical", "why": "AzureWebJobsStorage account key lists the Function App content share. List containers only — do not upload packages or write wwwroot."},
            {"vuln": "Peer Function App via -dev- naming", "severity": "high", "why": "Tenants pair ra-*-fa (prod) with ra-*-dev-fa. The same anonymous trigger is often on both."},
            {"vuln": "Managed identity / Key Vault blast radius (prerequisites only)", "severity": "critical", "why": "Storage key + MACHINEKEY can lead to code as the system-assigned MI with Key Vault secret get/set. Document prerequisites via ARM/Graph; do not inject code or wait for a restart."},
            {"vuln": "AAD client secret rotation order", "severity": "high", "why": "Env may hold an expired secret while Key Vault holds the live one. Rotate AAD secrets last, after Tester is removed, so new values cannot re-leak."},
        ],
    }

    async def detect_bug_chains(
        self,
        vuln_type: str,
        target: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> str:
        """Return vulnerability classes that commonly chain with a confirmed finding.

        Use this after confirming a vulnerability to discover what else to test.
        Returns chains ranked by severity with attack path explanations.

        Args:
            vuln_type: Confirmed or suspected vulnerability class. Supported:
                       ssrf, xss, sqli, idor, open_redirect, xxe, lfi, csrf,
                       broken_auth, rce, mass_assignment, business_logic,
                       subdomain_takeover, cache_poisoning, request_smuggling,
                       host_header, saml, graphql, default_login, js_secrets,
                       elasticsearch_unauth, azure_function_env_dump, arangodb_default,
                       mongodb_unauth, emqx_default, cors_credentials, unauth_account_lookup,
                       unauth_settings_write, email_change_ato, auth_header_bypass,
                       socketio_idor, ml_pipeline_rbac, client_role_param,
                       vendorjson_unauth, auth0_mgmt_token, gitlab_unauth, docker_registry,
                       django_debug, openai_proxy_unauth, wiki_open_reg, binary_hardcoded_creds,
                       client_side_auth.
            target: Optional hostname/URL for context in the output.
            notes: Optional notes about the confirmed finding.
        """
        key = (vuln_type or "").strip().lower().replace("-", "_").replace(" ", "_")
        alias_map = {
            "bola": "idor", "object_injection": "idor",
            "reflected_xss": "xss", "stored_xss": "xss", "dom_xss": "xss",
            "sql_injection": "sqli", "injection": "sqli",
            "redirect": "open_redirect",
            "xml_injection": "xxe",
            "path_traversal": "lfi", "directory_traversal": "lfi",
            "authentication_bypass": "broken_auth", "auth_bypass": "broken_auth",
            "account_takeover": "broken_auth",
            "code_execution": "rce", "command_injection": "rce", "cmdi": "rce",
            "parameter_pollution": "mass_assignment",
            "logic_flaw": "business_logic",
            "smuggling": "request_smuggling", "http_smuggling": "request_smuggling",
            "cache": "cache_poisoning", "web_cache": "cache_poisoning",
            "subdomain_takeover": "subdomain_takeover", "takeover": "subdomain_takeover",
            "hostheader": "host_header", "host_header_injection": "host_header",
            "password_reset_poisoning": "host_header",
            "default_credentials": "default_login", "default-login": "default_login",
            "default_creds": "default_login", "weak_password": "default_login",
            "grafana": "default_login", "grafana_default_login": "default_login",
            "cwe_1393": "default_login", "cwe-1393": "default_login",
            "couchdb": "default_login", "authsession": "default_login",
            "cookie_forgery": "default_login", "session_forgery": "default_login",
            "js_secrets": "js_secrets", "hardcoded_credentials": "js_secrets",
            "client_secret": "js_secrets", "cwe_312": "js_secrets", "cwe-312": "js_secrets",
            "cwe_540": "js_secrets", "cwe-540": "js_secrets",
            "cwe_321": "js_secrets", "cwe-321": "js_secrets",
            "hmac": "js_secrets", "hmac_key": "js_secrets", "signing_key": "js_secrets",
            "emailjs": "js_secrets", "email_js": "js_secrets",
            "elasticsearch": "elasticsearch_unauth",
            "elasticsearch_unauth": "elasticsearch_unauth",
            "exposed_elasticsearch": "elasticsearch_unauth",
            "xpack_security": "elasticsearch_unauth",
            "azure_function_env_dump": "azure_function_env_dump",
            "azure_function": "azure_function_env_dump",
            "function_app": "azure_function_env_dump",
            "authlevel_anonymous": "azure_function_env_dump",
            "tester_function": "azure_function_env_dump",
            "cwe_526": "azure_function_env_dump",
            "cwe-526": "azure_function_env_dump",
            "arangodb": "arangodb_default", "arangodb_default": "arangodb_default",
            "mongodb": "mongodb_unauth", "mongodb_unauth": "mongodb_unauth",
            "emqx": "emqx_default", "emqx_default": "emqx_default",
            "cors": "cors_credentials", "cors_credentials": "cors_credentials",
            "keycloak_password_grant": "keycloak_password_grant",
            "admin-cli": "keycloak_password_grant",
            "password_grant": "keycloak_password_grant",
            "cwe-307": "keycloak_password_grant",
            "unauth_account_lookup": "unauth_account_lookup",
            "user_enum": "unauth_account_lookup",
            "user_enumeration": "unauth_account_lookup",
            "account_enumeration": "unauth_account_lookup",
            "cwe-204": "unauth_account_lookup",
            "cwe_204": "unauth_account_lookup",
            "unauth_settings_write": "unauth_settings_write",
            "savesettings": "unauth_settings_write",
            "save_settings": "unauth_settings_write",
            "missing_authorize": "unauth_settings_write",
            "email_change_ato": "email_change_ato",
            "reset_email": "email_change_ato",
            "djoser": "email_change_ato",
            "auth_header_bypass": "auth_header_bypass",
            "bypassauthorization": "auth_header_bypass",
            "missing_authorization_header": "auth_header_bypass",
            "socketio_idor": "socketio_idor",
            "get_stream": "socketio_idor",
            "url_key": "socketio_idor",
            "ml_pipeline_rbac": "ml_pipeline_rbac",
            "celery_task": "ml_pipeline_rbac",
            "celery-task": "ml_pipeline_rbac",
            "usertype": "client_role_param", "client_role_param": "client_role_param",
            "vendorjson": "vendorjson_unauth", "vendorjson_unauth": "vendorjson_unauth",
            "auth0": "auth0_mgmt_token", "auth0_mgmt_token": "auth0_mgmt_token",
            "gitlab": "gitlab_unauth", "gitlab_unauth": "gitlab_unauth",
            "docker_registry": "docker_registry",
            "acr": "docker_registry",
            "azurecr": "docker_registry",
            "anonymous_pull": "docker_registry",
            "anonymouspullenabled": "docker_registry",
            "django": "django_debug", "django_debug": "django_debug",
            "openai_proxy": "openai_proxy_unauth", "openai_proxy_unauth": "openai_proxy_unauth",
            "wiki": "wiki_open_reg", "wiki_open_reg": "wiki_open_reg",
            "binary_hardcoded_creds": "binary_hardcoded_creds",
            "downloadable_binary": "binary_hardcoded_creds",
            "client_side_auth": "client_side_auth",
            "sso": "saml", "saml_sso": "saml",
            "gql": "graphql",
        }
        key = alias_map.get(key, key)
        chains = self._BUG_CHAINS.get(key)
        if not chains:
            return json.dumps({
                "error": f"No chain data for '{vuln_type}'.",
                "supported_types": sorted(self._BUG_CHAINS.keys()),
            }, indent=2)
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        ranked = sorted(chains, key=lambda c: sev_order.get(c.get("severity", "medium"), 4))
        by_sev: Dict[str, list] = {}
        for c in ranked:
            by_sev.setdefault(c["severity"], []).append(c)
        return json.dumps({
            "confirmed_vuln": vuln_type,
            "target": target or "not specified",
            "notes": notes or None,
            "chain_count": len(chains),
            "chains_by_severity": by_sev,
            "next_steps": [
                f"[{c['severity'].upper()}] Test for {c['vuln']}: {c['why']}"
                for c in ranked
            ],
        }, indent=2)

    async def validate_finding(
        self,
        title: str,
        description: str,
        severity: str = "medium",
        target: Optional[str] = None,
        evidence: Optional[str] = None,
        cve_id: Optional[str] = None,
        remediation: Optional[str] = None,
    ) -> str:
        """Validation gate — score a proposed finding before reporting.

        Evaluates the finding against demonstrated-compromise criteria and returns
        SUBMIT, IMPROVE, or DROP. Default/weak login IMPROVE until privileged
        API impact is documented.

        Args:
            title: Short finding title.
            description: Full description of the vulnerability.
            severity: Proposed severity (critical/high/medium/low/info).
            target: Affected hostname or URL.
            evidence: Request/response snippet or reproduction proof.
            cve_id: Optional CVE ID if mapping to a known CVE.
            remediation: Optional remediation guidance.
        """
        text = f"{title} {description} {evidence or ''} {remediation or ''}".lower()
        questions: List[Dict[str, Any]] = []

        # Q1: Demonstrable technical impact
        impact_words = ["access", "execute", "exfiltrat", "bypass", "steal", "read", "write",
                        "delete", "escalat", "takeover", "inject", "expose", "leak", "dump",
                        "disclose", "overwrite", "redirect", "forge"]
        q1 = any(w in text for w in impact_words)
        questions.append({
            "question": "Is there demonstrable technical impact?",
            "pass": q1,
            "feedback": "PASS — clear impact language found." if q1 else
                        "FAIL — describe the concrete impact (data exposed, action achievable, etc.).",
        })

        # Q2: Reachable by an external attacker
        privileged_only = any(w in text for w in ["requires admin", "internal only", "localhost only",
                                                    "requires physical", "requires vpn access",
                                                    "not internet-facing"])
        q2 = not privileged_only
        questions.append({
            "question": "Is this reachable by an external attacker without prior privileged access?",
            "pass": q2,
            "feedback": "PASS — no privileged-access gating found." if q2 else
                        "FAIL — if it requires admin/VPN/internal access, severity and scope need adjustment.",
        })

        # Q3: Reproducible attack path
        path_words = ["step", "request", "payload", "parameter", "endpoint", "curl", "poc",
                      "proof", "reproduct", "navigate", "visit", "send", "intercept"]
        q3 = any(w in text for w in path_words) or bool(evidence and len(evidence.strip()) > 20)
        questions.append({
            "question": "Is there a clear, reproducible attack path?",
            "pass": q3,
            "feedback": "PASS — reproduction steps or evidence present." if q3 else
                        "FAIL — add step-by-step reproduction instructions or a PoC request.",
        })

        # Q4: Crosses a meaningful security boundary
        boundary_words = ["other user", "another user", "admin", "privilege", "unauthorized",
                          "unauthenticated", "tenant", "account", "cross-user", "cross-tenant",
                          "without authentication", "without authorization", "arbitrary"]
        q4 = any(w in text for w in boundary_words)
        questions.append({
            "question": "Does the impact cross an auth, privilege, or data-ownership boundary?",
            "pass": q4,
            "feedback": "PASS — boundary crossing language found." if q4 else
                        "FAIL — clarify the security boundary violated (e.g. 'access another user's data').",
        })

        # Q5: Has direct evidence (not purely theoretical)
        theoretical_words = ["might", "could potentially", "it is possible that", "theoretically",
                              "in theory", "may be possible", "hypothetically"]
        q5_theoretical = any(w in text for w in theoretical_words)
        q5_has_evidence = bool(evidence and len(evidence.strip()) > 30)
        q5 = q5_has_evidence or not q5_theoretical
        questions.append({
            "question": "Is the finding backed by direct evidence (not purely theoretical)?",
            "pass": q5,
            "feedback": "PASS — evidence provided or non-theoretical language." if q5 else
                        "FAIL — replace theoretical language with a tested payload and observed response.",
        })

        # Q6: Non-trivial severity
        sev_weight = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        q6 = sev_weight.get(severity.strip().lower(), 0) >= 2
        questions.append({
            "question": "Is the severity at least Medium (meaningful real-world impact)?",
            "pass": q6,
            "feedback": f"PASS — severity '{severity}' is medium or above." if q6 else
                        f"FAIL — severity '{severity}' findings rarely justify submission effort.",
        })

        # Q7: Would survive duplicate/informational review
        dupe_risk_words = ["default page", "missing header", "server version", "banner",
                           "clickjacking", "self-xss", "csrf on logout", "logout csrf",
                           "rate limit on non-sensitive", "no rate limit on login page only",
                           "options method", "http methods", "cors wildcard on public",
                           "graphql introspection alone", "open redirect alone",
                           "host header alone", "dns callback only"]
        q7 = not any(w in text for w in dupe_risk_words)
        questions.append({
            "question": "Is this unlikely to be marked as N/A / Informational / Duplicate?",
            "pass": q7,
            "feedback": "PASS — no common N/A patterns detected." if q7 else
                        "FAIL — common low-value pattern detected; review program policy for acceptability.",
        })

        # Q8: Identity discipline for authz-class findings
        authz_signal = any(w in text for w in [
            "idor", "bola", "bfla", "authorization", "authz", "other user",
            "another user", "cross-user", "cross-tenant", "object-level",
        ])
        identity_signal = any(w in text for w in [
            "user a", "user b", "anonymous", "unauthenticated", "without auth",
            "session a", "session b", "low-priv", "cross-identity", "two accounts",
            "victim user", "attacker account",
            "any authenticated", "shared across", "all users", "readonly",
            "request serializer", "writable id",
            "acao", "allow-credentials", "credentialed", "preflight", "canary origin",
        ])
        q8 = (not authz_signal) or identity_signal
        questions.append({
            "question": "For authz findings: is the proving identity documented (anon / A / B)?",
            "pass": q8,
            "feedback": "PASS — identity context present or not an authz finding." if q8 else
                        "FAIL — document anonymous vs user-A vs user-B repro before submitting IDOR/BOLA.",
        })

        # Q9: Demonstrated-compromise writeup for default/weak credential findings
        cred_finding = any(w in text for w in [
            "default login", "default-login", "default credential", "weak password",
            "prom-operator", "cwe-1393", "cwe 1393", "kube-prometheus",
            "client_secret", "hardcoded credential", "hardcoded api",
            "javascript bundle", "js bundle", "_next/static", "cwe-312", "cwe-540",
            "couchdb-default", "authsession", "couch_httpd_auth", "kevin:kevin",
            "emailjs", "api.emailjs.com",
        ])
        privileged_followup = any(w in text for w in [
            "admin/settings", "/api/admin", "datasources", "serviceaccount",
            "service account", "prometheus", "internal", "cluster", "proxy",
            "retrieved", "enumerated", "disclosed", "pod identity", "grafana.ini",
            "records", "locations", "accountid", "accountname", "postalcode",
            "_node/_local/_config", "couch_httpd_auth", "_all_dbs", "userctx",
            "_admin", "authsession", "forged cookie", "session cookie",
            "template_params", "sent email", "canary inbox", "email/send",
            "duckdb", "fork/exec", "/api/ds/query", "sql expression",
        ])
        q9 = (not cred_finding) or privileged_followup
        questions.append({
            "question": (
                "For default/weak creds or JS-leaked secrets: is privileged impact proven "
                "(admin APIs, live API records) — not merely login success or a key in a bundle?"
            ),
            "pass": q9,
            "feedback": (
                "PASS — privileged impact present or not a credential/secret finding." if q9 else
                "FAIL — foothold only. Prove privileged APIs or a live in-scope API response "
                "(count + redacted sample) before SUBMIT."
            ),
        })

        # Q10: Elasticsearch unauth — banner is a foothold
        es_finding = any(w in text for w in [
            "elasticsearch", ":9200", "xpack.security", "you know, for search",
        ])
        es_read = any(w in text for w in [
            "_cat/indices", "indices", "cluster_name", "_nodes", "_cluster/health",
            "sample", "read_me",
        ])
        es_write = any(w in text for w in [
            "aegis_test_index", "test_index", "acknowledged", "write access",
        ])
        q10 = (not es_finding) or (es_read and es_write)
        questions.append({
            "question": (
                "For unauthenticated Elasticsearch: are indices enumerated AND write "
                "proven (create+delete test index) — not merely an open :9200 banner?"
            ),
            "pass": q10,
            "feedback": (
                "PASS — ES read+write proven or not an Elasticsearch finding." if q10 else
                "FAIL — banner is a foothold. Prove GET /_cat/indices + sample read and "
                "PUT+DELETE aegis_test_index. Do not dump all docs or run Painless RCE."
            ),
        })

        # Q11: Azure Function env dump — classify secret classes, not 'env leaked'.
        # Do NOT match bare *.azurewebsites.net (ASP.NET App Service missing-[Authorize]
        # writes live there too). Require Function/Tester/env-dump language.
        azfn_finding = any(w in text for w in [
            "azure function", "function app", "authlevel", "azurewebjobsstorage",
            "machinekey", "website_auth", "tester function",
            "cwe-526", "cwe 526",
        ]) or (
            "azurewebsites.net" in text
            and any(w in text for w in [
                "tester", "function app", "authlevel", "env dump",
                "environment variable", "azurewebjobs",
            ])
        )
        azfn_classified = any(w in text for w in [
            "cosmos", "storage account", "azurewebjobsstorage", "machinekey",
            "easyauth", "website_auth", "client secret", "application insights",
            "key vault", "instrumentation key",
        ])
        q11 = (not azfn_finding) or azfn_classified
        questions.append({
            "question": (
                "For anonymous Azure Function env dump: are leaked secret classes named "
                "(Cosmos, Storage, MACHINEKEY, EasyAuth, AAD) — not merely 'env vars leaked'?"
            ),
            "pass": q11,
            "feedback": (
                "PASS — secret classes classified or not an Azure Function env-dump finding."
                if q11 else
                "FAIL — env dump is a foothold. Name which classes were retrieved "
                "(Cosmos / Storage / MACHINEKEY / EasyAuth / AAD). Do not inject code; "
                "list managed-identity ACE under not_demonstrated."
            ),
        })

        # Q12: OpenAPI/DRF mass assignment — schema-confirmed writable fields.
        # Do not match bare OpenAPI/schema mentions (account-lookup writeups cite
        # the schema without being mass assignment).
        ma_finding = any(w in text for w in [
            "mass assignment", "mass-assignment", "writable id", "extra_kwargs",
            "property-level", "property level authorization", "cwe-915",
            "request serializer",
        ])
        ma_proof = any(w in text for w in [
            "readonly", "read_only", "writable id", "writable user",
            "shared across", "all users", "periodic_task", "extra_kwargs",
            "not readonly", "without readonly",
        ])
        q12 = (not ma_finding) or ma_proof
        questions.append({
            "question": (
                "For OpenAPI/DRF mass assignment: are writable privileged fields named "
                "(id/created/user without readOnly) or is missing tenant isolation quoted "
                "— not merely 'swagger found'? A down database is not a fail."
            ),
            "pass": q12,
            "feedback": (
                "PASS — schema names writable privileged fields / shared-list, or not a "
                "mass-assignment finding." if q12 else
                "FAIL — OpenAPI without field analysis is a foothold. Count request "
                "serializers missing readOnly on id/created/user, or quote 'all users' "
                "list text. Do not kill because the DB is down."
            ),
        })

        # Q13: CORS ACAO + credentials — header proof is enough.
        # ACAO * without credentials is not this bug (and is extra on account-lookup writeups).
        cors_finding = any(w in text for w in [
            "weborigins",
            "allow-credentials", "allow_credentials",
            "cors reflection", "credentialed cors",
            "acao+credentials",
        ]) or (
            ("acao" in text or "access-control-allow-origin" in text or "cors origin" in text)
            and any(w in text for w in [
                "allow-credentials", "credentials: true", "credentials=true",
                "weborigins", "credentialed cors",
            ])
        )
        cors_proof = any(w in text for w in [
            "credentials: true", "credentials=true", "allow-credentials: true",
            "allow-credentials=true", "reflected", "canary origin", "echoes",
            "echoed", "aegis-cors-canary",
        ])
        q13 = (not cors_finding) or cors_proof
        questions.append({
            "question": (
                "For CORS: is ACAO reflection of a canary Origin proven WITH "
                "Access-Control-Allow-Credentials: true — not merely 'CORS enabled'? "
                "A missing victim browser tab is not a fail."
            ),
            "pass": q13,
            "feedback": (
                "PASS — ACAO+credentials proven or not a CORS finding." if q13 else
                "FAIL — 'CORS enabled' is a foothold. Prove a never-seen Origin is "
                "reflected in ACAO with credentials=true. Do not ship an HTML exploit; "
                "do not dump Keycloak /users. Kill only ACAO=* without credentials."
            ),
        })

        # Q14: Keycloak admin-cli password grant / no lockout
        kc_grant_finding = any(w in text for w in [
            "admin-cli", "admin_cli", "password grant", "direct access grant",
            "resource owner password", "invalid_grant", "cwe-307",
        ])
        kc_grant_proof = any(w in text for w in [
            "invalid_grant", "no client_secret", "without a client secret",
            "public client", "no 429", "no lockout", "not invalid_client",
            "unsupported_grant_type",
        ])
        q14 = (not kc_grant_finding) or kc_grant_proof
        questions.append({
            "question": (
                "For Keycloak admin-cli: is the public password grant proven "
                "(invalid_grant without client_secret) and/or no lockout on a bounded "
                "probe — not merely 'token endpoint exists'? Guessing a valid password "
                "is not required."
            ),
            "pass": q14,
            "feedback": (
                "PASS — public password grant / no-lockout proven, or not an admin-cli finding."
                if q14 else
                "FAIL — prove POST grant_type=password client_id=admin-cli with no secret "
                "returns invalid_grant (not invalid_client). Cap lockout tests at 8. "
                "Do not hydra/rockyou. Do not kill because no password was guessed."
            ),
        })

        # Account lookup schema/status signals are leads, never proof or severity overrides.
        acct_finding = any(w in text for w in ("/api/auth/account", "account lookup", "user enumeration"))
        questions.append({"question": "Does account-lookup impact have independent execution proof?",
                          "pass": not acct_finding,
                          "feedback": "Schema fields and HTTP errors remain candidates; use independent verification."})

        # Q16: Unauth ASP.NET / API settings write — paired 401 vs 200 void.
        # GET 500 / missing read-back is not a fail. Do not require destructive overwrite.
        from app.services.agent.unauth_settings_write import (
            has_settings_write_proof,
            is_settings_write_finding,
        )

        settings_write_finding = is_settings_write_finding(text)
        settings_write_proof = has_settings_write_proof(text)
        q16 = (not settings_write_finding) or settings_write_proof
        questions.append({
            "question": (
                "For unauth settings/config write: is missing auth proven by a sibling "
                "write 401 vs SaveSettings (or mapped Save*/Write*) 200 void — not merely "
                "'endpoint exists'? GET 500 / no read-back is not a fail. One canary key; "
                "do not replace production settings."
            ),
            "pass": q16,
            "feedback": (
                "PASS — paired 401-vs-200 void proven, or not a settings-write finding."
                if q16 else
                "FAIL — 'Settings API exists' is a foothold. compare_requests a protected "
                "write (expect 401) vs unauth POST /api/Settings/SaveSettings (200 + "
                "Content-Length: 0 is ASP.NET void success). Do not kill because "
                "GetSettings is 500. One canary key (aegis-verify-*); do not flip "
                "enableNotifications/createPlannerTasks/powerBIReportId."
            ),
        })

        # Q19: Unauth email-change ATO (djoser reset_email).
        from app.services.agent.email_change_ato import (
            has_email_change_proof,
            is_email_change_finding,
        )

        email_change_finding = is_email_change_finding(text)
        email_change_proof = has_email_change_proof(text)
        q19 = (not email_change_finding) or email_change_proof
        questions.append({
            "question": (
                "For unauth email-change: is JWT skip proven by set_password 401 vs "
                "reset_email 204/200 — not merely 'endpoint exists'? One canary; do not "
                "complete ATO on a real mailbox."
            ),
            "pass": q19,
            "feedback": (
                "PASS — sibling 401 vs reset_email 204 proven, or not an email-change finding."
                if q19 else
                "FAIL — 'reset_email exists' is a foothold. compare_requests unauth "
                "set_password (401) vs reset_email canary (204). Do not spray inboxes."
            ),
        })

        # Q20: Auth middleware skipped when Authorization header is absent.
        from app.services.agent.auth_header_bypass import (
            has_auth_header_proof,
            is_auth_header_finding,
        )

        header_bypass_finding = is_auth_header_finding(text)
        header_bypass_proof = has_auth_header_proof(text)
        q20 = (not header_bypass_finding) or header_bypass_proof
        questions.append({
            "question": (
                "For auth-header bypass: is middleware skip proven by no-header 200/400 "
                "(controller ran) vs invalid Bearer 401 — not merely 'API exists'? "
                "400 missing-params is a bypass, not a fail."
            ),
            "pass": q20,
            "feedback": (
                "PASS — no-header vs invalid-bearer differential proven, or not this finding."
                if q20 else
                "FAIL — omit Authorization and send Bearer aegis-invalid on the same path. "
                "SUBMIT if no-header is 200/400 AND invalid-bearer is 401. Do not dump."
            ),
        })

        # Q21: Socket.IO get_stream IDOR.
        from app.services.agent.socketio_idor import (
            has_socketio_proof,
            is_socketio_finding,
        )

        socketio_finding = is_socketio_finding(text)
        socketio_proof = has_socketio_proof(text)
        q21 = (not socketio_finding) or socketio_proof
        questions.append({
            "question": (
                "For Socket.IO stream IDOR: did anonymous get_stream return a url_key for "
                "a fabricated siteId — not merely 'socket.io open'? Do not fetch video; "
                "do not send null crash loops."
            ),
            "pass": q21,
            "feedback": (
                "PASS — url_key for fabricated siteId proven, or not a Socket.IO IDOR finding."
                if q21 else
                "FAIL — Engine.IO polling then 42[\"get_stream\", fabricated siteId]. "
                "SUBMIT on url_key. Do not dump footage. Do not crash the Node process."
            ),
        })

        # Q22: ML pipeline missing RBAC.
        from app.services.agent.ml_pipeline_rbac import (
            has_ml_rbac_proof,
            is_ml_rbac_finding,
        )

        ml_finding = is_ml_rbac_finding(text)
        ml_proof = has_ml_rbac_proof(text)
        q22 = (not ml_finding) or ml_proof
        questions.append({
            "question": (
                "For ML train/delete missing RBAC: can a self-registered / low-priv session "
                "train or delete — not merely 'endpoint exists'? Do not delete production models."
            ),
            "pass": q22,
            "feedback": (
                "PASS — low-priv train/delete proven, or not an ML-RBAC finding."
                if q22 else
                "FAIL — throwaway self-reg (if open) then POST /api/v1/train/ or DELETE "
                "celery-task. Do not destroy production models."
            ),
        })

        # Q23: Blind SSRF/XXE/OOB — Interactsh poll, not Canarytokens.
        from app.services.agent.interactsh_proof import (
            has_ssrf_proof,
            is_oob_finding,
        )

        oob_finding = is_oob_finding(text)
        oob_proof = has_ssrf_proof(text)
        q23 = (not oob_finding) or oob_proof
        questions.append({
            "question": (
                "For SSRF/XXE/OOB: did execute_interactsh poll show a DNS/HTTP/SMTP "
                "interaction (or an internal HTTP body) — not merely 'webhook exists'? "
                "Do not use Canarytokens."
            ),
            "pass": q23,
            "feedback": (
                "PASS — Interactsh poll or internal body proven, or not an OOB finding."
                if q23 else
                "FAIL — 'URL-fetch exists' is a foothold. execute_interactsh register, "
                "plant payload_url, poll. Canarytokens/operator inbox is not proof. "
                "Never 169.254.169.254 / localhost if Lictor blocks."
            ),
        })

        # Q17/Q18: ACR / Docker Registry anonymous pull.
        from app.services.agent.finding_gate import acr_anonymous_pull_signals

        acr_sig = acr_anonymous_pull_signals(text)
        q17 = (not acr_sig["is_finding"]) or acr_sig["has_anon_proof"]
        questions.append({
            "question": (
                "For ACR/Docker anonymous pull: was an anonymous oauth2 bearer "
                "(registry:catalog:*) issued AND/OR /v2/_catalog returned repository "
                "names — not merely 'registry exists'? Do not pull the whole catalog."
            ),
            "pass": q17,
            "feedback": (
                "PASS — anonymous token/catalog proven, or not a registry finding."
                if q17 else
                "FAIL — hostname/banner is a foothold. Prove unauth /oauth2/token "
                "issues an access_token and /v2/_catalog lists repositories. Do not "
                "push; do not pull every image."
            ),
        })
        sev_l = (severity or "").strip().lower()
        q18 = (
            not (acr_sig["is_finding"] and acr_sig["live_privileged_token"])
            or sev_l == "critical"
        )
        questions.append({
            "question": (
                "For registry image secrets: if a classic GitHub PAT / git+https "
                "token with repo/workflow/admin was recovered, is severity Critical "
                "— not High 'anonymous pull' only? Do not re-authenticate recovered PATs."
            ),
            "pass": q18,
            "feedback": (
                "PASS — severity matches blast radius, or no live privileged token in images."
                if q18 else
                "FAIL — raise to Critical. Anonymously pullable images with live ghp_* "
                "(admin/workflow/packages) are org-repo/CI compromise, not a High "
                "misconfiguration. Expired ghs_* stays a leak pattern. Do not re-hit GitHub."
            ),
        })

        score = sum(1 for q in questions if q["pass"])
        total = len(questions)
        if cred_finding and not privileged_followup:
            verdict = "IMPROVE"
            verdict_detail = (
                "Default/weak login or a JS-leaked secret is a foothold, not a finding. "
                "Prove privileged impact (admin APIs, or live API records from leaked "
                "client_id/client_secret) and write description + impact + assets + remediation."
            )
        elif es_finding and not (es_read and es_write):
            verdict = "IMPROVE"
            verdict_detail = (
                "Unauthenticated Elasticsearch banner is a foothold, not a finding. "
                "Prove index enumeration + sample read and PUT+DELETE aegis_test_index. "
                "Do not dump all documents or run Painless RCE."
            )
        elif azfn_finding and not azfn_classified:
            verdict = "IMPROVE"
            verdict_detail = (
                "Anonymous Azure Function env dump is a foothold until leaked secret "
                "classes are named (Cosmos, Storage, MACHINEKEY, EasyAuth, AAD). "
                "Do not inject code as the managed identity; list ACE under not_demonstrated. "
                "Write description + impact + assets + remediation (remove Tester or "
                "authLevel=function; rotate keys; AAD secrets last)."
            )
        elif ma_finding and not ma_proof:
            verdict = "IMPROVE"
            verdict_detail = (
                "OpenAPI without named writable privileged fields is a foothold. "
                "Count request serializers missing readOnly on id/created/user/owner, "
                "or quote a list description that shares objects across all users. "
                "A down database is not a kill."
            )
        elif cors_finding and not cors_proof:
            verdict = "IMPROVE"
            verdict_detail = (
                "'CORS enabled' is a foothold. Prove a never-seen Origin is reflected "
                "in ACAO with Access-Control-Allow-Credentials: true. Header proof is "
                "enough — no victim tab. Do not dump Keycloak /users or ship an HTML exploit."
            )
        elif kc_grant_finding and not kc_grant_proof:
            verdict = "IMPROVE"
            verdict_detail = (
                "Keycloak token endpoint existence is a foothold. Prove admin-cli accepts "
                "grant_type=password with no client_secret (invalid_grant) and/or that "
                "<=8 failures have no 429/lockout. Do not hydra. Do not kill because a "
                "valid password was not guessed."
            )
        elif acct_finding:
            verdict = "IMPROVE"
            verdict_detail = (
                "Schema hints and error status differences are candidates only. "
                "Use controlled accounts and independent execution proof. "
                "Do not infer data access or Critical severity from 404/500 responses."
            )
        elif settings_write_finding and not settings_write_proof:
            verdict = "IMPROVE"
            verdict_detail = (
                "Settings/config API existence is a foothold. Prove missing [Authorize] "
                "with a paired write: protected sibling 401 vs unauth SaveSettings 200 "
                "(ASP.NET void, Content-Length: 0). GET 500 is not a kill. One canary "
                "key; do not replace the production settings collection."
            )
        elif email_change_finding and not email_change_proof:
            verdict = "IMPROVE"
            verdict_detail = (
                "reset_email existence is a foothold. Prove JWT skip with unauth "
                "set_password 401 vs reset_email canary 204/200. One "
                "aegis-ato-canary@example.invalid; do not complete ATO; do not spray."
            )
        elif header_bypass_finding and not header_bypass_proof:
            verdict = "IMPROVE"
            verdict_detail = (
                "API existence is a foothold. Prove middleware skip: no Authorization "
                "200/400 (controller ran) vs Bearer aegis-invalid 401. 400 missing-params "
                "is a bypass. Do not dump."
            )
        elif socketio_finding and not socketio_proof:
            verdict = "IMPROVE"
            verdict_detail = (
                "Socket.IO open is a foothold. Prove anonymous get_stream returns url_key "
                "for a fabricated siteId. Do not fetch video. Do not send null crash loops."
            )
        elif ml_finding and not ml_proof:
            verdict = "IMPROVE"
            verdict_detail = (
                "ML train/celery existence is a foothold. Prove a self-reg/low-priv "
                "session gets 200/202/204 on POST /api/v1/train/. Do not DELETE "
                "production models."
            )
        elif oob_finding and not oob_proof:
            verdict = "IMPROVE"
            verdict_detail = (
                "URL-fetch/webhook existence is a foothold. Prove OOB with "
                "execute_interactsh register → plant payload_url → poll (DNS/HTTP/SMTP), "
                "or an internal HTTP body. Do not use Canarytokens. Never metadata/"
                "localhost if Lictor blocks."
            )
        elif acr_sig["is_finding"] and not acr_sig["has_anon_proof"]:
            verdict = "IMPROVE"
            verdict_detail = (
                "ACR/Docker registry existence is a foothold. Prove an anonymous "
                "oauth2 access_token (registry:catalog:*) and/or /v2/_catalog "
                "repository names. Do not push; do not pull the whole catalog."
            )
        elif acr_sig["is_finding"] and acr_sig["live_privileged_token"] and sev_l != "critical":
            verdict = "IMPROVE"
            verdict_detail = (
                "Raise to Critical. Anonymous catalog is High; live classic GitHub PATs "
                "(repo/workflow/admin) in pullable images are org-repo and CI compromise. "
                "Do not re-authenticate recovered tokens. Expired ghs_* is a leak pattern."
            )
        elif score >= total - 1:
            verdict = "SUBMIT"
            verdict_detail = "Strong finding. Submit with the evidence and steps provided."
        elif score >= 3:
            verdict = "IMPROVE"
            gaps = [q["feedback"] for q in questions if not q["pass"]]
            verdict_detail = "Address the gaps before submitting: " + " | ".join(gaps)
        else:
            verdict = "DROP"
            verdict_detail = "Fundamental issues — likely to be rejected. Address all failing questions."

        receipt_id = None
        if verdict == "SUBMIT":
            from app.services.agent.finding_gate import record_submit_receipt

            if not hasattr(self, "_finding_receipts") or self._finding_receipts is None:
                self._finding_receipts = {}
            receipt_id = record_submit_receipt(
                self._finding_receipts,
                title=title or "",
                target=target,
                severity=severity or "info",
                score=f"{score}/{total}",
            )

        return json.dumps({
            "title": title,
            "severity": severity,
            "target": target or "not specified",
            "score": f"{score}/{total}",
            "verdict": verdict,
            "verdict_detail": verdict_detail,
            "receipt_id": receipt_id,
            "questions": questions,
            "has_evidence": bool(evidence),
            "has_remediation": bool(remediation),
            "has_cve": bool(cve_id),
            "next_step": (
                "create_finding with the same title/target is now unlocked for medium+"
                if receipt_id
                else "Do not create_finding until verdict is SUBMIT"
            ),
        }, indent=2)

    async def read_evidence(self, evidence_id: str, offset: int = 0, limit: int = 6000) -> str:
        """Read a redacted execution artifact without losing text beyond the preview."""
        from app.services.agent.evidence_store import evidence_store
        return json.dumps(evidence_store(self).read(evidence_id, offset, limit))

    async def search_evidence(self, query: str, kind: str = "http_exchange", limit: int = 5) -> str:
        """Search recorded, redacted HTTP exchanges in this session by text.

        Use before re-requesting a URL: find leaked paths, internal hosts, stack
        traces, key names or error formats in responses already seen. Every
        term must match. Read a hit in full with read_evidence(evidence_id, offset).
        """
        from app.services.agent.evidence_store import evidence_store
        try:
            hits = evidence_store(self).search(query, kind=kind, limit=limit)
        except ValueError as exc:
            return json.dumps({"ok": False, "error": str(exc)})
        return json.dumps({"ok": True, "count": len(hits), "matches": hits})

    async def submit_finding_candidate(
        self,
        title: str,
        description: str = "",
        severity: str = "medium",
        target: str = "",
        evidence: str = "",
        hypothesis_id: str = "",
        threat_id: str = "",
        claimed_request: str = "",
        specialist: str = "",
        coverage_cell_id: str = "",
        capture_id: str = "",
        evidence_ids: Optional[List[str]] = None,
        proof_run_id: str = "",
        proof_escalation_id: str = "",
        vulnerability_class: str = "",
        challenge: Any = None,
    ) -> str:
        """Queue a medium+ finding for independent verification.

        challenge: the hunter's adversarial self-review, an object with
        reachability, preconditions, downstream_controls, scope,
        benign_explanation, strongest_objection and disproof_test (one or two
        sentences each). Required when AGENT_SELF_CHALLENGE is on, except for
        execution-owned coverage-cell proofs.

        Set vulnerability_class to exposure, sql_injection, xss, authorization,
        ssrf, xxe, command_injection, path_traversal, csrf, known_cve, or
        account_enumeration. Unsupported classes remain inconclusive until a
        matching proof validator exists. Hunters must not create_finding.
        """
        from app.services.agent.engagement_brain import engagement_brain_from_dict
        from app.services.agent.independent_verify import (
            observed_sql_cell_for_proof, observed_xss_cell_for_proof,
            resolve_observed_sql_candidate_proof, submit_candidate,
        )
        from app.services.agent.proof_policy import inferred_vulnerability_class
        from types import SimpleNamespace

        from app.services.agent.independent_verify import (
            SELF_CHALLENGE_FIELDS, normalize_challenge, self_challenge_required,
        )

        clean_challenge, missing_challenge = normalize_challenge(challenge)
        # Coverage-cell handoffs carry execution-owned proof receipts and come
        # from the deterministic pipeline; every other claim argues against
        # itself before it reaches the verifier.
        if self_challenge_required() and missing_challenge and not (coverage_cell_id and evidence_ids):
            return json.dumps({
                "error": "self_challenge_required",
                "missing": missing_challenge,
                "detail": (
                    "Before submitting, argue against your own claim and pass challenge="
                    "{" + ", ".join(f'"{name}": "..."' for name in SELF_CHALLENGE_FIELDS) + "}. "
                    "Answer each with what you actually observed. If the argument kills the "
                    "claim, do not submit: record the negative with evidence instead. "
                    "disproof_test is one concrete request that would refute it."
                ),
            })
        self._require_independent_verify = True
        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        trace = {}
        claim_class = vulnerability_class or inferred_vulnerability_class(
            SimpleNamespace(title=title, description=description),
        )
        if claim_class == "sql_injection":
            from app.services.agent.evidence_store import evidence_store

            linked_proof = resolve_observed_sql_candidate_proof(
                brain, evidence_store(self), target=target,
                evidence_ids=evidence_ids or [],
                claim=f"{title} {claimed_request}",
            )
            if linked_proof:
                target, linked_cell, artifact_id = linked_proof
                if coverage_cell_id and coverage_cell_id != linked_cell["id"]:
                    return json.dumps({"error": "Candidate proof belongs to a different coverage cell"})
                coverage_cell_id = str(linked_cell["id"])
                evidence_ids = list(dict.fromkeys([*(evidence_ids or []), artifact_id]))
                # One observed input and bug class represent one candidate. A
                # new execution receipt revises it instead of creating another
                # title-variant candidate for the same SQLi proof.
                prior = next((row for row in brain.candidates
                              if isinstance(row, dict)
                              and row.get("coverage_cell_id") == coverage_cell_id
                              and row.get("target") == target
                              and row.get("vulnerability_class") == "sql_injection"), None)
                if prior:
                    title = str(prior["title"])
                vulnerability_class = "sql_injection"
        if evidence_ids:
            from app.services.agent.evidence_store import evidence_store

            store = evidence_store(self)
            evidence_rows = [store.records.get(item) for item in evidence_ids]
            inferred_cells = {
                str(row.get("coverage_cell_id") or "")
                for row in evidence_rows
                if row and row.get("coverage_cell_id")
            }
            if coverage_cell_id and inferred_cells - {coverage_cell_id}:
                return json.dumps(
                    {"error": "Candidate evidence belongs to a different coverage cell"},
                    indent=2,
                )
            if not coverage_cell_id and len(inferred_cells) == 1:
                coverage_cell_id = inferred_cells.pop()
            if not coverage_cell_id:
                sql_cell = observed_sql_cell_for_proof(
                    brain, store, target=target, evidence_ids=evidence_ids,
                )
                xss_cell = observed_xss_cell_for_proof(
                    brain, store, target=target, evidence_ids=evidence_ids,
                )
                linked = [row for row in (sql_cell, xss_cell) if row]
                if len(linked) == 1:
                    coverage_cell_id = str(linked[0]["id"])
        if coverage_cell_id:
            from app.services.agent.coverage_cells import (
                migrate_coverage_cells,
                trace_for_cell,
            )
            from app.services.agent.engagement_brain import denominator_surfaces

            migrate_coverage_cells(brain, denominator=denominator_surfaces(brain))
            trace = trace_for_cell(brain, coverage_cell_id)
            if not trace:
                return json.dumps({"error": "Unknown coverage_cell_id"}, indent=2)
            if hypothesis_id and trace.get("hypothesis_id") not in ("", hypothesis_id):
                return json.dumps(
                    {"error": "Coverage cell does not belong to this hypothesis"}, indent=2
                )
            hypothesis_id = hypothesis_id or str(trace.get("hypothesis_id") or "")
            if not proof_escalation_id:
                proof_escalation_id = next(
                    (
                        str(cell.get("proof_escalation_id") or "")
                        for cell in brain.coverage_cells
                        if cell.get("id") == coverage_cell_id
                    ),
                    "",
                )
        cand = submit_candidate(
            brain,
            title=title or "",
            description=description or "",
            severity=severity or "medium",
            target=target or "",
            evidence=evidence or "",
            hypothesis_id=hypothesis_id or "",
            threat_id=threat_id or "",
            claimed_request=claimed_request or "",
            specialist=specialist or "",
            operation_id=str(trace.get("operation_id") or ""),
            identity=str(trace.get("identity") or ""),
            tenant=str(trace.get("tenant") or ""),
            parameter=str(trace.get("parameter") or ""),
            test_type=str(trace.get("test_type") or ""),
            coverage_cell_id=coverage_cell_id or "",
            capture_id=capture_id or "",
            evidence_ids=evidence_ids or [],
            proof_run_id=proof_run_id or "",
            proof_escalation_id=proof_escalation_id or "",
            vulnerability_class=vulnerability_class or "",
            challenge=clean_challenge,
        )
        if coverage_cell_id and evidence_ids:
            for cell in brain.coverage_cells:
                if (cell.get("id") == coverage_cell_id
                        and cell.get("first_pass_evidence_id") in cand.evidence_ids):
                    cell.pop("first_pass_candidate_handoff_error", None)
                    break
        self._engagement_brain = brain.to_dict()
        return json.dumps(
            {
                "candidate": cand.to_dict(),
                "hint": (
                    "Call independent_verify (or wait for the fireteam second wave). "
                    "create_finding only after verdict=confirmed."
                ),
                "engagement_brain": self._engagement_brain,
            },
            indent=2,
        )[:_tool_output_max_chars()]

    async def record_verify_verdict(
        self,
        candidate_id: str,
        verdict: str,
        evidence: str = "",
        summary: str = "",
        nonce_observed: bool = False,
        evidence_ids: Optional[List[str]] = None,
        proof: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Independent verifier issues confirmed|refuted|inconclusive for a candidate."""
        from app.services.agent.independent_verify import apply_verdict

        cand = apply_verdict(
            self,
            candidate_id=candidate_id or "",
            verdict=verdict or "",
            evidence=evidence or "",
            summary=summary or "",
            nonce_observed=bool(nonce_observed),
            evidence_ids=evidence_ids,
            proof=proof,
        )
        if not cand:
            return json.dumps(
                {
                    "error": (
                        "active verifier context, current candidate, and valid verdict required "
                        "(need confirmed|refuted|inconclusive)"
                    ),
                    "candidate_id": candidate_id,
                },
                indent=2,
            )
        return json.dumps(
            {
                "candidate": cand.to_dict(),
                "engagement_brain": getattr(self, "_engagement_brain", None),
            },
            indent=2,
        )[:_tool_output_max_chars()]

    async def independent_verify(
        self,
        candidate_id: str = "",
        max_parallel: int = 3,
        candidate_revision: int = 0,
    ) -> str:
        """Spawn a fresh verifier agent per pending candidate (no hunter transcript)."""
        from app.services.agent.engagement_brain import engagement_brain_from_dict
        from app.services.agent.independent_verify import (
            candidate_from_dict,
            run_independent_verifiers,
        )

        self._require_independent_verify = True
        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cands = [
            c
            for c in (candidate_from_dict(raw) for raw in (brain.candidates or []))
            if c
        ]
        if candidate_id:
            wanted = candidate_id.strip()
            cands = [c for c in cands if c.id == wanted or c.title == wanted]
        if candidate_revision and any(c.revision != candidate_revision for c in cands):
            return json.dumps({"error": "candidate_revision_changed",
                               "candidate_id": candidate_id})
        threat_slice = ""
        if brain.threat_model:
            try:
                from app.services.agent.threat_model import format_threat_model_for_prompt
                threat_slice = format_threat_model_for_prompt(brain.threat_model)[:2500]
            except Exception:
                threat_slice = ""
        reports = await run_independent_verifiers(
            cands,
            llm=self._cheap_llm(),
            tools_manager=self,
            targets=[brain.target] if brain.target else [],
            threat_slice=threat_slice,
            max_parallel=int(max_parallel or 3),
        )
        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        return json.dumps(
            {
                "verify_wave": reports,
                "candidates": brain.candidates,
                "engagement_brain": brain.to_dict(),
            },
            indent=2,
        )[:_tool_output_max_chars()]
