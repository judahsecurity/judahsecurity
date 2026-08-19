"""
Auto Tool Selector

Context-aware tool recommendation engine that analyzes discovered target state
(technologies, ports, parameters, WAF) and returns prioritized tool chains
the agent should execute next.

This replaces guesswork with deterministic, rules-based recommendations
that the LLM uses to make faster, smarter tool choices.
"""

import logging
from typing import List, Dict, Any, Optional, Set

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Target classification rules
# ---------------------------------------------------------------------------

# Technology keywords → target type mapping
_TECH_CLASSIFIERS: Dict[str, List[str]] = {
    "wordpress": ["wordpress", "wp-content", "wp-includes", "wp-json"],
    "joomla": ["joomla", "com_content"],
    "drupal": ["drupal"],
    "cms": ["wordpress", "joomla", "drupal", "magento", "shopify", "squarespace", "wix", "ghost", "typo3"],
    "php": ["php", "laravel", "symfony", "codeigniter", "cakephp", "yii"],
    "dotnet": [".net", "asp.net", "aspnet", "iis", "blazor"],
    "java": ["java", "spring", "tomcat", "jboss", "wildfly", "jetty", "struts"],
    "python": ["python", "django", "flask", "fastapi", "gunicorn", "uvicorn"],
    "nodejs": ["node.js", "express", "next.js", "nuxt", "koa", "nest"],
    "ruby": ["ruby", "rails", "sinatra", "puma", "unicorn"],
    "api": ["swagger", "openapi", "graphql", "rest", "api-docs", "redoc"],
    "spa": ["react", "angular", "vue", "svelte", "ember"],
    "auth": ["jwt", "oauth", "oauth2", "oidc", "openid", "saml", "auth0", "keycloak", "okta", "cognito", "firebase auth"],
    "container": ["docker", "dockerfile", "kubernetes", "k8s", "containerd", "podman", "helm", "openshift"],
    "source": ["github", "gitlab", "bitbucket", ".git", "source map", "sourcemap"],
    "nginx": ["nginx"],
    "apache": ["apache"],
    "elasticsearch": ["elasticsearch", "you know, for search"],
    "cdn": ["cloudflare", "akamai", "fastly", "cloudfront", "incapsula"],
    "waf": ["cloudflare", "akamai", "imperva", "incapsula", "f5", "modsecurity", "sucuri", "barracuda"],
    "chatbot": [
        "openai", "anthropic", "langchain", "chatbot", "chatgpt",
        "intercom", "drift", "zendesk", "zendesk chat", "crisp", "tawk",
        "tawk.to", "livechat", "freshchat", "helpscout", "hubspot chat",
        "salesforce chat", "custom chat widget", "live chat",
    ],
}

# Port → service type mapping for common non-HTTP services
_PORT_SERVICE_MAP: Dict[int, str] = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    110: "pop3",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    8529: "arangodb",
    9200: "elasticsearch",
    18083: "emqx",
    27017: "mongodb",
}


# ---------------------------------------------------------------------------
# Tool recommendation chains
# ---------------------------------------------------------------------------

class ToolRecommendation:
    """A single tool recommendation with priority and rationale."""

    def __init__(
        self,
        tool_name: str,
        args_template: str,
        priority: int,
        rationale: str,
        phase_required: str = "informational",
        category: str = "general",
    ):
        self.tool_name = tool_name
        self.args_template = args_template  # uses {target} placeholder
        self.priority = priority  # 1 = highest
        self.rationale = rationale
        self.phase_required = phase_required
        self.category = category

    def format_args(self, target: str) -> str:
        return self.args_template.format(target=target)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "args_template": self.args_template,
            "priority": self.priority,
            "rationale": self.rationale,
            "phase_required": self.phase_required,
            "category": self.category,
        }


class ToolSelector:
    """
    Context-aware tool selector that analyzes the current assessment state
    and recommends which tools to run next.

    Usage:
        selector = ToolSelector(target_info, execution_trace, current_phase)
        recommendations = selector.get_recommendations()
    """

    def __init__(
        self,
        target: str,
        target_info: Dict[str, Any],
        execution_trace: List[Dict[str, Any]],
        current_phase: str = "informational",
        parameters: Optional[Dict[str, Any]] = None,
        waf_detected: Optional[str] = None,
    ):
        self.target = target
        self.target_info = target_info or {}
        self.execution_trace = execution_trace or []
        self.current_phase = current_phase
        self.parameters = parameters or {}
        self.waf_detected = waf_detected

        # Derived state
        self._tools_already_run: Set[str] = self._extract_tools_run()
        self._technologies: Set[str] = self._extract_technologies()
        self._ports: Set[int] = set(self.target_info.get("ports", []))
        self._services: Set[str] = set(s.lower() for s in self.target_info.get("services", []))
        self._vulns: List[str] = self.target_info.get("vulnerabilities", [])
        self._target_types: Set[str] = self._classify_target()

    # ------------------------------------------------------------------
    # State extraction helpers
    # ------------------------------------------------------------------

    def _extract_tools_run(self) -> Set[str]:
        """Get set of tools already executed in this session."""
        tools = set()
        for step in self.execution_trace:
            tool = step.get("tool_name")
            if tool:
                tools.add(tool)
        return tools

    def _extract_technologies(self) -> Set[str]:
        """Get lowercase set of discovered technologies."""
        return set(t.lower() for t in self.target_info.get("technologies", []))

    def _classify_target(self) -> Set[str]:
        """Classify the target based on discovered technologies."""
        types: Set[str] = set()
        tech_str = " ".join(self._technologies)

        for target_type, keywords in _TECH_CLASSIFIERS.items():
            for kw in keywords:
                if kw in tech_str:
                    types.add(target_type)
                    break

        # Classify by ports
        if self._ports:
            http_ports = {80, 443, 8080, 8443, 8000, 3000, 5000}
            if self._ports & http_ports:
                types.add("web")
            db_ports = {3306, 5432, 1433, 1521, 27017, 6379, 9200, 9300, 5984, 8529}
            if self._ports & db_ports:
                types.add("database")

        # Default: if nothing detected, assume web
        if not types:
            types.add("web")

        return types

    # ------------------------------------------------------------------
    # Core recommendation engine
    # ------------------------------------------------------------------

    def get_recommendations(self) -> List[Dict[str, Any]]:
        """
        Return prioritized list of tool recommendations based on current state.

        Each recommendation has: tool_name, args_template, priority, rationale,
        phase_required, category.
        """
        recs: List[ToolRecommendation] = []

        # Phase 1: Reconnaissance (always recommend if not done)
        recs.extend(self._recon_recommendations())

        # Phase 2: Technology-specific tools
        recs.extend(self._technology_recommendations())

        # Phase 3: Parameter discovery & injection testing
        recs.extend(self._injection_recommendations())

        # Phase 4: Active scanning (exploitation phase)
        recs.extend(self._active_scan_recommendations())

        # Phase 5: Specialty scans based on findings
        recs.extend(self._specialty_recommendations())

        # Filter out already-run tools, dedupe by tool name, sort by priority.
        # CMS hunts (WordPress) jump the recon-first queue — once WP is
        # fingerprinted, wpscan / REST user enum should be the next action.
        seen: Set[str] = set()
        filtered: List[ToolRecommendation] = []
        for r in sorted(recs, key=lambda x: (0 if x.category == "cms" else 1, x.priority)):
            if r.tool_name in self._tools_already_run or r.tool_name in seen:
                continue
            seen.add(r.tool_name)
            filtered.append(r)

        return [r.to_dict() for r in filtered]

    def get_recommendations_text(self) -> str:
        """Format recommendations as text for prompt injection."""
        recs = self.get_recommendations()
        if not recs:
            return "All recommended tools have been executed. Consider completing or deepening specific findings."

        lines = ["### Smart Tool Recommendations (based on discovered state)"]
        lines.append(f"**Target classification**: {', '.join(sorted(self._target_types))}")
        if self.waf_detected:
            lines.append(f"**WAF detected**: {self.waf_detected} — use evasion-aware payloads")
        lines.append("")

        # Group by category
        by_category: Dict[str, List[Dict[str, Any]]] = {}
        for r in recs:
            cat = r.get("category", "general")
            by_category.setdefault(cat, []).append(r)

        priority_order = [
            "cms", "reconnaissance", "technology", "waf_detection",
            "parameter_discovery", "injection_testing",
            "active_scanning", "tls_ssl", "api", "ai_security",
            "source_sast", "supply_chain", "general",
        ]

        for cat in priority_order:
            items = by_category.get(cat, [])
            if not items:
                continue
            lines.append(f"**{cat.replace('_', ' ').title()}**:")
            for r in items[:5]:  # Top 5 per category
                phase_tag = f" [{r['phase_required']}]" if r["phase_required"] != "informational" else ""
                lines.append(
                    f"  {r['priority']}. `{r['tool_name']}` — {r['rationale']}{phase_tag}"
                )
            lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Recommendation generators
    # ------------------------------------------------------------------

    def _recon_recommendations(self) -> List[ToolRecommendation]:
        """Basic reconnaissance tools that should always run first."""
        recs = []
        t = self.target

        if "execute_httpx" not in self._tools_already_run:
            recs.append(ToolRecommendation(
                tool_name="execute_httpx",
                args_template="-u {target} -json -tech-detect -status-code -title -follow-redirects",
                priority=1,
                rationale="HTTP probing — get status, tech stack, redirects. Run first to understand the target.",
                category="reconnaissance",
            ))

        if "execute_dnsx" not in self._tools_already_run:
            recs.append(ToolRecommendation(
                tool_name="execute_dnsx",
                args_template="-d {target} -a -aaaa -mx -ns -cname -json",
                priority=2,
                rationale="DNS resolution — get IPs, mail servers, nameservers. Essential baseline.",
                category="reconnaissance",
            ))

        if "execute_wafw00f" not in self._tools_already_run:
            recs.append(ToolRecommendation(
                tool_name="execute_wafw00f",
                args_template="-a https://{target}",
                priority=3,
                rationale="WAF detection — identify protections BEFORE injection testing.",
                category="waf_detection",
            ))

        if "execute_wappalyzer" not in self._tools_already_run and "execute_whatweb" not in self._tools_already_run:
            recs.append(ToolRecommendation(
                tool_name="execute_wappalyzer",
                args_template="https://{target}",
                priority=4,
                rationale="Technology fingerprinting — identify CMS, frameworks, server stack with 6000+ signatures.",
                category="technology",
            ))

        # Passive asset expansion — real tester always widens the surface early
        if "execute_subfinder" not in self._tools_already_run:
            recs.append(ToolRecommendation(
                tool_name="execute_subfinder",
                args_template="-d {target} -silent -json",
                priority=3,
                rationale="Passive subdomain enum — expand attack surface before deep testing a single host.",
                category="reconnaissance",
            ))

        if "execute_uncover" not in self._tools_already_run:
            recs.append(ToolRecommendation(
                tool_name="execute_uncover",
                args_template='query=ssl:"{target}" engines=["shodan","censys","fofa"] limit=200 persist=True',
                priority=4,
                rationale="InternetDB expansion (Uncover) — find related hosts/ports via Shodan/Censys/FOFA without active probing.",
                category="reconnaissance",
            ))

        if "execute_katana" not in self._tools_already_run:
            recs.append(ToolRecommendation(
                tool_name="execute_katana",
                args_template="-u https://{target} -d 2 -jc -json",
                priority=5,
                rationale="Crawl live site for endpoints, forms, and JS — feeds param mining and JS secret scans.",
                category="reconnaissance",
            ))

        return recs

    def _technology_recommendations(self) -> List[ToolRecommendation]:
        """Technology-specific tool recommendations."""
        recs = []

        es_hit = (
            "elasticsearch" in self._target_types
            or "elasticsearch" in self._services
            or bool(self._ports & {9200, 9300})
            or ":9200" in (self.target or "").lower()
        )
        if es_hit:
            recs.append(ToolRecommendation(
                tool_name="execute_curl",
                args_template="-sS -D- http://{target}:9200/",
                priority=2,
                rationale=(
                    "Elasticsearch :9200 observed — unauth GET / for cluster name/version/node. "
                    "Banner is a foothold: then /_cluster/health, /_nodes/os,jvm, /_cat/indices, "
                    "size=1 sample read, PUT+DELETE aegis_test_index. No Painless RCE, no bulk dump."
                ),
                phase_required="exploitation",
                category="data_store",
            ))

        arango_hit = (
            "arangodb" in self._target_types
            or "arangodb" in self._services
            or bool(self._ports & {8529})
            or ":8529" in (self.target or "").lower()
        )
        if arango_hit:
            recs.append(ToolRecommendation(
                tool_name="execute_curl",
                args_template='-sS -D- -H Content-Type: application/json -d {"username":"root","password":""} http://{target}:8529/_open/auth',
                priority=2,
                rationale=(
                    "ArangoDB :8529 observed — POST /_open/auth root with empty password only. "
                    "On JWT: list databases + one collection sample. No PII dump."
                ),
                phase_required="exploitation",
                category="data_store",
            ))

        # WordPress detected — scan immediately (informational). Do not wait
        # for methodology cards or phase promotion. Token is env-injected.
        if "wordpress" in self._target_types:
            recs.append(ToolRecommendation(
                tool_name="execute_wpscan",
                args_template=(
                    "--url https://{target} --enumerate vp,u "
                    "--plugins-detection passive --random-user-agent"
                ),
                priority=1,
                rationale=(
                    "WordPress detected — run WPScan NOW. Then GET "
                    "/wp-json/wp/v2/users and probe /wp-admin/admin-ajax.php "
                    "(loadmore / tax_query) for SQLi."
                ),
                phase_required="informational",
                category="cms",
            ))
            recs.append(ToolRecommendation(
                tool_name="execute_curl",
                args_template="-sS -D- https://{target}/wp-json/wp/v2/users?per_page=100",
                priority=1,
                rationale=(
                    "WordPress REST user enumeration — unauthenticated "
                    "GET /wp-json/wp/v2/users often leaks admin logins (200 + slug)."
                ),
                phase_required="informational",
                category="cms",
            ))

        # Other CMS
        if "cms" in self._target_types and "wordpress" not in self._target_types:
            if "execute_cmseek" not in self._tools_already_run:
                recs.append(ToolRecommendation(
                    tool_name="execute_cmseek",
                    args_template="-u https://{target}",
                    priority=5,
                    rationale="CMS detected — identify CMS type and known vulnerabilities.",
                    category="cms",
                ))

        # API/Swagger/GraphQL detected
        if "api" in self._target_types:
            recs.append(ToolRecommendation(
                tool_name="execute_curl",
                args_template="-sS -D- https://{target}/api/schema/",
                priority=4,
                rationale=(
                    "OpenAPI/Swagger likely — GET /api/schema/ (or swagger.json). Hunt "
                    "security: {} on /api/auth/account/?email= and writable request fields. "
                    "Do not spray schemathesis before quoting the public operations."
                ),
                category="api",
            ))
            recs.append(ToolRecommendation(
                tool_name="compare_requests",
                args_template=(
                    '{"baseline":{"method":"GET","url":"https://{target}/api/auth/profile/"},'
                    '"mutant":{"method":"GET","url":"https://{target}/api/auth/account/'
                    '?email=aegis-enum-canary@example.invalid"}}'
                ),
                priority=5,
                rationale=(
                    "Unauth account lookup: sibling 401 vs lookup 200/500 proves JWT was "
                    "skipped. One canary email only — do not spray. A down database is SUBMIT."
                ),
                category="api",
            ))
            recs.append(ToolRecommendation(
                tool_name="execute_astf",
                args_template='{"url":"https://{target}","token":""}',
                priority=6,
                rationale=(
                    "API surface detected — run OWASP ASTF (API Top 10 / GraphQL / JWT) as "
                    "complementary structural coverage. Pass bearer token when authed. "
                    "Prove CRITICAL/HIGH with compare_requests before create_finding."
                ),
                phase_required="exploitation",
                category="api",
            ))
            recs.append(ToolRecommendation(
                tool_name="execute_schemathesis",
                args_template="run https://{target}/openapi.json --checks all",
                priority=8,
                rationale=(
                    "After schema review: optional documented-endpoint checks. "
                    "500s from a down DB are not the account-lookup proof — use the "
                    "401-vs-500 differential on /api/auth/account/ instead."
                ),
                phase_required="exploitation",
                category="api",
            ))
            recs.append(ToolRecommendation(
                tool_name="execute_kiterunner",
                args_template="scan https://{target} -A=apiroutes-210228",
                priority=7,
                rationale="API detected — discover hidden REST/GraphQL routes.",
                category="api",
            ))

        # SPA / JavaScript-heavy
        if "spa" in self._target_types or "nodejs" in self._target_types:
            if "execute_katana" not in self._tools_already_run:
                recs.append(ToolRecommendation(
                    tool_name="execute_katana",
                    args_template="-u https://{target} -d 3 -jc -json",
                    priority=5,
                    rationale="SPA/JS-heavy app — deep crawl to find JS endpoints, API calls, and hidden routes.",
                    category="reconnaissance",
                ))
            recs.append(ToolRecommendation(
                tool_name="execute_browser",
                args_template='{"actions": [{"action": "navigate", "url": "https://{target}"}, {"action": "execute_js", "script": "JSON.stringify({cookies: document.cookie, localStorage: Object.keys(localStorage), scripts: Array.from(document.scripts).map(s=>s.src).filter(Boolean)})"}]}',
                priority=8,
                rationale="JS-heavy app — extract cookies, localStorage keys, and external script URLs for sensitive data leakage.",
                phase_required="exploitation",
                category="active_scanning",
            ))
            if "execute_retirejs" not in self._tools_already_run:
                recs.append(ToolRecommendation(
                    tool_name="execute_retirejs",
                    args_template="urls=<JS bundle URLs from katana/deep_crawl/gau>",
                    priority=6,
                    rationale="JS-heavy app — scan the crawled .js bundles for vulnerable libraries (jQuery/Angular/Lodash) with known CVEs.",
                    category="reconnaissance",
                ))

        # JWT / token-based auth detected
        if "auth" in self._target_types and "execute_jwt" not in self._tools_already_run:
            recs.append(ToolRecommendation(
                tool_name="execute_jwt",
                args_template="<JWT captured from cookie/Authorization header/JS>",
                priority=6,
                rationale="Token-based auth (JWT/OAuth/OIDC) detected — decode captured JWTs and test alg:none, key confusion, and weak-secret cracking.",
                phase_required="exploitation",
                category="injection_testing",
            ))

        # Chatbot / AI endpoint detected
        if "chatbot" in self._target_types:
            recs.append(ToolRecommendation(
                tool_name="execute_llm_red_team",
                args_template="target_url=https://{target}",
                priority=6,
                rationale="AI/chatbot technology detected — run OWASP LLM Top 10 assessment.",
                category="ai_security",
            ))
            if "execute_garak" not in self._tools_already_run:
                recs.append(ToolRecommendation(
                    tool_name="execute_garak",
                    args_template=(
                        "--target_type rest --target_name https://{target} "
                        "--probes dan,promptinject,encoding,jailbreak "
                        "--report_prefix /tmp/garak_{target}"
                    ),
                    priority=8,
                    rationale="Confirmed AI surface — deepen with garak probe families after llm_red_team.",
                    phase_required="exploitation",
                    category="ai_security",
                ))

        # GraphQL signals → dedicated audit
        tech_blob = " ".join(self._technologies)
        if "graphql" in tech_blob or "graphql" in self._target_types:
            if "execute_graphql_cop" not in self._tools_already_run:
                recs.append(ToolRecommendation(
                    tool_name="execute_graphql_cop",
                    args_template="-t https://{target}/graphql",
                    priority=5,
                    rationale="GraphQL detected — audit introspection, CSRF, batching, and IDE exposure.",
                    category="api",
                ))
            recs.append(ToolRecommendation(
                tool_name="create_scan",
                args_template='scan_type=graphql_scan targets=["{target}"]',
                priority=6,
                rationale="Queue platform GraphQL scanner for full endpoint discovery + misconfig checks.",
                category="api",
            ))

        return recs

    def _injection_recommendations(self) -> List[ToolRecommendation]:
        """Parameter discovery and injection testing recommendations."""
        recs = []

        # Parameter discovery
        if "discover_parameters" not in self._tools_already_run:
            recs.append(ToolRecommendation(
                tool_name="discover_parameters",
                args_template="https://{target}",
                priority=5,
                rationale="Discover injectable parameters — forms, query strings, hidden inputs, JS variables.",
                category="parameter_discovery",
            ))

        if "execute_arjun" not in self._tools_already_run:
            recs.append(ToolRecommendation(
                tool_name="execute_arjun",
                args_template="-u https://{target}",
                priority=6,
                rationale="Find hidden HTTP parameters with smart wordlists and response analysis.",
                category="parameter_discovery",
            ))

        # If parameters have been discovered, recommend injection tools
        if self.parameters:
            sqli_params = []
            xss_params = []
            ssrf_params = []
            for name, info in self.parameters.items():
                vulns = info.get("likely_vulnerable_to", [])
                if "sqli" in vulns:
                    sqli_params.append(name)
                if "xss" in vulns:
                    xss_params.append(name)
                if "ssrf" in vulns:
                    ssrf_params.append(name)

            # Blind/OOB-prone params (SSRF, or blind SQLi/RCE) — stand up an OOB collaborator
            if (ssrf_params or sqli_params) and "execute_interactsh" not in self._tools_already_run:
                recs.append(ToolRecommendation(
                    tool_name="execute_interactsh",
                    args_template="register",
                    priority=6,
                    rationale=(
                        "Params prone to blind SSRF/SQLi/RCE found — register an OOB collaborator, "
                        "plant its payload URL in the sink, then poll for DNS/HTTP callbacks."
                    ),
                    phase_required="exploitation",
                    category="injection_testing",
                ))

            if sqli_params:
                first_param = sqli_params[0]
                recs.append(ToolRecommendation(
                    tool_name="execute_sqlmap",
                    args_template=f'-u "https://{{target}}/?{first_param}=1" --batch --dbs --level=3 --risk=2',
                    priority=7,
                    rationale=f"SQLi-prone params found ({', '.join(sqli_params[:3])}) — automated SQL injection testing.",
                    phase_required="exploitation",
                    category="injection_testing",
                ))

            if xss_params:
                first_param = xss_params[0]
                recs.append(ToolRecommendation(
                    tool_name="execute_xsstrike",
                    args_template=f'-u "https://{{target}}/?{first_param}=test" --crawl',
                    priority=7,
                    rationale=f"XSS-prone params found ({', '.join(xss_params[:3])}) — advanced XSS scanning.",
                    phase_required="exploitation",
                    category="injection_testing",
                ))

            # Generate payloads for manual testing
            if sqli_params and "generate_injection_payloads" not in self._tools_already_run:
                recs.append(ToolRecommendation(
                    tool_name="generate_injection_payloads",
                    args_template="vuln_type=sqli",
                    priority=6,
                    rationale="Generate SQLi payloads (error-based, time-based, boolean-based) for manual testing.",
                    category="injection_testing",
                ))

            if xss_params and "generate_injection_payloads" not in self._tools_already_run:
                recs.append(ToolRecommendation(
                    tool_name="generate_injection_payloads",
                    args_template="vuln_type=xss",
                    priority=6,
                    rationale="Generate XSS payloads (reflected, stored, DOM) for manual testing.",
                    category="injection_testing",
                ))

        return recs

    def _active_scan_recommendations(self) -> List[ToolRecommendation]:
        """Active scanning tools (require exploitation phase)."""
        recs = []

        recs.append(ToolRecommendation(
            tool_name="execute_nuclei",
            args_template="-u https://{target} -jsonl",
            priority=6,
            rationale="Comprehensive vulnerability scan — CVEs, misconfigs, exposures, tech detection (all severities).",
            phase_required="exploitation",
            category="active_scanning",
        ))

        recs.append(ToolRecommendation(
            tool_name="execute_naabu",
            args_template="-host {target} -top-ports 1000 -json",
            priority=7,
            rationale="Port scan — discover open ports beyond 80/443.",
            phase_required="exploitation",
            category="active_scanning",
        ))

        recs.append(ToolRecommendation(
            tool_name="execute_nikto",
            args_template="-h https://{target} -Format json",
            priority=8,
            rationale="Web server vulnerability scan — 6,700+ dangerous CGIs, configs, and default files.",
            phase_required="exploitation",
            category="active_scanning",
        ))

        # TLS/SSL testing
        if "execute_testssl" not in self._tools_already_run and "execute_sslyze" not in self._tools_already_run:
            recs.append(ToolRecommendation(
                tool_name="execute_testssl",
                args_template="https://{target}",
                priority=8,
                rationale="TLS/SSL testing — check for weak ciphers, expired certs, Heartbleed, POODLE, BEAST.",
                category="tls_ssl",
            ))

        # Browser-based testing for JS-heavy sites
        recs.append(ToolRecommendation(
            tool_name="execute_browser",
            args_template='{"actions": [{"action": "check_xss", "url": "https://{target}"}]}',
            priority=9,
            rationale="Headless browser XSS verification — test for reflected/DOM XSS with real browser.",
            phase_required="exploitation",
            category="active_scanning",
        ))

        return recs

    def _specialty_recommendations(self) -> List[ToolRecommendation]:
        """Specialty tools based on specific findings or context."""
        recs = []

        # Historical URL discovery (useful for finding old endpoints)
        if "execute_gau" not in self._tools_already_run and "execute_waybackurls" not in self._tools_already_run:
            recs.append(ToolRecommendation(
                tool_name="execute_gau",
                args_template="{target} --subs",
                priority=9,
                rationale="Discover historical URLs from Wayback, CommonCrawl, OTX — find old endpoints and params.",
                category="reconnaissance",
            ))

        # Content discovery + API brute after baseline recon
        browser_done = (
            "execute_interceptor" in self._tools_already_run
            or "execute_deep_crawl" in self._tools_already_run
        )
        if browser_done and "execute_feroxbuster" not in self._tools_already_run:
            recs.append(ToolRecommendation(
                tool_name="execute_feroxbuster",
                args_template=(
                    "-u https://{target} -w /opt/wordlists/app-dirs-common.txt "
                    "-d 1 -t 20 --rate-limit 50 -q --status-codes 200,204,301,302,401,403"
                ),
                priority=4,
                rationale=(
                    "After the browser walkthrough: bounded directory/path enum "
                    "(login, reset, admin, .git, swagger, backups) for misconfig context — "
                    "not a full DirBuster spray. Then ingest_urls_into_map."
                ),
                category="reconnaissance",
            ))
        if browser_done and "execute_katana" not in self._tools_already_run:
            recs.append(ToolRecommendation(
                tool_name="execute_katana",
                args_template=(
                    "-u https://{target} -d 3 -jc -fx "
                    "-ef woff,css,png,svg,jpg,woff2,jpeg,gif -jsonl -silent"
                ),
                priority=5,
                rationale=(
                    "Enrich path inventory with katana JS/asset crawl; merge via ingest_urls_into_map."
                ),
                category="reconnaissance",
            ))
        if (
            browser_done
            and "ingest_urls_into_map" not in self._tools_already_run
            and (
                "execute_feroxbuster" in self._tools_already_run
                or "execute_katana" in self._tools_already_run
                or "execute_gau" in self._tools_already_run
            )
        ):
            recs.append(ToolRecommendation(
                tool_name="ingest_urls_into_map",
                args_template='urls=<newline paths from ferox/katana/gau>',
                priority=3,
                rationale="Fold discovered directories/paths into the capability map and refresh methodologies.",
                category="reconnaissance",
            ))
        if "execute_ffuf" not in self._tools_already_run and browser_done:
            recs.append(ToolRecommendation(
                tool_name="execute_ffuf",
                args_template=(
                    "-u https://{target}/FUZZ -w /opt/wordlists/app-dirs-common.txt "
                    "-mc 200,204,301,302,401,403 -t 20 -rate 50"
                ),
                priority=7,
                rationale=(
                    "Optional second-pass path fuzz if ferox was thin — still use the "
                    "common dirs list, not a massive SecLists DirBuster wordlist."
                ),
                phase_required="exploitation",
                category="reconnaissance",
            ))

        if "execute_kiterunner" not in self._tools_already_run and (
            "api" in self._target_types or "spa" in self._target_types
        ):
            recs.append(ToolRecommendation(
                tool_name="execute_kiterunner",
                args_template="scan https://{target} -A=apiroutes-210228",
                priority=7,
                rationale="API/SPA signals — discover undocumented REST routes via smart wordlists.",
                category="api",
            ))

        # JS secret / sink analysis after crawl tools have run
        crawled = self._tools_already_run & {
            "execute_katana", "execute_gau", "execute_waybackurls",
            "execute_deep_crawl", "execute_interceptor",
        }
        if crawled and "scan_js_urls_for_secrets" not in self._tools_already_run:
            recs.append(ToolRecommendation(
                tool_name="scan_js_urls_for_secrets",
                args_template="urls=<JS URLs from katana/deep_crawl/gau/interceptor>",
                priority=6,
                rationale="JS bundles discovered — hunt hardcoded API keys/tokens before deeper testing.",
                category="reconnaissance",
            ))
        if crawled:
            recs.append(ToolRecommendation(
                tool_name="create_scan",
                args_template='scan_type=js_recon targets=["{target}"]',
                priority=7,
                rationale="Queue JS recon (secrets, source maps, dep-confusion, DOM sinks) via scanner worker.",
                category="reconnaissance",
            ))

        # Takeover sweep once DNS/subdomain work has happened
        dns_done = self._tools_already_run & {
            "execute_subfinder", "execute_dnsx", "execute_crtsh", "execute_subfaster",
        }
        if dns_done:
            recs.append(ToolRecommendation(
                tool_name="create_scan",
                args_template='scan_type=subdomain_takeover targets=["{target}"]',
                priority=8,
                rationale="Subdomains/DNS collected — sweep for dangling CNAMEs and takeover fingerprints.",
                category="reconnaissance",
            ))

        # Tester methodology: Interceptor walkthrough first (real Chrome), deep_crawl fallback
        browser_done = (
            "execute_interceptor" in self._tools_already_run
            or "execute_deep_crawl" in self._tools_already_run
        )
        if "execute_interceptor" not in self._tools_already_run:
            spa_boost = "spa" in self._target_types
            recs.append(ToolRecommendation(
                tool_name="execute_interceptor",
                args_template=(
                    '{"url":"https://{target}","depth":3,"max_pages":25,'
                    '"interact":true,"max_clicks":14}'
                ),
                priority=2 if spa_boost else 3,
                rationale=(
                    "Walk the app like a pentester with Interceptor Site Spider "
                    "(katana in a real Chrome tab) — interaction first, map functionality "
                    "(auth/forms/products/APIs) before spraying scanners."
                    + (" SPA fingerprint — prioritize Chrome-tab crawl." if spa_boost else "")
                ),
                category="reconnaissance",
            ))
        if "execute_deep_crawl" not in self._tools_already_run:
            # Fallback / enrichment if Interceptor workers offline or map stayed thin
            recs.append(ToolRecommendation(
                tool_name="execute_deep_crawl",
                args_template='{"url":"https://{target}","depth":3,"interact":true}',
                priority=5 if "execute_interceptor" in self._tools_already_run else 6,
                rationale=(
                    "Playwright deep_crawl — use when Interceptor workers are offline or "
                    "the capability map is still thin on forms/APIs after the Chrome crawl."
                ),
                category="reconnaissance",
            ))
        if browser_done and "fireteam_dispatch" not in self._tools_already_run:
            if "sync_engagement_brain" not in self._tools_already_run:
                recs.append(ToolRecommendation(
                    tool_name="sync_engagement_brain",
                    args_template="",
                    priority=2,
                    rationale=(
                        "Browser map ready — seed observation→methodology cards before fireteam."
                    ),
                    category="exploitation",
                ))
            recs.append(ToolRecommendation(
                tool_name="fireteam_dispatch",
                args_template='mission="Attack mapped surfaces" specialists="auto" targets=["https://{target}"]',
                priority=3,
                rationale=(
                    "Capability map available — spawn attack specialists matched to "
                    "auth/API/forms/GraphQL/uploads discovered in the browser walkthrough."
                ),
                category="exploitation",
            ))

        # Git secret scanning (if git repo indicators found)
        git_indicators = {"github", "gitlab", "bitbucket", ".git"}
        if git_indicators & self._technologies:
            recs.append(ToolRecommendation(
                tool_name="execute_gitleaks",
                args_template="detect --source . --report-format json",
                priority=7,
                rationale="Git repository indicators found — scan for hardcoded secrets and API keys.",
                category="general",
            ))

        # Source-aware SAST when repo / source indicators are present
        if "source" in self._target_types or git_indicators & self._technologies:
            if "execute_semgrep" not in self._tools_already_run:
                recs.append(ToolRecommendation(
                    tool_name="execute_semgrep",
                    args_template="--config auto /path/to/cloned/source",
                    priority=6,
                    rationale=(
                        "Source/repo indicators found — run Semgrep SAST on the local checkout "
                        "for OWASP sinks, insecure crypto, and secrets."
                    ),
                    category="source_sast",
                ))
            if "execute_trivy" not in self._tools_already_run:
                recs.append(ToolRecommendation(
                    tool_name="execute_trivy",
                    args_template="fs /path/to/cloned/source --severity CRITICAL,HIGH",
                    priority=7,
                    rationale="Source/repo available — scan dependencies and secrets with Trivy fs.",
                    category="supply_chain",
                ))

        # Container / IaC supply-chain scanning
        if "container" in self._target_types and "execute_trivy" not in self._tools_already_run:
            recs.append(ToolRecommendation(
                tool_name="execute_trivy",
                args_template="image <image:tag from tech fingerprint> --severity CRITICAL,HIGH",
                priority=6,
                rationale=(
                    "Container/K8s technology detected — scan the image (or IaC with "
                    "'config /path') for OS/lang CVEs and misconfigurations."
                ),
                category="supply_chain",
            ))

        # Certificate transparency for subdomain discovery
        if "execute_crtsh" not in self._tools_already_run:
            recs.append(ToolRecommendation(
                tool_name="execute_crtsh",
                args_template="{target}",
                priority=10,
                rationale="Certificate transparency — passively discover subdomains from CT logs.",
                category="reconnaissance",
            ))
        if "execute_crt_name" not in self._tools_already_run:
            recs.append(ToolRecommendation(
                tool_name="execute_crt_name",
                args_template="{target}",
                priority=10,
                rationale=(
                    "crt.name aggregated CT/DNS index — broader passive coverage "
                    "(live CT, backfill, Chaos, CZDS, probes) with first-seen dates."
                ),
                category="reconnaissance",
            ))
        if "execute_subfaster" not in self._tools_already_run:
            recs.append(ToolRecommendation(
                tool_name="execute_subfaster",
                args_template="-d {target}",
                priority=11,
                rationale=(
                    "Subfaster — fast passive enum with crt.name + shodanct + "
                    "rapiddns + thc/submd/hackertarget/sitedossier (no keys)."
                ),
                category="reconnaissance",
            ))

        return recs


# ---------------------------------------------------------------------------
# Convenience function for orchestrator integration
# ---------------------------------------------------------------------------

def get_tool_recommendations(
    target: str,
    target_info: Dict[str, Any],
    execution_trace: List[Dict[str, Any]],
    current_phase: str = "informational",
    parameters: Optional[Dict[str, Any]] = None,
    waf_detected: Optional[str] = None,
) -> str:
    """
    Get formatted tool recommendations for injection into the agent prompt.

    Called by the orchestrator's _think_node to provide context-aware guidance.
    """
    selector = ToolSelector(
        target=target,
        target_info=target_info,
        execution_trace=execution_trace,
        current_phase=current_phase,
        parameters=parameters,
        waf_detected=waf_detected,
    )
    return selector.get_recommendations_text()


def get_tool_recommendations_json(
    target: str,
    target_info: Dict[str, Any],
    execution_trace: List[Dict[str, Any]],
    current_phase: str = "informational",
    parameters: Optional[Dict[str, Any]] = None,
    waf_detected: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Get raw tool recommendations as a list of dicts.

    Used by the auto_select_tools agent tool for programmatic access.
    """
    selector = ToolSelector(
        target=target,
        target_info=target_info,
        execution_trace=execution_trace,
        current_phase=current_phase,
        parameters=parameters,
        waf_detected=waf_detected,
    )
    return selector.get_recommendations()
