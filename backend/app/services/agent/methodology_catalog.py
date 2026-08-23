"""
Observation → methodology catalog.

Maps crawl/observe signals (forms, APIs, auth, params, tech) to concrete test
methodologies with CWE / CAPEC / OWASP metadata so the engagement brain can
seed hypothesis cards the agent must prove or kill.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Sequence


@dataclass
class Methodology:
    """A concrete test methodology derived from observed surface."""

    id: str
    title: str
    hunt: str
    specialist: str
    priority: str  # critical | high | medium | low
    assumption: str
    test: str
    pass_criteria: str
    kill_criteria: str
    cwe_ids: List[str] = field(default_factory=list)
    capec_ids: List[str] = field(default_factory=list)
    owasp: str = ""
    evidence: str = ""
    why: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


_RESET_RE = re.compile(
    r"(password.?reset|forgot.?password|/reset|/recover|forgot|/change.?password)",
    re.I,
)
_INVITE_RE = re.compile(r"(invite|invitation|/signup|/register|/join|create.?account)", re.I)
_CHECKOUT_RE = re.compile(r"(checkout|cart|payment|order|billing|price|quantity)", re.I)
_OPENAPI_RE = re.compile(
    r"(swagger|openapi|/api-docs|/v3/api-docs|/docs\.json|redoc|"
    r"/schema\.json|/api/schema|spectacular|swagger-ui)",
    re.I,
)
_APIKEY_HINT_RE = re.compile(
    r"(api[_-]?key|access[_-]?token|secret[_-]?key|authorization|bearer|"
    r"client[_-]?id|client[_-]?secret)",
    re.I,
)
_NEXT_ADMIN_JS_RE = re.compile(
    r"(_next/static|/adminui|admin-ui|/admin/_next)",
    re.I,
)
_EMAILJS_RE = re.compile(
    r"(emailjs|emailjs[_-]?(?:user|service|template)id|api\.emailjs\.com)",
    re.I,
)
_ID_PARAM_RE = re.compile(
    r"(?:[?&](?:id|user_?id|account_?id|org_?id|tenant_?id|uid|uuid)=|/\{?\w*(?:id|uuid)\}?|/api/\w+/\d+)",
    re.I,
)
_REFLECT_PARAM_RE = re.compile(
    r"(?:[?&](?:q|query|search|s|keyword|term|name|message|comment|redirect|url|next|return)=)",
    re.I,
)
_SSRF_HINT_RE = re.compile(
    r"("
    r"webhook|callback|fetch|proxy|import|url=|uri=|link=|avatar|og:image|preview|"
    r"/actions|/execute|datasource|requesturl|request_url|httpurl|targeturl|"
    r"queryurl|endpoint=|callbackurl"
    r")",
    re.I,
)
_AZURE_FUNCTION_RE = re.compile(
    r"(azurewebsites\.net|azurefunctions\.net|/api/Tester\b|functions\.azure\.com)",
    re.I,
)
_ACR_RE = re.compile(
    r"(azurecr\.io|anonymous.?pull|anonymousPullEnabled|/v2/_catalog|docker.?registry)",
    re.I,
)
_SETTINGS_WRITE_RE = re.compile(
    r"("
    r"/api/settings|savesettings|getsettings|appsettings|"
    r"/api/\w*settings|"
    r"/api/logquery|/api/audit\b|/api/readtasks|/api/opendocument|"
    r"/api/\w+/(save|update|write|create)\w*"
    r")",
    re.I,
)
_ASPNET_API_RE = re.compile(
    r"("
    r"asp\.net|aspnetcore|microsoft-iis|"
    r"x-powered-by:\s*asp\.net|"
    r"doccentrum|docutrack"
    r")",
    re.I,
)
_ASPNET_MVC_ACTION_RE = re.compile(r"/api/[A-Z][A-Za-z]+/[A-Z][A-Za-z]+")
_WP_RE = re.compile(
    r"wordpress|wp-content|wp-json|wp-admin|wp-login|wp-includes|xmlrpc\.php",
    re.I,
)
_AI_AGENT_RE = re.compile(
    r"("
    r"/api/chat|/api/message|/api/ask|/api/completions|/v1/chat|/v1/messages|"
    r"chatbot|copilot|assistant|/mcp\b|model.?context.?protocol|"
    r"openai|anthropic|langchain|langgraph|function.?call|tool.?call|"
    r"intercom|drift|zendesk.?chat|crisp\.chat|tawk\.to|livechat|freshchat"
    r")",
    re.I,
)
_EMAIL_CHANGE_RE = re.compile(
    r"("
    r"reset_email|reset_email_confirm|change_email|update_email|"
    r"/email/change|/users/set_email|set_email|"
    r"users/reset_email"
    r")",
    re.I,
)
_JWT_AUTH_RE = re.compile(
    r"("
    r"authorization|bearer|jwt|oidc|openid|"
    r"bypassauthorization|bypass.?auth|"
    r"oidcapiauthorization|jwtAuth"
    r")",
    re.I,
)
_SOCKETIO_RE = re.compile(
    r"(socket\.io|/socket\.io/|get_stream\b|url_key)",
    re.I,
)
_ML_PIPELINE_RE = re.compile(
    r"("
    r"/api/v1/train|/api/v1/celery-task|logixtwin-train|"
    r"/api/drf-celery|/api/v1/optimize|"
    r"celery-task|model.?train|ml.?pipeline"
    r")",
    re.I,
)


def methodologies_from_capability_map(cmap: Any) -> List[Methodology]:
    """
    Derive ranked methodologies from a CapabilityMap (object or dict).

    Output is specific enough for hypothesis cards (not just specialist lanes).
    """
    if cmap is None:
        return []
    if isinstance(cmap, dict):
        g = cmap.get
    else:
        g = lambda k, default=None: getattr(cmap, k, default)  # noqa: E731

    pages = list(g("pages_visited") or [])
    forms = list(g("forms") or [])
    apis = list(g("api_endpoints") or [])
    js_files = list(g("js_files") or [])
    js_endpoints = list(g("js_endpoints") or [])
    websockets = list(g("websockets") or [])
    sse = list(g("sse") or [])
    source_maps = list(g("source_maps") or [])
    param_paths = list(g("param_rich_paths") or [])
    api_samples = list(g("api_samples") or [])

    has_login = bool(g("has_login_form"))
    has_auth = bool(g("has_auth"))
    has_oauth = bool(g("has_oauth_sso"))
    has_upload = bool(g("has_upload"))
    has_search = bool(g("has_search"))
    has_graphql = bool(g("has_graphql"))
    has_admin = bool(g("has_admin"))
    has_api = bool(g("has_api"))
    has_spa = bool(g("has_spa_signals"))

    pages_blob = " ".join(str(p) for p in pages)
    forms_blob = " ".join(
        f"{f.get('action', '')} {' '.join(f.get('inputs') or [])}" for f in forms if isinstance(f, dict)
    )
    api_blob = " ".join(
        f"{e.get('method', '')} {e.get('path', '')} {e.get('host', '')}"
        for e in apis if isinstance(e, dict)
    )
    target = str(g("target") or "")
    combined = f"{pages_blob} {forms_blob} {api_blob} {' '.join(param_paths)} {target}"
    has_ai = bool(g("has_ai_agent")) or bool(
        _AI_AGENT_RE.search(f"{combined} {' '.join(str(j) for j in js_endpoints)}")
    )

    out: List[Methodology] = []
    seen: set[str] = set()

    def add(m: Methodology) -> None:
        if m.id in seen:
            return
        seen.add(m.id)
        out.append(m)

    # --- WordPress (thin maps still hunt; do not wait on WPScan) ---
    try:
        from app.services.agent.wordpress_surface import wordpress_from_map
        has_wordpress = wordpress_from_map(cmap) or bool(_WP_RE.search(combined))
    except Exception:
        has_wordpress = bool(_WP_RE.search(combined))
    if has_wordpress:
        origin = str(g("target") or "")
        wp_ev = next(
            (p for p in pages if _WP_RE.search(str(p))),
            next(
                (
                    str(e.get("path") or "")
                    for e in apis
                    if isinstance(e, dict) and _WP_RE.search(str(e.get("path") or ""))
                ),
                origin or "wordpress",
            ),
        )
        add(Methodology(
            id="wp_rest_user_enum",
            title="WordPress REST user enumeration",
            hunt="wordpress",
            specialist="injection",
            priority="high",
            assumption="Unauthenticated GET /wp-json/wp/v2/users returns slugs/names",
            test=(
                "execute_curl GET {origin}/wp-json/wp/v2/users?per_page=100. "
                "Do not wait on WPScan. 200 + slug/name is SUBMIT (CWE-200)."
            ).replace("{origin}", origin.rstrip("/") or "https://TARGET"),
            pass_criteria="JSON lists at least one user slug or name without auth",
            kill_criteria="401/403/empty list/HTML login — record status as kill evidence",
            cwe_ids=["CWE-200", "CWE-204"],
            capec_ids=["CAPEC-169"],
            owasp="A01:2021 Broken Access Control",
            evidence=wp_ev,
            why="WordPress fingerprinted — REST user enum is mandatory on thin maps",
        ))
        add(Methodology(
            id="wp_ajax_tax_query_sqli",
            title="WordPress admin-ajax nested tax_query time-based SQLi",
            hunt="wordpress",
            specialist="injection",
            priority="high",
            assumption=(
                "POST /wp-admin/admin-ajax.php loadmore/tax_query interpolates terms "
                "into WP_Query (CVE-2022-21661 class / plugin variants)"
            ),
            test=(
                "compare_requests POST admin-ajax.php action=loadmore nested tax_query "
                "SLEEP(0) vs SLEEP(2), timeout=20. Delta ≥1.5s → SLEEP(4) then "
                "execute_sqlmap --technique=BT. Timing table is the finding."
            ),
            pass_criteria="Elapsed delta ≥ 1.5s that scales with SLEEP(4)",
            kill_criteria="No timing delta after both sleeps; record the table and kill",
            cwe_ids=["CWE-89"],
            capec_ids=["CAPEC-66"],
            owasp="A03:2021 Injection",
            evidence=wp_ev,
            why="WordPress fingerprinted — ajax SQLi is the human-tester next probe, not WPScan",
        ))

    # --- Auth / credentials ---
    if has_login or has_auth:
        login_ev = next(
            (str(f.get("action") or f.get("page") or "") for f in forms if isinstance(f, dict)
             and any(re.search(r"pass|user|email|login", i or "", re.I) for i in (f.get("inputs") or []))),
            next((p for p in pages if re.search(r"login|signin|auth", p, re.I)), pages[0] if pages else ""),
        )
        add(Methodology(
            id="default_weak_creds",
            title="Default / weak credential assault",
            hunt="credential_assault",
            specialist="credential_assault",
            priority="high",
            assumption="Login accepts product defaults or weak credentials",
            test=(
                "Tiny known-default lists via test_credential_spray or bounded hydra (-f) "
                "on the mapped login; stash working session"
            ),
            pass_criteria="Working authenticated session with verified credentials",
            kill_criteria="Defaults rejected; lockout without success",
            cwe_ids=["CWE-798", "CWE-521", "CWE-287", "CWE-1393"],
            capec_ids=["CAPEC-70", "CAPEC-49"],
            owasp="A07:2021 Identification and Authentication Failures",
            evidence=login_ev,
            why="Login/auth surface observed",
        ))
        add(Methodology(
            id="auth_session_boundary",
            title="Auth / session boundary abuse",
            hunt="auth_logic",
            specialist="auth_logic",
            priority="high",
            assumption="Session cookies, forced browsing, or authz gates fail on mapped paths",
            test=(
                "Compare anonymous vs authenticated access to auth/admin paths; "
                "probe session fixation, cookie flags, and forced browse"
            ),
            pass_criteria="Protected resource reachable without auth, or elevated session obtained",
            kill_criteria="Auth required consistently; no forced-browse success",
            cwe_ids=["CWE-287", "CWE-306", "CWE-384"],
            capec_ids=["CAPEC-115", "CAPEC-61"],
            owasp="A07:2021 Identification and Authentication Failures",
            evidence=login_ev,
            why="Auth surface present",
        ))
        add(Methodology(
            id="session_token_quality",
            title="Session token generation & handling",
            hunt="auth_logic",
            specialist="auth_logic",
            priority="medium",
            assumption="Session identifiers are predictable, fixable, or poorly scoped/flagged",
            test=(
                "Inspect Set-Cookie flags; compare pre/post-login tokens; test fixation and "
                "post-logout replay"
            ),
            pass_criteria="Fixation, non-rotation, or weak cookie flags with a concrete abuse path",
            kill_criteria="Strong flags, rotate on login, invalidate on logout",
            cwe_ids=["CWE-384", "CWE-613", "CWE-1004"],
            capec_ids=["CAPEC-61", "CAPEC-31"],
            owasp="A07:2021 Identification and Authentication Failures",
            evidence=login_ev,
            why="Login/auth issues session cookies",
        ))
        add(Methodology(
            id="csrf_state_changing",
            title="CSRF on state-changing authenticated actions",
            hunt="auth_logic",
            specialist="auth_logic",
            priority="high",
            assumption="Cookie-authenticated state changes lack effective anti-CSRF controls",
            test=(
                "Replay password/email/admin/state-changing requests without CSRF token; "
                "confirm real state change via compare_requests"
            ),
            pass_criteria="Authenticated state changed without a valid anti-CSRF token",
            kill_criteria="Token required and bound; SameSite adequately blocks with no alternate vector",
            cwe_ids=["CWE-352"],
            capec_ids=["CAPEC-62"],
            owasp="A01:2021 Broken Access Control",
            evidence=login_ev,
            why="Authenticated cookie session enables CSRF testing on state-changing actions",
        ))

    # Open redirect — login/OAuth/logout style params
    _REDIRECT_RE = re.compile(
        r"(?:[?&](?:redirect|redir|next|return|returnUrl|return_url|url|continue|goto|dest|destination)=)",
        re.I,
    )
    redirect_hits = [p for p in param_paths if _REDIRECT_RE.search(p)] + [
        p for p in pages if _REDIRECT_RE.search(p) or re.search(
            r"redirect|returnUrl|oauth.*callback", p, re.I
        )
    ]
    if redirect_hits or (has_login and re.search(r"redirect|next=|return=", combined, re.I)):
        ev = redirect_hits[0] if redirect_hits else "redirect-param"
        add(Methodology(
            id="open_redirect",
            title="Open redirection",
            hunt="auth_logic",
            specialist="auth_logic",
            priority="medium",
            assumption="Redirect/next/return parameters accept off-site destinations",
            test=(
                "Set redirect params to an engagement canary host; confirm Location or "
                "client-side navigation off-domain"
            ),
            pass_criteria="Browser/HTTP redirect to external canary",
            kill_criteria="Allowlist rejects external hosts after disciplined probes",
            cwe_ids=["CWE-601"],
            capec_ids=["CAPEC-194"],
            owasp="A01:2021 Broken Access Control",
            evidence=ev,
            why="Redirect-style parameters or auth redirect flows observed",
        ))

    target = str(g("target") or "")
    grafana_blob = f"{target} {pages_blob} {combined}"
    if re.search(r"grafana", grafana_blob, re.I):
        add(Methodology(
            id="grafana_kube_prometheus_defaults",
            title="Grafana kube-prometheus-stack default admin (CWE-1393)",
            hunt="credential_assault",
            specialist="credential_assault",
            priority="critical",
            assumption=(
                "Internet-facing Grafana still uses the Helm-chart default "
                "admin:prom-operator (or admin:admin / admin:grafana) without rotation"
            ),
            test=(
                "Tiny product-default list only: admin:prom-operator, admin:admin, admin:grafana. "
                "Prefer nuclei grafana-default-login or POST /login. On success stash creds and "
                "queue default_login follow-ups (admin APIs + existing Prometheus datasource proxy)."
            ),
            pass_criteria="Working Grafana session (grafana_session cookie or dashboard redirect)",
            kill_criteria="Defaults rejected; MFA/SSO required; lockout",
            cwe_ids=["CWE-1393", "CWE-798", "CWE-521"],
            capec_ids=["CAPEC-70", "CAPEC-49"],
            owasp="A07:2021 Identification and Authentication Failures",
            evidence=target or next((p for p in pages if re.search(r"grafana", p, re.I)), ""),
            why="Grafana hostname/UI observed — kube-prometheus-stack default is a common unrotated credential",
        ))
        add(Methodology(
            id="grafana_cve_9264_sql_expressions",
            title="Grafana SQL expressions CVE-2024-9264 (Viewer+ /api/ds/query)",
            hunt="coverage",
            specialist="coverage",
            priority="critical",
            assumption=(
                "Grafana 11.0.x still forks DuckDB for type=sql expressions; Viewer and "
                "service accounts can reach /api/ds/query; sqlExpressions=0 in /metrics "
                "does not disable the backend; missing DuckDB is not a patch"
            ),
            test=(
                "Authenticated POST /api/ds/query type=sql (Viewer is enough). Confirm "
                "fork/exec of duckdb — file-read canary if present, or 'no such file' error. "
                "GET /metrics for the toggle (do not treat 0 as patched). Upgrade to 11.2.2+."
            ),
            pass_criteria=(
                "SQL expression accepted and DuckDB invoked (file contents OR fork/exec error)"
            ),
            kill_criteria=(
                "Engine rejects SQL expressions without forking DuckDB; version >= 11.2.2 patched"
            ),
            cwe_ids=["CWE-89", "CWE-94", "CWE-863"],
            capec_ids=["CAPEC-66", "CAPEC-242"],
            owasp="A03:2021 Injection",
            evidence=target or next((p for p in pages if re.search(r"grafana", p, re.I)), ""),
            why="Grafana observed — CVE-2024-9264 is reachable by Viewer if unpatched",
        ))

    es_blob = f"{target} {pages_blob} {combined}"
    if re.search(
        r":9200\b|:9300\b|elasticsearch|you know, for search|xpack\.security",
        es_blob,
        re.I,
    ):
        add(Methodology(
            id="elasticsearch_unauth_exposure",
            title="Unauthenticated Elasticsearch (xpack.security disabled, CWE-306)",
            hunt="elasticsearch_unauth",
            specialist="coverage",
            priority="critical",
            assumption=(
                "Internet-facing Elasticsearch on :9200 has xpack.security.enabled unset, "
                "so any client can read and write the cluster without credentials"
            ),
            test=(
                "Unauthenticated GET / (cluster name, version, node, tagline). "
                "Banner-only is a foothold — queue elasticsearch_unauth follow-ups: "
                "/_cluster/health + /_nodes/os,jvm, /_cat/indices, limited sample read of "
                "user indices, then PUT+DELETE a uniquely named empty test index "
                "(aegis_test_index). Do not dump all documents, do not run Painless RCE, "
                "do not pivot."
            ),
            pass_criteria=(
                "HTTP 200 cluster JSON without credentials (name/version/tagline). "
                "Writeup still IMPROVE until indices enumerated and write proven."
            ),
            kill_criteria="401/403 with security enabled; not Elasticsearch; port filtered",
            cwe_ids=["CWE-306", "CWE-284", "CWE-200"],
            capec_ids=["CAPEC-115", "CAPEC-1"],
            owasp="A01:2021 Broken Access Control",
            evidence=target or next(
                (p for p in pages if re.search(r":9200|elasticsearch", p, re.I)),
                "",
            ),
            why="Elasticsearch HTTP API / :9200 observed — unauthenticated clusters are a common internet exposure",
        ))

    if re.search(r"couchdb|_all_dbs|_utils|_node/_local/_config|:5984\b", grafana_blob, re.I):
        add(Methodology(
            id="couchdb_default_admin",
            title="CouchDB default/weak admin (CWE-1393) → _config + AuthSession",
            hunt="credential_assault",
            specialist="credential_assault",
            priority="critical",
            assumption=(
                "Internet-facing CouchDB still accepts product defaults (admin:admin / "
                "admin:password / couchdb:couchdb) or a leftover app default, unlocking _admin"
            ),
            test=(
                "Tiny product-default list only: admin:admin, admin:password, couchdb:couchdb. "
                "Prefer nuclei couchdb-default-login or GET / with Basic. On success stash creds "
                "and queue default_login follow-ups (_config secret/salts, then AuthSession forgery)."
            ),
            pass_criteria="Working CouchDB _admin session (Welcome JSON or /_session roles _admin)",
            kill_criteria="Defaults rejected; auth required without success; lockout",
            cwe_ids=["CWE-1393", "CWE-798", "CWE-200", "CWE-613"],
            capec_ids=["CAPEC-70", "CAPEC-49", "CAPEC-115"],
            owasp="A07:2021 Identification and Authentication Failures",
            evidence=target or next(
                (p for p in pages if re.search(r"couchdb|_utils|_all_dbs", p, re.I)),
                "",
            ),
            why="CouchDB hostname/API observed — default admin plus readable _config enables cookie forgery independent of password rotation",
        ))

    if re.search(r":8529\b|arangodb|aardvark|_open/auth", es_blob, re.I):
        add(Methodology(
            id="arangodb_root_empty",
            title="ArangoDB root empty password (CWE-1393 / CWE-306)",
            hunt="credential_assault",
            specialist="credential_assault",
            priority="critical",
            assumption="Internet-facing ArangoDB accepts root with an empty password at /_open/auth",
            test=(
                "POST /_open/auth {\"username\":\"root\",\"password\":\"\"} only — no other guesses. "
                "On JWT, queue arangodb_default follow-ups (list databases, one collection sample). "
                "Do not dump PII collections."
            ),
            pass_criteria="JWT for root with empty password",
            kill_criteria="401/403; password required",
            cwe_ids=["CWE-1393", "CWE-306", "CWE-798"],
            capec_ids=["CAPEC-70", "CAPEC-49"],
            owasp="A07:2021 Identification and Authentication Failures",
            evidence=target or next((p for p in pages if re.search(r":8529|arangodb", p, re.I)), ""),
            why="ArangoDB HTTP API / :8529 observed",
        ))

    if re.search(r":27017\b|mongodb", es_blob, re.I):
        add(Methodology(
            id="mongodb_anonymous",
            title="MongoDB anonymous login (CWE-306)",
            hunt="mongodb_unauth",
            specialist="coverage",
            priority="critical",
            assumption="Internet-facing MongoDB on :27017 has no authentication (often AKS LoadBalancer)",
            test=(
                "nuclei mongodb-unauth or listDatabases. Record db names only. "
                "Note READ_ME_TO_RECOVER_YOUR_DATA if present. Do not dump or drop."
            ),
            pass_criteria="Unauthenticated listDatabases succeeds",
            kill_criteria="auth required; port filtered",
            cwe_ids=["CWE-306", "CWE-284"],
            capec_ids=["CAPEC-115"],
            owasp="A01:2021 Broken Access Control",
            evidence=target,
            why="MongoDB / :27017 observed",
        ))

    if re.search(r"emqx|:18083\b|:18084\b", es_blob, re.I):
        add(Methodology(
            id="emqx_dashboard_defaults",
            title="EMQX dashboard default admin (CWE-1393)",
            hunt="credential_assault",
            specialist="credential_assault",
            priority="critical",
            assumption="EMQX dashboard still uses admin:public",
            test="Tiny list: admin:public then admin:admin. On success queue emqx_default (read-only APIs). No plugin upload.",
            pass_criteria="Dashboard/API session as admin",
            kill_criteria="Defaults rejected",
            cwe_ids=["CWE-1393", "CWE-798"],
            capec_ids=["CAPEC-70"],
            owasp="A07:2021 Identification and Authentication Failures",
            evidence=target,
            why="EMQX dashboard observed",
        ))

    if re.search(
        r"socket\.io|access-control-allow-origin|:6147\b|keycloak|"
        r"/auth/realms|openid-connect|/auth/admin/realms",
        es_blob,
        re.I,
    ):
        add(Methodology(
            id="cors_acao_credentials",
            title="CORS origin reflection with credentials (CWE-942)",
            hunt="cors_credentials",
            specialist="api_authz",
            priority="high",
            assumption=(
                "ACAO reflects an arbitrary Origin while Access-Control-Allow-Credentials "
                "is true, so a victim's browser will attach cookies and let attacker JS "
                "read the body. ACAO=* without credentials is NOT this bug"
            ),
            test=(
                "compare_requests: Origin=https://aegis-cors-canary-<rand>.example vs no Origin. "
                "Use a never-seen origin (allowlists often deny evil.com). PASS if ACAO echoes "
                "that origin AND credentials=true. Also OPTIONS preflight with "
                "Access-Control-Request-Headers: Authorization and Request-Method: POST. "
                "Socket.IO: unauth get_stream url_key only — no video dump, "
                "no null-input crash loops."
            ),
            pass_criteria=(
                "ACAO equals the canary origin AND Access-Control-Allow-Credentials is true"
            ),
            kill_criteria=(
                "Allowlist rejects the canary origin; ACAO is * without credentials. "
                "Do NOT kill solely because no victim browser session was available"
            ),
            cwe_ids=["CWE-942", "CWE-346"],
            capec_ids=["CAPEC-113"],
            owasp="A05:2021 Security Misconfiguration",
            evidence=target,
            why="CORS / Socket.IO / IdP surface observed",
        ))

    if re.search(
        r"keycloak|/auth/realms|openid-connect|/protocol/openid|/auth/admin/realms",
        es_blob,
        re.I,
    ):
        add(Methodology(
            id="keycloak_cors_web_origins",
            title="Keycloak webOrigins=* — credentialed CORS on token/userinfo/admin",
            hunt="cors_credentials",
            specialist="api_authz",
            priority="critical",
            assumption=(
                "Keycloak client webOrigins is * (or a reverse proxy injects ACAO reflection "
                "+ credentials). That applies to /auth/realms/*/protocol/openid-connect/token, "
                "userinfo, certs/JWKS, and /auth/admin/realms/*"
            ),
            test=(
                "Authenticated-cookie CORS is proven with headers, not a phishing page. "
                "GET/OPTIONS each of: token, userinfo, JWKS, /auth/admin/realms/<realm>/users "
                "with Origin=https://aegis-cors-canary-<rand>.example. Record ACAO, ACAC, "
                "Allow-Methods, Allow-Headers (Authorization). Do not dump the user directory; "
                "header proof is SUBMIT. If an engagement admin session exists, ONE bounded "
                "GET users?max=1 then stop. Remediation: webOrigins explicit allowlist or '+' "
                "(valid redirect URIs), never '*'; audit proxies that override CORS."
            ),
            pass_criteria=(
                "Canary Origin is reflected with credentials=true on token and/or userinfo "
                "and/or admin API (preflight allowing POST+Authorization strengthens impact)"
            ),
            kill_criteria=(
                "webOrigins allowlist / '+' only; canary Origin not echoed; ACAO=* without "
                "credentials. Do NOT kill because JWKS is public or no victim tab was open"
            ),
            cwe_ids=["CWE-942", "CWE-346", "CWE-284"],
            capec_ids=["CAPEC-113", "CAPEC-62"],
            owasp="A05:2021 Security Misconfiguration",
            evidence=target or next(
                (p for p in pages if re.search(r"keycloak|openid-connect|/auth/realms", p, re.I)),
                "",
            ),
            why="Keycloak / OIDC surface observed — webOrigins=* is a common IdP CORS footgun",
        ))
        add(Methodology(
            id="keycloak_admin_cli_password_grant",
            title="Keycloak admin-cli public + password grant with no brute-force defense",
            hunt="credential_assault",
            specialist="credential_assault",
            priority="critical",
            assumption=(
                "admin-cli is a public client (no client_secret) with Direct Access Grants "
                "(OAuth2 password / ROPC) enabled on master and application realms. The token "
                "endpoint accepts username/password with no rate limit, lockout, or CAPTCHA. "
                "Guessing a valid password is NOT required — unbounded invalid_grant is the finding"
            ),
            test=(
                "POST /auth/realms/{master|other}/protocol/openid-connect/token with "
                "grant_type=password, client_id=admin-cli, and NO client_secret. A fake user "
                "returning invalid_grant (not invalid_client / unauthorized_client / "
                "unsupported_grant_type) proves the public password grant. Then at most 8 "
                "failed attempts with unique fake passwords — record 429 / lockout / slowing. "
                "Do NOT hydra or rockyou. Optional tiny defaults only: admin:admin, "
                "admin:password, admin:keycloak (stop on hit). Master realm is highest impact. "
                "CORS stuffing is a separate card. If a token is issued: stash and ONE "
                "GET /auth/admin/realms?briefRepresentation=true (or users?max=1); do not dump."
            ),
            pass_criteria=(
                "Password grant accepted without a client secret (invalid_grant on a bad "
                "password) AND the bounded 8-attempt probe shows no 429 and no lockout"
            ),
            kill_criteria=(
                "invalid_client / unauthorized_client (confidential); unsupported_grant_type; "
                "429 or brute-force lockout within the 8-attempt cap. "
                "Do NOT kill solely because no valid password was guessed"
            ),
            cwe_ids=["CWE-307", "CWE-799", "CWE-287"],
            capec_ids=["CAPEC-49", "CAPEC-70"],
            owasp="A07:2021 Identification and Authentication Failures",
            evidence=target or next(
                (p for p in pages if re.search(r"keycloak|openid-connect|/auth/realms", p, re.I)),
                "",
            ),
            why="Keycloak observed — public admin-cli + password grant is a common internet-facing misconfig",
        ))

    if re.search(r"usertype|publicportal|userType", es_blob, re.I):
        add(Methodology(
            id="client_supplied_usertype",
            title="Client-supplied userType/admin role (CWE-639 / CWE-807)",
            hunt="client_role_param",
            specialist="api_authz",
            priority="critical",
            assumption="API trusts body userType/userId without a server session",
            test=(
                "compare_requests userType empty vs Admin (decode base64 bodies if the client does). "
                "Bounded sample; do not export the full site inventory."
            ),
            pass_criteria="Admin mutant returns cross-tenant or privileged fields",
            kill_criteria="401/403; userType ignored",
            cwe_ids=["CWE-639", "CWE-807", "CWE-285"],
            capec_ids=["CAPEC-1", "CAPEC-122"],
            owasp="A01:2021 Broken Access Control",
            evidence=target,
            why="userType / publicPortal observed",
        ))

    if re.search(r"vendorjson|vendorJson|userManagement/api", es_blob, re.I):
        add(Methodology(
            id="vendorjson_unauth_manifest",
            title="Unauth vendorJson multi-tenant manifest (CWE-200)",
            hunt="vendorjson_unauth",
            specialist="api_authz",
            priority="high",
            assumption="/glens/userManagement/api/v3.0/vendorJson returns all tenants without auth",
            test="Unauth GET vendorJson; record tenant count + 1–2 hosts; do not dump the full blob.",
            pass_criteria="Multiple tenants or internal userId/role/IP fields without auth",
            kill_criteria="401/403; current-tenant display only",
            cwe_ids=["CWE-200", "CWE-306"],
            capec_ids=["CAPEC-116"],
            owasp="A01:2021 Broken Access Control",
            evidence=target,
            why="GLens vendorJson / userManagement API observed",
        ))

    if re.search(r"identitymigrate|/api/token|auth0", es_blob, re.I):
        add(Methodology(
            id="auth0_mgmt_token_unauth",
            title="Unauth Auth0 Management API token (CWE-306)",
            hunt="auth0_mgmt_token",
            specialist="coverage",
            priority="critical",
            assumption="Public /api/token returns an Auth0 Management JWT",
            test=(
                "Unauth GET token URL. Prove with ONE /api/v2/clients?per_page=1 or users?per_page=1. "
                "Redact JWT. Do not enumerate the directory."
            ),
            pass_criteria="Token issued unauthenticated AND Management API accepts a read",
            kill_criteria="401; token rejected",
            cwe_ids=["CWE-306", "CWE-200", "CWE-798"],
            capec_ids=["CAPEC-115"],
            owasp="A01:2021 Broken Access Control",
            evidence=target,
            why="Auth0 / identitymigrate /api/token observed",
        ))

    if re.search(r"gitlab|/api/v4/projects", es_blob, re.I):
        add(Methodology(
            id="gitlab_unauth_projects",
            title="Unauth GitLab project API (CWE-306)",
            hunt="gitlab_unauth",
            specialist="js_secrets",
            priority="critical",
            assumption="GitLab /api/v4/projects lists public repos; files may hold secrets",
            test="GET /api/v4/projects?per_page=5. Sample ONE file for secrets. Do not clone all.",
            pass_criteria="Unauth project list and/or a sampled hardcoded secret",
            kill_criteria="401/403; no public projects",
            cwe_ids=["CWE-306", "CWE-798", "CWE-540"],
            capec_ids=["CAPEC-116"],
            owasp="A01:2021 Broken Access Control",
            evidence=target,
            why="GitLab API observed",
        ))

    if _ACR_RE.search(es_blob):
        acr_host = bool(re.search(r"azurecr\.io|anonymous.?pull", es_blob, re.I))
        add(Methodology(
            id="acr_anonymous_pull" if acr_host else "docker_registry_unauth",
            title=(
                "Azure Container Registry anonymous pull (CWE-306 / CWE-798)"
                if acr_host
                else "Unauth Docker Registry catalog (CWE-306)"
            ),
            hunt="docker_registry",
            specialist="coverage",
            priority="high",
            assumption=(
                "ACR anonymousPullEnabled issues an oauth2 bearer for registry:catalog:* "
                "with no credentials, then /v2/_catalog lists first-party images"
                if acr_host
                else "/v2/_catalog requires no credentials"
            ),
            test=(
                "Unauth GET /oauth2/token?service=<registry>&scope=registry:catalog:*. "
                "If an access_token is issued, GET /v2/_catalog (n<=200) with the bearer. "
                "Record repository count. Then tags/list + config/history on at most 1–3 "
                "first-party repos (prefer graphql/enrollment/:latest) for ghp_ / git+https "
                "/ ghs_ / Artifactory / NATS. queue_finding_followups("
                "vuln_type='docker_registry'). Do not pull the whole catalog; do not push; "
                "do not delete tags; do not authenticate recovered PATs against GitHub."
                if acr_host
                else (
                    "GET /v2/ then GET /v2/_catalog. Count names. Optional one manifest/"
                    "config if a credential is obvious. Do not push images."
                )
            ),
            pass_criteria=(
                "Anonymous token issued AND catalog returns repository names"
                if acr_host
                else "200 catalog with repository names"
            ),
            kill_criteria=(
                "Anonymous token denied; catalog 401/403. Do NOT kill because a secret "
                "scan of extra tags was skipped"
            ),
            cwe_ids=["CWE-306", "CWE-798", "CWE-540"] if acr_host else ["CWE-306"],
            capec_ids=["CAPEC-115", "CAPEC-37"],
            owasp="A01:2021 Broken Access Control",
            evidence=target,
            why=(
                "Azure Container Registry hostname / anonymous-pull surface observed"
                if acr_host
                else "Docker Registry observed"
            ),
        ))

    if re.search(r"django|/admin/login|/api/token-pair", es_blob, re.I):
        add(Methodology(
            id="django_admin_debug",
            title="Django admin:admin + DEBUG traceback (CWE-1393 / CWE-215)",
            hunt="credential_assault",
            specialist="credential_assault",
            priority="critical",
            assumption="Django accepts admin:admin and DEBUG=True dumps env on 500",
            test=(
                "Tiny list admin:admin on /admin/login/ and /api/token-pair/. On success queue "
                "django_debug (safe 500 → Redis/env classes). Redact keys. Do not flush Redis."
            ),
            pass_criteria="admin:admin session or JWT",
            kill_criteria="Defaults rejected",
            cwe_ids=["CWE-1393", "CWE-215", "CWE-209"],
            capec_ids=["CAPEC-70"],
            owasp="A07:2021 Identification and Authentication Failures",
            evidence=target,
            why="Django admin / token-pair observed",
        ))

    if re.search(r"/api/chat|azure.?openai|openai", es_blob, re.I) and re.search(
        r"chat|openai|gpt", es_blob, re.I
    ):
        add(Methodology(
            id="openai_chat_proxy_unauth",
            title="Unauth Azure OpenAI /api/chat proxy (CWE-306)",
            hunt="openai_proxy_unauth",
            specialist="agent_tools",
            priority="high",
            assumption="POST /api/chat proxies to Azure OpenAI with no session",
            test="One cheap canary completion. Do not burn tokens. Do not jailbreak for harm.",
            pass_criteria="Unauth model completion",
            kill_criteria="401/403",
            cwe_ids=["CWE-306", "CWE-770"],
            capec_ids=["CAPEC-115"],
            owasp="A01:2021 Broken Access Control",
            evidence=target,
            why="Chat/OpenAI proxy observed",
        ))

    if _ML_PIPELINE_RE.search(combined):
        ev = next(
            (
                f"{e.get('method', '')} {e.get('path', '')}".strip()
                for e in apis
                if isinstance(e, dict) and _ML_PIPELINE_RE.search(
                    f"{e.get('method', '')} {e.get('path', '')}"
                )
            ),
            None,
        ) or next(
            (str(p) for p in pages if _ML_PIPELINE_RE.search(str(p))),
            "/api/v1/train/",
        )
        add(Methodology(
            id="ml_pipeline_missing_rbac",
            title="Self-registered user can train/delete ML models (missing RBAC)",
            hunt="ml_pipeline_rbac",
            specialist="api_authz",
            priority="high",
            assumption=(
                "JWT authenticates but does not authorize: any self-registered account "
                "can POST /api/v1/train/, DELETE /api/v1/celery-task/, or queue Celery "
                "jobs. Open signup is the internet exposure, not a second finding"
            ),
            test=(
                "If signup is open: create ONE throwaway account. compare_requests a "
                "privileged ML write (POST /api/v1/train/ or DELETE /api/v1/celery-task/) "
                "as that user vs a documented admin-only sibling. PASS if the self-reg "
                "session is 200/202/204. Do not delete production models; prefer OPTIONS/"
                "authz probe or one canary train on a tiny fixture. Do not dump datasets. "
                "queue_finding_followups(vuln_type='ml_pipeline_rbac')."
            ),
            pass_criteria=(
                "Self-registered (or low-priv) session can train, delete, or queue ML/"
                "Celery jobs that should be admin/ML-engineer only"
            ),
            kill_criteria=(
                "Train/delete/celery return 403 for non-admin; role checks hold. "
                "Do not kill solely because signup is closed — still probe mapped "
                "low-priv tokens"
            ),
            cwe_ids=["CWE-285", "CWE-863", "CWE-269"],
            capec_ids=["CAPEC-122", "CAPEC-1"],
            owasp="A01:2021 Broken Access Control",
            evidence=str(ev),
            why="ML train / Celery / optimize APIs observed — self-reg often has no RBAC",
        ))

    if re.search(
        r"wiki|mediawiki|confluence|dokuwiki|special:createaccount",
        es_blob,
        re.I,
    ) and _INVITE_RE.search(combined):
        add(Methodology(
            id="wiki_open_self_registration",
            title="Open wiki self-registration (CWE-284)",
            hunt="wiki_open_reg",
            specialist="auth_logic",
            priority="high",
            assumption="Wiki/Confluence allows CreateAccount/signup without approval and grants write or internal pages",
            test=(
                "Create ONE throwaway account. Prove sandbox/user-page write OR one internal "
                "page with employee PII. Do not deface production articles. Do not scrape."
            ),
            pass_criteria="Self-registered session can write a sandbox page or read non-public wiki content",
            kill_criteria="Registration closed; captcha/approval; no write/internal read",
            cwe_ids=["CWE-284", "CWE-269", "CWE-200"],
            capec_ids=["CAPEC-122", "CAPEC-1"],
            owasp="A01:2021 Broken Access Control",
            evidence=target,
            why="Wiki + signup/register surface observed",
        ))

    if re.search(
        r"\.(exe|msi|apk|dmg|ipa)\b|firmware|installer|publicly-downloadable",
        es_blob,
        re.I,
    ):
        add(Methodology(
            id="binary_hardcoded_credentials",
            title="Hardcoded credentials in a public downloadable binary (CWE-798)",
            hunt="binary_hardcoded_creds",
            specialist="js_secrets",
            priority="critical",
            assumption="Public installer/firmware/APK embeds production passwords or connection strings",
            test=(
                "Download the public binary. strings/grep for password/secret/connection (bounded). "
                "Prove ONE extracted credential on an in-scope login if safe. Redact secrets. "
                "Do not reverse for exploits; do not attach the binary."
            ),
            pass_criteria="Extracted production secret from a public download (optional live login)",
            kill_criteria="No secrets; placeholders only",
            cwe_ids=["CWE-798", "CWE-321", "CWE-540"],
            capec_ids=["CAPEC-70", "CAPEC-191"],
            owasp="A07:2021 Identification and Authentication Failures",
            evidence=target,
            why="Downloadable binary / installer / firmware observed",
        ))

    if has_spa and re.search(r"elogbook|/admin|dashboard", es_blob, re.I):
        add(Methodology(
            id="client_side_only_auth",
            title="Client-side-only authentication on admin UI (CWE-603 / CWE-807)",
            hunt="client_side_auth",
            specialist="auth_logic",
            priority="critical",
            assumption="Admin/eLogbook gates pages in JS without a server session",
            test=(
                "Forced-browse admin routes anonymous; compare_requests backing APIs without "
                "the client flag vs with a forged role. Do not mutate production rows."
            ),
            pass_criteria="Privileged page or API data without a server-side session",
            kill_criteria="401/403; empty bodies; server session required",
            cwe_ids=["CWE-603", "CWE-807", "CWE-287"],
            capec_ids=["CAPEC-115", "CAPEC-1"],
            owasp="A07:2021 Identification and Authentication Failures",
            evidence=target,
            why="SPA admin / eLogbook surface — client-side gates are a common miss",
        ))

    if _RESET_RE.search(combined):
        ev = next((p for p in pages if _RESET_RE.search(p)), "") or next(
            (str(f.get("action") or "") for f in forms if isinstance(f, dict) and _RESET_RE.search(
                f"{f.get('action', '')} {' '.join(f.get('inputs') or [])}"
            )),
            "password-reset",
        )
        add(Methodology(
            id="password_reset_abuse",
            title="Password-reset / recovery abuse",
            hunt="auth_logic",
            specialist="auth_logic",
            priority="high",
            assumption="Reset flow leaks users, uses predictable tokens, or trusts Host for links",
            test=(
                "Probe user enumeration on reset; Host/X-Forwarded-Host poisoning on reset request; "
                "token predictability if tokens appear in responses/links"
            ),
            pass_criteria="User enum, attacker-controlled reset link host, or weak token proven",
            kill_criteria="Generic responses; canonical host only; strong tokens",
            cwe_ids=["CWE-640", "CWE-200", "CWE-601"],
            capec_ids=["CAPEC-50"],
            owasp="A07:2021 Identification and Authentication Failures",
            evidence=ev,
            why="Password reset / recovery surface observed",
        ))

    if (
        _EMAIL_CHANGE_RE.search(combined)
        or (
            _OPENAPI_RE.search(combined)
            and re.search(r"/api/auth/users", combined, re.I)
        )
    ):
        ev = next(
            (str(p) for p in pages if _EMAIL_CHANGE_RE.search(str(p))),
            None,
        ) or next(
            (
                f"{e.get('method', '')} {e.get('path', '')}".strip()
                for e in apis
                if isinstance(e, dict) and _EMAIL_CHANGE_RE.search(
                    f"{e.get('method', '')} {e.get('path', '')}"
                )
            ),
            "/api/auth/users/reset_email/",
        )
        add(Methodology(
            id="email_change_ato",
            title="Unauthenticated email-change endpoints (djoser reset_email ATO chain)",
            hunt="email_change_ato",
            specialist="auth_logic",
            priority="high",
            assumption=(
                "POST /api/auth/users/reset_email/ and reset_email_confirm/ skip JWT "
                "even when OpenAPI declares jwtAuth. set_password correctly 401s. "
                "The remaining control is a token mailed to the attacker-controlled address"
            ),
            test=(
                "compare_requests: unauth POST /api/auth/users/set_password/ (expect 401) "
                "vs unauth POST /api/auth/users/reset_email/ with "
                "email=aegis-ato-canary@example.invalid (204/200). Then unauth POST "
                "reset_email_confirm with uid=MQ (base64 user 1) + garbage token — "
                "'Invalid token for given user' vs 'Invalid user id' enumerates users. "
                "One canary email; do not complete ATO on a real mailbox; do not spray. "
                "queue_finding_followups(vuln_type='email_change_ato')."
            ),
            pass_criteria=(
                "Unauth reset_email is accepted while a sibling account-mod (set_password) "
                "is 401, AND/OR confirm locates a user without a session"
            ),
            kill_criteria=(
                "Both email-change endpoints 401/403 like set_password. "
                "Do not kill because OPTIONS is 401 or the schema claims jwtAuth"
            ),
            cwe_ids=["CWE-306", "CWE-862", "CWE-640", "CWE-204"],
            capec_ids=["CAPEC-50", "CAPEC-575"],
            owasp="A07:2021 Identification and Authentication Failures",
            evidence=str(ev),
            why="Email-change / djoser users API observed — unauth reset_email is an ATO chain",
        ))

    if has_oauth or re.search(r"(oauth|/sso|/saml|/oidc|/authorize|/callback)", combined, re.I):
        ev = next(
            (p for p in pages if re.search(r"oauth|sso|saml|oidc|authorize|callback", p, re.I)),
            "oauth/sso",
        )
        add(Methodology(
            id="oauth_sso_misconfig",
            title="OAuth / SSO / SAML misconfiguration",
            hunt="saml_sso",
            specialist="saml_sso",
            priority="high",
            assumption="Authorize/callback mishandles redirect_uri, state, or signatures",
            test=(
                "test_saml_sso + redirect_uri / state / Host / callback tampering on mapped SSO URLs"
            ),
            pass_criteria="Open redirect to token theft, unsigned assertion, or OIDC misconfig with impact",
            kill_criteria="Strict redirect allowlist and signature checks",
            cwe_ids=["CWE-601", "CWE-346", "CWE-287"],
            capec_ids=["CAPEC-194", "CAPEC-98"],
            owasp="A07:2021 Identification and Authentication Failures",
            evidence=ev,
            why="OAuth/SSO/SAML indicators observed",
        ))

    if _INVITE_RE.search(combined):
        ev = next((p for p in pages if _INVITE_RE.search(p)), "signup/invite")
        add(Methodology(
            id="registration_invite_abuse",
            title="Registration / invite workflow abuse",
            hunt="business_logic",
            specialist="business_logic",
            priority="high",
            assumption="Signup/invite flows allow privilege escalation, takeover, or mass assignment",
            test=(
                "Tamper role/plan fields on register; reuse invite tokens; skip verification steps; "
                "probe account enumeration on signup"
            ),
            pass_criteria="Privileged account created, invite reuse, or verification bypass with evidence",
            kill_criteria="Server enforces role/verification; tokens single-use",
            cwe_ids=["CWE-266", "CWE-269", "CWE-840"],
            capec_ids=["CAPEC-122", "CAPEC-210"],
            owasp="A01:2021 Broken Access Control",
            evidence=ev,
            why="Signup/invite/register surface observed",
        ))

    if _OPENAPI_RE.search(combined):
        ev = next((p for p in pages if _OPENAPI_RE.search(p)), None) or next(
            (f"{e.get('method')} {e.get('path')}" for e in apis
             if isinstance(e, dict) and _OPENAPI_RE.search(e.get("path", ""))),
            "openapi",
        )
        add(Methodology(
            id="openapi_schema_authz",
            title="OpenAPI / Swagger schema-driven authz testing",
            hunt="api_authz",
            specialist="api_authz",
            priority="high",
            assumption="Documented API operations lack consistent authz or expose privileged ops",
            test=(
                "Fetch OpenAPI/Swagger doc; enumerate operations; compare_requests anonymous vs auth "
                "on sensitive paths; run schemathesis if schema URL available"
            ),
            pass_criteria="Unauth/cross-user access to documented privileged operation",
            kill_criteria="Documented ops enforce authz consistently",
            cwe_ids=["CWE-862", "CWE-284", "CWE-200"],
            capec_ids=["CAPEC-1", "CAPEC-122"],
            owasp="A01:2021 Broken Access Control",
            evidence=str(ev),
            why="OpenAPI/Swagger documentation surface observed",
        ))
        add(Methodology(
            id="openapi_mass_assignment",
            title="OpenAPI/DRF request serializers — mass assignment of server-managed fields",
            hunt="api_authz",
            specialist="api_authz",
            priority="critical",
            assumption=(
                "DRF/Spectacular (and similar) request serializers expose writable id, "
                "created, updated, user/owner, schedule, or periodic_task without readOnly; "
                "list endpoints may document shared access across all users. A down database "
                "does not patch the contract"
            ),
            test=(
                "GET /api/schema/ (or swagger.json / openapi.json). For each *Request / "
                "requestBody component, record whether id, created, updated, user, owner, "
                "schedule, periodic_task are present AND not readOnly. Count affected "
                "serializers. Read operation descriptions for 'all users' / 'shared across'. "
                "If the DB is up: ONE bounded canary write on a test object (do not enable "
                "ICS/OT schedules, do not dump the hierarchy, do not overwrite other users' "
                "production rows). If the DB is down (500 / OperationalError): still SUBMIT "
                "on the schema evidence — do not kill."
            ),
            pass_criteria=(
                "One or more request serializers expose writable privileged fields without "
                "readOnly, AND/OR a list endpoint documents cross-user sharing. Live write "
                "is stronger but not required when the schema already proves the contract"
            ),
            kill_criteria=(
                "Privileged fields are readOnly / extra_kwargs read_only; object-level 403 "
                "on foreign id/user; list endpoints return only the caller's objects. "
                "Do NOT kill solely because the database is unavailable"
            ),
            cwe_ids=["CWE-915", "CWE-639", "CWE-284"],
            capec_ids=["CAPEC-126", "CAPEC-1"],
            owasp="API3:2023 Broken Object Property Level Authorization",
            evidence=str(ev),
            why="OpenAPI/Swagger observed — request schemas often leak mass-assignment surface",
        ))

    if _OPENAPI_RE.search(combined) or re.search(r"/api/auth/account", combined, re.I):
        add(Methodology(
            id="openapi_unauth_account_lookup",
            title="Unauth OpenAPI account lookup (security: {} / email → role)",
            hunt="unauth_account_lookup",
            specialist="api_authz",
            priority="critical",
            assumption=(
                "OpenAPI marks /api/auth/account/ (or similar email lookup) with security: {} "
                "and a response schema of email, is_active, valid_through, is_staff, role. "
                "A 500 from a down database is not an auth rejection — siblings return 401"
            ),
            test=(
                "Quote the schema: security: {} / 'without authentication' / public account "
                "statistics, plus UserAccount fields (is_staff, role, valid_through). "
                "compare_requests: unauth GET a protected sibling (/api/auth/profile/, "
                "/api/auth/users/me/) vs GET /api/auth/account/?email=aegis-enum-canary@example.invalid. "
                "PASS if the lookup is 200 with those fields OR 404 'User does not exist!' "
                "OR 500/app error while siblings are 401. File Critical. "
                "One canary email only — do not spray employee inboxes. Do not dump ICS users. "
                "Do not claim a 200 role body unless stdout has it. "
                "ACAO * is extra, not a substitute for the 401-vs-500/404 differential."
            ),
            pass_criteria=(
                "Schema documents unauth account lookup returning privilege fields, AND/OR "
                "unauth request reaches app code (200, 404 existence oracle, or 500) while "
                "protected siblings 401"
            ),
            kill_criteria=(
                "Lookup returns 401/403 like siblings; schema requires JWT; response is a "
                "generic non-enumerating boolean. Do NOT kill solely because the database "
                "is unavailable, the canary is unregistered, or the lookup is 404"
            ),
            cwe_ids=["CWE-204", "CWE-200", "CWE-862"],
            capec_ids=["CAPEC-575", "CAPEC-169"],
            owasp="A01:2021 Broken Access Control",
            evidence=(
                next((p for p in pages if _OPENAPI_RE.search(str(p))), None)
                or next((p for p in pages if re.search(r"/api/auth/account", str(p), re.I)), "")
                or "/api/auth/account/"
            ),
            why="Public account/email lookup in schema or crawl — unauth user enum + role leak",
        ))

    settings_ev = next(
        (
            f"{e.get('method', '')} {e.get('path', '')}".strip()
            for e in apis
            if isinstance(e, dict) and _SETTINGS_WRITE_RE.search(
                f"{e.get('method', '')} {e.get('path', '')}"
            )
        ),
        None,
    ) or next(
        (str(p) for p in pages if _SETTINGS_WRITE_RE.search(str(p))),
        None,
    )
    if (
        has_api
        and (
            settings_ev
            or _SETTINGS_WRITE_RE.search(combined)
            or _ASPNET_API_RE.search(combined)
            or _ASPNET_MVC_ACTION_RE.search(combined)
        )
    ):
        add(Methodology(
            id="aspnet_unauth_settings_write",
            title="Unauthenticated ASP.NET / API settings write (missing [Authorize])",
            hunt="unauth_settings_write",
            specialist="api_authz",
            priority="high",
            assumption=(
                "SettingsController (or mapped Save*/Write* config APIs) lack [Authorize] "
                "while sibling controllers on the same app enforce it. ASP.NET Core void "
                "actions return HTTP 200 Content-Length: 0 when the write is accepted. "
                "GET 500 / NullReferenceException is not an auth rejection"
            ),
            test=(
                "compare_requests: unauth POST a protected write sibling "
                "(/api/TaskAdmin/UpdateTask or another 401 write) vs unauth POST "
                "/api/Settings/SaveSettings (or mapped Save*/Write*) with a JSON body "
                "matching the settings schema. PASS on sibling 401 AND SaveSettings 200 "
                "with Content-Length: 0 (void success). One canary key only "
                "(aegis-verify-<rand>); do not replace the full settings collection; "
                "do not flip enableNotifications/createPlannerTasks/powerBIReportId. "
                "GET GetSettings 500 is NOT a kill. Then probe other controllers "
                "(LogQuery, Audit, ReadTasks, OpenDocument) without 401 — file those "
                "as a sibling missing-auth card, not this High write. "
                "queue_finding_followups(vuln_type='unauth_settings_write')."
            ),
            pass_criteria=(
                "Unauth config/settings write is accepted (200/204 void) while a sibling "
                "write on the same app returns 401 without credentials"
            ),
            kill_criteria=(
                "SaveSettings returns 401/403 like siblings. Do NOT kill because "
                "GetSettings is 500, the canary was not read back, or Graph-downstream "
                "calls fail. Do not kill solely because the host is azurewebsites.net"
            ),
            cwe_ids=["CWE-306", "CWE-862", "CWE-284"],
            capec_ids=["CAPEC-1", "CAPEC-122"],
            owasp="A01:2021 Broken Access Control",
            evidence=str(
                settings_ev
                or next((p for p in pages if _ASPNET_API_RE.search(str(p))), None)
                or (g("target") if g("target") else "/api/Settings/SaveSettings")
            ),
            why=(
                "Settings/Save*/ASP.NET API surface — missing [Authorize] on writes "
                "is demonstrated by a 401 sibling vs 200 void"
            ),
        ))

    if has_api and (
        _JWT_AUTH_RE.search(combined)
        or _OPENAPI_RE.search(combined)
        or has_auth
        or has_oauth
    ):
        ev = next(
            (
                f"{e.get('method', '')} {e.get('path', '')}".strip()
                for e in apis
                if isinstance(e, dict) and e.get("path")
            ),
            target or "api",
        )
        add(Methodology(
            id="auth_header_bypass",
            title="Auth middleware skipped when Authorization header is absent",
            hunt="auth_header_bypass",
            specialist="api_authz",
            priority="high",
            assumption=(
                "OIDC/JWT middleware (ByPassAuthorization / 'skip if no header') only "
                "validates when Authorization is present. No header reaches the "
                "controller (400 missing params / 200). Invalid Bearer returns 401"
            ),
            test=(
                "compare_requests on mapped authenticated APIs: (1) no Authorization "
                "header vs (2) Authorization: Bearer aegis-invalid. PASS if no-header "
                "reaches app code (200/400 business error) AND invalid-bearer is 401. "
                "A 400 on missing body is still a bypass — the controller ran. Probe "
                "2–4 mapped routes (GetMenu, GetEntitiesById, Notes). Do not dump. "
                "queue_finding_followups(vuln_type='auth_header_bypass')."
            ),
            pass_criteria=(
                "Request without Authorization is not 401/403 while the same path with "
                "an invalid Bearer is 401 (middleware only runs when a header is sent)"
            ),
            kill_criteria=(
                "Missing header is 401/403 like invalid Bearer. Do not kill because "
                "the no-header response is 400 (missing required params)"
            ),
            cwe_ids=["CWE-287", "CWE-306", "CWE-862"],
            capec_ids=["CAPEC-115", "CAPEC-1"],
            owasp="A07:2021 Identification and Authentication Failures",
            evidence=str(ev),
            why="JWT/OIDC/OpenAPI APIs — conditional middleware often skips when the header is omitted",
        ))

    # --- Authorization / IDOR ---
    id_paths = [p for p in param_paths if _ID_PARAM_RE.search(p)]
    if has_api and (id_paths or any(_ID_PARAM_RE.search(e.get("path", "")) for e in apis if isinstance(e, dict))):
        ev = (id_paths[0] if id_paths else "") or next(
            (f"{e.get('method')} {e.get('path')}" for e in apis
             if isinstance(e, dict) and _ID_PARAM_RE.search(e.get("path", ""))),
            apis[0].get("path", "") if apis and isinstance(apis[0], dict) else "api",
        )
        add(Methodology(
            id="api_idor_bola",
            title="API object/tenant authorization gap (IDOR/BOLA)",
            hunt="api_authz",
            specialist="api_authz",
            priority="high",
            assumption="Object IDs or tenant context are not enforced server-side",
            test=(
                "compare_requests across anonymous / user A / user B (or adjacent object IDs) "
                "on mapped APIs with id/uuid params"
            ),
            pass_criteria="Cross-identity or unauth response contains another user's/tenant's data",
            kill_criteria="401/403 consistently, or body only reflects caller's own objects",
            cwe_ids=["CWE-639", "CWE-862", "CWE-284"],
            capec_ids=["CAPEC-1", "CAPEC-122"],
            owasp="A01:2021 Broken Access Control",
            evidence=ev,
            why="API endpoints with object identifiers observed",
        ))
    elif has_api:
        ev = f"{apis[0].get('method')} {apis[0].get('path')}" if apis and isinstance(apis[0], dict) else "api"
        add(Methodology(
            id="api_authz_generic",
            title="API authorization / verb tampering",
            hunt="api_authz",
            specialist="api_authz",
            priority="high",
            assumption="First-party APIs trust client role or HTTP method incorrectly",
            test="compare_requests on mapped APIs; try verb swap GET↔POST/PUT/DELETE; probe unauth access",
            pass_criteria="Privileged data/action without proper authz",
            kill_criteria="Authz holds across identities and methods",
            cwe_ids=["CWE-284", "CWE-863", "CWE-650"],
            capec_ids=["CAPEC-122"],
            owasp="A01:2021 Broken Access Control",
            evidence=ev,
            why="First-party APIs captured",
        ))

    if has_api or _OPENAPI_RE.search(combined) or has_graphql:
        api_base = (
            next((p for p in pages if re.search(r"/api|/graphql|/swagger|/openapi", str(p), re.I)), None)
            or (g("target") if g("target") else None)
            or (pages[0] if pages else "https://target")
        )
        add(Methodology(
            id="owasp_api_astf",
            title="OWASP API Top 10 structural scan (ASTF)",
            hunt="api_authz",
            specialist="api_authz",
            priority="high",
            assumption=(
                "Detected REST/OpenAPI/GraphQL surfaces have structural API Top 10 issues "
                "(BOLA/BFLA, JWT weakness, missing auth, GraphQL abuse) that ASTF can flag"
            ),
            test=(
                "execute_astf on the API base URL (include bearer token when session exists). "
                "Triage CRITICAL/HIGH findings; prove with compare_requests / replay_http_request "
                "before create_finding. Complements dual-identity authz — does not replace it."
            ),
            pass_criteria=(
                "ASTF CRITICAL/HIGH finding reproduced with dual-identity or unauth differential evidence"
            ),
            kill_criteria=(
                "ASTF clean on in-scope API base, or flagged issues fail dual-identity reproduction"
            ),
            cwe_ids=["CWE-639", "CWE-862", "CWE-284", "CWE-347"],
            capec_ids=["CAPEC-1", "CAPEC-122"],
            owasp="API1:2023 Broken Object Level Authorization",
            evidence=str(api_base),
            why="API/OpenAPI/GraphQL surface observed — run complementary ASTF Top 10 scan",
        ))

    # Multi-host → tenant isolation
    hosts: set[str] = set()
    for p in pages:
        m = re.match(r"https?://([^/]+)", str(p))
        if m:
            hosts.add(m.group(1).lower())
    for e in apis:
        if isinstance(e, dict) and e.get("host"):
            hosts.add(str(e["host"]).lower())
    if len(hosts) >= 2 or any(re.match(r"^[a-z0-9-]+\.[a-z0-9-]+\.", h) for h in hosts):
        add(Methodology(
            id="host_tenant_isolation",
            title="Host-header tenant isolation bypass",
            hunt="host_tenant",
            specialist="host_tenant",
            priority="high",
            assumption="Tenant routing trusts Host / X-Forwarded-Host more than session binding",
            test=(
                "Keep session A; compare_requests with Host (and X-Forwarded-Host) set to peer tenant hostname"
            ),
            pass_criteria="Response contains tenant B objects/PII/config under session A",
            kill_criteria="Still tenant A content, hard 400/421, or connection rejected by vhost",
            cwe_ids=["CWE-284", "CWE-346"],
            capec_ids=["CAPEC-107"],
            owasp="A01:2021 Broken Access Control",
            evidence=", ".join(sorted(hosts)[:4]),
            why="Multiple hosts/subdomains observed",
        ))

    if has_admin:
        ev = next((p for p in pages if re.search(r"/admin|/dashboard|/manage|/console", p, re.I)), "admin")
        add(Methodology(
            id="admin_surface_exposure",
            title="Admin / management surface exposure",
            hunt="admin_surface",
            specialist="auth_logic",
            priority="medium",
            assumption="Admin paths are reachable without sufficient auth or leak privileged functions",
            test=(
                "Forced-browse admin paths anonymous vs auth; check default creds; "
                "map privileged APIs behind admin UI"
            ),
            pass_criteria="Unauth/admin function access or default-cred admin session",
            kill_criteria="Admin consistently gated; no privileged leak",
            cwe_ids=["CWE-306", "CWE-284", "CWE-200"],
            capec_ids=["CAPEC-115", "CAPEC-1"],
            owasp="A01:2021 Broken Access Control",
            evidence=ev,
            why="Admin/dashboard paths observed",
        ))

    # Directory/path context — misconfigs and routes the crawl may not have linked.
    if pages or has_api or g("target"):
        ev = str(g("target") or (pages[0] if pages else ""))
        add(Methodology(
            id="path_directory_context",
            title="Directory / path enumeration for app context",
            hunt="path_enum",
            specialist="content_api",
            priority="high",
            assumption=(
                "Interesting directories and paths (login, reset, admin, .git, swagger, backups) "
                "exist beyond what the browser crawl linked — useful for misconfig and attack surface"
            ),
            test=(
                "After Interceptor/deep_crawl: (1) fetch robots.txt + sitemap.xml; "
                "(2) execute_feroxbuster with /opt/wordlists/app-dirs-common.txt "
                "(-d 1 -t 20 --rate-limit 50) OR execute_ffuf with the same list — "
                "MANDATORY if the root is 404/empty (a 404 is not a clean host); "
                "(3) execute_katana/gau for passive URLs; (4) ingest_urls_into_map. "
                "Do NOT run huge SecLists DirBuster-style sprays before the capability map exists. "
                "Flag 200/301/302/403 on sensitive paths for follow-up."
            ),
            pass_criteria=(
                "New high-value paths discovered (auth, admin, API docs, VCS, backups) "
                "ingested into the map with status evidence"
            ),
            kill_criteria=(
                "Bounded common-dirs pass finds nothing beyond the crawl; robots/sitemap empty"
            ),
            cwe_ids=["CWE-538", "CWE-200", "CWE-552"],
            capec_ids=["CAPEC-87", "CAPEC-150"],
            owasp="A05:2021 Security Misconfiguration",
            evidence=ev,
            why="Web app assessments need directory/path context for misconfigurations",
        ))
        add(Methodology(
            id="path_parameter_mining",
            title="Hidden parameter / unlinked input discovery",
            hunt="path_enum",
            specialist="content_api",
            priority="high",
            assumption=(
                "Live paths expose query/body/header parameters the HTML crawl did not "
                "link — including JSON APIs, hidden fields, and JS-driven execute/query endpoints"
            ),
            test=(
                "On every live URL from crawl/ferox: discover_parameters (forms, query, hidden, JS) "
                "then execute_arjun GET+POST. Treat url/uri/request/datasource/execute/query fields "
                "as SSRF candidates. Ingest new params into the map for injection/api_authz. "
                "This is unknown-bug hunting, not a CVE template pass."
            ),
            pass_criteria=(
                "New parameters discovered and handed to injection/api_authz, or bounded Arjun "
                "pass documents none on the live set"
            ),
            kill_criteria="Bounded param mining on crawled+ferox URLs finds no extra inputs",
            cwe_ids=["CWE-20", "CWE-918", "CWE-89"],
            capec_ids=["CAPEC-137", "CAPEC-664"],
            owasp="A03:2021 Injection",
            evidence=ev,
            why="Curious testers mine parameters on whatever the dir brute and crawl uncovered",
        ))

    # --- Injection / XSS ---
    reflect_paths = [p for p in param_paths if _REFLECT_PARAM_RE.search(p)]
    if has_search or reflect_paths:
        ev = reflect_paths[0] if reflect_paths else next(
            (str(f.get("action") or "") for f in forms if isinstance(f, dict)
             and any(re.search(r"q|query|search", i or "", re.I) for i in (f.get("inputs") or []))),
            "search",
        )
        add(Methodology(
            id="reflected_xss",
            title="Reflected / stored XSS on search & reflect params",
            hunt="xss",
            specialist="xss",
            priority="high",
            assumption="User-controlled search/reflect params are rendered without neutralization",
            test=(
                "Inject XSS canaries into search/reflect params; confirm reflection/execution "
                "via browser or response differential"
            ),
            pass_criteria="Script execution or unambiguous HTML context injection with concrete param",
            kill_criteria="Output encoded/escaped; CSP blocks without bypass attempt only = incomplete",
            cwe_ids=["CWE-79"],
            capec_ids=["CAPEC-86", "CAPEC-198"],
            owasp="A03:2021 Injection",
            evidence=ev,
            why="Search form or reflect-style parameters observed",
        ))

    if param_paths or has_search:
        # Broader injection (SQLi/SSTI/cmd) when params exist
        non_reflect = [p for p in param_paths if p not in reflect_paths] or param_paths
        ev = non_reflect[0] if non_reflect else "params"
        add(Methodology(
            id="param_injection",
            title="Injection on mapped parameters (SQLi/SSTI/cmd)",
            hunt="sqli",
            specialist="sqli",
            priority="high",
            assumption="Query/body params from the map are unsafely interpolated into queries/templates/shell",
            test=(
                "Probe ranked params with SQLi/SSTI/cmd canaries; escalate with sqlmap/xsstrike "
                "only on anomalous hits"
            ),
            pass_criteria="Error/time/boolean differential or template/command impact with concrete param",
            kill_criteria="No anomalous responses after disciplined probes",
            cwe_ids=["CWE-89", "CWE-94", "CWE-78"],
            capec_ids=["CAPEC-66", "CAPEC-242", "CAPEC-88"],
            owasp="A03:2021 Injection",
            evidence=ev,
            why="Parameter-rich paths or searchable inputs observed",
        ))

    if _SSRF_HINT_RE.search(combined) or any(
        _SSRF_HINT_RE.search(str(s.get("url") or s.get("path") or ""))
        for s in api_samples if isinstance(s, dict)
    ):
        ev = next(
            (p for p in param_paths if _SSRF_HINT_RE.search(p)),
            next((p for p in pages if _SSRF_HINT_RE.search(p)), "url-fetch"),
        )
        add(Methodology(
            id="ssrf_url_fetch",
            title="SSRF via URL-fetch / webhook / proxy features",
            hunt="ssrf",
            specialist="ssrf",
            priority="high",
            assumption="Server fetches attacker-controlled URLs (webhooks, imports, previews, proxies)",
            test=(
                "execute_interactsh register → plant payload_url in the URL-fetch "
                "param → poll. Then compare_requests benign URL vs in-scope canary. "
                "Do not use Canarytokens. Never metadata/localhost if Lictor blocks."
            ),
            pass_criteria=(
                "execute_interactsh poll shows DNS/HTTP/SMTP interaction, and/or "
                "internal HTTP body in the response"
            ),
            kill_criteria="URL fetch blocked / egress filtered; OOB-only without internal body",
            cwe_ids=["CWE-918"],
            capec_ids=["CAPEC-664"],
            owasp="A10:2021 Server-Side Request Forgery",
            evidence=ev,
            why="URL-fetch / webhook / proxy style surface observed",
        ))

    # --- Upload / GraphQL / realtime / JS ---
    if has_upload:
        ev = next(
            (str(f.get("action") or "") for f in forms if isinstance(f, dict)
             and any(re.search(r"file|upload|attachment", i or "", re.I) for i in (f.get("inputs") or []))),
            "upload",
        )
        add(Methodology(
            id="unsafe_file_upload",
            title="Unsafe file upload",
            hunt="file_upload",
            specialist="file_upload",
            priority="high",
            assumption="Upload path trusts client content-type/filename",
            test="Content-type/extension bypass and stored XSS/path tricks on mapped upload forms",
            pass_criteria="Executable/HTML content stored or path traversal confirmed",
            kill_criteria="Strict type/extension and content validation",
            cwe_ids=["CWE-434", "CWE-79", "CWE-22"],
            capec_ids=["CAPEC-1", "CAPEC-126"],
            owasp="A04:2021 Insecure Design",
            evidence=ev,
            why="Upload form/inputs observed",
        ))

    if has_graphql:
        ev = next(
            (e.get("path", "") for e in apis if isinstance(e, dict) and re.search(r"graphql|/gql", e.get("path", ""), re.I)),
            "graphql",
        )
        add(Methodology(
            id="graphql_authz",
            title="GraphQL authz / introspection abuse",
            hunt="graphql",
            specialist="graphql_api",
            priority="high",
            assumption="GraphQL exposes introspection or cross-user node access",
            test="Introspection + dual-identity queries on node/viewer/mutations from the map",
            pass_criteria="Cross-user data or unauth mutation/impact proven (introspection alone is not enough)",
            kill_criteria="Introspection disabled and object authz holds across identities",
            cwe_ids=["CWE-862", "CWE-200", "CWE-285"],
            capec_ids=["CAPEC-122", "CAPEC-1"],
            owasp="A01:2021 Broken Access Control",
            evidence=ev,
            why="GraphQL endpoint/path signals observed",
        ))

    if websockets or sse or g("has_websocket") or g("has_sse"):
        ev = (websockets or sse or [""])[0]
        add(Methodology(
            id="realtime_channel_auth",
            title="WebSocket / SSE channel abuse",
            hunt="realtime",
            specialist="api_authz",
            priority="high" if _SOCKETIO_RE.search(combined) else "medium",
            assumption="Realtime channels lack auth on upgrade or accept injected messages",
            test=(
                "Connect without/with weak auth; attempt cross-user subscription and "
                "message injection. Socket.IO: also run the get_stream / url_key card."
            ),
            pass_criteria="Unauth channel data or cross-user message impact",
            kill_criteria="Upgrade requires auth; messages scoped to identity",
            cwe_ids=["CWE-306", "CWE-284"],
            capec_ids=["CAPEC-115"],
            owasp="A01:2021 Broken Access Control",
            evidence=str(ev),
            why="WebSocket/SSE channels observed",
        ))

    if _SOCKETIO_RE.search(combined) or any(
        _SOCKETIO_RE.search(str(w)) for w in (websockets or [])
    ):
        ev = next(
            (str(w) for w in (websockets or []) if _SOCKETIO_RE.search(str(w))),
            None,
        ) or next(
            (str(p) for p in pages if _SOCKETIO_RE.search(str(p))),
            "/socket.io/",
        )
        add(Methodology(
            id="socketio_unauth_stream_idor",
            title="Unauth Socket.IO get_stream IDOR (url_key / camera namespace)",
            hunt="socketio_idor",
            specialist="api_authz",
            priority="high",
            assumption=(
                "Socket.IO accepts anonymous connections and get_stream (or sibling "
                "events) returns a url_key / stream namespace for arbitrary siteId/"
                "analyzerId. Client JS may hardcode userType=Admin — cosmetic, not auth"
            ),
            test=(
                "Engine.IO polling: GET /socket.io/?EIO=3&transport=polling then POST "
                "42[\"get_stream\", {siteId: fabricated, userId: ATTACKER, userType: "
                "Anonymous}]. PASS if a url_key / namespace is returned without a "
                "session. Repeat 1–2 other siteIds. Do not fetch the video stream. "
                "Do not send null/malformed crash loops (ICS availability). "
                "queue_finding_followups(vuln_type='socketio_idor'). Then CORS on "
                "/socket.io/ (queue cors_credentials) and JS hardcoded siteId "
                "(queue js_secrets)."
            ),
            pass_criteria=(
                "Anonymous get_stream (or sibling) returns url_key / stream namespace "
                "for a fabricated siteId"
            ),
            kill_criteria=(
                "Upgrade/event requires auth; get_stream 401/403; no url_key. "
                "Do not kill because the video URL was not downloaded"
            ),
            cwe_ids=["CWE-639", "CWE-306", "CWE-284"],
            capec_ids=["CAPEC-1", "CAPEC-87"],
            owasp="A01:2021 Broken Access Control",
            evidence=str(ev),
            why="Socket.IO / get_stream observed — unauth industrial camera streams are a recurring miss",
        ))

    if js_files:
        add(Methodology(
            id="js_secrets_retire",
            title="Secrets / vulnerable libs in JS bundles",
            hunt="js_secrets",
            specialist="js_secrets",
            priority="medium",
            assumption="Bundles leak credentials, keys, or ship known-CVE client libraries",
            test="scan_js_urls_for_secrets + execute_retirejs on first-party bundles from the map",
            pass_criteria="Live/production credential, CWE-321 reconstructed HMAC key, ICS MQTT/RFID creds, or confirmed vulnerable library with CVE",
            kill_criteria="Only public config / test stubs; no actionable CVEs",
            cwe_ids=["CWE-798", "CWE-200", "CWE-1104", "CWE-312", "CWE-321"],
            capec_ids=["CAPEC-70"],
            owasp="A02:2021 Cryptographic Failures",
            evidence=js_files[0],
            why="JS bundles present",
        ))
        js_surface = " ".join(js_endpoints + js_files + pages + [str(g("target") or "")])
        if _APIKEY_HINT_RE.search(js_surface):
            add(Methodology(
                id="js_apikey_exposure",
                title="API key / token exposure in client assets",
                hunt="js_secrets",
                specialist="js_secrets",
                priority="high",
                assumption="Client-side assets expose API keys or bearer tokens usable against first-party APIs",
                test=(
                    "scan_js_urls_for_secrets on mapped bundles; validate any key against live APIs "
                    "with minimal read-only calls"
                ),
                pass_criteria="Working key/token with confirmed API access beyond public scope",
                kill_criteria="Public publishable keys only / revoked / no impact",
                cwe_ids=["CWE-798", "CWE-312", "CWE-200"],
                capec_ids=["CAPEC-70"],
                owasp="A02:2021 Cryptographic Failures",
                evidence=next((e for e in js_endpoints if _APIKEY_HINT_RE.search(e)), js_files[0]),
                why="API key / token naming hints in JS surface",
            ))
        if _NEXT_ADMIN_JS_RE.search(js_surface) or bool(g("has_admin")):
            add(Methodology(
                id="js_hostname_keyed_api_creds",
                title="Hostname-keyed API credentials in client JS (CWE-798 / CWE-312)",
                hunt="js_secrets",
                specialist="js_secrets",
                priority="critical",
                assumption=(
                    "Admin/Next.js bundles ship client_id/client_secret maps keyed by "
                    "environment hostname; sandbox UIs often include production pairs"
                ),
                test=(
                    "scan_js_urls_for_secrets on /_next/static/chunks/*.js. Extract hostname-keyed "
                    "client_id + client_secret (prod/dev/qa). Note header scheme from the bundle. "
                    "Stash creds; prove with ONE in-scope read-only API call (count + redacted sample). "
                    "Do not bulk-export. Prod API only if in scope."
                ),
                pass_criteria=(
                    "Non-publishable client_secret in a public bundle AND/OR live API returns "
                    "non-public records with those headers"
                ),
                kill_criteria="Publishable keys only; API rejects; no hostname-keyed map",
                cwe_ids=["CWE-798", "CWE-312", "CWE-540"],
                capec_ids=["CAPEC-70", "CAPEC-37"],
                owasp="A02:2021 Cryptographic Failures",
                evidence=next(
                    (f for f in js_files if _NEXT_ADMIN_JS_RE.search(f)),
                    js_files[0],
                ),
                why="Next.js/admin JS surface — hostname-keyed OAuth client secrets are a common leak",
            ))
        if _EMAILJS_RE.search(js_surface):
            add(Methodology(
                id="js_emailjs_client_send",
                title="EmailJS keys in client JS — unauthorized mail send (CWE-798)",
                hunt="js_secrets",
                specialist="js_secrets",
                priority="critical",
                assumption=(
                    "Bundles embed EmailJS user_id/service_id/template_id; any page can "
                    "POST api.emailjs.com from a visitor's browser and set the recipient"
                ),
                test=(
                    "Extract emailjs_userid, emailjs_serviceid, emailjs_templateid. "
                    "execute_interactsh register, then ONE browser-context POST "
                    "/api/v1.0/email/send with recipient aegis@<payload_domain>. "
                    "Never send to employees or arbitrary inboxes. curl Origin-block "
                    "is not a kill. Cap two templates."
                ),
                pass_criteria=(
                    "200/OK from browser send and/or execute_interactsh poll shows "
                    "SMTP/HTTP interaction"
                ),
                kill_criteria="Keys rejected from browser; domain allowlist + auth required",
                cwe_ids=["CWE-798", "CWE-312", "CWE-540"],
                capec_ids=["CAPEC-70", "CAPEC-163"],
                owasp="A02:2021 Cryptographic Failures",
                evidence=next(
                    (f for f in js_files if _EMAILJS_RE.search(f)),
                    js_files[0],
                ),
                why="EmailJS identifiers observed in JS surface",
            ))
        add(Methodology(
            id="js_client_hmac_signing",
            title="CWE-321 client HMAC-SHA256 / ICS creds in public JS",
            hunt="js_secrets",
            specialist="js_secrets",
            priority="high",
            assumption=(
                "Webpack/Angular bundles hide HMAC signing keys as empty-string object "
                "property names (Object.keys join / for-in) and embed MQTT/RFID ICS creds"
            ),
            test=(
                "scan_js_urls_for_secrets on main*.js / main-es2015*.js (do not skip 5–10MB "
                "bundles). Read client_signing_findings. Reconstruction + HmacSHA256/HS256 "
                "or MQTT/RFID fields is PASS. Live API/broker accept is extra; timeout is "
                "not a kill. Do not require token minting."
            ),
            pass_criteria=(
                "Public bundle reconstructs a signing secret used with HS256, or MQTT/RFID "
                "credentials are present next to broker/RFID usage"
            ),
            kill_criteria="No reconstruction; HMAC uses a server-issued session secret; placeholders only",
            cwe_ids=["CWE-321", "CWE-798", "CWE-312"],
            capec_ids=["CAPEC-191", "CAPEC-70"],
            owasp="A02:2021 Cryptographic Failures",
            evidence=next(
                (f for f in js_files if re.search(r"main[-.]|es2015", f, re.I)),
                js_files[0],
            ),
            why="First-party JS bundles — client HMAC and ICS creds are a recurring CWE-321 leak",
        ))
        add(Methodology(
            id="js_client_encryption_key",
            title="CWE-321 client encryption_key in public JS env object",
            hunt="js_secrets",
            specialist="js_secrets",
            priority="critical",
            assumption=(
                "SPA env objects (often next to EmailJS ids) embed a symmetric "
                "encryption_key / encryptionKey used to encrypt client payloads"
            ),
            test=(
                "scan_js_urls_for_secrets on main*.js. Read client_signing_findings "
                "kind=client_encryption_key. Presence of a non-placeholder encryption_key "
                "literal in a public bundle is PASS. File a SEPARATE finding from EmailJS. "
                "Do not bury the key in EmailJS verification notes."
            ),
            pass_criteria=(
                "Public unauthenticated bundle contains a non-placeholder encryption_key "
                "or encryptionKey string used for client-side crypto"
            ),
            kill_criteria="Placeholder only (YOUR_KEY / changeme); key not present; crypto is WebCrypto with server-issued material",
            cwe_ids=["CWE-321", "CWE-798", "CWE-312"],
            capec_ids=["CAPEC-37", "CAPEC-191"],
            owasp="A02:2021 Cryptographic Failures",
            evidence=next(
                (f for f in js_files if re.search(r"main[-.]|es2015", f, re.I)),
                js_files[0],
            ),
            why="Same env object that leaks EmailJS often also ships a client encryption_key",
        ))

    if has_spa or source_maps or len(js_files) >= 3:
        add(Methodology(
            id="spa_dom_hidden_api",
            title="SPA client-side / DOM / hidden API abuse",
            hunt="spa_client",
            specialist="spa_client",
            priority="medium",
            assumption="Client routing or DOM sinks allow XSS or hidden API abuse",
            test="Browser DOM checks + hidden API routes from JS against authz. Also forced-browse admin UI without the client-side isAdmin/localStorage flag.",
            pass_criteria="DOM XSS execution or hidden API missing auth with data impact",
            kill_criteria="No sinks and APIs enforce authz",
            cwe_ids=["CWE-79", "CWE-862"],
            capec_ids=["CAPEC-86", "CAPEC-1"],
            owasp="A03:2021 Injection",
            evidence=pages[0] if pages else (js_endpoints[0] if js_endpoints else "spa"),
            why="SPA / heavy JS signals observed",
        ))

    # Business logic: multi-form / checkout / invite
    if len(forms) >= 2 or _CHECKOUT_RE.search(combined) or _INVITE_RE.search(combined):
        ev = next(
            (str(f.get("action") or "") for f in forms if isinstance(f, dict) and _CHECKOUT_RE.search(
                f"{f.get('action', '')} {' '.join(f.get('inputs') or [])}"
            )),
            (forms[0].get("action") if forms and isinstance(forms[0], dict) else "") or "workflow",
        )
        add(Methodology(
            id="business_logic_workflow",
            title="Workflow / business-logic abuse",
            hunt="business_logic",
            specialist="business_logic",
            priority="medium",
            assumption="Multi-step or state-changing flows trust client-controlled steps/fields",
            test="Skip steps, tamper price/role/quantity, or mass-assign privileged fields on mapped workflows",
            pass_criteria="Unexpected state transition or privileged field accepted with evidence",
            kill_criteria="Server rejects skips/tampering consistently",
            cwe_ids=["CWE-840", "CWE-915", "CWE-284"],
            capec_ids=["CAPEC-210"],
            owasp="A04:2021 Insecure Design",
            evidence=str(ev),
            why="Multiple forms/workflows or checkout/invite surface observed",
        ))

    # AI agents / chatbots — tools are the attack surface; params are injection points
    if has_ai:
        chat_ev = next(
            (str(p) for p in pages if _AI_AGENT_RE.search(str(p))),
            next(
                (f"{e.get('method', '')} {e.get('path', '')}".strip()
                 for e in apis if isinstance(e, dict) and _AI_AGENT_RE.search(str(e.get("path", "")))),
                "chat",
            ),
        )
        add(Methodology(
            id="agent_tool_enumeration",
            title="Agent tool enumeration + parameter abuse",
            hunt="agent_tools",
            specialist="agent_tools",
            priority="high",
            assumption=(
                "Exposed agent tools define the AI attack surface the way open ports "
                "define a host; each tool parameter is an injection point "
                "(user_id→IDOR, email→phishing/PII, refund→fraud, send_now→immediate action)"
            ),
            test=(
                "1) Enumerate tools/schemas (AI port scan) via execute_llm_red_team "
                "categories=tool_enumeration "
                "2) Abuse high-impact tools: email, refund/payment, DB/query "
                "3) Tamper identity params (user_id) and side-effect flags (send_now) "
                "4) Follow with full llm_red_team + optional garak"
            ),
            pass_criteria=(
                "Tool list/schema disclosed, or a tool call succeeds for phishing/refund/"
                "exfil/IDOR/immediate-action with prompt+response evidence"
            ),
            kill_criteria=(
                "Agent refuses tool disclosure and rejects cross-tenant/side-effect tool abuse"
            ),
            cwe_ids=["CWE-200", "CWE-639", "CWE-862", "CWE-359"],
            capec_ids=["CAPEC-116", "CAPEC-1"],
            owasp="LLM08 Excessive Agency / LLM01 Prompt Injection",
            evidence=str(chat_ev),
            why="Chatbot/AI/agent/MCP surface observed — enumerate tools before payload spray",
        ))

    # Azure Function Apps — anonymous HTTP triggers that dump process env
    if _AZURE_FUNCTION_RE.search(combined):
        az_ev = next(
            (str(p) for p in pages if _AZURE_FUNCTION_RE.search(str(p))),
            target or (pages[0] if pages else "azurewebsites.net"),
        )
        add(Methodology(
            id="azure_function_anonymous_env",
            title="Anonymous Azure Function HTTP trigger env dump",
            hunt="azure_function",
            specialist="coverage",
            priority="critical",
            assumption=(
                "A Function App ships an HTTP trigger (often Tester) with authLevel:anonymous "
                "and no network restrictions, returning the process environment as JSON"
            ),
            test=(
                "Unauthenticated GET /api/Tester, then /api/test, /api/debug, /api/env, "
                "/api/HttpTrigger1. PASS if the body is runtime env (AzureWebJobsStorage, "
                "Cosmos keys, MACHINEKEY, WEBSITE_AUTH_*). Classify secret classes; "
                "queue_finding_followups(vuln_type='azure_function_env_dump'). "
                "Do not upload packages or inject code."
            ),
            pass_criteria=(
                "Unauth HTTP 200 JSON includes Function App process settings / secret names"
            ),
            kill_criteria="401/403 function key required; 404; body is not process environment",
            cwe_ids=["CWE-526", "CWE-200", "CWE-798", "CWE-284"],
            capec_ids=["CAPEC-37", "CAPEC-116"],
            owasp="A01:2021 Broken Access Control",
            evidence=str(az_ev),
            why="Azure Function App hostname / HTTP trigger surface observed",
        ))

    # Coverage leftovers when we have something to scan
    if pages or apis:
        add(Methodology(
            id="coverage_known_vulns",
            title="Coverage scan for known vulns/misconfig",
            hunt="coverage",
            specialist="coverage",
            priority="medium",
            assumption="Known CVE/misconfig templates may hit remaining inventory after logic hunts",
            test=(
                "execute_nuclei without severity filter on primary live URLs; "
                "authenticated -var if engagement credentials exist"
            ),
            pass_criteria="Template match with corroborating response evidence",
            kill_criteria="No actionable template hits after scoped coverage",
            cwe_ids=[],
            capec_ids=[],
            owasp="A06:2021 Vulnerable and Outdated Components",
            evidence=str(g("target") or (pages[0] if pages else "")),
            why="Live web surface mapped — run coverage after logic hunts",
        ))

    if not out and pages:
        add(Methodology(
            id="baseline_web",
            title="Baseline web vulnerability checks",
            hunt="baseline_web",
            specialist="xss",
            priority="medium",
            assumption="Browsable UI may have common web flaws despite thin signals",
            test="Baseline XSS/open-redirect/header checks on browsed pages + light nuclei",
            pass_criteria="Concrete finding with response evidence",
            kill_criteria="No actionable issues after baseline probes",
            cwe_ids=["CWE-79", "CWE-601"],
            capec_ids=["CAPEC-86"],
            owasp="A03:2021 Injection",
            evidence=pages[0],
            why="Browsable UI with limited signals",
        ))

    return _rank(out)


def _rank(items: Sequence[Methodology]) -> List[Methodology]:
    pri = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(list(items), key=lambda m: (pri.get(m.priority, 9), m.id))


def methodologies_to_hunt_queue(methodologies: Sequence[Methodology]) -> List[Dict[str, str]]:
    """Collapse methodologies into the capability-map hunt queue shape (unique hunts)."""
    queue: List[Dict[str, str]] = []
    seen_hunts: set[str] = set()
    for m in methodologies:
        if m.hunt in seen_hunts:
            continue
        seen_hunts.add(m.hunt)
        queue.append({
            "priority": m.priority,
            "hunt": m.hunt,
            "why": m.why or m.title,
            "evidence": (m.evidence or "")[:240],
            "methodology_id": m.id,
            "cwe_ids": ",".join(m.cwe_ids),
        })
    return queue[:22]


def format_methodologies_for_prompt(methodologies: Optional[Sequence[Any]]) -> str:
    """Compact prompt block listing observation-derived methodologies."""
    if not methodologies:
        return ""
    rows: List[Methodology] = []
    for m in methodologies:
        if isinstance(m, Methodology):
            rows.append(m)
        elif isinstance(m, dict) and m.get("id"):
            rows.append(Methodology(
                id=str(m.get("id")),
                title=str(m.get("title") or m.get("id")),
                hunt=str(m.get("hunt") or ""),
                specialist=str(m.get("specialist") or ""),
                priority=str(m.get("priority") or "medium"),
                assumption=str(m.get("assumption") or ""),
                test=str(m.get("test") or ""),
                pass_criteria=str(m.get("pass_criteria") or ""),
                kill_criteria=str(m.get("kill_criteria") or ""),
                cwe_ids=list(m.get("cwe_ids") or []),
                capec_ids=list(m.get("capec_ids") or []),
                owasp=str(m.get("owasp") or ""),
                evidence=str(m.get("evidence") or ""),
                why=str(m.get("why") or ""),
            ))
    if not rows:
        return ""
    lines = ["Observation → methodologies (prove or kill these):"]
    for i, m in enumerate(rows[:12], 1):
        cwes = ",".join(m.cwe_ids[:4]) if m.cwe_ids else "—"
        lines.append(
            f"  {i}. [{m.priority}] {m.id} → {m.specialist} | {m.title} "
            f"(CWE: {cwes}; OWASP: {m.owasp or '—'})"
        )
        lines.append(f"      test: {m.test}")
        if m.evidence:
            lines.append(f"      evidence: {m.evidence[:160]}")
    return "\n".join(lines)
