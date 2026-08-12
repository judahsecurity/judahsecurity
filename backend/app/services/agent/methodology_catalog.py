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
    r"(swagger|openapi|/api-docs|/v3/api-docs|/docs\.json|redoc|/schema\.json)",
    re.I,
)
_APIKEY_HINT_RE = re.compile(
    r"(api[_-]?key|access[_-]?token|secret[_-]?key|authorization|bearer)",
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
    r"(webhook|callback|fetch|proxy|import|url=|uri=|link=|avatar|og:image|preview)",
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
    api_blob = " ".join(f"{e.get('method', '')} {e.get('path', '')}" for e in apis if isinstance(e, dict))
    combined = f"{pages_blob} {forms_blob} {api_blob} {' '.join(param_paths)}"
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
            cwe_ids=["CWE-798", "CWE-521", "CWE-287"],
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
            hunt="injection",
            specialist="injection",
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
            hunt="injection",
            specialist="injection",
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
            hunt="injection",
            specialist="injection",
            priority="high",
            assumption="Server fetches attacker-controlled URLs (webhooks, imports, previews, proxies)",
            test=(
                "Probe URL-accepting params with interactsh + safe internal canaries "
                "(metadata IP, localhost version); compare_requests vs benign URL"
            ),
            pass_criteria="OOB hit plus internal HTTP body, or confirmed metadata/internal content",
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
            priority="medium",
            assumption="Realtime channels lack auth on upgrade or accept injected messages",
            test="Connect without/with weak auth; attempt cross-user subscription and message injection",
            pass_criteria="Unauth channel data or cross-user message impact",
            kill_criteria="Upgrade requires auth; messages scoped to identity",
            cwe_ids=["CWE-306", "CWE-284"],
            capec_ids=["CAPEC-115"],
            owasp="A01:2021 Broken Access Control",
            evidence=str(ev),
            why="WebSocket/SSE channels observed",
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
            pass_criteria="Live/production credential or confirmed vulnerable library with CVE",
            kill_criteria="Only public config / test stubs; no actionable CVEs",
            cwe_ids=["CWE-798", "CWE-200", "CWE-1104"],
            capec_ids=["CAPEC-70"],
            owasp="A02:2021 Cryptographic Failures",
            evidence=js_files[0],
            why="JS bundles present",
        ))
        js_surface = " ".join(js_endpoints + js_files + pages)
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

    if has_spa or source_maps or len(js_files) >= 3:
        add(Methodology(
            id="spa_dom_hidden_api",
            title="SPA client-side / DOM / hidden API abuse",
            hunt="spa_client",
            specialist="spa_client",
            priority="medium",
            assumption="Client routing or DOM sinks allow XSS or hidden API abuse",
            test="Browser DOM checks + hidden API routes from JS against authz",
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
            specialist="injection",
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
    return queue[:14]


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
