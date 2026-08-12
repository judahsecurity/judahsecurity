"""
Application Capability Map — tester-style understanding of a web app.

Built from interaction-first browser recon (deep_crawl / interceptor). Models
what a human tester learns by clicking around: pages, forms, APIs, auth hints,
uploads, websockets — then recommends which specialist sub-agents to spawn.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field, fields
from typing import Any, Dict, Iterable, List, Optional, Set


# ---------------------------------------------------------------------------
# Structured map
# ---------------------------------------------------------------------------


@dataclass
class CapabilityMap:
    """First-class attack-surface understanding for the agent loop."""

    target: str = ""
    scope: str = ""
    authenticated: Optional[bool] = None
    pages_visited: List[str] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    api_endpoints: List[Dict[str, str]] = field(default_factory=list)  # method, path, host
    js_endpoints: List[str] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    websockets: List[str] = field(default_factory=list)
    sse: List[str] = field(default_factory=list)
    source_maps: List[str] = field(default_factory=list)
    third_party: List[str] = field(default_factory=list)
    # Sample captured XHR/fetch for replay_http_request
    api_samples: List[Dict[str, Any]] = field(default_factory=list)

    # Derived capability flags (tester mental model)
    has_auth: bool = False
    has_login_form: bool = False
    has_upload: bool = False
    has_search: bool = False
    has_graphql: bool = False
    has_websocket: bool = False
    has_sse: bool = False
    has_api: bool = False
    has_admin: bool = False
    has_oauth_sso: bool = False
    has_spa_signals: bool = False
    has_ai_agent: bool = False
    param_rich_paths: List[str] = field(default_factory=list)

    capabilities: List[str] = field(default_factory=list)
    ranked_hunt_queue: List[Dict[str, str]] = field(default_factory=list)
    # Observation → concrete methodologies (CWE/CAPEC/OWASP-tagged test cards)
    methodologies: List[Dict[str, Any]] = field(default_factory=list)
    quality_score: float = 0.0
    ready_for_attack: bool = False
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


_AUTH_INPUTS = re.compile(
    r"(pass(word)?|passwd|pwd|user(name)?|email|login|otp|totp|token|auth)",
    re.I,
)
_UPLOAD_INPUTS = re.compile(r"(file|upload|attachment|avatar|image|document)", re.I)
_SEARCH_INPUTS = re.compile(r"(q|query|search|keyword|term)", re.I)
_GRAPHQL_RE = re.compile(r"graphql|/gql\b|/graph\b", re.I)
_ADMIN_RE = re.compile(r"/admin|/dashboard|/manage|/console|/internal", re.I)
_OAUTH_RE = re.compile(
    r"(oauth|/sso|/saml|/oidc|/authorize|/callback|openid|/login|/signin|/auth/)",
    re.I,
)
_SPA_HINTS = re.compile(r"(_next/|react|vue|angular|webpack|vite|spa)", re.I)
# Chatbots / copilots / MCP-style agent tool surfaces (AI attack surface)
_AI_AGENT_RE = re.compile(
    r"("
    r"/api/chat|/api/message|/api/ask|/api/completions|/v1/chat|/v1/messages|"
    r"chatbot|copilot|assistant|/mcp\b|model.?context.?protocol|"
    r"openai|anthropic|langchain|langgraph|function.?call|tool.?call|"
    r"intercom|drift|zendesk.?chat|crisp\.chat|tawk\.to|livechat|freshchat|"
    r"helpscout|olark|hubspot.?chat|genesys|salesforce.?chat"
    r")",
    re.I,
)


def build_capability_map_from_crawl(crawl: Any) -> CapabilityMap:
    """Build a CapabilityMap from a deep_crawl CrawlResult (or duck-typed)."""
    target = getattr(crawl, "target", "") or ""
    scope = getattr(crawl, "scope", "") or ""
    pages = list(getattr(crawl, "pages_visited", []) or [])
    forms = list(getattr(crawl, "forms", []) or [])
    js_files = sorted(getattr(crawl, "js_files", set()) or [])
    js_endpoints = sorted(getattr(crawl, "endpoints_from_js", set()) or [])
    websockets = sorted(getattr(crawl, "websockets", set()) or [])
    sse = sorted(getattr(crawl, "sse", set()) or [])
    source_maps = sorted(getattr(crawl, "source_maps", set()) or [])
    third_party = sorted(getattr(crawl, "third_party", set()) or [])
    authenticated = getattr(crawl, "authenticated", None)
    api_samples = list(getattr(crawl, "api_samples", []) or [])[:40]

    api_endpoints: List[Dict[str, str]] = []
    api_calls = getattr(crawl, "api_calls", {}) or {}
    for host, keys in api_calls.items():
        for key in sorted(keys):
            # key format: "METHOD path?query"
            parts = str(key).split(" ", 1)
            method = parts[0] if len(parts) == 2 else "GET"
            path = parts[1] if len(parts) == 2 else parts[0]
            api_endpoints.append({"host": host, "method": method, "path": path})

    return finalize_capability_map(
        CapabilityMap(
            target=target,
            scope=scope,
            authenticated=authenticated,
            pages_visited=pages[:80],
            forms=forms[:60],
            api_endpoints=api_endpoints[:200],
            js_endpoints=js_endpoints[:200],
            js_files=js_files[:120],
            websockets=websockets[:40],
            sse=sse[:40],
            source_maps=source_maps[:40],
            third_party=third_party[:40],
            api_samples=api_samples,
        )
    )


def build_capability_map_from_dict(data: Dict[str, Any]) -> CapabilityMap:
    """Rebuild / normalize a map from a previously serialized dict."""
    if not data:
        return CapabilityMap()
    known = {f.name for f in fields(CapabilityMap)}
    filtered = {k: v for k, v in data.items() if k in known}
    return finalize_capability_map(CapabilityMap(**filtered))


def finalize_capability_map(cmap: CapabilityMap) -> CapabilityMap:
    """Derive flags, hunt queue, and quality score from raw crawl fields."""
    pages_blob = " ".join(cmap.pages_visited)
    api_blob = " ".join(f"{e.get('method')} {e.get('path')}" for e in cmap.api_endpoints)
    js_blob = " ".join(cmap.js_endpoints + cmap.js_files)
    form_inputs = []
    for f in cmap.forms:
        form_inputs.extend(f.get("inputs") or [])
        action = f.get("action") or ""
        if _AUTH_INPUTS.search(" ".join(f.get("inputs") or [])) or _OAUTH_RE.search(action):
            cmap.has_login_form = True
        if any(_UPLOAD_INPUTS.search(i or "") for i in (f.get("inputs") or [])):
            cmap.has_upload = True
        if any(_SEARCH_INPUTS.search(i or "") for i in (f.get("inputs") or [])):
            cmap.has_search = True

    inputs_blob = " ".join(str(i) for i in form_inputs)
    combined = f"{pages_blob} {api_blob} {js_blob} {inputs_blob}"

    cmap.has_api = bool(cmap.api_endpoints) or bool(cmap.js_endpoints)
    cmap.has_websocket = bool(cmap.websockets)
    cmap.has_sse = bool(cmap.sse)
    cmap.has_graphql = bool(_GRAPHQL_RE.search(combined))
    cmap.has_admin = bool(_ADMIN_RE.search(combined))
    cmap.has_oauth_sso = bool(_OAUTH_RE.search(combined))
    cmap.has_auth = bool(
        cmap.has_login_form
        or cmap.has_oauth_sso
        or cmap.authenticated is True
        or _AUTH_INPUTS.search(inputs_blob)
    )
    cmap.has_spa_signals = bool(_SPA_HINTS.search(combined)) or len(cmap.js_files) >= 3
    third_blob = " ".join(cmap.third_party or [])
    cmap.has_ai_agent = bool(_AI_AGENT_RE.search(f"{combined} {third_blob}"))

    # Parameter-looking paths (query strings or REST-ish ids)
    param_paths: List[str] = []
    for e in cmap.api_endpoints:
        path = e.get("path") or ""
        if "?" in path or re.search(r"/\{?\w*(id|uuid|token|key)\}?", path, re.I):
            param_paths.append(f"{e.get('method')} {path}")
    for e in cmap.js_endpoints:
        if "?" in e or "=" in e:
            param_paths.append(e)
    cmap.param_rich_paths = list(dict.fromkeys(param_paths))[:40]

    caps: List[str] = []
    if cmap.pages_visited:
        caps.append("browsable_ui")
    if cmap.has_spa_signals:
        caps.append("spa")
    if cmap.has_ai_agent:
        caps.append("ai_agent")
    if cmap.has_api:
        caps.append("api")
    if cmap.has_graphql:
        caps.append("graphql")
    if cmap.has_auth:
        caps.append("auth")
    if cmap.has_login_form:
        caps.append("login_form")
    if cmap.has_oauth_sso:
        caps.append("oauth_sso")
    if cmap.has_upload:
        caps.append("file_upload")
    if cmap.has_search:
        caps.append("search")
    if cmap.has_admin:
        caps.append("admin")
    if cmap.has_websocket:
        caps.append("websocket")
    if cmap.has_sse:
        caps.append("sse")
    if cmap.js_files:
        caps.append("javascript")
    if cmap.source_maps:
        caps.append("source_maps")
    if cmap.param_rich_paths:
        caps.append("injectable_params")
    if cmap.forms:
        caps.append("forms")
    cmap.capabilities = caps

    # Observation → methodologies first; hunt queue collapses those + legacy hunts
    from app.services.agent.methodology_catalog import (
        methodologies_from_capability_map,
        methodologies_to_hunt_queue,
    )

    methods = methodologies_from_capability_map(cmap)
    cmap.methodologies = [m.to_dict() for m in methods]
    method_queue = methodologies_to_hunt_queue(methods)
    legacy_queue = _build_hunt_queue(cmap)
    # Prefer methodology-backed hunts; append legacy hunts not already covered
    seen_hunts = {h.get("hunt") for h in method_queue}
    merged_queue = list(method_queue)
    for h in legacy_queue:
        if h.get("hunt") not in seen_hunts:
            merged_queue.append(h)
            seen_hunts.add(h.get("hunt"))
    cmap.ranked_hunt_queue = merged_queue[:14]
    cmap.quality_score = _score_map(cmap)
    # Ready when we actually browsed something useful — not just a blank fail.
    cmap.ready_for_attack = (
        cmap.quality_score >= 0.35
        and (len(cmap.pages_visited) >= 1 or len(cmap.api_endpoints) >= 1)
    )
    if not cmap.ready_for_attack:
        cmap.notes.append(
            "Capability map is thin — browse more pages (raise max_pages) or provide "
            "an authenticated session before heavy exploitation."
        )
    return cmap


def _build_hunt_queue(cmap: CapabilityMap) -> List[Dict[str, str]]:
    queue: List[Dict[str, str]] = []

    def add(priority: str, hunt: str, why: str, evidence: str = "") -> None:
        queue.append({
            "priority": priority,
            "hunt": hunt,
            "why": why,
            "evidence": evidence[:240],
        })

    if cmap.has_auth or cmap.has_login_form:
        add(
            "high",
            "credential_assault",
            "Login form present — Samson: default/weak credential assault with tiny lists",
            next((p for p in cmap.pages_visited if _OAUTH_RE.search(p)), "")
            or (cmap.forms[0].get("action") if cmap.forms else ""),
        )
        add("high", "auth_logic", "Login/auth surface discovered — probe authz and session logic",
            next((p for p in cmap.pages_visited if _OAUTH_RE.search(p)), "")
            or (cmap.forms[0].get("action") if cmap.forms else ""))
    if cmap.has_oauth_sso:
        add("high", "saml_sso", "OAuth/SSO/SAML indicators — misconfig and redirect abuse",
            next((p for p in cmap.pages_visited if _OAUTH_RE.search(p)), ""))
    if cmap.has_graphql:
        add("high", "graphql", "GraphQL endpoint/path signals — introspection, authz, batching",
            next((e.get("path", "") for e in cmap.api_endpoints if _GRAPHQL_RE.search(e.get("path", ""))), "graphql"))
    if cmap.has_upload:
        add("high", "file_upload", "Upload form/inputs — content-type, path traversal, XSS via file",
            next((str(f.get("action", "")) for f in cmap.forms
                  if any(_UPLOAD_INPUTS.search(i or "") for i in (f.get("inputs") or []))), ""))
    if cmap.has_api:
        add("high", "api_authz", "First-party APIs captured — IDOR/authz and verb tampering",
            cmap.api_endpoints[0].get("path", "") if cmap.api_endpoints else "")
    # Multi-host / subdomain pages → host-header tenant isolation card
    hosts = set()
    for p in cmap.pages_visited:
        m = re.match(r"https?://([^/]+)", str(p))
        if m:
            hosts.add(m.group(1).lower())
    for e in cmap.api_endpoints:
        if e.get("host"):
            hosts.add(str(e["host"]).lower())
    if len(hosts) >= 2 or any(re.match(r"^[a-z0-9-]+\.[a-z0-9-]+\.", h) for h in hosts):
        add(
            "high",
            "host_tenant",
            "Multiple hosts/subdomains — test Host/X-Forwarded-Host tenant isolation with same session",
            ", ".join(sorted(hosts)[:4]),
        )
    if len(cmap.forms) >= 2:
        add(
            "medium",
            "business_logic",
            "Multiple forms/workflows — step skip, mass assignment, state tamper",
            (cmap.forms[0].get("action") if cmap.forms else "") or "",
        )
    if cmap.param_rich_paths or cmap.has_search:
        add("high", "injection", "Query/body params or search forms — SQLi/XSS/SSTI candidates",
            (cmap.param_rich_paths[0] if cmap.param_rich_paths else "search"))
    if cmap.has_admin:
        add("medium", "admin_surface", "Admin/dashboard paths — privilege and exposure checks",
            next((p for p in cmap.pages_visited if _ADMIN_RE.search(p)), ""))
    if cmap.js_files:
        add("medium", "js_secrets", "JS bundles present — secrets, source maps, retire.js CVEs",
            cmap.js_files[0] if cmap.js_files else "")
    if cmap.has_websocket or cmap.has_sse:
        add("medium", "realtime", "WebSocket/SSE channels — auth on upgrade and message injection",
            (cmap.websockets or cmap.sse or [""])[0])
    if cmap.has_spa_signals:
        add("medium", "spa_client", "SPA signals — DOM XSS, client routing, hidden API routes",
            cmap.pages_visited[0] if cmap.pages_visited else "")
    if cmap.has_ai_agent:
        add(
            "high",
            "agent_tools",
            "AI/chatbot/agent surface — enumerate tools (AI port scan), then abuse params "
            "(user_id→IDOR, email→phishing, refund→fraud, send_now→immediate action)",
            next(
                (p for p in (cmap.pages_visited + [e.get("path", "") for e in cmap.api_endpoints])
                  if _AI_AGENT_RE.search(str(p))),
                "chat",
            ),
        )
    if not queue and cmap.pages_visited:
        add("medium", "baseline_web", "Browsable UI with limited signals — baseline web vulns + nuclei",
            cmap.pages_visited[0])
    if cmap.pages_visited or cmap.api_endpoints:
        add(
            "medium",
            "coverage",
            "After logic hunts — Nuclei/misconfig/CVE coverage (authenticated if creds exist)",
            cmap.target or (cmap.pages_visited[0] if cmap.pages_visited else ""),
        )
    return queue[:14]


def _score_map(cmap: CapabilityMap) -> float:
    score = 0.0
    score += min(0.35, 0.05 * len(cmap.pages_visited))
    score += min(0.25, 0.02 * len(cmap.api_endpoints))
    score += min(0.15, 0.03 * len(cmap.forms))
    score += min(0.10, 0.01 * len(cmap.js_files))
    if cmap.has_auth:
        score += 0.08
    if cmap.has_api:
        score += 0.07
    if cmap.has_graphql or cmap.has_upload:
        score += 0.05
    if cmap.has_ai_agent:
        score += 0.12  # chatbot/agent surface is high-value even with few pages
    if cmap.authenticated is True:
        score += 0.05
    return round(min(1.0, score), 3)


# ---------------------------------------------------------------------------
# Specialist selection
# ---------------------------------------------------------------------------


# Attack-oriented specialists (complement existing recon profiles in fireteam_service)
ATTACK_SPECIALIST_NAMES = [
    "app_mapper",
    "credential_assault",
    "auth_logic",
    "api_authz",
    "host_tenant",
    "business_logic",
    "injection",
    "graphql_api",
    "js_secrets",
    "file_upload",
    "saml_sso",
    "spa_client",
    "agent_tools",
    "coverage",
    "finding_judge",
    "vuln_triage",
]


def select_specialists_for_map(
    cmap: Optional[CapabilityMap | Dict[str, Any]],
    *,
    max_specialists: int = 6,
    include_recon: bool = False,
) -> List[str]:
    """Pick fireteam specialists from a capability map (tester branching)."""
    if isinstance(cmap, dict):
        cmap = build_capability_map_from_dict(cmap)
    if not cmap or not cmap.ready_for_attack:
        # Thin map: still map + secrets + triage, avoid spray.
        # If an AI/chat surface is already visible, prioritize tool enumeration.
        if cmap and getattr(cmap, "has_ai_agent", False):
            thin = ["app_mapper", "agent_tools", "vuln_triage"]
        else:
            thin = ["app_mapper", "js_secrets", "vuln_triage"]
        return (thin if not include_recon
                else ["web_recon"] + thin[1:])[:max_specialists]

    selected: List[str] = ["app_mapper"]
    hunt_to_specialist = {
        "credential_assault": "credential_assault",
        "auth_logic": "auth_logic",
        "saml_sso": "saml_sso",
        "graphql": "graphql_api",
        "file_upload": "file_upload",
        "api_authz": "api_authz",
        "host_tenant": "host_tenant",
        "business_logic": "business_logic",
        "injection": "injection",
        "js_secrets": "js_secrets",
        "spa_client": "spa_client",
        "agent_tools": "agent_tools",
        "coverage": "coverage",
        "admin_surface": "auth_logic",
        "realtime": "api_authz",
        "baseline_web": "injection",
    }
    for item in cmap.ranked_hunt_queue:
        name = hunt_to_specialist.get(item.get("hunt", ""))
        if name and name not in selected:
            selected.append(name)
        if len(selected) >= max_specialists - 1:
            break

    # Close with Solomon (finding judge) — demonstrated-compromise bar
    if "finding_judge" not in selected:
        if len(selected) >= max_specialists:
            selected = selected[: max_specialists - 1]
        selected.append("finding_judge")
    elif "vuln_triage" not in selected and len(selected) < max_specialists:
        selected.append("vuln_triage")
    if include_recon and "web_recon" not in selected:
        selected.insert(0, "web_recon")
    return selected[:max_specialists]


def format_capability_map_for_prompt(cmap: Optional[CapabilityMap | Dict[str, Any]]) -> str:
    """Compact prompt block for the main ReAct agent."""
    if not cmap:
        return (
            "No application capability map yet. Before spraying scanners, run "
            "**execute_deep_crawl** on the primary web target (click/interact like a tester), "
            "then call **fireteam_dispatch** with specialists=\"auto\" to spawn hunters "
            "matched to what the browser learned."
        )
    if isinstance(cmap, dict):
        cmap = build_capability_map_from_dict(cmap)

    lines = [
        f"Target: {cmap.target or '(unknown)'}  scope={cmap.scope or '?'}",
        f"Quality: {cmap.quality_score:.2f}  ready_for_attack={cmap.ready_for_attack}  "
        f"authenticated={cmap.authenticated}",
        f"Pages browsed: {len(cmap.pages_visited)}  forms={len(cmap.forms)}  "
        f"APIs={len(cmap.api_endpoints)}  JS bundles={len(cmap.js_files)}",
        f"Capabilities: {', '.join(cmap.capabilities) or '(none)'}",
    ]
    if cmap.pages_visited:
        lines.append("Sample pages:")
        for p in cmap.pages_visited[:8]:
            lines.append(f"  - {p}")
    if cmap.api_endpoints:
        lines.append("Sample APIs:")
        for e in cmap.api_endpoints[:10]:
            lines.append(f"  - {e.get('method')} {e.get('host')}{e.get('path')}")
    if cmap.forms:
        lines.append("Forms:")
        for f in cmap.forms[:6]:
            inputs = ",".join((f.get("inputs") or [])[:8])
            lines.append(f"  - {f.get('method')} {f.get('action') or '(self)'} inputs=[{inputs}]")
    if cmap.methodologies:
        from app.services.agent.methodology_catalog import format_methodologies_for_prompt
        lines.append(format_methodologies_for_prompt(cmap.methodologies))
    elif cmap.ranked_hunt_queue:
        lines.append("Ranked hunt queue (spawn specialists for these):")
        for i, h in enumerate(cmap.ranked_hunt_queue[:8], 1):
            lines.append(f"  {i}. [{h.get('priority')}] {h.get('hunt')}: {h.get('why')}")
    suggested = select_specialists_for_map(cmap)
    lines.append(
        f"Suggested fireteam: fireteam_dispatch(mission=..., specialists={suggested!r}) "
        f"or specialists=\"auto\""
    )
    for n in cmap.notes[:3]:
        lines.append(f"Note: {n}")
    return "\n".join(lines)


def mission_from_capability_map(cmap: CapabilityMap | Dict[str, Any]) -> str:
    """Build a fireteam mission string grounded in the capability map."""
    if isinstance(cmap, dict):
        cmap = build_capability_map_from_dict(cmap)
    hunts = ", ".join(h.get("hunt", "") for h in cmap.ranked_hunt_queue[:6]) or "baseline web"
    return (
        f"Attack the application using the browser-built capability map for {cmap.target}. "
        f"Focus hunts: {hunts}. Use concrete endpoints/forms from the map; do not spray "
        f"unrelated tools. Prove impact with evidence before reporting."
    )


def merge_capability_maps(
    existing: Optional[Dict[str, Any]],
    new: CapabilityMap | Dict[str, Any],
) -> Dict[str, Any]:
    """Merge a new crawl map into session state (union of surfaces)."""
    if isinstance(new, dict):
        new = build_capability_map_from_dict(new)
    if not existing:
        return new.to_dict()
    old = build_capability_map_from_dict(existing)

    def _uniq(seq: Iterable[Any]) -> List[Any]:
        out: List[Any] = []
        seen: Set[str] = set()
        for item in seq:
            key = str(item)
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
        return out

    merged = CapabilityMap(
        target=new.target or old.target,
        scope=new.scope or old.scope,
        authenticated=new.authenticated if new.authenticated is not None else old.authenticated,
        pages_visited=_uniq(list(old.pages_visited) + list(new.pages_visited))[:120],
        forms=_uniq(list(old.forms) + list(new.forms))[:80],
        api_endpoints=_uniq(list(old.api_endpoints) + list(new.api_endpoints))[:300],
        js_endpoints=_uniq(list(old.js_endpoints) + list(new.js_endpoints))[:300],
        js_files=_uniq(list(old.js_files) + list(new.js_files))[:160],
        websockets=_uniq(list(old.websockets) + list(new.websockets))[:60],
        sse=_uniq(list(old.sse) + list(new.sse))[:60],
        source_maps=_uniq(list(old.source_maps) + list(new.source_maps))[:60],
        third_party=_uniq(list(old.third_party) + list(new.third_party))[:60],
        api_samples=_uniq(list(old.api_samples) + list(new.api_samples))[:60],
    )
    return finalize_capability_map(merged).to_dict()


def ingest_passive_urls(
    existing: Optional[Dict[str, Any]],
    urls: Iterable[str],
    *,
    target: str = "",
    source: str = "passive",
) -> Dict[str, Any]:
    """
    Merge katana/gau/wayback/httpx URL lists into the capability map.

    Passive URLs enrich pages/API/JS signals so methodologies fire even when
    Playwright deep_crawl missed a path.
    """
    url_list = [str(u).strip() for u in (urls or []) if str(u).strip()]
    if not url_list:
        return existing or finalize_capability_map(CapabilityMap(target=target)).to_dict()

    pages: List[str] = []
    apis: List[Dict[str, str]] = []
    js_files: List[str] = []
    js_endpoints: List[str] = []

    for raw in url_list[:400]:
        u = raw
        if not u.startswith(("http://", "https://", "/")):
            # bare path
            if u.startswith("api/") or "/api/" in u:
                apis.append({"host": "", "method": "GET", "path": u if u.startswith("/") else f"/{u}"})
            else:
                pages.append(u)
            continue
        lower = u.lower()
        path = u
        try:
            from urllib.parse import urlparse
            parsed = urlparse(u)
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
            host = parsed.netloc or ""
        except Exception:
            host = ""
        if any(lower.endswith(ext) for ext in (".js", ".mjs", ".map")):
            if lower.endswith(".map"):
                continue
            js_files.append(u)
            continue
        if re.search(r"/api/|/graphql|/gql\b|/v\d+/|swagger|openapi", path, re.I):
            apis.append({"host": host, "method": "GET", "path": path})
        elif "?" in path or re.search(r"/\d{1,12}(?:/|$)", path):
            apis.append({"host": host, "method": "GET", "path": path})
            pages.append(u)
        else:
            pages.append(u)
        if "/api/" in path or path.startswith("/api"):
            js_endpoints.append(path)

    existing_target = ""
    if isinstance(existing, dict):
        existing_target = str(existing.get("target") or "")
    patch = CapabilityMap(
        target=target or existing_target,
        pages_visited=pages[:80],
        api_endpoints=apis[:200],
        js_files=js_files[:80],
        js_endpoints=js_endpoints[:80],
        notes=[f"Ingested {len(url_list)} URLs from {source}"],
    )
    return merge_capability_maps(existing, finalize_capability_map(patch))
