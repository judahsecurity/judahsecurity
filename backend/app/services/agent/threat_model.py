"""
Engagement threat model — the map; vulnerability discovery is the metal detector.

A threat ("unauth user reads another tenant's orders") survives a one-line patch.
A vulnerability ("/api/orders/:id missing an owner check") does not. This module
produces threats plus a surface inventory and focus-area partition so fireteam
hunters do not all pile onto the same shallow bug.

Bootstrap is deterministic (capability map, URL hints, or a local checkout).
The agent may refine rows via update_threat_model (owner interview).
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field, fields
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urlparse


ACTORS = (
    "remote_unauth",
    "remote_auth",
    "adjacent_network",
    "local_user",
    "local_admin",
    "supply_chain",
    "insider",
)
IMPACTS = ("low", "medium", "high", "critical", "existential")
LIKELIHOODS = ("very_rare", "rare", "possible", "likely", "almost_certain")
STATUSES = ("unmitigated", "partially_mitigated", "mitigated", "risk_accepted")
SENSITIVITIES = ("low", "medium", "high", "critical")

_IMPACT_RANK = {v: i for i, v in enumerate(IMPACTS)}
_LIKE_RANK = {v: i for i, v in enumerate(LIKELIHOODS)}

_SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    "vendor",
    ".next",
    "coverage",
    "target",
    ".tox",
}


@dataclass
class Asset:
    asset: str
    description: str = ""
    sensitivity: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EntryPoint:
    entry_point: str
    description: str = ""
    trust_boundary: str = ""
    reachable_assets: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Threat:
    id: str
    threat: str
    actor: str = "remote_unauth"
    surface: str = ""
    asset: str = ""
    impact: str = "high"
    likelihood: str = "possible"
    status: str = "unmitigated"
    controls: str = "none"
    evidence: str = ""
    specialist: str = "injection"
    shape: str = ""  # structural property, not a CWE checklist

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Deprioritized:
    threat: str
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Mitigation:
    mitigation: str
    threat_ids: str = ""
    closes_class: str = "partial"
    effort: str = "M"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Surface:
    method: str = "GET"
    path: str = ""
    takes_input: bool = False
    auth: str = "unknown"
    source: str = "map"
    host: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FocusArea:
    id: str
    title: str
    specialist: str
    threat_ids: List[str] = field(default_factory=list)
    surfaces: List[str] = field(default_factory=list)
    why: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ThreatModel:
    system_name: str = ""
    target: str = ""
    mode: str = "bootstrap"  # bootstrap | interview | bootstrap-then-interview | url | code
    context: str = ""
    assets: List[Asset] = field(default_factory=list)
    entry_points: List[EntryPoint] = field(default_factory=list)
    threats: List[Threat] = field(default_factory=list)
    deprioritized: List[Deprioritized] = field(default_factory=list)
    open_questions: List[str] = field(default_factory=list)
    mitigations: List[Mitigation] = field(default_factory=list)
    surfaces: List[Surface] = field(default_factory=list)
    focus_areas: List[FocusArea] = field(default_factory=list)
    provenance: Dict[str, str] = field(default_factory=dict)
    languages: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "system_name": self.system_name,
            "target": self.target,
            "mode": self.mode,
            "context": self.context,
            "assets": [a.to_dict() for a in self.assets],
            "entry_points": [e.to_dict() for e in self.entry_points],
            "threats": [t.to_dict() for t in self.threats],
            "deprioritized": [d.to_dict() for d in self.deprioritized],
            "open_questions": list(self.open_questions),
            "mitigations": [m.to_dict() for m in self.mitigations],
            "surfaces": [s.to_dict() for s in self.surfaces],
            "focus_areas": [f.to_dict() for f in self.focus_areas],
            "provenance": dict(self.provenance),
            "languages": list(self.languages),
            "frameworks": list(self.frameworks),
        }

    def ranked_threats(self) -> List[Threat]:
        active = [t for t in self.threats if t.status not in ("mitigated", "risk_accepted")]
        return sorted(
            active,
            key=lambda t: (
                -_IMPACT_RANK.get(t.impact, 0),
                -_LIKE_RANK.get(t.likelihood, 0),
                t.id,
            ),
        )


def threat_model_from_dict(data: Optional[Dict[str, Any]]) -> ThreatModel:
    if not data:
        return ThreatModel()
    known = {f.name for f in fields(ThreatModel)}
    filtered = {k: v for k, v in data.items() if k in known}
    assets = [_coerce(Asset, a) for a in (filtered.pop("assets", None) or [])]
    entries = [_coerce(EntryPoint, e) for e in (filtered.pop("entry_points", None) or [])]
    threats = [_coerce(Threat, t) for t in (filtered.pop("threats", None) or [])]
    depri = [_coerce(Deprioritized, d) for d in (filtered.pop("deprioritized", None) or [])]
    mitigations = [_coerce(Mitigation, m) for m in (filtered.pop("mitigations", None) or [])]
    surfaces = [_coerce(Surface, s) for s in (filtered.pop("surfaces", None) or [])]
    focus = [_coerce(FocusArea, f) for f in (filtered.pop("focus_areas", None) or [])]
    model = ThreatModel(**filtered)
    model.assets = [a for a in assets if a]
    model.entry_points = [e for e in entries if e]
    model.threats = [t for t in threats if t]
    model.deprioritized = [d for d in depri if d]
    model.mitigations = [m for m in mitigations if m]
    model.surfaces = [s for s in surfaces if s]
    model.focus_areas = [f for f in focus if f]
    return model


def _coerce(cls: Any, raw: Any) -> Optional[Any]:
    if not isinstance(raw, dict):
        return None
    allowed = {f.name for f in fields(cls)}
    return cls(**{k: v for k, v in raw.items() if k in allowed})


# ---------------------------------------------------------------------------
# Surfaces + focus areas
# ---------------------------------------------------------------------------


_ID_PATH_RE = re.compile(
    r"(?:/(?:api|v\d+)/[\w.-]+/\d+|[?&](?:id|user_?id|account_?id|org_?id|tenant_?id|uid|uuid)=|/:\w+|/\{\w+\})",
    re.I,
)
_INPUT_PATH_RE = re.compile(
    r"(?:[?&](?:q|query|search|s|url|redirect|next|callback|file|path)=|/search|/upload|/import)",
    re.I,
)


def surfaces_from_capability_map(cmap: Optional[Dict[str, Any]]) -> List[Surface]:
    if not cmap:
        return []
    out: List[Surface] = []
    seen: set[str] = set()

    def add(method: str, path: str, host: str = "", source: str = "map", auth: str = "unknown") -> None:
        path = (path or "").strip() or "/"
        key = f"{method.upper()} {host}{path}"
        if key in seen:
            return
        seen.add(key)
        takes = bool(_ID_PATH_RE.search(path) or _INPUT_PATH_RE.search(path) or method.upper() in ("POST", "PUT", "PATCH"))
        out.append(
            Surface(
                method=method.upper() or "GET",
                path=path[:300],
                takes_input=takes,
                auth=auth,
                source=source,
                host=host,
            )
        )

    for e in cmap.get("api_endpoints") or []:
        if isinstance(e, dict):
            add(str(e.get("method") or "GET"), str(e.get("path") or ""), str(e.get("host") or ""), "api")
        elif isinstance(e, str):
            parts = e.split(" ", 1)
            add(parts[0] if len(parts) == 2 else "GET", parts[-1], source="api")

    for p in cmap.get("pages_visited") or []:
        parsed = urlparse(str(p))
        add("GET", parsed.path or "/", parsed.netloc, "page")

    for f in cmap.get("forms") or []:
        if isinstance(f, dict):
            add(str(f.get("method") or "POST"), str(f.get("action") or "/"), source="form", auth="form")

    for js in (cmap.get("js_endpoints") or [])[:80]:
        add("GET", str(js), source="js")

    auth = "authenticated" if cmap.get("authenticated") else "anonymous"
    for s in out:
        if s.auth == "unknown":
            s.auth = auth
    return out[:250]


def focus_areas_from_model(model: ThreatModel) -> List[FocusArea]:
    """Partition hunters by surface/threat class so parallel agents do not converge."""
    by_spec: Dict[str, FocusArea] = {}
    for i, threat in enumerate(model.ranked_threats(), 1):
        spec = threat.specialist or "injection"
        fa = by_spec.get(spec)
        if not fa:
            fa = FocusArea(
                id=f"FA-{spec}",
                title=threat.threat.split(" via ")[0][:80],
                specialist=spec,
                why=threat.shape or threat.threat,
            )
            by_spec[spec] = fa
        if threat.id not in fa.threat_ids:
            fa.threat_ids.append(threat.id)
        if threat.surface and threat.surface not in fa.surfaces:
            fa.surfaces.append(threat.surface[:200])

    # Attach concrete inventory rows that match each specialist's surfaces.
    for fa in by_spec.values():
        needles = [s.lower() for s in fa.surfaces if s]
        extra: List[str] = []
        for surf in model.surfaces:
            blob = f"{surf.method} {surf.host}{surf.path}".lower()
            if any(n and n[:40].lower() in blob for n in needles):
                extra.append(f"{surf.method} {surf.path}")
            elif fa.specialist == "api_authz" and surf.takes_input and "/api" in surf.path.lower():
                extra.append(f"{surf.method} {surf.path}")
            elif fa.specialist == "auth_logic" and any(
                k in surf.path.lower() for k in ("login", "auth", "session", "sso", "reset")
            ):
                extra.append(f"{surf.method} {surf.path}")
        for row in extra[:12]:
            if row not in fa.surfaces:
                fa.surfaces.append(row)

    areas = list(by_spec.values())
    # Coverage leftover: inventory not claimed by any focus area.
    claimed = {s.lower() for fa in areas for s in fa.surfaces}
    leftover = [
        f"{s.method} {s.path}"
        for s in model.surfaces
        if f"{s.method} {s.path}".lower() not in claimed and s.takes_input
    ][:15]
    if leftover:
        areas.append(
            FocusArea(
                id="FA-unclaimed",
                title="Unclaimed input surfaces",
                specialist="coverage",
                surfaces=leftover,
                why="Inventory rows with input that no ranked threat claimed — coverage, not a spray.",
            )
        )
    return areas[:8]


def format_threat_model_for_prompt(data: Optional[Dict[str, Any]]) -> str:
    model = threat_model_from_dict(data if isinstance(data, dict) else None)
    if not model.threats and not model.assets:
        return (
            "No threat model yet. After observe (URL crawl) or a local checkout, call "
            "build_threat_model (or sync_engagement_brain, which bootstraps one). "
            "The threat model aims hunters; findings instantiate threats."
        )
    lines = [
        f"Threat model: {model.system_name or model.target or '?'}  mode={model.mode}",
    ]
    if model.context:
        lines.append(model.context.strip().split("\n")[0][:240])
    if model.languages or model.frameworks:
        lines.append(
            "Stack: "
            + ", ".join((model.languages or [])[:6] + (model.frameworks or [])[:6])
        )
    lines.append("Ranked threats (aim fireteam at these; a finding must instantiate one):")
    for t in model.ranked_threats()[:8]:
        lines.append(
            f"  - {t.id} [{t.impact}/{t.likelihood}/{t.status}] {t.actor} @ {t.surface or '?'} "
            f"→ {t.specialist}: {t.threat}"
        )
        if t.shape:
            lines.append(f"      shape: {t.shape}")
    if model.deprioritized:
        lines.append("Deprioritized (do not spend turns here unless ROE changes):")
        for d in model.deprioritized[:5]:
            lines.append(f"  - {d.threat} ({d.reason})")
    if model.focus_areas:
        lines.append("Focus areas (partition — one specialist per slice):")
        for fa in model.focus_areas[:6]:
            lines.append(
                f"  - {fa.id} {fa.specialist}: {fa.title} "
                f"threats={','.join(fa.threat_ids[:4]) or '—'} "
                f"surfaces={len(fa.surfaces)}"
            )
    if model.open_questions:
        lines.append("Open questions (ask the owner if present):")
        for q in model.open_questions[:4]:
            lines.append(f"  - {q}")
    lines.append(
        "Litmus: if patching one line would erase the row, it was a vulnerability, not a threat."
    )
    return "\n".join(lines)


def to_markdown(model: ThreatModel) -> str:
    """Human-readable artifact (save_note / reports). Headings are a contract."""
    def table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
        head = "| " + " | ".join(headers) + " |"
        sep = "| " + " | ".join("---" for _ in headers) + " |"
        body = "\n".join("| " + " | ".join(str(c).replace("|", "/") for c in r) + " |" for r in rows)
        return "\n".join([head, sep, body] if rows else [head, sep, "| — | " + " | ".join("—" for _ in headers[1:]) + " |"])

    lines = [
        f"# Threat Model: {model.system_name or model.target or 'target'}",
        "",
        "## 1. System context",
        "",
        model.context or "(bootstrap — refine with owner interview)",
        "",
        "## 2. Assets",
        "",
        table(
            ["asset", "description", "sensitivity"],
            [(a.asset, a.description, a.sensitivity) for a in model.assets],
        ),
        "",
        "## 3. Entry points & trust boundaries",
        "",
        table(
            ["entry_point", "description", "trust_boundary", "reachable_assets"],
            [
                (e.entry_point, e.description, e.trust_boundary, e.reachable_assets)
                for e in model.entry_points
            ],
        ),
        "",
        "## 4. Threats",
        "",
        table(
            ["id", "threat", "actor", "surface", "asset", "impact", "likelihood", "status", "controls", "evidence"],
            [
                (
                    t.id, t.threat, t.actor, t.surface, t.asset, t.impact,
                    t.likelihood, t.status, t.controls, t.evidence,
                )
                for t in model.ranked_threats() or model.threats
            ],
        ),
        "",
        "## 5. Deprioritized",
        "",
        table(
            ["threat", "reason"],
            [(d.threat, d.reason) for d in model.deprioritized] or [("none", "—")],
        ),
        "",
        "## 6. Open questions",
        "",
    ]
    if model.open_questions:
        lines.extend(f"- {q}" for q in model.open_questions)
    else:
        lines.append("- none")
    lines.extend([
        "",
        "## 7. Provenance",
        "",
        f"- mode: {model.mode}",
        f"- date: {model.provenance.get('date') or date.today().isoformat()}",
        f"- target: {model.target or model.provenance.get('target') or ''}",
        f"- inputs: {model.provenance.get('inputs') or 'capability map / code inventory'}",
        "",
        "## 8. Recommended mitigations",
        "",
        table(
            ["mitigation", "threat_ids", "closes_class", "effort"],
            [
                (m.mitigation, m.threat_ids, m.closes_class, m.effort)
                for m in model.mitigations
            ] or [("none yet", "—", "—", "—")],
        ),
        "",
        "## Focus areas",
        "",
    ])
    for fa in model.focus_areas:
        lines.append(f"- **{fa.id}** ({fa.specialist}): {fa.title} — {fa.why}")
        if fa.surfaces:
            lines.append(f"  surfaces: {', '.join(fa.surfaces[:8])}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Bootstrap: URL / capability map
# ---------------------------------------------------------------------------


def _g(cmap: Dict[str, Any], key: str, default: Any = None) -> Any:
    return cmap.get(key, default) if isinstance(cmap, dict) else default


def bootstrap_from_capability_map(
    cmap: Optional[Dict[str, Any]],
    *,
    system_name: str = "",
    owner_notes: str = "",
) -> ThreatModel:
    cmap = cmap or {}
    target = str(_g(cmap, "target") or "")
    host = urlparse(target).netloc or target
    name = system_name or host or "web application"
    auth = bool(_g(cmap, "authenticated"))
    has_login = bool(_g(cmap, "has_login_form") or _g(cmap, "has_auth"))
    has_api = bool(_g(cmap, "has_api") or _g(cmap, "api_endpoints"))
    has_upload = bool(_g(cmap, "has_upload"))
    has_search = bool(_g(cmap, "has_search"))
    has_graphql = bool(_g(cmap, "has_graphql"))
    has_admin = bool(_g(cmap, "has_admin"))
    has_oauth = bool(_g(cmap, "has_oauth_sso"))
    has_ai = bool(_g(cmap, "has_ai_agent"))
    js_files = list(_g(cmap, "js_files") or [])
    forms = list(_g(cmap, "forms") or [])

    hosts: set[str] = set()
    for p in _g(cmap, "pages_visited") or []:
        m = re.match(r"https?://([^/]+)", str(p))
        if m:
            hosts.add(m.group(1).lower())
    for e in _g(cmap, "api_endpoints") or []:
        if isinstance(e, dict) and e.get("host"):
            hosts.add(str(e["host"]).lower())
    multi_tenant = len(hosts) >= 2

    assets = [
        Asset("session integrity", "Authenticated user sessions and tokens", "high"),
        Asset("application data", "Records reachable through mapped APIs and pages", "high"),
        Asset("service availability", "Uptime of the primary web app", "medium"),
    ]
    if has_admin:
        assets.append(Asset("admin plane", "Administrative UI / APIs", "critical"))

    entries: List[EntryPoint] = []
    threats: List[Threat] = []
    questions: List[str] = []

    def add_entry(name: str, desc: str, boundary: str, assets_s: str) -> None:
        entries.append(EntryPoint(name, desc, boundary, assets_s))

    def add_threat(**kwargs: Any) -> None:
        threats.append(Threat(**kwargs))

    context_bits = [
        f"{name} is a live web application" + (f" at {target}" if target else "") + ".",
        "Bootstrap derived from a browser capability map (pages, forms, APIs, auth).",
    ]
    if owner_notes:
        context_bits.append(owner_notes.strip()[:500])
    if auth:
        context_bits.append("Crawl obtained an authenticated session.")
    else:
        context_bits.append("Crawl is anonymous; authenticated threats are hypothesized, not confirmed.")
        questions.append("Are test identities (user A / user B / admin) available for authz proofs?")

    if has_login:
        add_entry("login / session", "Credential and session establishment", "unauth internet → authenticated session", "session integrity")
        add_threat(
            id="T-auth-boundary",
            threat="Attacker obtains or bypasses an authenticated session via the login/session boundary",
            actor="remote_unauth",
            surface="login / session",
            asset="session integrity",
            impact="critical",
            likelihood="likely" if has_login else "possible",
            specialist="auth_logic",
            shape="Trust decision sits in the client or a guessable default rather than a server-side session binding",
            evidence="login form observed" if has_login else "",
        )
        add_threat(
            id="T-default-creds",
            threat="Remote attacker authenticates with product-default or weak credentials",
            actor="remote_unauth",
            surface="login / session",
            asset="session integrity",
            impact="critical",
            likelihood="possible",
            specialist="credential_assault",
            shape="Login accepts a well-known default pair without lockout",
        )

    if has_api or _g(cmap, "param_rich_paths"):
        add_entry("object APIs", "REST/JSON endpoints with object or tenant identifiers", "authz check (or lack of one) → records", "application data")
        add_threat(
            id="T-object-authz",
            threat="Authenticated (or anonymous) caller reads or mutates another user's or tenant's objects",
            actor="remote_auth" if has_login or auth else "remote_unauth",
            surface="object APIs",
            asset="application data",
            impact="critical",
            likelihood="likely" if has_api else "possible",
            specialist="api_authz",
            shape="Authorization is implied by knowing an identifier, not by a server-side owner/tenant check",
            evidence=f"{len(_g(cmap, 'api_endpoints') or [])} APIs mapped",
        )

    if multi_tenant:
        add_entry("tenant host routing", "Multiple hostnames share the app", "Host / X-Forwarded-Host → tenant data", "application data")
        add_threat(
            id="T-tenant-isolation",
            threat="Caller in tenant A reads tenant B data by mutating Host or forwarded-host headers",
            actor="remote_auth",
            surface="tenant host routing",
            asset="application data",
            impact="critical",
            likelihood="possible",
            specialist="host_tenant",
            shape="Tenant selection trusts the Host header more than the session's tenant binding",
            evidence=", ".join(sorted(hosts)[:4]),
        )

    if has_search or forms:
        add_entry("user-controlled parameters", "Search, forms, and query strings", "untrusted string → interpreter / renderer", "application data, service availability")
        add_threat(
            id="T-interpreted-input",
            threat="Attacker input alters the syntactic structure of an interpreted language or query",
            actor="remote_unauth" if not auth else "remote_auth",
            surface="user-controlled parameters",
            asset="application data",
            impact="critical",
            likelihood="possible",
            specialist="injection",
            shape="Untrusted bytes are concatenated into SQL, OS, template, or HTML context instead of bound/encoded",
        )

    if has_upload:
        add_entry("file upload", "User-supplied files", "untrusted file → process / object store", "application data, service availability")
        add_threat(
            id="T-upload",
            threat="Malicious upload is stored or executed such that it reads arbitrary files or runs code",
            actor="remote_auth" if has_login else "remote_unauth",
            surface="file upload",
            asset="application data",
            impact="critical",
            likelihood="possible",
            specialist="file_upload",
            shape="Name, type, or contents of an upload cross a trust boundary without a content-disposition/allowlist gate",
        )

    if has_graphql:
        add_entry("GraphQL", "GraphQL endpoint", "query → resolver authz", "application data")
        add_threat(
            id="T-graphql-authz",
            threat="GraphQL query reaches objects or mutations the caller should not access",
            actor="remote_unauth",
            surface="GraphQL",
            asset="application data",
            impact="high",
            likelihood="likely",
            specialist="graphql_api",
            shape="Resolver trusts the selection set; batching or introspection expands the reachable graph",
        )

    if has_oauth:
        add_entry("SSO / OAuth", "Identity federation", "IdP assertion → local session", "session integrity")
        add_threat(
            id="T-sso",
            threat="Federation message (SAML/OAuth/OIDC/JWT) is accepted without binding to the intended audience or algorithm",
            actor="remote_unauth",
            surface="SSO / OAuth",
            asset="session integrity",
            impact="critical",
            likelihood="possible",
            specialist="saml_sso",
            shape="Token or assertion is trusted by shape (alg, redirect, wrapping) rather than by verified audience + signature",
        )

    if has_admin:
        add_entry("admin UI", "Privileged management surface", "low-priv session → admin function", "admin plane")
        add_threat(
            id="T-privilege",
            threat="Low-privilege caller reaches an administrative function or data plane",
            actor="remote_auth",
            surface="admin UI",
            asset="admin plane",
            impact="critical",
            likelihood="possible",
            specialist="auth_logic",
            shape="Privilege is enforced in the UI or a client flag, not on the privileged API",
        )

    if has_ai:
        add_entry("LLM / agent tools", "Chat, copilot, or MCP-style tools", "untrusted prompt → tool invocation", "application data")
        add_threat(
            id="T-agent-tools",
            threat="Untrusted prompt causes an agent tool to run with the app's privileges or leak other users' data",
            actor="remote_unauth",
            surface="LLM / agent tools",
            asset="application data",
            impact="critical",
            likelihood="likely",
            specialist="agent_tools",
            shape="Tool arguments are taken from model output without a same-user authorization check",
        )

    if js_files:
        add_entry("first-party JS", "Browser bundles", "public JS → secrets / hidden APIs", "session integrity")
        add_threat(
            id="T-client-secrets",
            threat="Secrets or privileged API contracts leak from first-party JavaScript and are replayable",
            actor="remote_unauth",
            surface="first-party JS",
            asset="session integrity",
            impact="high",
            likelihood="likely",
            specialist="js_secrets",
            shape="A credential or privileged route exists in a public bundle without a corresponding server-side secret store",
            evidence=f"{len(js_files)} JS bundles",
        )

    if not threats:
        add_threat(
            id="T-baseline-web",
            threat="Untrusted HTTP input reaches a sensitive sink on the primary origin",
            actor="remote_unauth",
            surface="primary origin",
            asset="application data",
            impact="high",
            likelihood="possible",
            specialist="injection",
            shape="Any parameter that crosses into a query, file, or renderer without an encoding boundary",
        )
        questions.append("Capability map is thin — is a deeper authenticated crawl possible?")

    questions.append("Which data is in-scope to prove (PII, other tenants, admin config)?")
    if not auth and has_login:
        questions.append("Can the owner provide two test accounts for dual-identity authz?")

    model = ThreatModel(
        system_name=name,
        target=target,
        mode="url",
        context=" ".join(context_bits),
        assets=assets,
        entry_points=entries,
        threats=threats,
        open_questions=questions,
        provenance={
            "date": date.today().isoformat(),
            "target": target,
            "inputs": "capability map",
            "mode": "url",
        },
    )
    model.surfaces = surfaces_from_capability_map(cmap)
    model.focus_areas = focus_areas_from_model(model)
    model.mitigations = _default_mitigations(model)
    return model


def bootstrap_from_url(
    url: str,
    *,
    technologies: Optional[Sequence[str]] = None,
    owner_notes: str = "",
) -> ThreatModel:
    """Thin pre-crawl model from a URL (+ optional tech list) so assessment can aim immediately."""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    target = parsed.geturl() if parsed.scheme else f"https://{url}"
    path = (parsed.path or "/").lower()
    tech = [t.lower() for t in (technologies or [])]
    cmap: Dict[str, Any] = {
        "target": target,
        "pages_visited": [target],
        "has_login_form": any(k in path for k in ("login", "signin", "auth")),
        "has_auth": any(k in path for k in ("login", "account", "app", "dashboard")),
        "has_api": "/api" in path or any("api" in t for t in tech),
        "has_graphql": "graphql" in path or any("graphql" in t for t in tech),
        "has_admin": "admin" in path,
        "has_oauth_sso": any(k in path for k in ("sso", "saml", "oauth", "oidc")),
        "has_upload": "upload" in path,
        "has_search": "search" in path,
        "has_ai_agent": any(k in path for k in ("chat", "copilot", "assistant")),
        "api_endpoints": [{"method": "GET", "path": parsed.path or "/", "host": parsed.netloc}],
        "js_files": [],
        "forms": [],
    }
    if any(t in {"next.js", "nextjs", "react"} for t in tech):
        cmap["js_files"] = ["/_next/static/chunks/app.js"]
        cmap["has_spa_signals"] = True
    model = bootstrap_from_capability_map(cmap, owner_notes=owner_notes)
    model.mode = "url"
    model.frameworks = list(technologies or [])
    model.provenance["inputs"] = "url" + (f" + tech {','.join(tech)}" if tech else "")
    model.open_questions.insert(0, "Confirm with a crawl — this model is from the URL/tech only.")
    return model


# ---------------------------------------------------------------------------
# Bootstrap: local checkout (static, never execute target code)
# ---------------------------------------------------------------------------


_LOCKFILE_LANG = {
    "package.json": "javascript",
    "package-lock.json": "javascript",
    "yarn.lock": "javascript",
    "pnpm-lock.yaml": "javascript",
    "requirements.txt": "python",
    "pyproject.toml": "python",
    "Pipfile": "python",
    "go.mod": "go",
    "Cargo.toml": "rust",
    "pom.xml": "java",
    "build.gradle": "java",
    "Gemfile": "ruby",
    "composer.json": "php",
    "Dockerfile": "container",
    "docker-compose.yml": "container",
    "docker-compose.yaml": "container",
}

_FRAMEWORK_MARKERS = (
    ("next", ("next",), "javascript"),
    ("express", ("express",), "javascript"),
    ("django", ("django",), "python"),
    ("flask", ("flask",), "python"),
    ("fastapi", ("fastapi",), "python"),
    ("spring", ("springframework", "spring-boot", "springboot"), "java"),
    ("laravel", ("laravel/framework", "illuminate/"), "php"),
    ("rails", ("rails",), "ruby"),
    ("gin", ("github.com/gin-gonic/gin",), "go"),
    ("echo", ("github.com/labstack/echo",), "go"),
)


def inventory_checkout(repo_path: str, *, max_files: int = 400) -> Dict[str, Any]:
    """Read-only inventory of a local checkout. Never executes target code."""
    root = Path(repo_path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        return {"error": f"checkout not found: {repo_path}", "path": str(root)}

    languages: set[str] = set()
    frameworks: set[str] = set()
    markers: List[str] = []
    interesting: List[str] = []
    n_files = 0

    def consider(path: Path) -> None:
        nonlocal n_files
        if n_files >= max_files:
            return
        rel = str(path.relative_to(root))
        name = path.name
        n_files += 1
        lang = _LOCKFILE_LANG.get(name)
        if lang:
            languages.add(lang)
            markers.append(rel)
        suffix = path.suffix.lower()
        suffix_lang = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "javascript",
            ".tsx": "javascript",
            ".go": "go",
            ".java": "java",
            ".rb": "ruby",
            ".php": "php",
            ".rs": "rust",
        }.get(suffix)
        if suffix_lang:
            languages.add(suffix_lang)
        low = rel.lower()
        if any(
            k in low
            for k in (
                "auth", "login", "session", "upload", "graphql", "sso", "oauth",
                "jwt", "crypto", "deserialize", "pickle", "eval", "exec",
                "webhook", "proxy", "ssrf", "admin", "middleware",
            )
        ):
            interesting.append(rel)

    try:
        for child in root.iterdir():
            if child.is_file():
                consider(child)
    except OSError:
        pass

    for dirpath, dirnames, filenames in _walk_bounded(root, max_depth=4):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            if n_files >= max_files:
                break
            consider(Path(dirpath) / fn)

    # Cheap framework sniff from lock/manifest contents (text only, small files).
    for rel in list(markers)[:12]:
        p = root / rel
        try:
            if p.stat().st_size > 400_000:
                continue
            text = p.read_text(encoding="utf-8", errors="ignore")[:80_000].lower()
        except OSError:
            continue
        for fw, needles, _lang in _FRAMEWORK_MARKERS:
            if any(n in text for n in needles):
                frameworks.add(fw)

    return {
        "path": str(root),
        "languages": sorted(languages),
        "frameworks": sorted(frameworks),
        "markers": markers[:40],
        "interesting_paths": interesting[:60],
        "files_seen": n_files,
    }


def _walk_bounded(root: Path, max_depth: int = 4):
    root_s = str(root)
    for dirpath, dirnames, filenames in __import__("os").walk(root_s):
        rel = Path(dirpath).relative_to(root)
        depth = 0 if str(rel) == "." else len(rel.parts)
        if depth >= max_depth:
            dirnames[:] = []
        yield dirpath, dirnames, filenames


def bootstrap_from_code(
    repo_path: str,
    *,
    languages: Optional[Sequence[str]] = None,
    frameworks: Optional[Sequence[str]] = None,
    owner_notes: str = "",
    system_name: str = "",
) -> ThreatModel:
    inv = inventory_checkout(repo_path) if repo_path else {}
    langs = [x.lower() for x in (languages or inv.get("languages") or [])]
    fws = [x.lower() for x in (frameworks or inv.get("frameworks") or [])]
    name = system_name or Path(repo_path).name if repo_path else "codebase"
    interesting = list(inv.get("interesting_paths") or [])

    assets = [
        Asset("process integrity", "Application process / runtime", "critical"),
        Asset("data stores", "Databases and object stores the code talks to", "high"),
        Asset("secrets", "Keys, tokens, and credentials in config or env", "critical"),
        Asset("source confidentiality", "Non-public source and design", "medium"),
    ]
    entries: List[EntryPoint] = [
        EntryPoint(
            "untrusted input parsers",
            "HTTP handlers, CLIs, file parsers, deserializers",
            "untrusted bytes → process memory / query",
            "process integrity, data stores",
        ),
        EntryPoint(
            "dependency / build pipeline",
            "Lockfiles and container images",
            "supply chain → runtime",
            "process integrity",
        ),
    ]
    threats: List[Threat] = []
    questions: List[str] = [
        "Which entrypoints are internet-exposed vs internal?",
        "Is there a running instance we can use to verify reachability after SAST?",
    ]

    def T(**kwargs: Any) -> None:
        threats.append(Threat(**kwargs))

    T(
        id="T-code-injection",
        threat="Untrusted input alters the syntactic structure of a query, template, or command in this codebase",
        actor="remote_unauth",
        surface="untrusted input parsers",
        asset="data stores",
        impact="critical",
        likelihood="possible",
        specialist="code_sast",
        shape="Concatenation or format-string into SQL/OS/template/HTML rather than bind/encode",
        evidence=", ".join(interesting[:4]),
    )
    T(
        id="T-code-authz",
        threat="An object or admin function is reachable without a server-side owner/role check",
        actor="remote_auth",
        surface="HTTP handlers / resolvers",
        asset="data stores",
        impact="critical",
        likelihood="possible",
        specialist="code_sast",
        shape="Identifier in the request is trusted as authorization",
    )
    T(
        id="T-code-secrets",
        threat="A secret in source, env samples, or client bundles is replayable against a real service",
        actor="remote_unauth",
        surface="repo + config",
        asset="secrets",
        impact="high",
        likelihood="likely",
        specialist="js_secrets",
        shape="High-entropy credential checked into the tree or baked into a public bundle",
    )
    T(
        id="T-supply-chain",
        threat="A compromised or known-vulnerable dependency executes in the application trust boundary",
        actor="supply_chain",
        surface="dependency / build pipeline",
        asset="process integrity",
        impact="high",
        likelihood="possible",
        specialist="code_sast",
        shape="Unpinned or advisory-listed package is imported on a reachable path",
    )

    blob = " ".join(langs + fws + interesting).lower()
    if any(x in blob for x in ("pickle", "yaml.load", "deserialize", "objectinput", "unserialize")):
        T(
            id="T-insecure-deserialize",
            threat="Untrusted serialized object is decoded into executable or gadget-bearing types",
            actor="remote_unauth",
            surface="deserializers",
            asset="process integrity",
            impact="critical",
            likelihood="possible",
            specialist="code_sast",
            shape="Deserializer accepts attacker-controlled type information",
        )
    if any(x in blob for x in ("upload", "multipart", "sendfile", "readfile")):
        T(
            id="T-code-upload",
            threat="Uploaded or path-joined file is read or executed outside the intended directory",
            actor="remote_auth",
            surface="file handlers",
            asset="process integrity",
            impact="critical",
            likelihood="possible",
            specialist="file_upload",
            shape="User-controlled path segments join onto a filesystem API without a root jail",
        )
    if any(x in blob for x in ("ssrf", "webhook", "requests.get", "httpclient", "fetch(")):
        T(
            id="T-ssrf",
            threat="Server fetches a caller-controlled URL and reaches an internal network or cloud metadata service",
            actor="remote_auth",
            surface="URL-fetch helpers",
            asset="process integrity",
            impact="high",
            likelihood="possible",
            specialist="injection",
            shape="Destination of an outbound request is taken from request input",
        )
    if "next" in fws or "next.js" in fws:
        T(
            id="T-next-middleware",
            threat="Next.js middleware or Server Action trust boundary is skipped via a static/RSC path",
            actor="remote_unauth",
            surface="/_next and Server Actions",
            asset="session integrity",
            impact="critical",
            likelihood="possible",
            specialist="spa_client",
            shape="Auth middleware matches a prefix that static or RSC routes do not share",
        )
    if "spring" in fws:
        T(
            id="T-actuator",
            threat="Spring actuator or SpEL evaluation exposes env, heap, or RCE preconditions",
            actor="remote_unauth",
            surface="/actuator",
            asset="secrets",
            impact="critical",
            likelihood="possible",
            specialist="code_sast",
            shape="Management endpoints are reachable without the same authz as the business API",
        )
    if "django" in fws or "flask" in fws or "laravel" in fws:
        T(
            id="T-debug-surface",
            threat="Debug/toolbar/Ignition/Telescope surfaces leak secrets or accept dangerous eval in non-prod configs that are actually exposed",
            actor="remote_unauth",
            surface="debug endpoints",
            asset="secrets",
            impact="high",
            likelihood="possible",
            specialist="code_sast",
            shape="DEBUG or equivalent is true on a reachable deployment, not only in tests",
        )

    context = (
        f"{name} is a local checkout at {inv.get('path') or repo_path}. "
        f"Languages: {', '.join(langs) or 'unknown'}. "
        f"Frameworks: {', '.join(fws) or 'unknown'}. "
        "Static bootstrap only — target code was not executed."
    )
    if owner_notes:
        context += " " + owner_notes.strip()[:400]

    model = ThreatModel(
        system_name=name,
        target=str(inv.get("path") or repo_path),
        mode="code",
        context=context,
        assets=assets,
        entry_points=entries,
        threats=threats,
        open_questions=questions,
        languages=langs,
        frameworks=fws,
        provenance={
            "date": date.today().isoformat(),
            "target": str(inv.get("path") or repo_path),
            "inputs": "local checkout inventory (no execution)",
            "mode": "code",
        },
    )
    # Surfaces from interesting paths (not HTTP).
    model.surfaces = [
        Surface(method="READ", path=p, takes_input=True, source="code")
        for p in interesting[:80]
    ]
    model.focus_areas = focus_areas_from_model(model)
    model.mitigations = _default_mitigations(model)
    if inv.get("error"):
        model.open_questions.insert(0, inv["error"])
    return model


def _default_mitigations(model: ThreatModel) -> List[Mitigation]:
    rows: List[Mitigation] = []
    ids = {t.id for t in model.threats}
    if "T-object-authz" in ids or "T-code-authz" in ids:
        rows.append(Mitigation(
            "Enforce object/tenant checks on every identifier-bearing handler (deny by default)",
            ",".join(i for i in ("T-object-authz", "T-code-authz") if i in ids),
            "yes",
            "M",
        ))
    if "T-interpreted-input" in ids or "T-code-injection" in ids:
        rows.append(Mitigation(
            "Bind/encode at the sink — never concatenate untrusted input into queries or templates",
            ",".join(i for i in ("T-interpreted-input", "T-code-injection") if i in ids),
            "yes",
            "M",
        ))
    if "T-auth-boundary" in ids or "T-default-creds" in ids:
        rows.append(Mitigation(
            "Server-side session binding; reject known defaults; lockout + MFA on admin",
            ",".join(i for i in ("T-auth-boundary", "T-default-creds") if i in ids),
            "partial",
            "S",
        ))
    return rows


def merge_threat_models(base: ThreatModel, overlay: ThreatModel) -> ThreatModel:
    """Overlay wins on matching threat ids; new rows append. Surfaces unioned."""
    by_id = {t.id: t for t in base.threats}
    for t in overlay.threats:
        by_id[t.id] = t
    base.threats = list(by_id.values())
    if overlay.context and overlay.context not in base.context:
        base.context = (base.context + " " + overlay.context).strip()
    seen_assets = {a.asset for a in base.assets}
    for a in overlay.assets:
        if a.asset not in seen_assets:
            base.assets.append(a)
    seen_ep = {e.entry_point for e in base.entry_points}
    for e in overlay.entry_points:
        if e.entry_point not in seen_ep:
            base.entry_points.append(e)
    for q in overlay.open_questions:
        if q not in base.open_questions:
            base.open_questions.append(q)
    if overlay.languages:
        base.languages = sorted(set(base.languages) | set(overlay.languages))
    if overlay.frameworks:
        base.frameworks = sorted(set(base.frameworks) | set(overlay.frameworks))
    if overlay.mode:
        base.mode = overlay.mode
    surf_keys = {f"{s.method} {s.host}{s.path}" for s in base.surfaces}
    for s in overlay.surfaces:
        k = f"{s.method} {s.host}{s.path}"
        if k not in surf_keys:
            base.surfaces.append(s)
            surf_keys.add(k)
    base.focus_areas = focus_areas_from_model(base)
    return base


def apply_threat_patch(
    model: ThreatModel,
    threat_id: str,
    *,
    status: Optional[str] = None,
    likelihood: Optional[str] = None,
    controls: Optional[str] = None,
    evidence: Optional[str] = None,
    deprioritize_reason: Optional[str] = None,
) -> Optional[Threat]:
    for t in model.threats:
        if t.id == threat_id or t.threat == threat_id:
            if status and status in STATUSES:
                t.status = status
            if likelihood and likelihood in LIKELIHOODS:
                t.likelihood = likelihood
            if controls is not None:
                t.controls = controls
            if evidence:
                t.evidence = ((t.evidence + " | ") if t.evidence else "") + evidence[:500]
            if deprioritize_reason:
                t.status = "risk_accepted"
                model.deprioritized.append(Deprioritized(t.threat, deprioritize_reason))
            model.focus_areas = focus_areas_from_model(model)
            return t
    return None


def threats_as_hypothesis_dicts(
    model: ThreatModel,
    *,
    target: str = "",
) -> List[Dict[str, Any]]:
    """Cards the engagement brain can seed. Pass/kill are shapes, not scanner hits."""
    cards: List[Dict[str, Any]] = []
    for t in model.ranked_threats():
        if t.status in ("mitigated", "risk_accepted"):
            continue
        pri = "critical" if t.impact in ("critical", "existential") else (
            "high" if t.impact == "high" else "medium"
        )
        cards.append(
            {
                "id": t.id,
                "title": t.threat,
                "assumption": t.shape or t.threat,
                "test": (
                    f"On surface '{t.surface}', prove the outcome with a differential or "
                    f"reachable sink. Specialist={t.specialist}."
                ),
                "pass_criteria": (
                    f"Concrete {t.actor} demonstration that {t.asset} is affected "
                    f"(not a scanner banner)."
                ),
                "kill_criteria": (
                    f"Control holds on the live/code path: {t.controls or 'existing authz/encoding'}."
                ),
                "specialist": t.specialist,
                "priority": pri,
                "target": target or model.target,
                "evidence": t.evidence,
                "source": "threat_model",
                "methodology_id": t.id,
                "cwe_ids": [],
                "capec_ids": [],
                "owasp": "",
                "why": t.shape,
            }
        )
    return cards


def specialist_focus_block(model: ThreatModel, specialist: str) -> str:
    """Slice injected into a fireteam specialist so they hunt their partition only."""
    fas = [f for f in model.focus_areas if f.specialist == specialist]
    threats = [t for t in model.ranked_threats() if t.specialist == specialist]
    if not fas and not threats:
        return ""
    lines = ["THREAT-MODEL SLICE (stay in this partition; do not wander to other specialists' surfaces):"]
    for t in threats[:4]:
        lines.append(f"- {t.id}: {t.threat} | shape: {t.shape or t.threat}")
    for fa in fas[:2]:
        if fa.surfaces:
            lines.append("Surfaces: " + ", ".join(fa.surfaces[:10]))
    return "\n".join(lines)


def build_auto(
    *,
    cmap: Optional[Dict[str, Any]] = None,
    url: str = "",
    repo_path: str = "",
    languages: Optional[Sequence[str]] = None,
    frameworks: Optional[Sequence[str]] = None,
    owner_notes: str = "",
    existing: Optional[Dict[str, Any]] = None,
    source: str = "auto",
) -> ThreatModel:
    """Pick bootstrap source. 'auto' prefers map, then repo, then URL."""
    source = (source or "auto").strip().lower()
    existing_model = threat_model_from_dict(existing) if existing else ThreatModel()

    built: Optional[ThreatModel] = None
    if source in ("auto", "map", "url") and cmap and (
        cmap.get("pages_visited") or cmap.get("api_endpoints") or cmap.get("forms")
    ):
        built = bootstrap_from_capability_map(cmap, owner_notes=owner_notes)
    elif source in ("code",) or (source == "auto" and repo_path):
        built = bootstrap_from_code(
            repo_path,
            languages=languages,
            frameworks=frameworks,
            owner_notes=owner_notes,
        )
    elif source in ("url", "auto") and (url or (cmap or {}).get("target")):
        built = bootstrap_from_url(
            url or str((cmap or {}).get("target") or ""),
            technologies=frameworks,
            owner_notes=owner_notes,
        )
    elif source == "code" and not repo_path:
        built = ThreatModel(
            mode="code",
            open_questions=["repo_path is required for a code threat model"],
        )
    else:
        built = existing_model if existing_model.threats else ThreatModel(
            open_questions=["Need a URL, capability map, or local checkout to bootstrap"],
        )

    if existing_model.threats and built.threats:
        return merge_threat_models(existing_model, built)
    if existing_model.threats and not built.threats:
        return existing_model
    return built
