"""
Engagement Brain — tester-process control plane for the ASM agent.

Keeps structured engagement memory that survives chat noise:

* **threat model** (ranked actor→outcome rows + focus-area partition)
* capability-map-seeded **hypotheses** (open / proven / killed)
* discovered **credentials** (for authenticated follow-ups)
* **approaches tried** + **next steps**
* automatic **chain cards** after confirmed findings

The orchestrator owns this state; specialists consume slices of it.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional


HypothesisStatus = str  # open | in_progress | proven | killed


@dataclass
class Hypothesis:
    id: str
    title: str
    assumption: str
    test: str
    pass_criteria: str
    kill_criteria: str
    specialist: str
    status: HypothesisStatus = "open"
    priority: str = "high"  # high | medium | low
    target: str = ""
    evidence: str = ""
    source: str = "map"  # map | chain | manual | finding | methodology | threat_model
    parent_finding: str = ""
    methodology_id: str = ""
    cwe_ids: List[str] = field(default_factory=list)
    capec_ids: List[str] = field(default_factory=list)
    owasp: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CredentialRecord:
    username: str
    secret: str
    secret_type: str = "password"
    source: str = "unknown"
    valid_on: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def redacted(self) -> Dict[str, Any]:
        secret = self.secret or ""
        masked = ("*" * max(0, len(secret) - 2)) + secret[-2:] if secret else ""
        return {
            "username": self.username,
            "secret": masked,
            "secret_type": self.secret_type,
            "source": self.source,
            "valid_on": list(self.valid_on),
            "notes": self.notes,
        }


@dataclass
class ApproachRecord:
    technique: str
    target: str = ""
    result: str = "failed"  # failed | inconclusive | success
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EngagementBrain:
    """Session-scoped tester process memory."""

    phase: str = "recon"  # recon | map | attack | coverage | report
    target: str = ""
    identities: List[str] = field(default_factory=lambda: ["anonymous"])
    credentials: List[CredentialRecord] = field(default_factory=list)
    hypotheses: List[Hypothesis] = field(default_factory=list)
    approaches: List[ApproachRecord] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)
    confirmed_findings: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    threat_model: Dict[str, Any] = field(default_factory=dict)
    surfaces: List[Dict[str, Any]] = field(default_factory=list)
    focus_areas: List[Dict[str, Any]] = field(default_factory=list)
    candidates: List[Dict[str, Any]] = field(default_factory=list)
    coverage: List[Dict[str, Any]] = field(default_factory=list)
    task_graph: Dict[str, Any] = field(default_factory=dict)
    pending_risk_assessments: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase": self.phase,
            "target": self.target,
            "identities": list(self.identities),
            "credentials": [c.to_dict() for c in self.credentials],
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "approaches": [a.to_dict() for a in self.approaches],
            "next_steps": list(self.next_steps),
            "confirmed_findings": list(self.confirmed_findings),
            "notes": list(self.notes),
            "threat_model": dict(self.threat_model or {}),
            "surfaces": list(self.surfaces or []),
            "focus_areas": list(self.focus_areas or []),
            "candidates": list(self.candidates or []),
            "coverage": list(self.coverage or []),
            "task_graph": dict(self.task_graph or {}),
            "pending_risk_assessments": list(self.pending_risk_assessments or []),
        }


def engagement_brain_from_dict(data: Optional[Dict[str, Any]]) -> EngagementBrain:
    if not data:
        return EngagementBrain()
    known = {f.name for f in fields(EngagementBrain)}
    filtered = {k: v for k, v in data.items() if k in known}
    creds = [
        CredentialRecord(**{kk: vv for kk, vv in (c or {}).items() if kk in CredentialRecord.__dataclass_fields__})
        for c in (filtered.pop("credentials", None) or [])
        if isinstance(c, dict)
    ]
    hyps = [
        Hypothesis(**{kk: vv for kk, vv in (h or {}).items() if kk in Hypothesis.__dataclass_fields__})
        for h in (filtered.pop("hypotheses", None) or [])
        if isinstance(h, dict)
    ]
    approaches = [
        ApproachRecord(**{kk: vv for kk, vv in (a or {}).items() if kk in ApproachRecord.__dataclass_fields__})
        for a in (filtered.pop("approaches", None) or [])
        if isinstance(a, dict)
    ]
    brain = EngagementBrain(**filtered)
    brain.credentials = creds
    brain.hypotheses = hyps
    brain.approaches = approaches
    return brain


def _hyp_id(*parts: str) -> str:
    raw = "|".join(p.strip().lower() for p in parts if p)
    return hashlib.sha1(raw.encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Hypothesis cards (map-seeded + chain cards)
# ---------------------------------------------------------------------------


_HUNT_CARDS: Dict[str, Dict[str, str]] = {
    "auth_logic": {
        "title": "Auth / session boundary abuse",
        "assumption": "Login, session cookies, or forced browsing control access incorrectly",
        "test": "Probe login/default creds; compare anonymous vs authenticated access to mapped auth/admin paths",
        "pass_criteria": "Working session with elevated access, or protected resource reachable without auth",
        "kill_criteria": "Auth required consistently; no default creds; no forced-browse success",
        "specialist": "auth_logic",
        "priority": "high",
    },
    "credential_assault": {
        "title": "Default / weak credential assault",
        "assumption": "Login forms accept product default or weak credentials",
        "test": "Tiny known-default lists via test_credential_spray or bounded hydra (-f) on mapped login",
        "pass_criteria": "Working session with verified credentials (stash + follow-up chains)",
        "kill_criteria": "Defaults rejected; lockout without success; no inventing passwords",
        "specialist": "credential_assault",
        "priority": "high",
    },
    "api_authz": {
        "title": "API object/tenant authorization gap (IDOR/BOLA)",
        "assumption": "Object IDs or tenant context are not enforced server-side",
        "test": "compare_requests across anonymous / user A / user B (or adjacent object IDs) on mapped APIs",
        "pass_criteria": "Cross-identity or unauth response contains another user's/tenant's data fields",
        "kill_criteria": "401/403 consistently, or body only reflects caller's own objects",
        "specialist": "api_authz",
        "priority": "high",
    },
    "host_tenant": {
        "title": "Host-header tenant isolation bypass",
        "assumption": "Tenant routing trusts Host / X-Forwarded-Host more than session binding",
        "test": "Keep session A; compare_requests with Host (and X-Forwarded-Host) set to peer tenant hostname",
        "pass_criteria": "Response contains tenant B objects/PII/config under session A",
        "kill_criteria": "Still tenant A content, hard 400/421, or connection rejected by vhost",
        "specialist": "host_tenant",
        "priority": "high",
    },
    "injection": {
        "title": "Injection on mapped parameters",
        "assumption": "Query/body params from the capability map are unsafely interpolated",
        "test": "Probe ranked params with canaries; confirm with sqlmap/xsstrike/browser only on hits",
        "pass_criteria": "Differential/error/time proof or reflected execution with concrete param",
        "kill_criteria": "No anomalous responses after disciplined probes; WAF blocks without bypass attempt only = incomplete",
        "specialist": "injection",
        "priority": "high",
    },
    "xss": {
        "title": "XSS on search and reflect params",
        "assumption": "User-controlled search/reflect params are rendered without neutralization",
        "test": "XSS canaries into observed search/reflect params; confirm via browser or HTML context",
        "pass_criteria": "Script execution or unambiguous HTML context injection with a concrete param",
        "kill_criteria": "Output encoded/escaped; CSP-only block without a bypass attempt is incomplete",
        "specialist": "xss",
        "priority": "high",
    },
    "sqli": {
        "title": "SQLi/SSTI/command injection on mapped params",
        "assumption": "Query/body params are unsafely interpolated into queries/templates/shell",
        "test": "Canaries first; sqlmap/commix only on anomalous hits",
        "pass_criteria": "Error/time/boolean differential or template/command impact with a concrete param",
        "kill_criteria": "No anomalous responses after disciplined probes",
        "specialist": "sqli",
        "priority": "high",
    },
    "ssrf": {
        "title": "SSRF via URL-fetch / webhook / proxy",
        "assumption": "Server fetches attacker-controlled URLs",
        "test": "execute_interactsh register → plant payload_url → poll; then benign vs in-scope canary. Never Canarytokens. Never metadata/localhost if Lictor blocks",
        "pass_criteria": "execute_interactsh poll DNS/HTTP/SMTP hit, or confirmed internal HTTP body",
        "kill_criteria": "URL fetch blocked / egress filtered; OOB-only without internal body",
        "specialist": "ssrf",
        "priority": "high",
    },
    "business_logic": {
        "title": "Workflow / business-logic abuse",
        "assumption": "Multi-step or state-changing flows trust client-controlled steps/fields",
        "test": "Skip steps, tamper price/role/quantity, or mass-assign privileged fields on mapped workflows",
        "pass_criteria": "Unexpected state transition or privileged field accepted with evidence",
        "kill_criteria": "Server rejects skips/tampering consistently",
        "specialist": "business_logic",
        "priority": "medium",
    },
    "graphql": {
        "title": "GraphQL authz / introspection abuse",
        "assumption": "GraphQL exposes introspection or cross-user node access",
        "test": "Introspection + dual-identity queries on node/viewer/mutations from the map",
        "pass_criteria": "Cross-user data or unauth mutation/impact proven (introspection alone is not enough)",
        "kill_criteria": "Introspection disabled and object authz holds across identities",
        "specialist": "graphql_api",
        "priority": "high",
    },
    "file_upload": {
        "title": "Unsafe file upload",
        "assumption": "Upload path trusts client content-type/filename",
        "test": "Content-type/extension bypass and stored XSS/path tricks on mapped upload forms",
        "pass_criteria": "Executable/HTML content stored or path traversal confirmed",
        "kill_criteria": "Strict type/extension and content validation",
        "specialist": "file_upload",
        "priority": "high",
    },
    "saml_sso": {
        "title": "SSO / OAuth / SAML misconfig",
        "assumption": "Authorize/callback/SAML endpoints mishandle redirects or signatures",
        "test": "test_saml_sso + redirect_uri / Host / callback tampering on mapped SSO URLs",
        "pass_criteria": "Open redirect to token theft, unsigned assertion accepted, or OIDC misconfig with impact",
        "kill_criteria": "Strict redirect allowlist and signature checks",
        "specialist": "saml_sso",
        "priority": "high",
    },
    "js_secrets": {
        "title": "Secrets / sensitive data in JS",
        "assumption": "Bundles leak credentials, HMAC signing keys, ICS MQTT/RFID, or hidden admin APIs",
        "test": "scan_js_urls_for_secrets (incl. client_signing_findings) + retire.js on first-party bundles from the map",
        "pass_criteria": (
            "Live or clearly production credential / CWE-321 reconstructed HMAC key / "
            "ICS MQTT-RFID creds in a public bundle. HMAC/ICS: reconstruction is enough; "
            "API timeout is not a kill."
        ),
        "kill_criteria": "Only public config / test stubs",
        "specialist": "js_secrets",
        "priority": "medium",
    },
    "spa_client": {
        "title": "SPA client-side / DOM abuse",
        "assumption": "Client routing or DOM sinks allow XSS or hidden API abuse",
        "test": "Browser DOM checks + hidden API routes from JS against authz",
        "pass_criteria": "DOM XSS execution or hidden API missing auth with data impact",
        "kill_criteria": "No sinks and APIs enforce authz",
        "specialist": "spa_client",
        "priority": "medium",
    },
    "elasticsearch_unauth": {
        "title": "Unauthenticated Elasticsearch (xpack.security disabled)",
        "assumption": (
            "Internet-facing Elasticsearch on :9200 has xpack.security.enabled unset"
        ),
        "test": (
            "Unauth GET / then /_cluster/health, /_nodes/os,jvm, /_cat/indices, "
            "limited sample read, PUT+DELETE aegis_test_index. No Painless RCE, no bulk dump."
        ),
        "pass_criteria": "Cluster JSON without credentials; indices listed; write proven via test index",
        "kill_criteria": "401/403; security enabled; not Elasticsearch",
        "specialist": "coverage",
        "priority": "critical",
    },
    "arangodb_default": {
        "title": "ArangoDB root empty password",
        "assumption": "Internet-facing ArangoDB /_open/auth accepts root with an empty password",
        "test": "POST /_open/auth root+empty password; list DBs; one collection sample. No PII dump.",
        "pass_criteria": "JWT for root AND at least one database/collection listed",
        "kill_criteria": "401/403; password required",
        "specialist": "coverage",
        "priority": "critical",
    },
    "mongodb_unauth": {
        "title": "MongoDB anonymous login",
        "assumption": "Port 27017 accepts unauthenticated connections",
        "test": "listDatabases only; note ransomware-note DBs. Do not dump or drop.",
        "pass_criteria": "Unauthenticated listDatabases succeeds",
        "kill_criteria": "auth required; port filtered",
        "specialist": "coverage",
        "priority": "critical",
    },
    "emqx_default": {
        "title": "EMQX dashboard default login",
        "assumption": "EMQX dashboard still uses admin:public",
        "test": "Tiny list admin:public then admin:admin; read-only listeners/users. No plugin upload.",
        "pass_criteria": "Admin dashboard/API session",
        "kill_criteria": "Defaults rejected",
        "specialist": "credential_assault",
        "priority": "critical",
    },
    "cors_credentials": {
        "title": "CORS origin reflection with credentials",
        "assumption": (
            "ACAO reflects an arbitrary Origin while Access-Control-Allow-Credentials is true. "
            "On Keycloak this is usually client webOrigins=*"
        ),
        "test": (
            "compare_requests Origin=https://aegis-cors-canary-<rand>.example vs none. "
            "PASS if ACAO echoes AND credentials=true. OPTIONS preflight Authorization+POST. "
            "Keycloak: also hit token, userinfo, admin users. Socket.IO: url_key only."
        ),
        "pass_criteria": "ACAO echoes attacker origin AND credentials true",
        "kill_criteria": (
            "Allowlist rejects canary; ACAO * without credentials. "
            "Do not kill solely because no victim browser session was available"
        ),
        "specialist": "api_authz",
        "priority": "high",
    },
    "keycloak_password_grant": {
        "title": "Keycloak admin-cli public password grant / no lockout",
        "assumption": (
            "admin-cli is public with Direct Access Grants; token endpoint has no brute-force defense"
        ),
        "test": (
            "POST grant_type=password client_id=admin-cli with no secret. invalid_grant proves "
            "the grant. At most 8 failed attempts — no 429. Tiny defaults only; no hydra/rockyou."
        ),
        "pass_criteria": "Password grant without client_secret AND no lockout on the bounded probe",
        "kill_criteria": (
            "Confidential client; password grant disabled; 429/lockout within 8 attempts. "
            "Do not kill because no valid password was guessed"
        ),
        "specialist": "credential_assault",
        "priority": "critical",
    },
    "unauth_account_lookup": {
        "title": "Unauth OpenAPI account lookup (security: {} / email → role)",
        "assumption": (
            "GET /api/auth/account/?email= is documented unauthenticated and returns "
            "is_staff/role, or it reaches app code while siblings 401"
        ),
        "test": (
            "Quote security: {} / 'without authentication'. compare_requests unauth "
            "GET /api/auth/profile/ vs /api/auth/account/?email=aegis-enum-canary@example.invalid. "
            "PASS on 200 with privilege fields OR 404 existence oracle OR 500 vs sibling 401. "
            "File Critical. One canary; do not spray. Do not claim a 200 role body unless stdout has it."
        ),
        "pass_criteria": (
            "Schema unauth + is_staff/role, OR lookup is not 401 while a protected sibling is "
            "(200, 404, or 500 all count)"
        ),
        "kill_criteria": (
            "Lookup 401/403 like siblings; schema requires JWT; generic boolean only. "
            "Do not kill because the database is unavailable or the lookup is 404"
        ),
        "specialist": "api_authz",
        "priority": "critical",
    },
    "unauth_settings_write": {
        "title": "Unauthenticated ASP.NET / API settings write (missing [Authorize])",
        "assumption": (
            "SettingsController or mapped Save*/Write* config APIs lack [Authorize] while "
            "sibling writes on the same app return 401. ASP.NET void success is 200 "
            "Content-Length: 0. GET 500 is not an auth rejection"
        ),
        "test": (
            "compare_requests: unauth POST a protected write sibling (TaskAdmin/UpdateTask) "
            "vs unauth POST /api/Settings/SaveSettings with one canary key (aegis-verify-*). "
            "PASS on sibling 401 AND SaveSettings 200 void. Do not replace the settings "
            "collection; do not flip production flags. GET GetSettings 500 is not a kill."
        ),
        "pass_criteria": (
            "Unauth settings/config write is accepted (200/204) while a sibling write is 401"
        ),
        "kill_criteria": (
            "SaveSettings 401/403 like siblings. Do not kill because GetSettings is 500 "
            "or the canary was not read back"
        ),
        "specialist": "api_authz",
        "priority": "high",
    },
    "client_role_param": {
        "title": "Client-supplied userType/admin role",
        "assumption": "API trusts body userType/userId without a server session",
        "test": "compare_requests userType empty vs Admin; bounded sample, not full inventory.",
        "pass_criteria": "Admin mutant returns cross-tenant or privileged fields",
        "kill_criteria": "401/403; userType ignored",
        "specialist": "api_authz",
        "priority": "critical",
    },
    "vendorjson_unauth": {
        "title": "Unauth vendorJson multi-tenant manifest",
        "assumption": "vendorJson returns all tenants without auth",
        "test": "Unauth GET; record tenant count + 1–2 hosts. Do not dump the full blob.",
        "pass_criteria": "Multiple tenants or internal userId/role/IP fields without auth",
        "kill_criteria": "401/403; current-tenant display only",
        "specialist": "api_authz",
        "priority": "high",
    },
    "auth0_mgmt_token": {
        "title": "Unauth Auth0 Management API token",
        "assumption": "Public /api/token returns an Auth0 Management JWT",
        "test": "Unauth GET token; ONE /api/v2/clients?per_page=1. Redact JWT. Do not enumerate the directory.",
        "pass_criteria": "Token issued unauthenticated AND Management API accepts a read",
        "kill_criteria": "401; token rejected",
        "specialist": "coverage",
        "priority": "critical",
    },
    "gitlab_unauth": {
        "title": "Unauth GitLab project API",
        "assumption": "GitLab /api/v4/projects lists public repos; files may hold secrets",
        "test": "GET /api/v4/projects?per_page=5. Sample ONE file. Do not clone all.",
        "pass_criteria": "Unauth project list and/or a sampled hardcoded secret",
        "kill_criteria": "401/403; no public projects",
        "specialist": "js_secrets",
        "priority": "critical",
    },
    "docker_registry": {
        "title": "Unauth Docker / ACR catalog + bounded image secrets",
        "assumption": (
            "Registry /v2/_catalog (ACR: anonymous oauth2 token for registry:catalog:*) "
            "requires no credentials; images may embed PATs in lockfiles/history"
        ),
        "test": (
            "Unauth oauth2 token then GET /v2/_catalog. Count names. Then tags/list + "
            "config/history on at most 1–3 first-party repos. Do not pull the catalog; "
            "do not push; do not authenticate recovered PATs."
        ),
        "pass_criteria": "Anonymous catalog with repository names (High); image secrets raise Critical",
        "kill_criteria": "Anonymous token denied; catalog 401",
        "specialist": "coverage",
        "priority": "high",
    },
    "django_debug": {
        "title": "Django DEBUG traceback after default admin",
        "assumption": "DEBUG=True plus admin:admin dumps env on 500",
        "test": "After admin:admin, safe 500 → secret classes; optional Redis ping. No FLUSHALL.",
        "pass_criteria": "Traceback discloses env secret classes, or Redis accepts the leaked key",
        "kill_criteria": "DEBUG off; defaults rejected",
        "specialist": "coverage",
        "priority": "critical",
    },
    "openai_proxy_unauth": {
        "title": "Unauth Azure OpenAI /api/chat proxy",
        "assumption": "POST /api/chat proxies to Azure OpenAI with no session",
        "test": "One cheap canary completion. Do not burn tokens. Do not jailbreak for harm.",
        "pass_criteria": "Unauth model completion",
        "kill_criteria": "401/403",
        "specialist": "agent_tools",
        "priority": "high",
    },
    "wiki_open_reg": {
        "title": "Open wiki self-registration → write / internal pages",
        "assumption": "Wiki/Confluence/MediaWiki allows anonymous CreateAccount and grants write or internal PII",
        "test": (
            "Create ONE throwaway account (Special:CreateAccount / signup). Prove write on a "
            "sandbox/user page OR read one internal page with employee PII. Do not deface "
            "production pages or scrape the wiki."
        ),
        "pass_criteria": "Self-registered session can edit a page or read non-public wiki content",
        "kill_criteria": "Registration closed; captcha/approval; no write/internal read",
        "specialist": "auth_logic",
        "priority": "high",
    },
    "binary_hardcoded_creds": {
        "title": "Hardcoded credentials in a public downloadable binary",
        "assumption": "Public installer/firmware/APK embeds production passwords or connection strings",
        "test": (
            "Download the public binary. strings/grep for password/secret/connection patterns. "
            "Prove ONE extracted credential against an in-scope login if safe. Redact secrets. "
            "Do not reverse for exploits; do not ship the binary into findings."
        ),
        "pass_criteria": "Extracted production credential (and optional live login) from a public download",
        "kill_criteria": "No secrets; only public config; binary not in scope",
        "specialist": "js_secrets",
        "priority": "critical",
    },
    "client_side_auth": {
        "title": "Client-side-only authentication on admin UI",
        "assumption": "Admin dashboard/eLogbook gates pages in JS (localStorage/userType) without a server session",
        "test": (
            "Forced-browse admin routes anonymous; compare_requests to the backing API without "
            "the client flag vs with a forged role. PASS if privileged data returns without a session."
        ),
        "pass_criteria": "Admin page or API returns privileged data without a server-side session",
        "kill_criteria": "401/403 on APIs; UI hide-only with empty bodies",
        "specialist": "auth_logic",
        "priority": "critical",
    },
    "email_change_ato": {
        "title": "Unauthenticated email-change ATO (djoser reset_email)",
        "assumption": (
            "reset_email / reset_email_confirm skip JWT while set_password returns 401. "
            "Token mailed to the attacker-controlled address is the remaining control"
        ),
        "test": (
            "compare_requests unauth POST set_password (401) vs reset_email with "
            "aegis-ato-canary@example.invalid (204). Then confirm uid=MQ + garbage token "
            "for user enum. One canary; do not complete ATO on a real mailbox."
        ),
        "pass_criteria": "Unauth email-change accepted while a sibling account-mod is 401",
        "kill_criteria": (
            "Both email-change endpoints 401/403 like set_password. "
            "Do not kill because OPTIONS is 401 or the schema claims jwtAuth"
        ),
        "specialist": "auth_logic",
        "priority": "high",
    },
    "auth_header_bypass": {
        "title": "Auth middleware skipped when Authorization header is absent",
        "assumption": (
            "JWT/OIDC middleware only runs when an Authorization header is present "
            "(ByPassAuthorization). No header reaches the controller"
        ),
        "test": (
            "compare_requests: no Authorization vs Authorization: Bearer aegis-invalid. "
            "PASS if no-header is 200/400 (controller ran) AND invalid-bearer is 401. "
            "Do not dump. 400 missing-params is still a bypass."
        ),
        "pass_criteria": "Missing header is not 401 while invalid Bearer is 401",
        "kill_criteria": "Missing header is 401/403 like invalid Bearer",
        "specialist": "api_authz",
        "priority": "high",
    },
    "socketio_idor": {
        "title": "Unauth Socket.IO get_stream IDOR (url_key)",
        "assumption": "Anonymous Socket.IO get_stream returns a stream namespace for arbitrary siteId",
        "test": (
            "Engine.IO polling then 42[\"get_stream\", fabricated siteId]. PASS on url_key. "
            "Do not fetch video. Do not send null crash loops."
        ),
        "pass_criteria": "Anonymous get_stream returns url_key for a fabricated siteId",
        "kill_criteria": "Auth required; no url_key. Do not kill because video was not downloaded",
        "specialist": "api_authz",
        "priority": "high",
    },
    "ml_pipeline_rbac": {
        "title": "Self-registered user can train/delete ML models",
        "assumption": "JWT authenticates but train/celery-task/delete have no role checks",
        "test": (
            "Throwaway self-reg if open. Probe POST /api/v1/train/ and DELETE "
            "/api/v1/celery-task/. Do not delete production models."
        ),
        "pass_criteria": "Low-priv/self-reg session can train, delete, or queue ML jobs",
        "kill_criteria": "403 for non-admin. Do not kill solely because signup is closed",
        "specialist": "api_authz",
        "priority": "high",
    },
    "coverage": {
        "title": "Coverage scan for known vulns/misconfig",
        "assumption": "Known CVE/misconfig templates may hit remaining inventory after logic hunts",
        "test": "execute_nuclei without severity filter on primary live URLs; authenticated -var if creds exist",
        "pass_criteria": "Template match with corroborating response evidence",
        "kill_criteria": "No actionable template hits after scoped coverage",
        "specialist": "coverage",
        "priority": "medium",
    },
    "admin_surface": {
        "title": "Admin / management surface exposure",
        "assumption": "Admin paths are reachable without sufficient auth or leak privileged functions",
        "test": "Forced-browse admin paths anonymous vs auth; check default creds; map privileged APIs",
        "pass_criteria": "Unauth/admin function access or default-cred admin session",
        "kill_criteria": "Admin consistently gated; no privileged leak",
        "specialist": "auth_logic",
        "priority": "medium",
    },
    "realtime": {
        "title": "WebSocket / SSE channel abuse",
        "assumption": "Realtime channels lack auth on upgrade or accept injected messages",
        "test": "Connect without/with weak auth; attempt cross-user subscription and message injection",
        "pass_criteria": "Unauth channel data or cross-user message impact",
        "kill_criteria": "Upgrade requires auth; messages scoped to identity",
        "specialist": "api_authz",
        "priority": "medium",
    },
    "baseline_web": {
        "title": "Baseline web vulnerability checks",
        "assumption": "Browsable UI may have common web flaws despite thin signals",
        "test": "Baseline XSS/open-redirect/header checks on browsed pages + light nuclei",
        "pass_criteria": "Concrete finding with response evidence",
        "kill_criteria": "No actionable issues after baseline probes",
        "specialist": "injection",
        "priority": "medium",
    },
    "azure_function": {
        "title": "Anonymous Azure Function HTTP trigger env dump",
        "assumption": (
            "A Function App (*.azurewebsites.net) ships an HTTP trigger such as Tester "
            "with authLevel:anonymous and no IP restrictions, returning process env as JSON"
        ),
        "test": (
            "Unauthenticated GET /api/Tester (then /api/test, /api/debug, /api/env, "
            "/api/HttpTrigger1) on the Function App hostname. PASS if the body is the "
            "runtime environment (AzureWebJobsStorage, Cosmos keys, WEBSITE_AUTH_*). "
            "Do not upload packages or inject code."
        ),
        "pass_criteria": (
            "Unauth HTTP 200 JSON includes Function App process settings / secret names"
        ),
        "kill_criteria": (
            "401/403 function key required; 404; body is not process environment"
        ),
        "specialist": "coverage",
        "priority": "critical",
    },
}


_CHAIN_CARDS: Dict[str, List[Dict[str, str]]] = {
    "default_login": [
        {
            "title": "Grafana Server Admin APIs: settings, datasources, service accounts",
            "assumption": (
                "Grafana Server Admin (often kube-prometheus-stack admin:prom-operator) unlocks "
                "GET /api/admin/settings, /api/datasources, and /api/serviceaccounts/search"
            ),
            "test": (
                "With Grafana admin session (cookie or Basic), read-only GETs only: "
                "1) GET /api/admin/settings — instance identity, grafana.ini, DB config, pod name; "
                "2) GET /api/datasources — existing Prometheus/Loki/etc URLs (in-cluster DNS); "
                "3) GET /api/serviceaccounts/search — names, roles, token counts. "
                "Do not create/rotate tokens or mutate settings."
            ),
            "pass_criteria": (
                "Settings JSON discloses instance/DB/config, OR datasources list internal "
                "cluster URLs, OR service accounts with roles/token counts are enumerated"
            ),
            "kill_criteria": (
                "Admin APIs 401/403; Viewer session cannot reach Server Admin endpoints"
            ),
            "specialist": "coverage",
            "priority": "critical",
            "id_suffix": "grafana-admin-apis",
        },
        {
            "title": "Grafana existing Prometheus datasource proxy → cluster service enum",
            "assumption": (
                "kube-prometheus-stack Grafana already has a Prometheus datasource at an "
                "in-cluster URL (e.g. http://kube-prometheus-stack-prometheus.monitoring:9090/). "
                "Server Admin can relay PromQL via /api/datasources/proxy without creating a new datasource"
            ),
            "test": (
                "1) GET /api/datasources — find type=prometheus with an internal URL; "
                "2) GET /api/datasources/proxy/<id>/api/v1/targets "
                "(or /api/v1/label/job/values, /api/v1/query?query=up) through the EXISTING datasource; "
                "3) Record cluster DNS names, exporter ports, kubelet/API-server scrape targets. "
                "Read-only Prometheus queries only. Creating a new datasource is a separate SSRF card."
            ),
            "pass_criteria": (
                "Proxy response lists internal scrape targets / jobs (exporters, kubelets, "
                "in-cluster service DNS) proving cluster topology via the existing datasource"
            ),
            "kill_criteria": (
                "No prometheus datasource; proxy 403/whitelist; empty targets"
            ),
            "specialist": "coverage",
            "priority": "critical",
            "id_suffix": "grafana-prom-proxy-enum",
        },
        {
            "title": "CouchDB _config exposure: auth secret, admin salts, session timeout",
            "assumption": (
                "CouchDB _admin (often a product default like admin:admin or an app default) "
                "can GET /_node/_local/_config. That endpoint returns couch_httpd_auth.secret, "
                "couch_httpd_auth.timeout, and PBKDF2 salts for every [admins] user — the two "
                "inputs that sign AuthSession cookies. Password rotation does not hide them."
            ),
            "test": (
                "With the CouchDB _admin session (Basic or cookie), read-only GETs only: "
                "1) GET /_node/_local/_config/couch_httpd_auth/secret; "
                "2) GET /_node/_local/_config/couch_httpd_auth/timeout; "
                "3) GET /_node/_local/_config/admins (usernames + hashed salts). "
                "sanitize_evidence before notes. Do not PUT the secret or mutate config."
            ),
            "pass_criteria": (
                "Secret value returned AND at least one admin salt visible AND/OR timeout "
                "is far above a normal session (e.g. 31536000 = one year)"
            ),
            "kill_criteria": (
                "_config 401/403; secret/admins sections empty; config restricted to localhost"
            ),
            "specialist": "coverage",
            "priority": "critical",
            "id_suffix": "couchdb-config-secret",
        },
        {
            "title": "CouchDB AuthSession cookie forgery (secret + admin salt)",
            "assumption": (
                "CouchDB 2.x signs AuthSession as HMAC-SHA1(secret + admin_salt, "
                "username:hex_timestamp). Server-admin salts come from "
                "/_node/_local/_config/admins/<user> — NOT org.couchdb.user derived_key "
                "(that HMAC fails 401/400). Forgery impersonates any [admins] account "
                "without their password and survives password rotation until the secret is rotated."
            ),
            "test": (
                "After the _config card: pick TWO [admins] usernames. Build the documented "
                "AuthSession cookie (base64 username:hex_timestamp:hmac) using secret+that "
                "admin's salt. Prove with Cookie: AuthSession=… and NO Basic auth: "
                "1) GET /_session → userCtx.name=<admin> roles includes _admin; "
                "2) GET /_all_dbs → database list (record count, not full dump). "
                "Read-only. Do not PUT/DELETE docs, do not rotate the secret, do not crack "
                "PBKDF2. Failed _users derived_key attempts belong in not_demonstrated. "
                "Redact secret, salts, and AuthSession via sanitize_evidence."
            ),
            "pass_criteria": (
                "/_session returns ok with _admin for a user whose password was not used, "
                "AND /_all_dbs returns the database list under that forged cookie"
            ),
            "kill_criteria": (
                "Forged cookie 401; secret not readable; cookie auth disabled; "
                "only the original Basic session works"
            ),
            "specialist": "coverage",
            "priority": "critical",
            "id_suffix": "couchdb-authsession-forgery",
        },
        {
            "title": "CouchDB sibling trivial admins (username=username, e.g. karen:karen)",
            "assumption": (
                "Besides the first hit (kevin:kevin / admin:admin), [_config/admins] often "
                "contains leftover test admins with username-as-password and 10 PBKDF2 iterations. "
                "Rotating one account does not kill the others."
            ),
            "test": (
                "From GET /_node/_local/_config/admins, take at most 8 short names "
                "(admin, kevin, karen, test, plus any name whose hash ends with ,10). "
                "Try username:username via GET /_session only — no invented passwords, no 169-account spray. "
                "On hit: stash add_engagement_credential and prove GET /_session _admin (do not re-dump all dbs). "
                "Each distinct trivial admin is its own finding; rotation of one is not remediation of others."
            ),
            "pass_criteria": (
                "A second [admins] account authenticates with username=username and returns _admin"
            ),
            "kill_criteria": (
                "Tiny sibling list rejected; no 10-iteration hashes; lockout"
            ),
            "specialist": "credential_assault",
            "priority": "critical",
            "id_suffix": "couchdb-sibling-trivial-admins",
        },
        {
            "title": "Authenticated CVE / post-auth misconfig with recovered creds",
            "assumption": "Default/weak login unlocks authenticated nuclei templates and admin APIs",
            "test": "Re-run nuclei with -var username/password (or authenticated curl) for product CVEs; probe admin APIs",
            "pass_criteria": "Authenticated template hit or privileged API impact with those creds",
            "kill_criteria": "No authenticated impact beyond the login itself",
            "specialist": "coverage",
            "priority": "critical",
            "id_suffix": "auth-cve",
        },
        {
            "title": "Grafana SQL Expressions RCE/LFI (CVE-2024-9264) — Viewer+ /api/ds/query",
            "assumption": (
                "Grafana 11.0.x expression engine accepts queries with type=sql from any "
                "authenticated user (including Viewer / service accounts) and forks "
                "/usr/local/bin/duckdb. The sqlExpressions feature toggle in /metrics may "
                "be 0 (UI hidden) while the backend still processes SQL expressions. "
                "A missing DuckDB binary is NOT a patch — it only blocks the last step"
            ),
            "test": (
                "With any Grafana session (Viewer is enough; cookie, Basic, or SA token): "
                "POST /api/ds/query with an expression query type=sql (nuclei CVE-2024-9264 "
                "with -var creds AND a direct curl — nuclei may miss the missing-binary case). "
                "Also GET /metrics and record grafana_feature_toggles_sqlExpressions (or similar) "
                "— value 0 does not kill. Do not install DuckDB. If the binary is present, "
                "a file-read canary is enough; do not run shell/system-command extensions."
            ),
            "pass_criteria": (
                "SQL expression is accepted and the server attempts DuckDB: either file "
                "contents in the query response, OR an error proving fork/exec of "
                "/usr/local/bin/duckdb (e.g. no such file or directory). Both are SUBMIT"
            ),
            "kill_criteria": (
                "Patched (>=11.2.2) or authz rejects SQL expressions without forking DuckDB "
                "(401/403/feature-disabled at the engine). Unauthenticated-only. "
                "Do NOT kill solely because DuckDB is absent or the UI toggle is off"
            ),
            "specialist": "coverage",
            "priority": "critical",
            "id_suffix": "grafana-9264",
        },
        {
            "title": "Grafana admin → datasource-proxy SSRF into internal AKS/K8s",
            "assumption": (
                "Server Admin / datasources:create can point a datasource at internal URLs "
                "(kubernetes.default.svc, metadata, cluster DNS) and read full responses via "
                "/api/datasources/proxy when data_source_proxy_whitelist is empty"
            ),
            "test": (
                "Only if no existing Prometheus datasource yielded cluster topology: "
                "1) POST /api/datasources with type=prometheus|testdata URL="
                "https://kubernetes.default.svc or http://169.254.169.254/ (or in-cluster DNS); "
                "2) GET /api/datasources/proxy/uid/<uid>/version or /api/v1/namespaces; "
                "3) Also try CallResource /api/datasources/uid/<uid>/resources/* if proxy whitelist blocks; "
                "4) Prefer read-only canaries (API discovery, /version) — no destructive writes"
            ),
            "pass_criteria": (
                "Proxy/resource response body shows internal K8s API, cloud metadata, "
                "cluster service content, or secrets metadata proving SSRF reachability"
            ),
            "kill_criteria": (
                "Datasource create denied; proxy whitelist blocks private ranges; "
                "network policy isolates Grafana from cluster API/metadata"
            ),
            "specialist": "coverage",
            "priority": "critical",
            "id_suffix": "grafana-ssrf-aks",
        },
        {
            "title": "Admin URL-fetch / webhook SSRF after default login",
            "assumption": "Admin UI features (webhooks, alert notifications, renderers, imports) fetch attacker-chosen URLs server-side",
            "test": (
                "From admin session, probe URL-accepting admin features with interactsh + "
                "safe internal canaries (metadata IP, localhost version endpoints). "
                "compare_requests only where a baseline non-internal URL exists."
            ),
            "pass_criteria": "OOB hit plus internal HTTP body, or confirmed metadata/internal content",
            "kill_criteria": "URL fetch blocked / egress filtered; OOB-only without internal body",
            "specialist": "injection",
            "priority": "high",
            "id_suffix": "admin-ssrf",
        },
    ],
    "host_header": [
        {
            "title": "Host-header tenant isolation bypass",
            "assumption": "Host influences tenant selection under an existing session",
            "test": "compare_requests: same cookies, Host/X-Forwarded-Host = peer tenant",
            "pass_criteria": "Cross-tenant data under attacker session",
            "kill_criteria": "No tenant swap; vhost reject",
            "specialist": "host_tenant",
            "priority": "critical",
            "id_suffix": "host-tenant",
        },
        {
            "title": "Password-reset poisoning via Host",
            "assumption": "Reset emails/absolute URLs use attacker Host",
            "test": "Trigger reset with Host/X-Forwarded-Host=attacker; inspect link",
            "pass_criteria": "Reset/email absolute URL uses injected host",
            "kill_criteria": "Link uses canonical host only",
            "specialist": "auth_logic",
            "priority": "high",
            "id_suffix": "reset-poison",
        },
    ],
    "idor": [
        {
            "title": "Write/export IDOR follow-on",
            "assumption": "Read IDOR implies write/export/share variants on same object family",
            "test": "compare_requests on PUT/PATCH/export/share for the same object IDs (read-only first)",
            "pass_criteria": "Cross-user write/export success or sensitive export content",
            "kill_criteria": "Mutations blocked; only own-object access",
            "specialist": "api_authz",
            "priority": "high",
            "id_suffix": "idor-write",
        },
        {
            "title": "Mass-assign id/user/owner on the same object family (schema first)",
            "assumption": (
                "Read IDOR or a shared list often pairs with DRF request serializers that "
                "leave id, created, and user writable (no readOnly)"
            ),
            "test": (
                "If OpenAPI exists (GET /api/schema/ or swagger.json): count *Request "
                "components where id/created/updated/user/owner/schedule/periodic_task "
                "are writable (not readOnly). Note list ops that say 'all users' / "
                "'shared across'. One bounded canary write only if the DB is up — do not "
                "enable ICS schedules or dump OT/ICS hierarchy."
            ),
            "pass_criteria": (
                "Schema shows writable privileged fields without readOnly, OR a list "
                "endpoint documents cross-user sharing. Live write optional"
            ),
            "kill_criteria": (
                "readOnly/extra_kwargs on those fields; object-level 403; caller-only lists. "
                "Do NOT kill because the database is unavailable"
            ),
            "specialist": "api_authz",
            "priority": "critical",
            "id_suffix": "idor-mass-assign",
        },
    ],
    "ssrf": [
        {
            "title": "SSRF → cloud metadata / internal pivot",
            "assumption": "Confirmed SSRF can reach metadata or internal services",
            "test": "Safe metadata/internal canaries via the SSRF sink; no destructive pivots",
            "pass_criteria": "Internal HTTP body or metadata keys returned",
            "kill_criteria": "DNS/OOB only with no internal body",
            "specialist": "injection",
            "priority": "critical",
            "id_suffix": "ssrf-meta",
        },
    ],
    "elasticsearch_unauth": [
        {
            "title": "Elasticsearch cluster/node metadata (OS, hostname, kernel)",
            "assumption": (
                "Unauthenticated GET / already returned cluster JSON; /_cluster/health and "
                "/_nodes/os,jvm disclose hostname, OS, kernel, and JVM without credentials"
            ),
            "test": (
                "Unauthenticated GET /_cluster/health and GET /_nodes/os,jvm?pretty "
                "(or /_nodes/_all/os,jvm). Record cluster_name, node name, OS name/pretty, "
                "kernel, JVM. Read-only. Do not change cluster settings."
            ),
            "pass_criteria": (
                "Node JSON discloses hostname and/or OS/kernel (or equivalent cluster health "
                "with unauthenticated 200)"
            ),
            "kill_criteria": "401/403 on /_nodes and /_cluster/health; security now enabled",
            "specialist": "coverage",
            "priority": "critical",
            "id_suffix": "es-nodes-os",
        },
        {
            "title": "Elasticsearch index enum + limited sample read",
            "assumption": (
                "xpack.security disabled allows listing all indices and reading documents"
            ),
            "test": (
                "GET /_cat/indices?v (names, docs, store size). Sample-read only: "
                "GET /<user-index>/_search?size=1 (or _doc/_search) on 1–3 non-system "
                "indices. Prefer notable names (read_me, ransomware notes, prompt/chat "
                "indices). Do NOT dump all documents or scroll the cluster."
            ),
            "pass_criteria": (
                "Index list returned unauthenticated AND at least one user-created index "
                "sample (or empty user indices with system indices listed)"
            ),
            "kill_criteria": "401/403 on _cat/indices; no indices; not Elasticsearch",
            "specialist": "coverage",
            "priority": "critical",
            "id_suffix": "es-indices-read",
        },
        {
            "title": "Elasticsearch write proof: create then delete test index",
            "assumption": (
                "Unauthenticated clients can create and delete indices when security is off"
            ),
            "test": (
                "PUT /aegis_test_index (empty index, no documents). Confirm "
                '{"acknowledged":true}. Immediately DELETE /aegis_test_index to clean up. '
                "Do not write into existing customer indices. Do not run Painless/scripting."
            ),
            "pass_criteria": (
                "Create acknowledged, then delete acknowledged (or 200) for aegis_test_index"
            ),
            "kill_criteria": (
                "Create 401/403/405; cluster is read-only; security enabled"
            ),
            "specialist": "coverage",
            "priority": "critical",
            "id_suffix": "es-write-test-index",
        },
    ],
    "js_secrets": [
        {
            "title": "Hostname-keyed client_id/client_secret map in client JS",
            "assumption": (
                "Next.js/admin UI chunks (_next/static/chunks) embed a hostname-keyed "
                "config object mapping prod/dev/qa hosts to OAuth client_id + client_secret"
            ),
            "test": (
                "scan_js_urls_for_secrets on first-party /_next/static/chunks/*.js (and other "
                "admin bundles). Extract every env pair and the API host each authenticates to. "
                "Note the header scheme from the bundle (often client_id/client_secret HTTP "
                "headers, not Authorization: Bearer). Stash via add_engagement_credential "
                "(secret_type=oauth_client). Redact values in notes."
            ),
            "pass_criteria": (
                "At least one non-publishable client_id/client_secret pair tied to an API host "
                "is recovered from a public JS bundle"
            ),
            "kill_criteria": (
                "Only public/publishable keys; no client_secret; map is empty stubs"
            ),
            "specialist": "js_secrets",
            "priority": "critical",
            "id_suffix": "js-hostname-cred-map",
        },
        {
            "title": "Live API impact with JS-leaked client credentials",
            "assumption": (
                "Extracted client_id/client_secret authenticate to the IAM/API gateway and "
                "return non-public records (locations, accounts, partners)"
            ),
            "test": (
                "Replay the header scheme from the bundle against the in-scope API host "
                "(prefer sandbox/dev first). ONE read-only request. If a search/queryText "
                "parameter exists, one targeted query is enough. Record status, result count, "
                "and 1-2 redacted sample field names (not full dumps). Do not paginate or "
                "bulk-export. Call prod only if that API host is in engagement scope."
            ),
            "pass_criteria": (
                "Authenticated response returns non-public records (count + redacted sample "
                "fields proving PII/business data)"
            ),
            "kill_criteria": (
                "401/403; publishable-key sandbox only; no record payload"
            ),
            "specialist": "js_secrets",
            "priority": "critical",
            "id_suffix": "js-cred-live-api",
        },
        {
            "title": "Cross-environment credential leak from sandbox/admin UI",
            "assumption": (
                "A sandbox or admin UI bundle ships production AND lower-env credential "
                "triples — rotating only the sandbox pair is insufficient"
            ),
            "test": (
                "From the hostname-keyed map, list every env (prod/dev/qa) and its API host. "
                "Remediation must rotate ALL pairs. Optional: one live check of an in-scope "
                "non-prod host. Do not call out-of-scope production APIs."
            ),
            "pass_criteria": (
                "Map contains more than one environment's secrets, or a sandbox UI contains "
                "a production client_secret"
            ),
            "kill_criteria": "Single-env publishable key only",
            "specialist": "js_secrets",
            "priority": "high",
            "id_suffix": "js-cred-cross-env",
        },
        {
            "title": "EmailJS public keys in client JS (service_id / user_id / template_id)",
            "assumption": (
                "Production bundles embed EmailJS emailjs_userid, emailjs_serviceid, and "
                "emailjs_templateid. Those keys let any page send mail through the app's "
                "authorized EmailJS integration"
            ),
            "test": (
                "scan_js_urls_for_secrets on first-party bundles (main.*.js, /_next/static/chunks). "
                "Extract service_id (service_*), user_id, and every template_id. Stash via "
                "add_engagement_credential(secret_type=emailjs). Note recipient template_params "
                "names from the bundle (to_mail, managerEmail, to_email, user_email, email). "
                "Redact keys in notes."
            ),
            "pass_criteria": (
                "Public bundle contains EmailJS user_id + service_id + at least one template_id"
            ),
            "kill_criteria": "No EmailJS keys; placeholders only; keys revoked",
            "specialist": "js_secrets",
            "priority": "critical",
            "id_suffix": "emailjs-keys",
        },
        {
            "title": "EmailJS send API — browser canary to engagement-controlled inbox",
            "assumption": (
                "EmailJS often blocks non-browser origins but still accepts POST "
                "https://api.emailjs.com/api/v1.0/email/send from a visitor's browser. "
                "template_params control the recipient, so any site embedding the keys can send"
            ),
            "test": (
                "ONE canary per template, max two templates. Recipient MUST be "
                "aegis@<payload_domain> from execute_interactsh register — never "
                "Canarytokens, never customer employees, never arbitrary third parties. "
                "Prefer execute_browser fetch() from the target origin (curl/server POST is often "
                "blocked by EmailJS origin checks; a 403 from curl is NOT a kill). "
                "Body: service_id, template_id, user_id, template_params with the recipient field "
                "from the bundle. PASS on HTTP 200 body OK or execute_interactsh poll SMTP/HTTP. Then stop."
            ),
            "pass_criteria": (
                "Browser-context send returns 200/OK and/or execute_interactsh poll "
                "shows SMTP/HTTP interaction from the EmailJS send"
            ),
            "kill_criteria": (
                "Keys rejected from browser and server; domain allowlist blocks foreign origins "
                "AND the first-party origin requires an authenticated session the agent does not have"
            ),
            "specialist": "js_secrets",
            "priority": "critical",
            "id_suffix": "emailjs-send-canary",
        },
        {
            "title": "CWE-321 client HMAC-SHA256 signing key in public JS",
            "assumption": (
                "The public bundle reconstructs an HMAC key from empty-string object "
                "property names (Object.keys(obj).join('') or for-in concat) and uses it "
                "to mint HS256 JWTs for every API request"
            ),
            "test": (
                "scan_js_urls_for_secrets on main*.js / main-es2015*.js (16MB cap; do not "
                "skip large Angular bundles). Read client_signing_findings. Reconstruction "
                "plus adjacent HmacSHA256 / alg:HS256 is PASS. Stash secret_type=hmac_key. "
                "Live token accept is optional extra proof; API timeout is NOT a kill. "
                "Do not require minting a token or connecting to MQTT to file this card."
            ),
            "pass_criteria": (
                "Public unauthenticated bundle reconstructs a signing secret and signs "
                "with HS256/HmacSHA256 in the same file"
            ),
            "kill_criteria": (
                "No Object.keys/for-in reconstruction; HMAC uses a server-issued session "
                "secret; placeholders only"
            ),
            "specialist": "js_secrets",
            "priority": "critical",
            "id_suffix": "hmac-client-signing",
        },
        {
            "title": "MQTT / RFID ICS credentials in the same client bundle",
            "assumption": (
                "The same webpack chunk that signs APIs also embeds MQTT broker "
                "username/password (Object.keys join) and RFID plaintext creds for "
                "ICS/SCADA topics (hmi/live_tags, digital twin)"
            ),
            "test": (
                "From client_signing_findings, record mqtt username/password reconstruction "
                "and rfidUserName/rfidPassword. Stash mqtt and rfid credentials. Remediation "
                "must rotate broker + badge accounts and keep them off the client. "
                "Do not brute-force or persist an ICS broker session."
            ),
            "pass_criteria": (
                "MQTT and/or RFID credentials recovered from a public JS bundle that "
                "references a broker or RFID fields"
            ),
            "kill_criteria": "Placeholders only; no MQTT/RFID usage in the bundle",
            "specialist": "js_secrets",
            "priority": "critical",
            "id_suffix": "mqtt-ics-creds",
        },
        {
            "title": "CWE-321 client encryption_key in public JS env object",
            "assumption": (
                "The same production env object that embeds EmailJS ids also ships a "
                "symmetric encryption_key / encryptionKey used to encrypt client payloads. "
                "Anyone who fetches the bundle can decrypt or forge those payloads."
            ),
            "test": (
                "From scan_js_urls_for_secrets client_signing_findings, record "
                "kind=client_encryption_key. create_finding Critical, separate from EmailJS. "
                "Stash secret_type=encryption_key (redact the value). Rotate the key; move "
                "crypto server-side. Do not use the key to decrypt customer data in the report."
            ),
            "pass_criteria": (
                "Public bundle contains a non-placeholder encryption_key/encryptionKey literal"
            ),
            "kill_criteria": "Placeholder only; key absent; crypto uses a server-issued secret",
            "specialist": "js_secrets",
            "priority": "critical",
            "id_suffix": "encrypt-client-key",
        },
    ],
    "azure_function_env_dump": [
        {
            "title": "Classify Function App runtime secret classes",
            "assumption": (
                "An anonymous HTTP trigger (often named Tester) returned the process "
                "environment loaded at startup: Cosmos master keys, Storage account keys, "
                "MACHINEKEY_DecryptionKey, EasyAuth WEBSITE_AUTH_* keys, AAD client secrets, "
                "App Insights instrumentation key, Key Vault URIs, managed-identity endpoints"
            ),
            "test": (
                "From the unauth JSON, inventory secret *classes* and resource names only. "
                "add_engagement_credential with secret_type labels and [REDACTED] values "
                "(never persist raw keys). sanitize_evidence before create_finding. "
                "Write Vulnerability Description + Impact (which classes, which data stores) "
                "+ Assets Affected + Recommendation: remove Tester or set authLevel=function; "
                "ipSecurityRestrictions or Private Endpoints; rotate every disclosed credential; "
                "decommission unused Function Apps / web apps / Cosmos / storage / Key Vaults / "
                "AAD apps. Rotate AAD client secrets last, after Tester is unreachable."
            ),
            "pass_criteria": (
                "Env JSON classified into concrete secret types (Cosmos / Storage / "
                "MACHINEKEY / EasyAuth / AAD / App Insights / Key Vault) with redacted evidence"
            ),
            "kill_criteria": "Body is not process env; only public config; function key required",
            "specialist": "coverage",
            "priority": "critical",
            "id_suffix": "azfn-classify-secrets",
        },
        {
            "title": "Cosmos master key → internet-accessible database (read-only)",
            "assumption": (
                "The leaked Cosmos master key grants read/write/delete on an internet-reachable "
                "account that may back employee identity and project records"
            ),
            "test": (
                "If ACCOUNT_ENDPOINT (or equivalent) is in the env JSON and in scope: ONE "
                "read-only list of databases/containers. Record account + container names only. "
                "No item dumps, no writes, no deletes. Redact the key in evidence."
            ),
            "pass_criteria": (
                "Read-only list proves the master key works against a reachable Cosmos account"
            ),
            "kill_criteria": (
                "Key rejected; account not internet-reachable; endpoint out of scope"
            ),
            "specialist": "coverage",
            "priority": "critical",
            "id_suffix": "azfn-cosmos-readonly",
        },
        {
            "title": "Storage account key inventory (list only)",
            "assumption": (
                "AzureWebJobsStorage holds an account key that can list (and, unused here, "
                "overwrite) the Function App content share"
            ),
            "test": (
                "List containers / share names only with the storage key. Do not upload blobs, "
                "do not replace function packages, do not write host.json or wwwroot. "
                "Presence of AccountKey + MACHINEKEY_DecryptionKey is the ACE prerequisite — "
                "record it; do not exercise it."
            ),
            "pass_criteria": (
                "List operation succeeds, proving the storage key is live (container names only)"
            ),
            "kill_criteria": "Key rejected; storage not reachable; no AccountKey in env",
            "specialist": "coverage",
            "priority": "critical",
            "id_suffix": "azfn-storage-list",
        },
        {
            "title": "Peer Function App via -dev- / production naming",
            "assumption": (
                "Tenants often pair ra-*-fa (production) with ra-*-dev-fa (development). "
                "The same anonymous Tester trigger is commonly deployed to both"
            ),
            "test": (
                "From the hostname, derive the peer (insert or strip a -dev- token) and "
                "unauthenticated GET the same HTTP trigger. Same authLevel probe only."
            ),
            "pass_criteria": "Peer Function App returns the same class of runtime env JSON",
            "kill_criteria": "Peer NXDOMAIN / 401/403 / no anonymous trigger",
            "specialist": "coverage",
            "priority": "high",
            "id_suffix": "azfn-peer-naming",
        },
        {
            "title": "Managed identity / Key Vault blast radius (prerequisites only)",
            "assumption": (
                "Storage account key + DataProtection/MACHINEKEY can lead to code execution "
                "as the Function App system-assigned managed identity, which may have secret "
                "get/set on the app Key Vault holding the live AAD client secret — and that "
                "principal may hold Graph directory enum plus ARM Owner on a resource group. "
                "Production ACE requires injecting code and waiting for a restart."
            ),
            "test": (
                "Record MSI / identity endpoint, Key Vault URI, and (if cloud ROE allows) "
                "read-only ARM/Graph checks of MI role assignments and Key Vault access policy. "
                "Do NOT upload function packages, do NOT write wwwroot, do NOT inject code, "
                "do NOT wait for a restart. Mark arbitrary code execution as not_demonstrated."
            ),
            "pass_criteria": (
                "Prerequisites documented (storage key + MACHINEKEY + Key Vault + MI roles) "
                "without executing code on the Function App"
            ),
            "kill_criteria": "No MI, no Key Vault URI, or cloud ROE forbids control-plane reads",
            "specialist": "cloud_audit",
            "priority": "high",
            "id_suffix": "azfn-mi-keyvault-prereq",
        },
        {
            "title": "AAD client secret handling and rotation order",
            "assumption": (
                "Env may include an expired AAD client secret while Key Vault holds the live "
                "one. Redeeming a live secret can yield Graph directory tokens and ARM as the "
                "Owner-bound service principal"
            ),
            "test": (
                "Note client_id / secret presence and expiry if shown. Do not redeem the "
                "secret for Graph or ARM tokens unless cloud control-plane testing is in ROE. "
                "Remediation must rotate AAD secrets LAST — after Tester is removed — so new "
                "values cannot re-leak on the next process restart."
            ),
            "pass_criteria": (
                "AAD app/secret presence (and expiry) recorded; rotation-order called out"
            ),
            "kill_criteria": "No AAD client secret / app id in the env JSON",
            "specialist": "coverage",
            "priority": "high",
            "id_suffix": "azfn-aad-rotation-order",
        },
    ],
    "arangodb_default": [
        {
            "title": "ArangoDB root empty-password → database/collection sample",
            "assumption": "Internet-facing ArangoDB /_open/auth accepts root with empty password and returns a JWT",
            "test": (
                "POST /_open/auth {\"username\":\"root\",\"password\":\"\"}. On JWT: "
                "GET /_api/database (names only), then GET /_api/collection on _system plus "
                "ONE user DB with limit=1 document sample. Do not dump PII collections. "
                "Do not mutate. Redact JWTs."
            ),
            "pass_criteria": "JWT issued for root AND at least one non-system database or collection listed",
            "kill_criteria": "401/403; password required; /_open/auth disabled",
            "specialist": "coverage",
            "priority": "critical",
            "id_suffix": "arangodb-root-enum",
        },
    ],
    "mongodb_unauth": [
        {
            "title": "MongoDB anonymous listDatabases + ransomware/integrity check",
            "assumption": "Port 27017 accepts unauthenticated connections (often AKS LoadBalancer)",
            "test": (
                "execute_nuclei -id mongodb-unauth or equivalent listDatabases. Record db names only. "
                "If READ_ME_TO_RECOVER_YOUR_DATA (or similar) is present, note prior compromise. "
                "Do not dump collections. Do not drop databases."
            ),
            "pass_criteria": "Unauthenticated listDatabases succeeds (or ransomware-note db visible)",
            "kill_criteria": "auth required; port filtered",
            "specialist": "coverage",
            "priority": "critical",
            "id_suffix": "mongo-listdbs",
        },
    ],
    "emqx_default": [
        {
            "title": "EMQX dashboard default login → broker admin APIs",
            "assumption": "EMQX dashboard still uses admin:public (or admin:admin)",
            "test": (
                "Tiny list only: admin:public then admin:admin on /api/v5/login or dashboard. "
                "On success: GET listeners/users/authn (read-only). Do not upload plugins, "
                "do not change authn, do not publish MQTT."
            ),
            "pass_criteria": "Dashboard/API session with admin role; listeners or users enumerated",
            "kill_criteria": "Defaults rejected; MFA/SSO; not EMQX",
            "specialist": "credential_assault",
            "priority": "critical",
            "id_suffix": "emqx-admin-apis",
        },
    ],
    "cors_credentials": [
        {
            "title": "CORS ACAO reflection + Access-Control-Allow-Credentials: true",
            "assumption": (
                "The server echoes an arbitrary Origin in ACAO while returning "
                "Access-Control-Allow-Credentials: true, so browsers will attach cookies "
                "and expose the response body to attacker JavaScript"
            ),
            "test": (
                "compare_requests / curl: Origin=https://aegis-cors-canary-<rand>.example "
                "(a never-seen origin — not evil.com, not null unless testing null) vs no Origin. "
                "PASS only if ACAO equals that origin AND credentials=true. Do not ship an "
                "HTML exploit page. Header proof is SUBMIT even without a victim tab."
            ),
            "pass_criteria": (
                "ACAO reflects the canary origin AND Access-Control-Allow-Credentials is true"
            ),
            "kill_criteria": (
                "Allowlist does not echo the canary; ACAO is * without credentials. "
                "Do NOT kill solely because no authenticated victim browser was available"
            ),
            "specialist": "api_authz",
            "priority": "critical",
            "id_suffix": "cors-acao-creds",
        },
        {
            "title": "CORS preflight allows Authorization + mutating methods from any origin",
            "assumption": (
                "OPTIONS from the canary origin is approved with Access-Control-Allow-Methods "
                "including POST/PUT/DELETE and Access-Control-Allow-Headers including Authorization"
            ),
            "test": (
                "OPTIONS on the same paths with Access-Control-Request-Method: POST and "
                "Access-Control-Request-Headers: Authorization. Record Allow-Methods and "
                "Allow-Headers. Do not send a real token from an attacker page."
            ),
            "pass_criteria": (
                "Preflight ACAO echoes the canary AND allows Authorization and/or POST/PUT/DELETE"
            ),
            "kill_criteria": (
                "Preflight 403/missing ACAO; Authorization not allowed. "
                "Do NOT kill because GET-only was allowed if credentialed GET still reflects"
            ),
            "specialist": "api_authz",
            "priority": "high",
            "id_suffix": "cors-preflight-authz",
        },
        {
            "title": "Keycloak IdP CORS — token, userinfo, JWKS, admin REST",
            "assumption": (
                "Keycloak client webOrigins=* (or a proxy override) applies to "
                "/auth/realms/<realm>/protocol/openid-connect/token, /userinfo, /certs, "
                "and /auth/admin/realms/<realm>/* — including users and clients"
            ),
            "test": (
                "Repeat the canary Origin GET/OPTIONS on token, userinfo, JWKS, and "
                "GET /auth/admin/realms/<realm>/users. Header proof on those paths is SUBMIT. "
                "Do not dump the user directory or client secrets. If an engagement admin "
                "session exists, ONE GET users?max=1 (count + 1 redacted username) then stop. "
                "Remediation: webOrigins explicit or '+' (redirect URIs), never '*'; audit "
                "reverse-proxy CORS that overrides Keycloak."
            ),
            "pass_criteria": (
                "Canary Origin + credentials=true on token and/or userinfo and/or admin API"
            ),
            "kill_criteria": (
                "webOrigins allowlist/'+' ; canary not echoed on IdP paths; ACAO=* without "
                "credentials. Do NOT kill because JWKS is public or no victim tab was open"
            ),
            "specialist": "api_authz",
            "priority": "critical",
            "id_suffix": "keycloak-cors-idp",
        },
        {
            "title": "Keycloak admin-cli public client + password grant (no client_secret)",
            "assumption": (
                "admin-cli is public with Direct Access Grants. POST grant_type=password "
                "without a client_secret yields invalid_grant, not invalid_client"
            ),
            "test": (
                "POST /auth/realms/master/protocol/openid-connect/token and one other realm "
                "with grant_type=password, client_id=admin-cli, username=aegis_lockout_probe, "
                "a fake password, NO client_secret. Repeat on discovered realms. "
                "Do not hydra. queue_finding_followups(vuln_type='keycloak_password_grant')."
            ),
            "pass_criteria": (
                "invalid_grant (or access_token) without presenting a client_secret — "
                "not invalid_client / unsupported_grant_type"
            ),
            "kill_criteria": (
                "invalid_client / unauthorized_client; unsupported_grant_type. "
                "Do NOT kill because the password was wrong"
            ),
            "specialist": "credential_assault",
            "priority": "critical",
            "id_suffix": "keycloak-admin-cli-public",
        },
        {
            "title": "Socket.IO unauth get_stream after CORS (url_key only)",
            "assumption": "After ACAO+credentials, get_stream accepts empty userType / arbitrary siteId",
            "test": (
                "Unauth get_stream; record url_key presence. Do not pull video frames; "
                "no null-crash loops."
            ),
            "pass_criteria": "Unauth stream url_key or equivalent handshake secret",
            "kill_criteria": "get_stream requires auth; no url_key",
            "specialist": "api_authz",
            "priority": "high",
            "id_suffix": "socketio-get-stream",
        },
    ],
    "keycloak_password_grant": [
        {
            "title": "admin-cli public + Resource Owner Password Credentials (no client_secret)",
            "assumption": (
                "Keycloak admin-cli in master and application realms is a public client with "
                "Direct Access Grants. Any network client can POST username/password to "
                "/auth/realms/{realm}/protocol/openid-connect/token without a client_secret. "
                "Master tokens are full realm-admin"
            ),
            "test": (
                "POST token on master and every discovered realm: grant_type=password, "
                "client_id=admin-cli, username=aegis_lockout_probe, password=not-a-real-secret, "
                "NO client_secret. invalid_grant proves the grant is enabled and public. "
                "Do not send a client_secret. Do not hydra."
            ),
            "pass_criteria": (
                "invalid_grant or access_token without a client_secret on master and/or "
                "another realm"
            ),
            "kill_criteria": (
                "invalid_client / unauthorized_client (confidential); unsupported_grant_type. "
                "Do NOT kill solely because no valid password was guessed"
            ),
            "specialist": "credential_assault",
            "priority": "critical",
            "id_suffix": "keycloak-admin-cli-public",
        },
        {
            "title": "Token endpoint has no lockout / 429 / CAPTCHA (bounded probe)",
            "assumption": (
                "Brute Force Detection is off. Sequential password-grant failures are all "
                "processed at full speed with invalid_grant and no 429"
            ),
            "test": (
                "At most 8 POSTs with unique fake passwords for the same probe user on master "
                "(then one other realm if the first is open). Record status, error, and whether "
                "latency grows. Stop at 8. No hydra, no rockyou, no employee username list. "
                "CORS-enabled stuffing is a separate finding."
            ),
            "pass_criteria": (
                "All <=8 attempts return invalid_grant (or equivalent) with no 429, no lockout "
                "message, and no meaningful slowdown"
            ),
            "kill_criteria": (
                "429; account locked; wait increment / max failures; CAPTCHA. "
                "Do NOT kill because a real admin password was not found"
            ),
            "specialist": "credential_assault",
            "priority": "critical",
            "id_suffix": "keycloak-token-no-lockout",
        },
        {
            "title": "Tiny admin-cli defaults on master (stop on hit)",
            "assumption": (
                "If password grant is public, product defaults (admin:admin / admin:keycloak) "
                "may still work on master"
            ),
            "test": (
                "Tiny list only on master then one other realm: admin:admin, admin:password, "
                "admin:keycloak. hydra -f / stop on first token. On hit: stash and ONE "
                "GET /auth/admin/realms (count) or users?max=1 — do not dump users or clients. "
                "No rockyou."
            ),
            "pass_criteria": "access_token issued for a tiny-list pair",
            "kill_criteria": "Tiny list rejected; do not continue spraying",
            "specialist": "credential_assault",
            "priority": "high",
            "id_suffix": "keycloak-admin-cli-defaults",
        },
    ],
    "client_role_param": [
        {
            "title": "Client-supplied userType/admin role bypasses tenant scoping",
            "assumption": "publicPortal (or similar) trusts body/query userType, userId, userName without a session",
            "test": (
                "compare_requests: baseline userType empty/User vs mutant userType=Admin "
                "(and SuperRegulator if seen in JS). Decode base64 bodies if the client does. "
                "PASS if Admin returns a larger/cross-tenant dataset. Sample counts + 1–2 redacted "
                "fields; do not export the full inventory."
            ),
            "pass_criteria": "Admin/userType mutant returns other-tenant or privileged fields vs baseline",
            "kill_criteria": "401/403; same body; server ignores userType",
            "specialist": "api_authz",
            "priority": "critical",
            "id_suffix": "usertype-admin",
        },
    ],
    "vendorjson_unauth": [
        {
            "title": "Unauth vendorJson multi-tenant configuration disclosure",
            "assumption": "/glens/userManagement/api/v3.0/vendorJson (or sibling) returns the full tenant manifest",
            "test": (
                "Unauth GET vendorJson. If base64, decode. Record tenant count, 1–2 hostnames, "
                "and whether userId/role/internal IPs appear. Do not dump the full 88-tenant blob "
                "into the finding."
            ),
            "pass_criteria": "Unauth response lists multiple tenants or internal userId/role/IP fields",
            "kill_criteria": "401/403; current-tenant display config only",
            "specialist": "api_authz",
            "priority": "high",
            "id_suffix": "vendorjson-manifest",
        },
    ],
    "auth0_mgmt_token": [
        {
            "title": "Unauth Auth0 Management API token → one bounded directory read",
            "assumption": "A public /api/token (identitymigrate) returns a client-credentials JWT for Auth0 /api/v2/",
            "test": (
                "Unauth GET the token URL. Decode aud/scopes (read:clients, read:users). "
                "Prove with ONE Management API call: GET /api/v2/clients?per_page=1 or "
                "users?per_page=1. Record count if present. Redact the JWT. Do not enumerate "
                "the full user directory or rotate secrets."
            ),
            "pass_criteria": "Token issued unauthenticated AND Management API accepts it for a read",
            "kill_criteria": "401 on token URL; token rejected by /api/v2",
            "specialist": "coverage",
            "priority": "critical",
            "id_suffix": "auth0-mgmt-read",
        },
    ],
    "gitlab_unauth": [
        {
            "title": "Unauth GitLab /api/v4/projects + bounded secret sample",
            "assumption": "GitLab API lists public projects without auth and repos contain hardcoded secrets",
            "test": (
                "GET /api/v4/projects?per_page=5&simple=true (count via X-Total if present). "
                "Sample-search ONE repo file for password/secret patterns. Do not clone all "
                "projects. Rotate-recommendation only for verified live secrets."
            ),
            "pass_criteria": "Unauth project list (count) AND/OR a hardcoded secret in a sampled file",
            "kill_criteria": "401/403; no public projects",
            "specialist": "js_secrets",
            "priority": "critical",
            "id_suffix": "gitlab-projects-sample",
        },
    ],
    "docker_registry": [
        {
            "title": "Unauth Docker / ACR /v2/_catalog",
            "assumption": (
                "Registry /v2 and /v2/_catalog require no credentials. On *.azurecr.io "
                "anonymousPullEnabled issues an oauth2 bearer for registry:catalog:*"
            ),
            "test": (
                "Unauth GET /oauth2/token?service=<host>&scope=registry:catalog:* "
                "(generic registry: GET /v2/ then /v2/_catalog). Record repository count "
                "(not all tags). Do not push. Do not pull the whole catalog."
            ),
            "pass_criteria": "Anonymous token and/or 200 catalog with repository names",
            "kill_criteria": "Anonymous token denied; 401 WWW-Authenticate; registry closed",
            "specialist": "coverage",
            "priority": "high",
            "id_suffix": "docker-catalog",
        },
        {
            "title": "Bounded image secret scan (lockfile PAT / history / .git)",
            "assumption": (
                "Anonymously pullable first-party images bake git+https PATs into "
                "package-lock.json, ghs_* into .git/config extraheaders, and build-history "
                "Artifactory/NATS/Keycloak strings"
            ),
            "test": (
                "tags/list + config/history on at most 1–3 first-party repos "
                "(prefer *-graphql*, *-enrollment*, :latest). Classify ghp_ / git+https / "
                "ghs_ / Artifactory / NATS. Raise to Critical if a classic PAT or admin/"
                "workflow/packages scope is in the image. Do not pull every catalog entry. "
                "Do not authenticate recovered tokens against api.github.com. Do not list "
                "Actions secrets. Expired ghs_* is a leak pattern. Internal-only hosts: "
                "rotate, do not hunt from the internet."
            ),
            "pass_criteria": (
                "Named secret class recovered from config/history/lockfile of a sampled image"
            ),
            "kill_criteria": (
                "Sampled configs have no credential patterns. Do NOT kill the catalog card "
                "because extra tags were not pulled"
            ),
            "specialist": "coverage",
            "priority": "critical",
            "id_suffix": "acr-image-secrets",
        },
        {
            "title": "Rotate leaked tokens and rebuild without .git/lockfile secrets",
            "assumption": (
                "Old tags remain pullable until deleted; new builds will re-leak ghs_* if "
                ".git is copied into the image"
            ),
            "test": (
                "Remediation-only: disable anonymousPullEnabled; revoke ghp_*; rotate "
                "NPM/Actions/Artifactory/NATS; rebuild without resolved git URLs or .git; "
                "delete secret-bearing tags. Retest is deny-only (anonymous token refused). "
                "Do not re-pull production images to 'confirm' the leak."
            ),
            "pass_criteria": "Owner confirms anonymous pull denied and leaked tokens revoked",
            "kill_criteria": "Not a hunt card — skip if catalog already 401",
            "specialist": "cloud_audit",
            "priority": "high",
            "id_suffix": "acr-rotate-rebuild",
        },
    ],
    "django_debug": [
        {
            "title": "Django DEBUG traceback leaks Redis/env after default admin",
            "assumption": "DEBUG=True plus admin:admin; a 500 on an API dumps env including Redis keys",
            "test": (
                "After admin:admin (session or /api/token-pair/), trigger a safe 500 "
                "(e.g. POST /api/v1/optimize/ with empty body). Extract secret *classes* "
                "(Redis, DB, Azure) from the traceback. Then optional read-only Redis ping "
                "if a key+host leaked. Redact keys. Do not flush Redis."
            ),
            "pass_criteria": "Traceback discloses env secret classes, or Redis accepts the leaked key",
            "kill_criteria": "DEBUG off; no traceback; defaults rejected",
            "specialist": "coverage",
            "priority": "critical",
            "id_suffix": "django-debug-env",
        },
    ],
    "openai_proxy_unauth": [
        {
            "title": "Unauth Azure OpenAI /api/chat proxy (token theft / spend)",
            "assumption": "POST /api/chat proxies to Azure OpenAI with no auth and client-only system prompt",
            "test": (
                "One cheap canary POST (short max_tokens) proving a model completion without a session. "
                "Note if tools/functions are accepted. Do not run a token-burn loop. Do not jailbreak "
                "for harmful content. queue llm_red_team tool_enumeration if tools work."
            ),
            "pass_criteria": "Unauth completion from the backend model (or tools executed)",
            "kill_criteria": "401/403; WAF; not a model proxy",
            "specialist": "agent_tools",
            "priority": "high",
            "id_suffix": "openai-chat-proxy",
        },
    ],
    "wiki_open_reg": [
        {
            "title": "Open wiki self-registration → sandbox write / internal read",
            "assumption": (
                "MediaWiki/Confluence/DokuWiki (or similar) allows Special:CreateAccount / "
                "signup without approval and grants write or visibility into internal pages"
            ),
            "test": (
                "Create ONE throwaway account. Prove (a) edit a user/sandbox page, or "
                "(b) read one internal page that shows employee PII/process docs. "
                "Do not deface production articles. Do not scrape the wiki."
            ),
            "pass_criteria": "Self-registered session can write a sandbox page or read non-public content",
            "kill_criteria": "Registration disabled; captcha+approval; anonymous cannot write or see internals",
            "specialist": "auth_logic",
            "priority": "high",
            "id_suffix": "wiki-self-reg",
        },
    ],
    "binary_hardcoded_creds": [
        {
            "title": "Strings-extract production creds from public binary + one live proof",
            "assumption": (
                "A publicly downloadable installer, APK, firmware, or desktop client embeds "
                "production passwords, DB URIs, or API keys"
            ),
            "test": (
                "Download from the public URL. strings | grep -iE 'password|secret|conn|api[_-]?key' "
                "(bounded). If a credential looks live, prove ONE in-scope login. Redact secrets. "
                "Do not reverse-engineer for exploits; do not attach the binary to the finding."
            ),
            "pass_criteria": "Hardcoded production secret extracted (and optional live auth)",
            "kill_criteria": "No secrets; placeholders only; download not in scope",
            "specialist": "js_secrets",
            "priority": "critical",
            "id_suffix": "binary-strings-creds",
        },
    ],
    "client_side_auth": [
        {
            "title": "Client-side-only admin gate — forced browse + API without session",
            "assumption": (
                "Admin/eLogbook UI hides routes in JS (localStorage, userType, isAdmin) "
                "while backing APIs skip server auth"
            ),
            "test": (
                "Forced-browse /admin (or eLogbook) without cookies. compare_requests the "
                "backing API anonymous vs with a forged client role flag. PASS if privileged "
                "records return. Do not mutate production eLogbook rows."
            ),
            "pass_criteria": "Privileged page or API data without a server session",
            "kill_criteria": "401/403; empty bodies; server session required",
            "specialist": "auth_logic",
            "priority": "critical",
            "id_suffix": "clientauth-forced-browse",
        },
    ],
    "mass_assignment": [
        {
            "title": "OpenAPI/DRF request serializers — writable id/created/user without readOnly",
            "assumption": (
                "Auto-generated OpenAPI (DRF Spectacular /api/schema/) request components "
                "expose server-managed fields as writable. The sql/UI-toggle analogue: "
                "a down database does not disable the serializer contract"
            ),
            "test": (
                "GET /api/schema/ (or swagger.json). For each *Request / requestBody, "
                "check id, created, updated, user, owner, schedule, periodic_task — "
                "present and not readOnly. Count serializers (systemic vs one-off). "
                "Do not install anything; do not dump ICS/OT asset trees."
            ),
            "pass_criteria": (
                "Count >= 1 request serializer with writable privileged fields (id/created/"
                "user/schedule/…). Schema evidence is SUBMIT even if writes 500"
            ),
            "kill_criteria": (
                "Those fields are readOnly or omitted from request schemas. "
                "Do NOT kill solely because the database is unavailable"
            ),
            "specialist": "api_authz",
            "priority": "critical",
            "id_suffix": "oa-readonly-fields",
        },
        {
            "title": "Writable user/owner on create/update — cross-user ownership",
            "assumption": (
                "Group/asset request serializers expose a writable user (or owner) field, "
                "so any authenticated caller can assign ownership to an arbitrary user"
            ),
            "test": (
                "From the schema, name the serializer and path (e.g. POST/PUT group_detail). "
                "If the DB is up: ONE canary with user=<other in-scope id> on a test object, "
                "then revert. If the DB is down: SUBMIT on the writable user field in the "
                "request schema. Do not reassign production ICS assets."
            ),
            "pass_criteria": (
                "Request schema has writable user/owner without readOnly, OR a canary "
                "changes ownership"
            ),
            "kill_criteria": (
                "user/owner is readOnly or stripped server-side (ignored in stored row). "
                "Do NOT kill because the database is unavailable"
            ),
            "specialist": "api_authz",
            "priority": "critical",
            "id_suffix": "oa-writable-user",
        },
        {
            "title": "List endpoints document no tenant isolation ('all users' / shared)",
            "assumption": (
                "OpenAPI operation descriptions that say 'queries all … shared across all "
                "users' are an explicit missing-isolation contract, not just a UI hint"
            ),
            "test": (
                "Quote the operation description. If two accounts exist, compare_requests "
                "on the list path (user A vs B) — other-user objects in the body. "
                "A documented 'all users' list is SUBMIT even when a second account or "
                "the DB is unavailable. Bounded sample only; do not export the hierarchy."
            ),
            "pass_criteria": (
                "Description documents shared/all-users access, OR list body contains "
                "another user's objects"
            ),
            "kill_criteria": (
                "List is owner-scoped (or explicit share ACL) in both schema and live body. "
                "Do NOT kill because the database is unavailable"
            ),
            "specialist": "api_authz",
            "priority": "critical",
            "id_suffix": "oa-shared-list",
        },
        {
            "title": "OpenAPI security: {} account/email lookup (unauth enum + role)",
            "assumption": (
                "The same schema often documents GET /api/auth/account/?email= with "
                "security: {} and UserAccount fields is_staff/role. 500 vs sibling 401 "
                "proves JWT was skipped"
            ),
            "test": (
                "Quote security: {} / 'without authentication'. compare_requests unauth "
                "GET /api/auth/profile/ (expect 401) vs /api/auth/account/?email="
                "aegis-enum-canary@example.invalid (200 with role/is_staff OR 404 OR 500). "
                "File Critical. One canary only. Do not claim a 200 role body unless stdout "
                "has it. queue_finding_followups(vuln_type='unauth_account_lookup')."
            ),
            "pass_criteria": (
                "Schema unauth + privilege fields, OR lookup is not 401 while siblings are "
                "(200, 404 existence oracle, or 500)"
            ),
            "kill_criteria": (
                "Lookup 401/403; JWT required in schema. Do NOT kill because the DB is down"
            ),
            "specialist": "api_authz",
            "priority": "critical",
            "id_suffix": "oa-unauth-account",
        },
    ],
    "unauth_account_lookup": [
        {
            "title": "Schema documents public account lookup (security: {} + is_staff/role)",
            "assumption": (
                "OpenAPI marks the account/email endpoint as unauthenticated and the "
                "response model includes email, is_active, valid_through, is_staff, role"
            ),
            "test": (
                "GET /api/schema/. Quote security: {} (or empty security) and the "
                "description 'without authentication' / 'check if a user is active'. "
                "Name the privilege fields. Do not spray emails."
            ),
            "pass_criteria": (
                "Operation is documented unauth AND response includes is_staff and/or role "
                "(or equivalent privilege)"
            ),
            "kill_criteria": (
                "Schema requires bearer/JWT; response is a non-enumerating boolean only"
            ),
            "specialist": "api_authz",
            "priority": "critical",
            "id_suffix": "account-schema-public",
        },
        {
            "title": "Unauth lookup reaches app code (500/200) while siblings 401",
            "assumption": (
                "Protected /api/auth/profile/ and /users/me/ return 401 without a token. "
                "/api/auth/account/ does not — 500 from a down DB still proves JWT was skipped"
            ),
            "test": (
                "compare_requests: unauth GET sibling vs GET /api/auth/account/?email="
                "aegis-enum-canary@example.invalid. PASS on 200 with UserAccount fields OR "
                "404 'User does not exist!' OR 500/OperationalError vs 401 on siblings. "
                "One canary email. Do not enumerate employee inboxes. Do not dump ICS/OT "
                "users. Do not claim a 200 role body unless stdout has it."
            ),
            "pass_criteria": (
                "Lookup is not 401/403 while a protected sibling is 401, or 200 discloses "
                "is_staff/role/valid_through, or 404 is an existence oracle"
            ),
            "kill_criteria": (
                "Lookup 401/403 matching siblings. Do NOT kill solely because the database "
                "is unavailable, the canary email is unregistered, or the lookup is 404"
            ),
            "specialist": "api_authz",
            "priority": "critical",
            "id_suffix": "account-401-vs-500",
        },
    ],
    "unauth_settings_write": [
        {
            "title": "Sibling controllers also skip [Authorize] (LogQuery/Audit/ReadTasks/OpenDocument)",
            "assumption": (
                "Missing [Authorize] is usually class-level and repeats across controllers "
                "that were never added to the auth convention"
            ),
            "test": (
                "Unauth GET/POST mapped siblings: /api/LogQuery/QueryLog, /api/Audit/WriteAudit, "
                "/api/ReadTasks/*, /api/OpenDocument/Open, /api/Metadata/ValidMediaTypes. "
                "Record status. File a separate missing-auth card if they process without 401. "
                "Empty arrays and Graph-downstream 500s/Forbidden are missing-auth, not the "
                "High settings write. Do not dump logs or open production documents."
            ),
            "pass_criteria": (
                "One or more sibling controllers reach app code (non-401) without credentials"
            ),
            "kill_criteria": (
                "All siblings 401/403 like TaskAdmin. Do NOT kill because Graph returns "
                "Forbidden or a GET 500s"
            ),
            "specialist": "api_authz",
            "priority": "high",
            "id_suffix": "settings-sibling-controllers",
        },
        {
            "title": "SaveSettings is authenticated but not admin-only (BFLA)",
            "assumption": (
                "Adding [Authorize] without Roles=Admin still lets any logged-in user "
                "overwrite org-wide notifications, Planner flags, and PowerBI IDs"
            ),
            "test": (
                "If a low-priv session exists: POST SaveSettings with the same canary key. "
                "PASS on 200 from a non-admin identity. Do not flip production flags. "
                "queue_finding_followups stays on unauth_settings_write."
            ),
            "pass_criteria": "Authenticated non-admin can SaveSettings (200/204)",
            "kill_criteria": (
                "Non-admin is 403; only Admin/role policy can write. Unauth 401 is the "
                "parent finding, not this card"
            ),
            "specialist": "api_authz",
            "priority": "high",
            "id_suffix": "settings-bfla-admin",
        },
    ],
    "email_change_ato": [
        {
            "title": "Unauth reset_email accepted while set_password 401s",
            "assumption": (
                "djoser reset_email is supposed to be IsAuthenticated. Unauth 204 vs "
                "sibling set_password 401 proves JWT was skipped"
            ),
            "test": (
                "compare_requests unauth POST /api/auth/users/set_password/ vs "
                "POST /api/auth/users/reset_email/ {email: aegis-ato-canary@example.invalid}. "
                "PASS on 204/200 vs 401. One canary; do not complete ATO on a real mailbox."
            ),
            "pass_criteria": "Unauth reset_email 204/200 AND set_password 401",
            "kill_criteria": (
                "reset_email 401/403 like set_password. Do not kill because OPTIONS is 401 "
                "or OpenAPI declares jwtAuth"
            ),
            "specialist": "auth_logic",
            "priority": "high",
            "id_suffix": "reset-email-unauth",
        },
        {
            "title": "reset_email_confirm enumerates users by uid (MQ = user 1)",
            "assumption": (
                "Confirm validates the token against the target user without a session. "
                "Existing users return 'Invalid token for given user'; missing ids return "
                "'Invalid user id'"
            ),
            "test": (
                "Unauth POST reset_email_confirm uid=MQ (base64 of 1) + garbage token, "
                "then uid=NA== (id 4+). Record the two error classes. Do not spray uids; "
                "2–4 probes max. Do not submit a real new_email for a production user."
            ),
            "pass_criteria": "Distinct errors for existing vs missing uid without a session",
            "kill_criteria": "Confirm 401/403; identical errors; no user locator",
            "specialist": "auth_logic",
            "priority": "high",
            "id_suffix": "reset-email-uid-enum",
        },
        {
            "title": "Rate-limit / lockout on email-change (bounded)",
            "assumption": "No throttle on reset_email lets an attacker spray mailbox changes",
            "test": (
                "At most 8 unauth reset_email posts to the canary. PASS if none return "
                "429/lockout. Do not hydra; do not hit employee inboxes."
            ),
            "pass_criteria": "No 429/lockout on the bounded probe",
            "kill_criteria": "429 or lockout within 8 attempts",
            "specialist": "auth_logic",
            "priority": "medium",
            "id_suffix": "reset-email-nolockout",
        },
    ],
    "auth_header_bypass": [
        {
            "title": "No Authorization header vs invalid Bearer (middleware skip)",
            "assumption": (
                "ByPassAuthorization / conditional OIDC only validates when Authorization "
                "is present. No header reaches the controller"
            ),
            "test": (
                "compare_requests on 2–4 mapped routes: no Authorization vs "
                "Authorization: Bearer aegis-invalid. PASS if no-header is 200/400 "
                "(controller ran) AND invalid-bearer is 401. 400 missing-params is a bypass. "
                "Do not dump records."
            ),
            "pass_criteria": "Missing header is not 401 while invalid Bearer is 401",
            "kill_criteria": "Missing header is 401/403 like invalid Bearer",
            "specialist": "api_authz",
            "priority": "high",
            "id_suffix": "missing-vs-invalid-bearer",
        },
        {
            "title": "Always-open mutating sibling (no header check at all)",
            "assumption": (
                "Some controllers (UpdateNote / Notes) skip auth even when a Bearer is sent"
            ),
            "test": (
                "Repeat the pair on mapped POST/PUT/DELETE (Notes, UpdateNote, DeleteNote). "
                "File separately if invalid-bearer is also 200/400. Do not mutate production "
                "rows — empty/canary body only."
            ),
            "pass_criteria": "Mutating route processes without 401 even with an invalid Bearer",
            "kill_criteria": "Invalid Bearer is 401 on mutating routes",
            "specialist": "api_authz",
            "priority": "high",
            "id_suffix": "always-open-write",
        },
    ],
    "socketio_idor": [
        {
            "title": "Anonymous get_stream returns url_key for fabricated siteId",
            "assumption": "Socket.IO get_stream has no server-side authz on siteId/analyzerId",
            "test": (
                "Engine.IO polling handshake, then 42[\"get_stream\", fabricated siteId/"
                "userId/userType]. PASS on url_key / namespace. 1–2 extra siteIds. "
                "Do not fetch the video stream. Do not send null crash loops."
            ),
            "pass_criteria": "url_key returned without a session for a fabricated siteId",
            "kill_criteria": (
                "Auth required; no url_key. Do not kill because video was not downloaded"
            ),
            "specialist": "api_authz",
            "priority": "high",
            "id_suffix": "get-stream-url-key",
        },
        {
            "title": "Socket.IO CORS + hardcoded Admin params in client JS",
            "assumption": (
                "ACAO reflection with credentials on /socket.io/ plus hardcoded "
                "siteId/userType=Admin in the page JS"
            ),
            "test": (
                "Canary Origin on /socket.io/ — queue cors_credentials if ACAO+credentials. "
                "Quote hardcoded siteId/userType from the page — queue js_secrets. "
                "Do not dump camera footage."
            ),
            "pass_criteria": "CORS credentials on socket.io AND/OR hardcoded Admin stream params",
            "kill_criteria": "Allowlist rejects canary; no hardcoded admin params",
            "specialist": "api_authz",
            "priority": "high",
            "id_suffix": "socketio-cors-js",
        },
    ],
    "ml_pipeline_rbac": [
        {
            "title": "Self-reg / low-priv can POST train or DELETE celery-task",
            "assumption": "ML pipeline endpoints authenticate JWT but do not check roles",
            "test": (
                "Throwaway self-reg if open. POST /api/v1/train/ or DELETE "
                "/api/v1/celery-task/ as that user. Do not delete production models; "
                "prefer OPTIONS/authz or one tiny canary train. Do not dump datasets."
            ),
            "pass_criteria": "Low-priv session gets 200/202/204 on train/delete/celery",
            "kill_criteria": "403 for non-admin. Do not kill solely because signup is closed",
            "specialist": "api_authz",
            "priority": "high",
            "id_suffix": "ml-train-delete",
        },
        {
            "title": "Celery / optimize queue injection as any registrant",
            "assumption": "POST /api/v1/celery-task/ or /api/v1/optimize/ is BFLA after signup",
            "test": (
                "One canary task payload as the throwaway user. Do not inject malicious "
                "pickle/code. Record 202/queued vs 403."
            ),
            "pass_criteria": "Non-admin can enqueue Celery/optimize jobs",
            "kill_criteria": "403 / admin-only",
            "specialist": "api_authz",
            "priority": "high",
            "id_suffix": "ml-celery-queue",
        },
    ],
}


_FINDING_CLASS_ALIASES = {
    "default_login": "default_login",
    "default-login": "default_login",
    "default_credentials": "default_login",
    "default-credentials": "default_login",
    "grafana-default-login": "default_login",
    "grafana_default_login": "default_login",
    "cwe-1393": "default_login",
    "cwe_1393": "default_login",
    "weak_password": "default_login",
    "weak_credential": "default_login",
    "couchdb": "default_login",
    "couchdb_config": "default_login",
    "session_forgery": "default_login",
    "cookie_forgery": "default_login",
    "authsession": "default_login",
    "host_header": "host_header",
    "host-header": "host_header",
    "host_header_injection": "host_header",
    "hostheader": "host_header",
    "password_reset_poisoning": "host_header",
    "idor": "idor",
    "bola": "idor",
    "authz": "idor",
    "broken_authz": "idor",
    "ssrf": "ssrf",
    "elasticsearch_unauth": "elasticsearch_unauth",
    "elasticsearch-unauth": "elasticsearch_unauth",
    "elasticsearch": "elasticsearch_unauth",
    "exposed_elasticsearch": "elasticsearch_unauth",
    "unauth_elasticsearch": "elasticsearch_unauth",
    "unauthenticated_elasticsearch": "elasticsearch_unauth",
    "xpack_security": "elasticsearch_unauth",
    "js_secrets": "js_secrets",
    "js-secrets": "js_secrets",
    "hardcoded_credentials": "js_secrets",
    "hardcoded-credentials": "js_secrets",
    "client_secret": "js_secrets",
    "client_id": "js_secrets",
    "cwe-312": "js_secrets",
    "cwe_312": "js_secrets",
    "cwe-540": "js_secrets",
    "cwe_540": "js_secrets",
    "cwe-321": "js_secrets",
    "cwe_321": "js_secrets",
    "hmac": "js_secrets",
    "hmac_key": "js_secrets",
    "client_hmac": "js_secrets",
    "signing_key": "js_secrets",
    "emailjs": "js_secrets",
    "email_js": "js_secrets",
    "email-js": "js_secrets",
    "azure_function_env_dump": "azure_function_env_dump",
    "azure_function": "azure_function_env_dump",
    "azure-function": "azure_function_env_dump",
    "function_app": "azure_function_env_dump",
    "function-app": "azure_function_env_dump",
    "authlevel_anonymous": "azure_function_env_dump",
    "authlevel-anonymous": "azure_function_env_dump",
    "tester_function": "azure_function_env_dump",
    "cwe-526": "azure_function_env_dump",
    "cwe_526": "azure_function_env_dump",
    "arangodb_default": "arangodb_default",
    "arangodb": "arangodb_default",
    "mongodb_unauth": "mongodb_unauth",
    "mongodb": "mongodb_unauth",
    "mongo_anon": "mongodb_unauth",
    "emqx_default": "emqx_default",
    "emqx": "emqx_default",
    "cors_credentials": "cors_credentials",
    "cors": "cors_credentials",
    "weborigins": "cors_credentials",
    "web_origins": "cors_credentials",
    "keycloak_cors": "cors_credentials",
    "keycloak_password_grant": "keycloak_password_grant",
    "keycloak-password-grant": "keycloak_password_grant",
    "admin-cli": "keycloak_password_grant",
    "admin_cli": "keycloak_password_grant",
    "password_grant": "keycloak_password_grant",
    "direct_access_grants": "keycloak_password_grant",
    "cwe-307": "keycloak_password_grant",
    "cwe_307": "keycloak_password_grant",
    "client_role_param": "client_role_param",
    "usertype": "client_role_param",
    "user_type": "client_role_param",
    "vendorjson_unauth": "vendorjson_unauth",
    "vendorjson": "vendorjson_unauth",
    "vendor_json": "vendorjson_unauth",
    "auth0_mgmt_token": "auth0_mgmt_token",
    "auth0": "auth0_mgmt_token",
    "gitlab_unauth": "gitlab_unauth",
    "gitlab": "gitlab_unauth",
    "docker_registry": "docker_registry",
    "docker-registry": "docker_registry",
    "acr": "docker_registry",
    "azurecr": "docker_registry",
    "anonymous_pull": "docker_registry",
    "anonymous-pull": "docker_registry",
    "anonymouspullenabled": "docker_registry",
    "django_debug": "django_debug",
    "django": "django_debug",
    "openai_proxy_unauth": "openai_proxy_unauth",
    "openai_proxy": "openai_proxy_unauth",
    "azure_openai": "openai_proxy_unauth",
    "wiki_open_reg": "wiki_open_reg",
    "wiki": "wiki_open_reg",
    "self_registration": "wiki_open_reg",
    "binary_hardcoded_creds": "binary_hardcoded_creds",
    "downloadable_binary": "binary_hardcoded_creds",
    "client_side_auth": "client_side_auth",
    "client-side-auth": "client_side_auth",
    "mass_assignment": "mass_assignment",
    "mass-assignment": "mass_assignment",
    "cwe-915": "mass_assignment",
    "cwe_915": "mass_assignment",
    "bopla": "mass_assignment",
    "property_level": "mass_assignment",
    "drf_mass_assignment": "mass_assignment",
    "unauth_account_lookup": "unauth_account_lookup",
    "unauth-account-lookup": "unauth_account_lookup",
    "user_enum": "unauth_account_lookup",
    "user_enumeration": "unauth_account_lookup",
    "account_enumeration": "unauth_account_lookup",
    "cwe-204": "unauth_account_lookup",
    "cwe_204": "unauth_account_lookup",
    "/api/auth/account": "unauth_account_lookup",
    "api/auth/account": "unauth_account_lookup",
    "unauth_settings_write": "unauth_settings_write",
    "unauth-settings-write": "unauth_settings_write",
    "savesettings": "unauth_settings_write",
    "save_settings": "unauth_settings_write",
    "missing_authorize": "unauth_settings_write",
    "missing-authorize": "unauth_settings_write",
    "/api/settings": "unauth_settings_write",
    "api/settings": "unauth_settings_write",
    "email_change_ato": "email_change_ato",
    "email-change-ato": "email_change_ato",
    "reset_email": "email_change_ato",
    "reset-email": "email_change_ato",
    "change_email": "email_change_ato",
    "djoser": "email_change_ato",
    "auth_header_bypass": "auth_header_bypass",
    "auth-header-bypass": "auth_header_bypass",
    "bypassauthorization": "auth_header_bypass",
    "missing_authorization_header": "auth_header_bypass",
    "missing-authorization-header": "auth_header_bypass",
    "socketio_idor": "socketio_idor",
    "socketio-idor": "socketio_idor",
    "get_stream": "socketio_idor",
    "url_key": "socketio_idor",
    "ml_pipeline_rbac": "ml_pipeline_rbac",
    "ml-pipeline-rbac": "ml_pipeline_rbac",
    "celery-task": "ml_pipeline_rbac",
    "celery_task": "ml_pipeline_rbac",
}


def seed_hypotheses_from_capability_map(
    brain: EngagementBrain,
    cmap: Optional[Dict[str, Any]],
) -> EngagementBrain:
    """Seed open hypotheses from observation methodologies + capability map hunt queue."""
    if not cmap:
        return brain
    brain.target = brain.target or str(cmap.get("target") or "")
    if cmap.get("authenticated") is True and "authenticated" not in brain.identities:
        brain.identities.append("authenticated")
    if brain.phase in ("recon",):
        brain.phase = "map" if not cmap.get("ready_for_attack") else "attack"

    existing = {h.id for h in brain.hypotheses}
    covered_hunts: set[str] = set()

    # Prefer observation → methodology cards (specific CWE/CAPEC-tagged tests)
    methodologies = list(cmap.get("methodologies") or [])
    if not methodologies:
        try:
            from app.services.agent.methodology_catalog import methodologies_from_capability_map
            methodologies = [m.to_dict() for m in methodologies_from_capability_map(cmap)]
        except Exception:
            methodologies = []

    for m in methodologies:
        if not isinstance(m, dict) or not m.get("id"):
            continue
        mid = str(m["id"])
        hid = _hyp_id(brain.target, "method", mid)
        if hid in existing:
            covered_hunts.add(str(m.get("hunt") or ""))
            continue
        brain.hypotheses.append(
            Hypothesis(
                id=hid,
                title=str(m.get("title") or mid),
                assumption=str(m.get("assumption") or ""),
                test=str(m.get("test") or ""),
                pass_criteria=str(m.get("pass_criteria") or ""),
                kill_criteria=str(m.get("kill_criteria") or ""),
                specialist=str(m.get("specialist") or "injection"),
                priority=str(m.get("priority") or "high"),
                target=brain.target,
                evidence=str(m.get("evidence") or "")[:500],
                source="methodology",
                methodology_id=mid,
                cwe_ids=list(m.get("cwe_ids") or []),
                capec_ids=list(m.get("capec_ids") or []),
                owasp=str(m.get("owasp") or ""),
            )
        )
        existing.add(hid)
        if m.get("hunt"):
            covered_hunts.add(str(m["hunt"]))

    queue = list(cmap.get("ranked_hunt_queue") or [])
    # Always consider coverage after logic hunts when map is attack-ready.
    hunt_names = [q.get("hunt") for q in queue if q.get("hunt")]
    if cmap.get("ready_for_attack") and "coverage" not in hunt_names:
        hunt_names.append("coverage")

    # Multi-tenant Host signal: subdomain-ish pages or multiple hosts in APIs.
    hosts = set()
    for p in cmap.get("pages_visited") or []:
        m = re.match(r"https?://([^/]+)", str(p))
        if m:
            hosts.add(m.group(1).lower())
    for e in cmap.get("api_endpoints") or []:
        if e.get("host"):
            hosts.add(str(e["host"]).lower())
    if len(hosts) >= 2 or any(re.match(r"^[a-z0-9-]+\.[a-z0-9-]+\.", h) for h in hosts):
        hunt_names.insert(0, "host_tenant")

    # Login surface → dedicated Samson credential assault card
    if (
        cmap.get("has_login_form") or cmap.get("has_auth")
    ) and "credential_assault" not in hunt_names:
        hunt_names.insert(0, "credential_assault")

    # Forms / multi-step UI → business logic card
    if len(cmap.get("forms") or []) >= 2 and "business_logic" not in hunt_names:
        hunt_names.append("business_logic")

    # Legacy hunt cards only for hunts not already covered by a methodology card
    for hunt in hunt_names:
        hunt_key = str(hunt)
        if hunt_key in covered_hunts:
            continue
        card = _HUNT_CARDS.get(hunt_key)
        if not card:
            continue
        hid = _hyp_id(brain.target, hunt_key, card["title"])
        if hid in existing:
            continue
        evidence = ""
        for q in queue:
            if q.get("hunt") == hunt:
                evidence = str(q.get("evidence") or "")
                break
        brain.hypotheses.append(
            Hypothesis(
                id=hid,
                title=card["title"],
                assumption=card["assumption"],
                test=card["test"],
                pass_criteria=card["pass_criteria"],
                kill_criteria=card["kill_criteria"],
                specialist=card["specialist"],
                priority=card.get("priority", "high"),
                target=brain.target,
                evidence=evidence,
                source="map",
            )
        )
        existing.add(hid)

    brain = ensure_threat_model(brain, cmap)
    brain.next_steps = _derive_next_steps(brain)
    try:
        from app.services.agent.penetration_task_graph import sync_graph_from_brain

        sync_graph_from_brain(brain)
    except Exception:
        pass
    return brain


def ensure_threat_model(
    brain: EngagementBrain,
    cmap: Optional[Dict[str, Any]] = None,
    *,
    repo_path: str = "",
    url: str = "",
    source: str = "auto",
    owner_notes: str = "",
    languages: Optional[List[str]] = None,
    frameworks: Optional[List[str]] = None,
    rebuild: bool = False,
) -> EngagementBrain:
    """Attach / refresh a threat model and seed threat-sourced hypothesis cards."""
    from app.services.agent.threat_model import (
        build_auto,
        threats_as_hypothesis_dicts,
        threat_model_from_dict,
    )

    existing = None if rebuild else (brain.threat_model or None)
    model = build_auto(
        cmap=cmap,
        url=url or brain.target,
        repo_path=repo_path,
        languages=languages,
        frameworks=frameworks,
        owner_notes=owner_notes,
        existing=existing,
        source=source,
    )
    brain.threat_model = model.to_dict()
    brain.surfaces = [s.to_dict() for s in model.surfaces]
    brain.focus_areas = [f.to_dict() for f in model.focus_areas]
    if not brain.target:
        brain.target = model.target or brain.target
    seed_coverage_from_surfaces(brain)
    return seed_hypotheses_from_threat_model(brain, model.to_dict())


def seed_hypotheses_from_threat_model(
    brain: EngagementBrain,
    model_dict: Optional[Dict[str, Any]],
) -> EngagementBrain:
    """Seed open hypotheses from ranked threats (skip if a methodology card already covers the specialist+title)."""
    if not model_dict:
        return brain
    from app.services.agent.threat_model import threats_as_hypothesis_dicts, threat_model_from_dict

    model = threat_model_from_dict(model_dict)
    existing_ids = {h.id for h in brain.hypotheses}
    for card in threats_as_hypothesis_dicts(model, target=brain.target):
        hid = _hyp_id(brain.target, "threat", card["id"])
        if hid in existing_ids:
            continue
        brain.hypotheses.append(
            Hypothesis(
                id=hid,
                title=str(card.get("title") or card["id"]),
                assumption=str(card.get("assumption") or ""),
                test=str(card.get("test") or ""),
                pass_criteria=str(card.get("pass_criteria") or ""),
                kill_criteria=str(card.get("kill_criteria") or ""),
                specialist=str(card.get("specialist") or "injection"),
                priority=str(card.get("priority") or "high"),
                target=brain.target or str(card.get("target") or ""),
                evidence=str(card.get("evidence") or "")[:500],
                source="threat_model",
                methodology_id=str(card.get("id") or ""),
            )
        )
        existing_ids.add(hid)
    return brain


def queue_followups_for_finding(
    brain: EngagementBrain,
    *,
    vuln_type: str,
    title: str = "",
    target: str = "",
    evidence: str = "",
) -> List[Hypothesis]:
    """Auto-enqueue chain cards after a confirmed finding. Returns new hyps."""
    key = _FINDING_CLASS_ALIASES.get(
        (vuln_type or "").strip().lower().replace(" ", "_"),
        "",
    )
    # Fuzzy title matching for nuclei template names
    blob = f"{vuln_type} {title}".lower()
    if not key:
        if "emqx" in blob:
            key = "emqx_default"
        elif "arangodb" in blob or ":8529" in blob:
            key = "arangodb_default"
        elif "default" in blob and ("login" in blob or "credential" in blob or "password" in blob):
            key = "default_login"
        elif "host" in blob and "header" in blob:
            key = "host_header"
        elif any(
            t in blob
            for t in (
                "/api/auth/account",
                "account lookup",
                "user enumeration",
                "user account statistics",
            )
        ) or ("is_staff" in blob and "email" in blob):
            key = "unauth_account_lookup"
        elif any(
            t in blob
            for t in (
                "savesettings",
                "save settings",
                "/api/settings",
                "missing [authorize]",
                "missing authorize",
                "unauth_settings_write",
                "unauthenticated settings write",
            )
        ):
            key = "unauth_settings_write"
        elif any(
            t in blob
            for t in (
                "reset_email",
                "reset-email",
                "email change",
                "change email",
                "email-change",
                "djoser",
            )
        ):
            key = "email_change_ato"
        elif any(
            t in blob
            for t in (
                "missing authorization header",
                "bypassauthorization",
                "bypass authorization",
                "auth middleware",
                "middleware bypass",
                "no authorization header",
                "without an authorization header",
            )
        ):
            key = "auth_header_bypass"
        elif any(t in blob for t in ("get_stream", "url_key")) or (
            ("socket.io" in blob or "socketio" in blob)
            and any(t in blob for t in ("idor", "unauth", "siteid", "camera stream"))
            and "cors" not in blob
            and "origin" not in blob
            and "acao" not in blob
        ):
            key = "socketio_idor"
        elif any(
            t in blob
            for t in (
                "celery-task",
                "celery_task",
                "ml model",
                "ml pipeline",
                "/api/v1/train",
                "logixtwin",
                "missing rbac",
                "missing role-based",
            )
        ):
            key = "ml_pipeline_rbac"
        elif any(
            t in blob
            for t in (
                "mass assignment",
                "mass-assignment",
                "writable id",
                "extra_kwargs",
                "property-level",
                "request serializer",
                "/api/schema",
            )
        ):
            key = "mass_assignment"
        elif "idor" in blob or "bola" in blob:
            key = "idor"
        elif "ssrf" in blob:
            key = "ssrf"
        elif "elasticsearch" in blob or ":9200" in blob or "xpack.security" in blob:
            key = "elasticsearch_unauth"
        elif "arangodb" in blob or ":8529" in blob:
            key = "arangodb_default"
        elif "mongodb" in blob or ":27017" in blob:
            key = "mongodb_unauth"
        elif "emqx" in blob:
            key = "emqx_default"
        elif "auth0" in blob or "identitymigrate" in blob:
            key = "auth0_mgmt_token"
        elif "gitlab" in blob:
            key = "gitlab_unauth"
        elif (
            "docker registry" in blob
            or "/v2/_catalog" in blob
            or "azurecr" in blob
            or "anonymous pull" in blob
            or "anonymouspullenabled" in blob
            or ("container registry" in blob and "anonymous" in blob)
        ):
            key = "docker_registry"
        elif "vendorjson" in blob:
            key = "vendorjson_unauth"
        elif "usertype" in blob or "publicportal" in blob or "public portal" in blob or "user-supplied" in blob:
            key = "client_role_param"
        elif any(
            t in blob
            for t in (
                "admin-cli",
                "admin_cli",
                "password grant",
                "direct access grant",
                "resource owner password",
                "invalid_grant",
            )
        ) or (
            "keycloak" in blob
            and any(t in blob for t in ("lockout", "brute", "rate limit", "429"))
        ):
            key = "keycloak_password_grant"
        elif (
            "cors" in blob
            or "weborigins" in blob
            or ("keycloak" in blob and "origin" in blob)
        ):
            key = "cors_credentials"
        elif "/api/chat" in blob or "openai" in blob:
            key = "openai_proxy_unauth"
        elif "django" in blob and "debug" in blob:
            key = "django_debug"
        elif "wiki" in blob and (
            "self-reg" in blob or "self-registered" in blob or "open registration" in blob
            or "open self-registration" in blob
        ):
            key = "wiki_open_reg"
        elif "downloadable binary" in blob or "publicly-downloadable" in blob:
            key = "binary_hardcoded_creds"
        elif "client-side-only" in blob or "client-side only" in blob:
            key = "client_side_auth"
        elif any(
            t in blob
            for t in (
                "azure function",
                "function app",
                "authlevel",
                "azurewebjobsstorage",
                "machinekey",
                "website_auth",
                "tester function",
                "azurewebsites.net",
            )
        ):
            key = "azure_function_env_dump"
        elif any(
            t in blob
            for t in (
                "client_secret",
                "hardcoded credential",
                "hardcoded api",
                "javascript bundle",
                "js bundle",
                "_next/static",
                "emailjs",
                "hmac",
                "hs256",
                "cwe-321",
                "signing key",
                "encryption_key",
                "encryptionkey",
                "rfid",
                "mqtt",
            )
        ):
            key = "js_secrets"
    if not key:
        return []

    if title and title not in brain.confirmed_findings:
        brain.confirmed_findings.append(title[:300])

    # Default login → record credential hint if present in evidence/title
    if key == "default_login":
        _maybe_extract_credential(brain, title=title, evidence=evidence, target=target)
    elif key == "js_secrets":
        _maybe_extract_oauth_client(brain, title=title, evidence=evidence, target=target)
        _maybe_extract_emailjs(brain, title=title, evidence=evidence, target=target)
        _maybe_extract_encryption_key(brain, title=title, evidence=evidence, target=target)

    existing = {h.id for h in brain.hypotheses}
    created: List[Hypothesis] = []
    for card in _CHAIN_CARDS.get(key, []):
        suffix = str(card.get("id_suffix") or "")
        hay = f"{blob} {target} {evidence}".lower()
        # Skip product-specific cards unless title/target/evidence smells like that product
        if suffix.startswith("grafana-") and "grafana" not in hay:
            continue
        if suffix.startswith("couchdb-") and not _looks_like_couchdb(hay):
            continue
        if suffix.startswith("es-") and not (
            "elasticsearch" in hay or ":9200" in hay or "xpack" in hay
        ):
            continue
        if suffix.startswith("arangodb-") and "arangodb" not in hay and ":8529" not in hay:
            continue
        if suffix.startswith("mongo-") and "mongo" not in hay and "27017" not in hay:
            continue
        if suffix.startswith("emqx-") and "emqx" not in hay:
            continue
        if suffix.startswith("cors-") and "cors" not in hay and "socket.io" not in hay:
            continue
        if suffix.startswith("keycloak-") and not any(
            t in hay for t in ("keycloak", "openid", "realms", "openid-connect")
        ):
            continue
        if suffix.startswith("socketio-") and "socket.io" not in hay:
            continue
        if suffix.startswith("usertype-") and not any(
            t in hay for t in ("usertype", "user type", "publicportal", "public portal", "user-supplied")
        ):
            continue
        if suffix.startswith("wiki-") and "wiki" not in hay:
            continue
        if suffix.startswith("binary-") and "binary" not in hay and ".exe" not in hay:
            continue
        if suffix.startswith("clientauth-") and "client-side" not in hay and "elogbook" not in hay:
            continue
        if suffix.startswith("vendorjson-") and "vendorjson" not in hay and "vendor json" not in hay:
            continue
        if suffix.startswith("auth0-") and "auth0" not in hay and "identitymigrate" not in hay:
            continue
        if suffix.startswith("gitlab-") and "gitlab" not in hay:
            continue
        if suffix.startswith("docker-") and not any(
            t in hay for t in ("docker", "registry", "azurecr", "anonymous pull", "catalog")
        ):
            continue
        if suffix.startswith("django-") and "django" not in hay:
            continue
        if suffix.startswith("openai-") and "openai" not in hay and "/api/chat" not in hay:
            continue
        if suffix.startswith("azfn-") and key != "azure_function_env_dump" and not any(
            t in hay for t in ("azure", "function app", "azurewebsites", "tester", "authlevel")
        ):
            continue
        if suffix.startswith("emailjs-") and "emailjs" not in hay:
            continue
        if suffix.startswith("hmac-") and not any(
            t in hay
            for t in (
                "hmac",
                "hs256",
                "cwe-321",
                "cwe_321",
                "signing key",
                "object.keys",
                "waste",
            )
        ):
            continue
        if suffix.startswith("mqtt-") and not any(
            t in hay
            for t in ("mqtt", "rfid", "scada", "ilens", "broker", "ics", "hmi/")
        ):
            continue
        if suffix.startswith("encrypt-") and not any(
            t in hay for t in ("encryption_key", "encryptionkey", "emailjs")
        ):
            continue
        hmac_only = any(
            t in hay for t in ("hmac", "hs256", "signing key", "object.keys")
        ) and "client_secret" not in hay and "emailjs" not in hay and "encryption_key" not in hay
        if hmac_only and suffix in (
            "js-hostname-cred-map",
            "js-cred-live-api",
            "js-cred-cross-env",
            "emailjs-keys",
            "emailjs-send-canary",
        ):
            continue
        hid = _hyp_id(target or brain.target, key, card.get("id_suffix") or card["title"])
        if hid in existing:
            continue
        hyp = Hypothesis(
            id=hid,
            title=card["title"],
            assumption=card["assumption"],
            test=card["test"],
            pass_criteria=card["pass_criteria"],
            kill_criteria=card["kill_criteria"],
            specialist=card["specialist"],
            priority=card.get("priority", "high"),
            target=target or brain.target,
            evidence=(evidence or "")[:500],
            source="chain",
            parent_finding=title or vuln_type,
        )
        brain.hypotheses.append(hyp)
        created.append(hyp)
        existing.add(hid)

    if brain.phase not in ("coverage", "report"):
        brain.phase = "attack"
    brain.next_steps = _derive_next_steps(brain)
    try:
        from app.services.agent.penetration_task_graph import sync_graph_from_brain

        sync_graph_from_brain(brain)
    except Exception:
        pass
    return created


def update_hypothesis(
    brain: EngagementBrain,
    hypothesis_id: str,
    *,
    status: Optional[str] = None,
    evidence: Optional[str] = None,
) -> Optional[Hypothesis]:
    for h in brain.hypotheses:
        if h.id == hypothesis_id or h.title == hypothesis_id:
            if status:
                h.status = status
            if evidence is not None:
                h.evidence = evidence[:2000]
            h.updated_at = datetime.now(timezone.utc).isoformat()
            if status in ("proven", "killed"):
                cov_status = "finding" if status == "proven" else "tested_clean"
                record_surface_coverage(
                    brain,
                    path=h.target or brain.target,
                    status=cov_status,
                    reason=f"hypothesis {h.id} {status}",
                    hypothesis_id=h.id,
                )
            brain.next_steps = _derive_next_steps(brain)
            return h
    return None


def add_credential(
    brain: EngagementBrain,
    *,
    username: str,
    secret: str,
    source: str = "manual",
    valid_on: Optional[List[str]] = None,
    secret_type: str = "password",
    notes: str = "",
) -> CredentialRecord:
    rec = CredentialRecord(
        username=username,
        secret=secret,
        secret_type=secret_type,
        source=source,
        valid_on=list(valid_on or []),
        notes=notes,
    )
    # de-dupe
    for existing in brain.credentials:
        if existing.username == username and existing.secret == secret:
            for v in rec.valid_on:
                if v not in existing.valid_on:
                    existing.valid_on.append(v)
            return existing
    brain.credentials.append(rec)
    if "authenticated" not in brain.identities:
        brain.identities.append("authenticated")
    brain.next_steps = _derive_next_steps(brain)
    return rec


def log_approach(
    brain: EngagementBrain,
    *,
    technique: str,
    target: str = "",
    result: str = "failed",
    detail: str = "",
) -> ApproachRecord:
    rec = ApproachRecord(
        technique=technique,
        target=target,
        result=result,
        detail=detail[:1000],
    )
    brain.approaches.append(rec)
    brain.approaches = brain.approaches[-40:]
    return rec


def ensure_spawned_hypotheses(
    brain: EngagementBrain,
    spawn_names: Iterable[str],
) -> List[Hypothesis]:
    """Add hunt cards for specialists discovered mid-swarm (dynamic spawn)."""
    created: List[Hypothesis] = []
    existing_open = {
        h.specialist
        for h in brain.hypotheses
        if h.status in ("open", "in_progress")
    }
    existing_ids = {h.id for h in brain.hypotheses}
    for raw in spawn_names or []:
        name = str(raw or "").strip()
        if not name or name in existing_open:
            continue
        card = _HUNT_CARDS.get(name)
        if not card:
            for _key, val in _HUNT_CARDS.items():
                if val.get("specialist") == name:
                    card = val
                    break
        if not card:
            continue
        hid = _hyp_id(brain.target, "spawn", name, card["title"])
        if hid in existing_ids:
            continue
        hyp = Hypothesis(
            id=hid,
            title=card["title"],
            assumption=card["assumption"],
            test=card["test"],
            pass_criteria=card["pass_criteria"],
            kill_criteria=card["kill_criteria"],
            specialist=card["specialist"],
            priority=card.get("priority", "high"),
            target=brain.target,
            source="spawn",
        )
        brain.hypotheses.append(hyp)
        created.append(hyp)
        existing_open.add(hyp.specialist)
        existing_ids.add(hid)
    if created:
        try:
            from app.services.agent.penetration_task_graph import sync_graph_from_brain

            sync_graph_from_brain(brain)
        except Exception:
            pass
        brain.next_steps = _derive_next_steps(brain)
    return created


def specialists_from_open_hypotheses(
    brain: EngagementBrain,
    *,
    max_specialists: int = 6,
) -> List[str]:
    """Pick fireteam specialists from open/in_progress hypotheses (priority order)."""
    pri = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    open_hyps = [
        h for h in brain.hypotheses if h.status in ("open", "in_progress")
    ]
    open_hyps.sort(key=lambda h: (pri.get(h.priority, 9), h.created_at))
    selected: List[str] = ["app_mapper"]
    for h in open_hyps:
        if h.specialist and h.specialist not in selected and h.specialist not in (
            "finding_judge",
            "independent_verifier",
        ):
            selected.append(h.specialist)
        if len(selected) >= max_specialists:
            break
    # Independent verifier is a SECOND WAVE after hunters file candidates — do not
    # sit Solomon or Deborah in the hunter conversation (finder grading its own homework).
    return [n for n in selected if n not in ("finding_judge", "independent_verifier")][:max_specialists]


def format_engagement_brain_for_prompt(
    data: Optional[Dict[str, Any]],
    *,
    redact_secrets: bool = True,
) -> str:
    brain = engagement_brain_from_dict(data)
    if (
        not brain.hypotheses
        and not brain.credentials
        and not brain.approaches
        and not brain.next_steps
        and not brain.threat_model
    ):
        return (
            "No engagement brain yet. After execute_deep_crawl (URL) or a local checkout "
            "(code), call build_threat_model then sync_engagement_brain (or fireteam_dispatch) "
            "so threats and methodology cards aim hunters. Use compare_requests for "
            "differential proof. On confirmed findings call queue_finding_followups."
        )

    lines = [
        f"Phase: {brain.phase}  target={brain.target or '?'}",
        f"Identities: {', '.join(brain.identities) or 'anonymous'}",
    ]

    if brain.threat_model:
        try:
            from app.services.agent.threat_model import format_threat_model_for_prompt
            lines.append(format_threat_model_for_prompt(brain.threat_model))
        except Exception:
            lines.append(f"Threat model: {len((brain.threat_model or {}).get('threats') or [])} threats")

    if brain.credentials:
        lines.append("Credentials (reuse for authenticated follow-ups):")
        for c in brain.credentials[:8]:
            view = c.redacted() if redact_secrets else c.to_dict()
            valid = f" on {', '.join(view['valid_on'])}" if view.get("valid_on") else ""
            lines.append(
                f"  - {view['username']}:{view['secret']} ({view['secret_type']}) "
                f"from {view['source']}{valid}"
            )

    open_hyps = [h for h in brain.hypotheses if h.status in ("open", "in_progress")]
    proven = [h for h in brain.hypotheses if h.status == "proven"]
    killed = [h for h in brain.hypotheses if h.status == "killed"]
    lines.append(
        f"Hypotheses: {len(open_hyps)} open, {len(proven)} proven, {len(killed)} killed"
    )
    if open_hyps:
        lines.append("Open hypothesis queue (dispatch specialists for these):")
        pri = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for h in sorted(open_hyps, key=lambda x: pri.get(x.priority, 9))[:10]:
            method_bit = f" method={h.methodology_id}" if h.methodology_id else ""
            cwe_bit = f" CWE={','.join(h.cwe_ids[:4])}" if h.cwe_ids else ""
            lines.append(
                f"  - [{h.priority}/{h.status}] id={h.id} specialist={h.specialist}"
                f"{method_bit}{cwe_bit} | {h.title}"
            )
            lines.append(f"      assumption: {h.assumption}")
            lines.append(f"      test: {h.test}")
            lines.append(f"      pass: {h.pass_criteria}")
            lines.append(f"      kill: {h.kill_criteria}")
            if h.owasp:
                lines.append(f"      owasp: {h.owasp}")
            if h.capec_ids:
                lines.append(f"      capec: {', '.join(h.capec_ids[:4])}")

        # Short procedure packs for top open methodologies (how to test)
        try:
            from app.services.agent.methodology_procedures import format_procedures_for_prompt

            open_mids = [
                h.methodology_id for h in sorted(open_hyps, key=lambda x: pri.get(x.priority, 9))
                if h.methodology_id
            ]
            procs = format_procedures_for_prompt(open_mids, limit=2)
            if procs:
                lines.append("")
                lines.append(procs)
                lines.append(
                    "(More packs: lookup_methodology_procedure(methodology_id=…) "
                    "or search_memory(room='methodologies').)"
                )
        except Exception:
            pass

    if brain.task_graph:
        try:
            from app.services.agent.penetration_task_graph import (
                format_graph_for_scheduler,
                graph_from_dict,
            )

            lines.append("")
            lines.append(format_graph_for_scheduler(graph_from_dict(brain.task_graph)))
        except Exception:
            pass

    if proven:
        lines.append("Proven:")
        for h in proven[:6]:
            lines.append(f"  - {h.title} ({h.evidence[:120]})")

    pending_cands = [
        c for c in (brain.candidates or [])
        if (c.get("status") if isinstance(c, dict) else getattr(c, "status", "")) == "pending"
    ]
    if pending_cands or brain.candidates:
        lines.append(
            f"Finding candidates: {len(pending_cands)} pending independent_verify "
            f"(total {len(brain.candidates or [])})"
        )
        for c in pending_cands[:6]:
            if isinstance(c, dict):
                lines.append(f"  - [{c.get('severity')}] {c.get('title')} id={c.get('id')}")

    pending_ras = [
        r for r in (brain.pending_risk_assessments or [])
        if isinstance(r, dict) and r.get("status") != "complete"
    ]
    if pending_ras:
        lines.append(
            f"Marcus RA pending: {len(pending_ras)} finding(s). "
            "Call assess_finding_risk (no live retest) before complete."
        )
        for r in pending_ras[:6]:
            lines.append(f"  - [{r.get('severity')}] {r.get('title')} id={r.get('finding_id')}")

    if brain.coverage:
        try:
            cov = coverage_progress(brain)
            lines.append(cov.get("summary") or "Coverage:")
            for u in (cov.get("untested") or [])[:6]:
                lines.append(f"  untested: {u.get('method')} {u.get('path')}")
        except Exception:
            pass

    if brain.approaches:
        lines.append("Approaches tried (do not blindly repeat failures):")
        for a in brain.approaches[-8:]:
            lines.append(f"  - {a.technique} @ {a.target or '?'} → {a.result}")

    if brain.next_steps:
        lines.append("Next steps:")
        for s in brain.next_steps[:8]:
            lines.append(f"  - {s}")

    specs = specialists_from_open_hypotheses(brain)
    lines.append(
        f"Suggested fireteam from hypotheses: fireteam_dispatch(specialists={specs!r}) "
        "or specialists=\"auto\""
    )
    # Methodology assessment checklist
    try:
        progress = methodology_progress(brain)
        lines.append(format_methodology_progress_for_prompt(progress))
    except Exception:
        pass
    lines.append(
        "Process: observe → threat model (aim) → methodology cards → spawn hunters "
        "(partitioned by focus area) → submit_finding_candidate → independent_verify "
        "(fresh agent) → create_finding → record_surface_coverage → report."
    )
    lines.append(
        "Findings: demonstrated-compromise writeups (description + impact + assets + "
        "remediation). Default/weak login is a foothold until privileged APIs are proven "
        "(Grafana: /api/admin/settings, /api/datasources, /api/serviceaccounts/search, "
        "existing Prometheus datasource proxy). JS-leaked client_id/client_secret is a "
        "foothold until a live in-scope API returns non-public records (bounded sample). "
        "CWE-321 client HMAC / Object.keys-join signing keys and MQTT/RFID ICS creds in a "
        "public bundle are the finding — reconstruction is enough; API timeout is not a kill. "
        "EmailJS keys in JS are a foothold until a browser-context canary send to an "
        "engagement-controlled inbox (never employees). "
        "Anonymous Azure Function env dump: classify leaked secret classes (Cosmos, Storage, "
        "MACHINEKEY, EasyAuth, AAD, App Insights); do not inject code as the managed identity. "
        "OpenAPI/DRF mass assignment: writable id/created/user without readOnly is SUBMIT "
        "even if the database is down; a 'shared across all users' list description is "
        "missing tenant isolation — do not dump ICS/OT hierarchies. "
        "Unauth OpenAPI account lookup (/api/auth/account/?email=): security: {} plus "
        "is_staff/role, OR 200/404/500 vs sibling 401, is SUBMIT Critical — a down "
        "database or 404 existence oracle is not a kill. One canary email only; do "
        "not spray employee inboxes. Do not claim a 200 role body unless stdout has it. "
        "Unauth ASP.NET settings write: sibling write 401 vs POST /api/Settings/SaveSettings "
        "200 Content-Length: 0 (void success) is SUBMIT (High). GET GetSettings 500 is "
        "not a kill. One canary key (aegis-verify-*); do not replace the settings "
        "collection or flip enableNotifications/createPlannerTasks. Remediation is "
        "[Authorize] + Admin role / FallbackPolicy. *.azurewebsites.net App Service is "
        "not an Azure Function env dump. "
        "CORS: ACAO reflecting a canary Origin AND credentials=true is SUBMIT (header proof; "
        "no victim tab required). Keycloak webOrigins=* on token/userinfo/admin is the IdP "
        "variant — do not dump /users; do not ship an HTML exploit page. "
        "Keycloak admin-cli password grant: invalid_grant without a client_secret plus no "
        "429/lockout on <=8 fake attempts is SUBMIT — do not hydra/rockyou; do not kill "
        "because a valid password was not guessed."
    )
    return "\n".join(lines)


def mission_from_hypotheses(brain: EngagementBrain) -> str:
    open_hyps = [h for h in brain.hypotheses if h.status in ("open", "in_progress")]
    if not open_hyps:
        return (
            f"Attack {brain.target or 'the target'} using tester process: prove or kill "
            "open trust-boundary hypotheses with differential evidence."
        )
    bullets = "; ".join(f"{h.specialist}:{h.title}" for h in open_hyps[:6])
    cred_note = ""
    if brain.credentials:
        cred_note = (
            f" Known credentials available ({len(brain.credentials)}); use for authenticated "
            "follow-ups (do not re-spray)."
        )
    threat_note = ""
    if brain.focus_areas:
        slices = "; ".join(
            f"{fa.get('specialist')}={fa.get('id')}" for fa in brain.focus_areas[:5]
        )
        threat_note = f" Stay inside your focus area ({slices})."
    return (
        f"Prove or kill these open hypotheses on {brain.target or 'target'}: {bullets}. "
        f"Use compare_requests for authz/tenant/Host diffs. "
        f"Stay in your specialist lane.{cred_note}{threat_note}"
    )


def classify_finding_type(title: str = "", description: str = "", tags: Optional[Iterable[str]] = None) -> str:
    """Best-effort vuln class for chain enqueue."""
    blob = f"{title} {description} {' '.join(tags or [])}".lower()
    if "emqx" in blob:
        return "emqx_default"
    if "arangodb" in blob or ":8529" in blob or "/_open/auth" in blob:
        return "arangodb_default"
    if any(
        t in blob
        for t in (
            "default-login",
            "default login",
            "default credential",
            "prom-operator",
            "cwe-1393",
            "weak credential",
            "trivial admin",
            "trivial credential",
            "username-as-password",
            "karen:karen",
            "kevin:kevin",
            "couchdb-default",
            "authsession",
            "cookie forgery",
            "couch_httpd_auth",
        )
    ):
        return "default_login"
    if "host header" in blob or "host-header" in blob or "x-forwarded-host" in blob:
        return "host_header"
    if (
        "/api/auth/account" in blob
        or "account lookup" in blob
        or "user enumeration" in blob
        or "user account statistics" in blob
        or ("is_staff" in blob and "email" in blob)
    ):
        return "unauth_account_lookup"
    if any(
        t in blob
        for t in (
            "savesettings",
            "save settings",
            "/api/settings",
            "missing [authorize]",
            "missing authorize",
            "unauthenticated settings write",
            "unauth_settings_write",
        )
    ):
        return "unauth_settings_write"
    if any(
        t in blob
        for t in (
            "reset_email",
            "reset-email",
            "email change",
            "change email",
            "email-change",
            "djoser",
        )
    ):
        return "email_change_ato"
    if any(
        t in blob
        for t in (
            "missing authorization header",
            "bypassauthorization",
            "bypass authorization",
            "auth middleware",
            "middleware bypass",
            "no authorization header",
            "without an authorization header",
        )
    ):
        return "auth_header_bypass"
    if any(t in blob for t in ("get_stream", "url_key")) or (
        ("socket.io" in blob or "socketio" in blob)
        and any(t in blob for t in ("idor", "unauth", "siteid", "camera stream"))
        and "cors" not in blob
        and "origin" not in blob
        and "acao" not in blob
    ):
        return "socketio_idor"
    if any(
        t in blob
        for t in (
            "celery-task",
            "celery_task",
            "ml model",
            "ml pipeline",
            "/api/v1/train",
            "logixtwin",
            "missing rbac",
            "missing role-based",
        )
    ):
        return "ml_pipeline_rbac"
    if any(
        t in blob
        for t in (
            "mass assignment",
            "mass-assignment",
            "writable id",
            "extra_kwargs",
            "property-level authorization",
            "property level authorization",
            "cwe-915",
            "request serializer",
            "/api/schema",
        )
    ):
        return "mass_assignment"
    if "idor" in blob or "bola" in blob or "broken object" in blob:
        return "idor"
    if "ssrf" in blob:
        return "ssrf"
    if "elasticsearch" in blob or ":9200" in blob or "xpack.security" in blob:
        return "elasticsearch_unauth"
    if "arangodb" in blob or ":8529" in blob or "/_open/auth" in blob:
        return "arangodb_default"
    if "mongodb" in blob or ":27017" in blob:
        return "mongodb_unauth"
    if "emqx" in blob:
        return "emqx_default"
    if "auth0" in blob or "identitymigrate" in blob:
        return "auth0_mgmt_token"
    if "gitlab" in blob:
        return "gitlab_unauth"
    if (
        "docker registry" in blob
        or "/v2/_catalog" in blob
        or "azurecr" in blob
        or "anonymous pull" in blob
        or "anonymouspullenabled" in blob
        or ("container registry" in blob and "anonymous" in blob)
    ):
        return "docker_registry"
    if "django debug" in blob or ("django" in blob and "debug" in blob):
        return "django_debug"
    if "vendorjson" in blob or "vendor json" in blob:
        return "vendorjson_unauth"
    if "usertype" in blob or "user-supplied admin" in blob or "publicportal" in blob or "public portal" in blob:
        return "client_role_param"
    if any(
        t in blob
        for t in (
            "admin-cli",
            "admin_cli",
            "password grant",
            "direct access grant",
            "resource owner password",
            "invalid_grant",
        )
    ) or (
        "keycloak" in blob
        and any(t in blob for t in ("lockout", "brute-force", "brute force", "rate limit"))
    ):
        return "keycloak_password_grant"
    if (
        "cors" in blob
        or "access-control-allow-origin" in blob
        or "weborigins" in blob
        or ("keycloak" in blob and "origin" in blob)
    ):
        return "cors_credentials"
    if "/api/chat" in blob or "azure openai" in blob or "openai api proxy" in blob:
        return "openai_proxy_unauth"
    if "wiki" in blob and (
        "self-reg" in blob
        or "self-registered" in blob
        or "open registration" in blob
        or "open self-registration" in blob
        or "wiki write" in blob
    ):
        return "wiki_open_reg"
    if (
        "downloadable binary" in blob
        or "publicly-downloadable" in blob
        or ("hardcoded" in blob and "binary" in blob)
    ):
        return "binary_hardcoded_creds"
    if "client-side-only" in blob or "client-side only" in blob:
        return "client_side_auth"
    if any(
        t in blob
        for t in (
            "azure function",
            "function app",
            "authlevel",
            "azurewebjobsstorage",
            "machinekey",
            "website_auth",
            "tester function",
            "cwe-526",
            "azurewebsites.net",
        )
    ):
        return "azure_function_env_dump"
    if any(
        t in blob
        for t in (
            "client_secret",
            "hardcoded api",
            "hardcoded credential",
            "javascript bundle",
            "js bundle",
            "_next/static",
            "cwe-312",
            "cwe-540",
            "emailjs",
            "hmac",
            "hs256",
            "cwe-321",
            "signing key",
            "encryption_key",
            "encryptionkey",
            "mqtt",
            "rfid",
        )
    ):
        return "js_secrets"
    return "unknown"


# ---------------------------------------------------------------------------
# Methodology progress / assessment readiness
# ---------------------------------------------------------------------------


_HIGH_PRI = {"critical", "high"}
# Coverage leftovers are expected last — do not block complete on them alone.
_COVERAGE_METHOD_IDS = {"coverage_known_vulns"}
_COVERAGE_HUNTS = {"coverage"}


def methodology_progress(
    brain: EngagementBrain | Dict[str, Any] | None,
    *,
    cmap: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Summarize methodology-card progress for gates and prompts.

    ready_for_coverage: map ready + at least one methodology/map card seeded
    ready_to_complete: no unresolved high-priority non-coverage methodology cards
    """
    if isinstance(brain, dict) or brain is None:
        brain = engagement_brain_from_dict(brain)

    cards = [
        h for h in brain.hypotheses
        if h.source in ("methodology", "map") or h.methodology_id
    ]
    open_cards = [h for h in cards if h.status in ("open", "in_progress")]
    proven = [h for h in cards if h.status == "proven"]
    killed = [h for h in cards if h.status == "killed"]

    def _is_coverage(h: Hypothesis) -> bool:
        mid = (h.methodology_id or "").lower()
        if mid in _COVERAGE_METHOD_IDS:
            return True
        if "coverage" in (h.title or "").lower() and h.specialist == "coverage":
            return True
        return False

    blocking = [
        h for h in open_cards
        if h.priority in _HIGH_PRI and not _is_coverage(h)
    ]
    open_coverage = [h for h in open_cards if _is_coverage(h)]

    map_ready = bool((cmap or {}).get("ready_for_attack")) if cmap else False
    has_method_cards = bool(cards) or bool((cmap or {}).get("methodologies"))
    seeded = has_method_cards or bool(brain.hypotheses)

    checklist = []
    for h in sorted(
        cards,
        key=lambda x: ({"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.priority, 9), x.title),
    ):
        checklist.append({
            "id": h.id,
            "methodology_id": h.methodology_id or "",
            "title": h.title,
            "status": h.status,
            "priority": h.priority,
            "specialist": h.specialist,
            "cwe_ids": list(h.cwe_ids or []),
            "owasp": h.owasp or "",
        })

    ready_for_coverage = map_ready and seeded and (
        # Prefer: high-pri logic cards resolved OR still open but brain exists
        # Coverage may run in parallel with remaining medium cards after fireteam started.
        len(proven) + len(killed) > 0 or len(blocking) == 0 or len(cards) > 0
    )
    # Stricter: coverage spray should wait until no high-pri blockers OR fireteam attempted
    ready_for_coverage_spray = seeded and (
        len(blocking) == 0 or any(h.status == "in_progress" for h in cards) or len(proven) + len(killed) > 0
    )

    ready_to_complete_methods = seeded and len(blocking) == 0
    cov = coverage_progress(brain)
    pending_candidates = [
        c for c in (brain.candidates or [])
        if (c.get("status") if isinstance(c, dict) else getattr(c, "status", "")) == "pending"
    ]
    pending_ras = [
        r for r in (brain.pending_risk_assessments or [])
        if isinstance(r, dict) and r.get("status") != "complete"
    ]
    ready_to_complete = (
        ready_to_complete_methods
        and cov.get("ready_to_complete_coverage", True)
        and not pending_candidates
        and not pending_ras
    )
    blockers = [
        {
            "id": h.id,
            "methodology_id": h.methodology_id,
            "title": h.title,
            "specialist": h.specialist,
            "priority": h.priority,
            "status": h.status,
        }
        for h in blocking[:12]
    ]
    for row in (cov.get("untested") or [])[:8]:
        blockers.append({
            "id": row.get("key") or row.get("path"),
            "methodology_id": "coverage",
            "title": f"untested {row.get('method', '')} {row.get('path', '')}".strip(),
            "specialist": "coverage",
            "priority": "high",
            "status": "untested",
        })
    for c in pending_candidates[:6]:
        if isinstance(c, dict):
            blockers.append({
                "id": c.get("id"),
                "methodology_id": "verify",
                "title": f"pending verify: {c.get('title')}",
                "specialist": "independent_verifier",
                "priority": "high",
                "status": "pending",
            })

    for r in pending_ras[:6]:
        blockers.append({
            "id": r.get("finding_id"),
            "methodology_id": "risk_assessment",
            "title": f"pending RA: {r.get('title')}",
            "specialist": "risk_assessor",
            "priority": "high",
            "status": "pending",
        })

    return {
        "seeded": seeded,
        "map_ready": map_ready,
        "total_cards": len(cards),
        "open": len(open_cards),
        "proven": len(proven),
        "killed": len(killed),
        "blocking_high_priority": len(blocking),
        "open_coverage": len(open_coverage),
        "ready_for_coverage": ready_for_coverage,
        "ready_for_coverage_spray": ready_for_coverage_spray or (map_ready and seeded and len(blocking) == 0),
        "ready_to_complete": ready_to_complete,
        "ready_to_complete_methods": ready_to_complete_methods,
        "coverage": cov,
        "pending_candidates": len(pending_candidates),
        "pending_risk_assessments": len(pending_ras),
        "blockers": blockers,
        "checklist": checklist,
        "summary": (
            f"Methodologies: {len(proven)} proven, {len(killed)} killed, "
            f"{len(open_cards)} open ({len(blocking)} high-priority blocking complete). "
            f"Coverage: {cov.get('summary', '')}. "
            f"Candidates pending verify: {len(pending_candidates)}. "
            f"Findings pending Marcus RA: {len(pending_ras)}."
        ),
    }


def format_methodology_progress_for_prompt(progress: Dict[str, Any]) -> str:
    if not progress or not progress.get("seeded"):
        return (
            "Methodology checklist: not seeded yet. Run execute_deep_crawl → "
            "sync_engagement_brain before coverage or complete."
        )
    lines = [
        progress.get("summary") or "Methodology progress:",
        f"ready_for_coverage_spray={progress.get('ready_for_coverage_spray')}  "
        f"ready_to_complete={progress.get('ready_to_complete')}",
    ]
    cov = progress.get("coverage") or {}
    if cov:
        lines.append(cov.get("summary") or "")
        for u in (cov.get("untested") or [])[:6]:
            lines.append(f"  untested: {u.get('method')} {u.get('path')}")
    if progress.get("pending_candidates"):
        lines.append(
            f"Pending independent_verify: {progress.get('pending_candidates')} candidate(s). "
            "Do not create_finding until confirmed."
        )
    if progress.get("pending_risk_assessments"):
        lines.append(
            f"Pending Marcus RA: {progress.get('pending_risk_assessments')} finding(s). "
            "Call assess_finding_risk (or fireteam_dispatch specialists=risk_assessor). "
            "Do not complete until RA is complete."
        )
    blockers = progress.get("blockers") or []
    if blockers:
        lines.append("Blocking (prove or kill before complete):")
        for b in blockers[:8]:
            lines.append(
                f"  - [{b.get('priority')}/{b.get('status')}] {b.get('methodology_id') or b.get('id')}: "
                f"{b.get('title')} → {b.get('specialist')}"
            )
    checklist = progress.get("checklist") or []
    if checklist:
        lines.append("Full methodology checklist:")
        for c in checklist[:14]:
            cwes = ",".join((c.get("cwe_ids") or [])[:3])
            mid = c.get("methodology_id") or "—"
            lines.append(
                f"  - [{c.get('status')}] {mid} | {c.get('title')}"
                + (f" (CWE {cwes})" if cwes else "")
            )
    if progress.get("ready_to_complete"):
        lines.append("All high-priority methodology cards resolved — safe to complete after coverage/report.")
    else:
        lines.append(
            "Do NOT complete yet. Prove/kill blocking cards (or completion_reason must include "
            "'defer methodologies' / 'force complete')."
        )
    return "\n".join(lines)


def boost_methodologies_for_cwes(
    brain: EngagementBrain,
    cwe_ids: Iterable[str],
    *,
    cve_id: str = "",
    evidence: str = "",
) -> List[Hypothesis]:
    """
    CVE→CWE loop-back: raise priority / annotate open methodology cards that share CWEs.

    Returns hypotheses that were boosted or annotated.
    """
    wanted = {str(c).upper() if str(c).upper().startswith("CWE-") else f"CWE-{c}" for c in cwe_ids if c}
    # Also accept bare numbers already normalized above
    wanted = {c if c.startswith("CWE-") else f"CWE-{c}" for c in wanted}
    touched: List[Hypothesis] = []
    note = f"CVE {cve_id} maps to {', '.join(sorted(wanted)[:6])}" if cve_id else ""
    for h in brain.hypotheses:
        if h.status not in ("open", "in_progress"):
            continue
        card_cwes = {str(c).upper() for c in (h.cwe_ids or [])}
        if not card_cwes.intersection(wanted):
            continue
        if h.priority not in ("critical",):
            if h.priority == "low":
                h.priority = "high"
            elif h.priority == "medium":
                h.priority = "high"
        if note and note not in (h.evidence or ""):
            h.evidence = ((h.evidence + " | ") if h.evidence else "") + note
            if evidence:
                h.evidence = (h.evidence + f"; {evidence[:200]}")[:2000]
        h.updated_at = datetime.now(timezone.utc).isoformat()
        touched.append(h)
    if touched:
        brain.next_steps = _derive_next_steps(brain)
        # Prepend CVE-driven next step
        brain.next_steps.insert(
            0,
            f"CVE→CWE loop-back: prioritize {', '.join(h.methodology_id or h.id for h in touched[:4])} "
            f"(shared CWEs with {cve_id or 'finding'})",
        )
        brain.next_steps = brain.next_steps[:8]
    return touched


# ---------------------------------------------------------------------------
# Coverage accounting (surfaces.json denominator)
# ---------------------------------------------------------------------------


_COVERAGE_STATUSES = ("untested", "in_focus", "finding", "tested_clean", "skipped")


def surface_key(method: str = "GET", path: str = "", host: str = "") -> str:
    method = (method or "GET").upper().strip()
    path = (path or "/").strip() or "/"
    host = (host or "").strip().lower()
    if path.startswith("http://") or path.startswith("https://"):
        from urllib.parse import urlparse
        parsed = urlparse(path)
        host = host or (parsed.netloc or "").lower()
        path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return f"{method} {host}{path}" if host else f"{method} {path}"


def _focus_surface_set(brain: EngagementBrain) -> set[str]:
    keys: set[str] = set()
    for fa in brain.focus_areas or []:
        for s in fa.get("surfaces") or []:
            text = str(s).strip()
            if not text:
                continue
            if " " in text and text.split(" ", 1)[0].isupper():
                keys.add(text)
            else:
                keys.add(f"GET {text}")
    return keys


def denominator_surfaces(brain: EngagementBrain) -> List[Dict[str, Any]]:
    """Inventory rows that must be accounted before complete.

    Focus-area surfaces plus takes_input rows (capped) — not every static asset.
    """
    focus = _focus_surface_set(brain)
    out: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for s in brain.surfaces or []:
        method = str(s.get("method") or "GET")
        path = str(s.get("path") or "/")
        host = str(s.get("host") or "")
        key = surface_key(method, path, host)
        takes = bool(s.get("takes_input"))
        in_focus = key in focus or any(path in f or f.endswith(path) for f in focus)
        if not takes and not in_focus:
            continue
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "key": key,
            "method": method,
            "path": path,
            "host": host,
            "takes_input": takes,
            "in_focus": in_focus,
        })
        if len(out) >= 60:
            break
    return out


def seed_coverage_from_surfaces(brain: EngagementBrain) -> EngagementBrain:
    rows = []
    existing: set[str] = set()
    for row in brain.coverage or []:
        if not isinstance(row, dict):
            continue
        row = dict(row)
        row["key"] = surface_key(
            row.get("method") or "GET",
            row.get("path") or "/",
            row.get("host") or "",
        )
        if row["key"] in existing:
            continue
        rows.append(row)
        existing.add(row["key"])
    for s in denominator_surfaces(brain):
        if s["key"] in existing:
            continue
        rows.append({
            "key": s["key"],
            "method": s["method"],
            "path": s["path"],
            "host": s.get("host") or "",
            "status": "in_focus" if s.get("in_focus") else "untested",
            "reason": "",
            "hypothesis_id": "",
            "finding_title": "",
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })
        existing.add(s["key"])
    brain.coverage = rows
    return brain


def record_surface_coverage(
    brain: EngagementBrain,
    *,
    method: str = "GET",
    path: str = "",
    status: str = "tested_clean",
    reason: str = "",
    hypothesis_id: str = "",
    finding_title: str = "",
    host: str = "",
) -> Dict[str, Any]:
    status = (status or "tested_clean").strip().lower()
    if status not in _COVERAGE_STATUSES:
        status = "tested_clean"
    if status == "skipped" and not (reason or "").strip():
        raise ValueError("skipped coverage requires a reason")
    path = (path or brain.target or "/").strip() or "/"
    host = (host or "").strip()
    key = surface_key(method, path, host)
    if path.startswith("http://") or path.startswith("https://"):
        from urllib.parse import urlparse
        parsed = urlparse(path)
        host = host or parsed.netloc
        path = parsed.path or "/"
    elif not path.startswith("/"):
        path = "/" + path
    now = datetime.now(timezone.utc).isoformat()
    rows = list(brain.coverage or [])
    rec_host = (host or "").strip().lower()
    for row in rows:
        row_host = (row.get("host") or "").strip().lower()
        if row.get("key") == key or (
            (row.get("path") or "") == path
            and (row.get("method") or "GET").upper() == method.upper()
            and row_host == rec_host
        ):
            row["status"] = status
            row["reason"] = reason[:500]
            row["hypothesis_id"] = hypothesis_id or row.get("hypothesis_id") or ""
            row["finding_title"] = finding_title or row.get("finding_title") or ""
            row["updated_at"] = now
            brain.coverage = rows
            return row
    rec = {
        "key": key,
        "method": method.upper(),
        "path": path,
        "host": host,
        "status": status,
        "reason": reason[:500],
        "hypothesis_id": hypothesis_id,
        "finding_title": finding_title,
        "updated_at": now,
    }
    rows.append(rec)
    brain.coverage = rows
    return rec


def coverage_progress(brain: EngagementBrain | Dict[str, Any] | None) -> Dict[str, Any]:
    if isinstance(brain, dict) or brain is None:
        brain = engagement_brain_from_dict(brain)
    seed_coverage_from_surfaces(brain)
    denom = denominator_surfaces(brain)
    by_key = {
        r.get("key"): r
        for r in (brain.coverage or [])
        if isinstance(r, dict) and r.get("key")
    }
    buckets = {s: [] for s in _COVERAGE_STATUSES}
    untested: List[Dict[str, Any]] = []
    for s in denom:
        row = by_key.get(s["key"]) or {}
        st = (row.get("status") or "untested").strip().lower()
        merged = {**s, **row}
        if st in ("finding", "tested_clean", "skipped"):
            buckets[st].append(merged)
        else:
            merged["status"] = "untested"
            untested.append(merged)
            buckets["untested"].append(merged)
    accounted = (
        len(buckets["finding"])
        + len(buckets["tested_clean"])
        + len(buckets["skipped"])
    )
    denom_n = len(denom)
    ready = len(untested) == 0
    return {
        "denominator": denom_n,
        "finding": len(buckets["finding"]),
        "tested_clean": len(buckets["tested_clean"]),
        "skipped": len(buckets["skipped"]),
        "untested_count": len(untested),
        "untested": untested[:20],
        "tested_clean_rows": buckets["tested_clean"][:20],
        "skipped_rows": buckets["skipped"][:20],
        "finding_rows": buckets["finding"][:20],
        "ready_to_complete_coverage": ready,
        "summary": (
            f"coverage {accounted}/{denom_n or 0} accounted "
            f"(finding={len(buckets['finding'])} clean={len(buckets['tested_clean'])} "
            f"skipped={len(buckets['skipped'])} untested={len(untested)})"
        ),
    }


# ---------------------------------------------------------------------------
# internals
# ---------------------------------------------------------------------------


def _derive_next_steps(brain: EngagementBrain) -> List[str]:
    steps: List[str] = []
    progress = methodology_progress(brain)
    blocking = progress.get("blockers") or []
    if blocking:
        steps.append(
            "Prove/kill blocking methodologies: "
            + ", ".join(
                f"{b.get('specialist')}({b.get('methodology_id') or b.get('id')})"
                for b in blocking[:4]
            )
        )
        steps.append("Use compare_requests for any authz/tenant/Host hypothesis before create_finding")
    open_hyps = [h for h in brain.hypotheses if h.status == "open"]
    if open_hyps and not blocking:
        top = sorted(
            open_hyps,
            key=lambda h: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(h.priority, 9),
        )[:4]
        steps.append(
            "fireteam_dispatch(specialists='auto') for: "
            + ", ".join(f"{h.specialist}({h.id})" for h in top)
        )
    if brain.credentials:
        steps.append(
            "Authenticated coverage: execute_nuclei with -var username/password from engagement credentials"
        )
    proven_chains = [h for h in brain.hypotheses if h.status == "proven" and h.source in ("map", "methodology")]
    if proven_chains and not any(h.source == "chain" and h.status == "open" for h in brain.hypotheses):
        steps.append("Call queue_finding_followups on proven findings to enqueue chain cards")
    pending = [
        c for c in (brain.candidates or [])
        if (c.get("status") if isinstance(c, dict) else getattr(c, "status", "")) == "pending"
    ]
    if pending:
        steps.insert(
            0,
            f"independent_verify pending candidates ({len(pending)}) — fresh agent, then create_finding",
        )
    cov = progress.get("coverage") or {}
    if cov.get("untested"):
        steps.append(
            "record_surface_coverage for untested inventory (finding | tested_clean | skipped+reason)"
        )
    if progress.get("ready_to_complete"):
        steps.append("High-priority methodologies and coverage denominator resolved — complete")
    if not steps:
        steps.append("execute_deep_crawl or inventory the checkout → build_threat_model → sync_engagement_brain")
    elif not brain.threat_model:
        steps.insert(0, "build_threat_model so hunters aim at ranked threats, not a scanner spray")
    return steps[:8]


def _looks_like_couchdb(hay: str) -> bool:
    h = (hay or "").lower()
    return any(
        s in h
        for s in (
            "couchdb",
            "_node/_local/_config",
            "authsession",
            "couch_httpd_auth",
            "/_all_dbs",
            "/_utils",
            ":5984",
        )
    )


def _maybe_extract_credential(
    brain: EngagementBrain,
    *,
    title: str,
    evidence: str,
    target: str,
) -> None:
    blob = f"{title}\n{evidence}"
    # patterns: admin:prom-operator, admin/prom-operator, user=admin password=...
    m = re.search(
        r"(?i)\b([a-z0-9._-]{1,64})\s*[:/]\s*([^\s,\"']{1,128})\b",
        blob,
    )
    if m and m.group(1).lower() in {
        "admin", "root", "user", "administrator", "grafana", "kevin", "couchdb", "guest", "tomcat",
    }:
        add_credential(
            brain,
            username=m.group(1),
            secret=m.group(2),
            source="default_login_finding",
            valid_on=[target] if target else [],
            notes=title[:200],
        )
        return
    if re.search(r"(?i)prom-operator", blob):
        add_credential(
            brain,
            username="admin",
            secret="prom-operator",
            source="default_login_finding",
            valid_on=[target] if target else [],
            notes=title[:200] or "Grafana kube-prometheus-stack default",
        )


def _maybe_extract_oauth_client(
    brain: EngagementBrain,
    *,
    title: str,
    evidence: str,
    target: str,
) -> None:
    """Stash client_id/client_secret pairs leaked from JS (redact in prompts)."""
    blob = f"{title}\n{evidence}"
    m = re.search(
        r"(?i)client[_-]?id[:\s=]+['\"]?([A-Za-z0-9_-]{16,64})['\"]?"
        r".{0,120}?"
        r"client[_-]?secret[:\s=]+['\"]?([A-Za-z0-9_-]{16,64})",
        blob,
        re.DOTALL,
    )
    if not m:
        m = re.search(
            r"(?i)client[_-]?secret[:\s=]+['\"]?([A-Za-z0-9_-]{16,64})['\"]?"
            r".{0,120}?"
            r"client[_-]?id[:\s=]+['\"]?([A-Za-z0-9_-]{16,64})",
            blob,
            re.DOTALL,
        )
        if m:
            secret, cid = m.group(1), m.group(2)
        else:
            return
    else:
        cid, secret = m.group(1), m.group(2)
    add_credential(
        brain,
        username=cid,
        secret=secret,
        secret_type="oauth_client",
        source="js_bundle",
        valid_on=[target] if target else [],
        notes=(title[:200] or "JS-leaked client_id/client_secret") + " (redact in findings)",
    )


def _maybe_extract_emailjs(
    brain: EngagementBrain,
    *,
    title: str,
    evidence: str,
    target: str,
) -> None:
    """Stash EmailJS user_id/service_id leaked from JS (redact in prompts)."""
    blob = f"{title}\n{evidence}"
    uid = re.search(
        r"(?i)(?:emailjs[_-]?user(?:_?id)?|user_id)\s*[:\s=]+\s*['\"]?([A-Za-z0-9_-]{8,64})",
        blob,
    )
    sid = re.search(
        r"(?i)(?:emailjs[_-]?service(?:_?id)?|service_id)\s*[:\s=]+\s*['\"]?(service_[A-Za-z0-9_-]+)",
        blob,
    )
    if not uid or not sid:
        return
    add_credential(
        brain,
        username=sid.group(1),
        secret=uid.group(1),
        secret_type="emailjs",
        source="js_bundle",
        valid_on=[target] if target else [],
        notes=(title[:200] or "JS-leaked EmailJS keys") + " (redact in findings)",
    )


def _maybe_extract_encryption_key(
    brain: EngagementBrain,
    *,
    title: str,
    evidence: str,
    target: str,
) -> None:
    """Stash a client encryption_key leaked from a public JS env object."""
    blob = f"{title}\n{evidence}"
    m = re.search(
        r"(?i)(?:encryption[_-]?key|encryptionKey)\s*[:\s=]+\s*['\"]([^'\"]{16,128})['\"]",
        blob,
    )
    if not m:
        return
    add_credential(
        brain,
        username="encryption_key",
        secret=m.group(1),
        secret_type="encryption_key",
        source="js_bundle",
        valid_on=[target] if target else [],
        notes=(title[:200] or "JS-leaked client encryption_key") + " (redact in findings)",
    )
