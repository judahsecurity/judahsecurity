"""
Engagement Brain — tester-process control plane for the ASM agent.

Keeps structured engagement memory that survives chat noise:

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
    source: str = "map"  # map | chain | manual | finding
    parent_finding: str = ""
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
        "assumption": "Bundles leak credentials, keys, or hidden admin APIs",
        "test": "scan_js_urls_for_secrets + retire.js on first-party bundles from the map",
        "pass_criteria": "Live or clearly production credential / sensitive key with validation notes",
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
    "coverage": {
        "title": "Coverage scan for known vulns/misconfig",
        "assumption": "Known CVE/misconfig templates may hit remaining inventory after logic hunts",
        "test": "execute_nuclei without severity filter on primary live URLs; authenticated -var if creds exist",
        "pass_criteria": "Template match with corroborating response evidence",
        "kill_criteria": "No actionable template hits after scoped coverage",
        "specialist": "coverage",
        "priority": "medium",
    },
}


_CHAIN_CARDS: Dict[str, List[Dict[str, str]]] = {
    "default_login": [
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
            "title": "Grafana SQL Expressions RCE/LFI (CVE-2024-9264) with session",
            "assumption": "Grafana + valid viewer+ session + duckdb path may allow SQL expression file read/RCE",
            "test": "With working Grafana session, POST /api/ds/query SQL expression read_blob('/etc/passwd') (or nuclei CVE-2024-9264 with creds)",
            "pass_criteria": "File contents or command impact in query response",
            "kill_criteria": "Patched version, duckdb absent, or query rejected",
            "specialist": "coverage",
            "priority": "critical",
            "id_suffix": "grafana-9264",
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
}


_FINDING_CLASS_ALIASES = {
    "default_login": "default_login",
    "default-login": "default_login",
    "default_credentials": "default_login",
    "default-credentials": "default_login",
    "grafana-default-login": "default_login",
    "weak_password": "default_login",
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
}


def seed_hypotheses_from_capability_map(
    brain: EngagementBrain,
    cmap: Optional[Dict[str, Any]],
) -> EngagementBrain:
    """Seed open hypotheses from the capability map hunt queue."""
    if not cmap:
        return brain
    brain.target = brain.target or str(cmap.get("target") or "")
    if cmap.get("authenticated") is True and "authenticated" not in brain.identities:
        brain.identities.append("authenticated")
    if brain.phase in ("recon",):
        brain.phase = "map" if not cmap.get("ready_for_attack") else "attack"

    existing = {h.id for h in brain.hypotheses}
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

    # Forms / multi-step UI → business logic card
    if len(cmap.get("forms") or []) >= 2 and "business_logic" not in hunt_names:
        hunt_names.append("business_logic")

    for hunt in hunt_names:
        card = _HUNT_CARDS.get(str(hunt))
        if not card:
            continue
        hid = _hyp_id(brain.target, hunt, card["title"])
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

    brain.next_steps = _derive_next_steps(brain)
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
        if "default" in blob and ("login" in blob or "credential" in blob or "password" in blob):
            key = "default_login"
        elif "host" in blob and "header" in blob:
            key = "host_header"
        elif "idor" in blob or "bola" in blob:
            key = "idor"
        elif "ssrf" in blob:
            key = "ssrf"
    if not key:
        return []

    if title and title not in brain.confirmed_findings:
        brain.confirmed_findings.append(title[:300])

    # Default login → record credential hint if present in evidence/title
    if key == "default_login":
        _maybe_extract_credential(brain, title=title, evidence=evidence, target=target)

    existing = {h.id for h in brain.hypotheses}
    created: List[Hypothesis] = []
    for card in _CHAIN_CARDS.get(key, []):
        # Skip Grafana-specific card unless target/title smells like Grafana
        if card.get("id_suffix") == "grafana-9264":
            if "grafana" not in blob and "grafana" not in (target or "").lower():
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
        if h.specialist and h.specialist not in selected:
            selected.append(h.specialist)
        if len(selected) >= max_specialists - 1:
            break
    if "vuln_triage" not in selected:
        selected.append("vuln_triage")
    return selected[:max_specialists]


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
    ):
        return (
            "No engagement brain yet. After execute_deep_crawl, call "
            "sync_engagement_brain (or fireteam_dispatch) to seed hypotheses from the "
            "capability map. Use compare_requests for differential proof. On confirmed "
            "findings call queue_finding_followups so authenticated/chain cards are enqueued."
        )

    lines = [
        f"Phase: {brain.phase}  target={brain.target or '?'}",
        f"Identities: {', '.join(brain.identities) or 'anonymous'}",
    ]

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
            lines.append(
                f"  - [{h.priority}/{h.status}] id={h.id} specialist={h.specialist} | {h.title}"
            )
            lines.append(f"      assumption: {h.assumption}")
            lines.append(f"      test: {h.test}")
            lines.append(f"      pass: {h.pass_criteria}")
            lines.append(f"      kill: {h.kill_criteria}")

    if proven:
        lines.append("Proven:")
        for h in proven[:6]:
            lines.append(f"  - {h.title} ({h.evidence[:120]})")

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
    lines.append(
        "Process: map → open hypotheses → spawn specialists → compare_requests proof → "
        "update_hypothesis → queue_finding_followups → coverage leftovers → report."
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
    return (
        f"Prove or kill these open hypotheses on {brain.target or 'target'}: {bullets}. "
        f"Use compare_requests for authz/tenant/Host diffs. "
        f"Stay in your specialist lane.{cred_note}"
    )


def classify_finding_type(title: str = "", description: str = "", tags: Optional[Iterable[str]] = None) -> str:
    """Best-effort vuln class for chain enqueue."""
    blob = f"{title} {description} {' '.join(tags or [])}".lower()
    if any(t in blob for t in ("default-login", "default login", "default credential", "prom-operator")):
        return "default_login"
    if "host header" in blob or "host-header" in blob or "x-forwarded-host" in blob:
        return "host_header"
    if "idor" in blob or "bola" in blob or "broken object" in blob:
        return "idor"
    if "ssrf" in blob:
        return "ssrf"
    return "unknown"


# ---------------------------------------------------------------------------
# internals
# ---------------------------------------------------------------------------


def _derive_next_steps(brain: EngagementBrain) -> List[str]:
    steps: List[str] = []
    open_hyps = [h for h in brain.hypotheses if h.status == "open"]
    if open_hyps:
        top = sorted(
            open_hyps,
            key=lambda h: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(h.priority, 9),
        )[:4]
        steps.append(
            "fireteam_dispatch(specialists='auto') for: "
            + ", ".join(f"{h.specialist}({h.id})" for h in top)
        )
        steps.append("Use compare_requests for any authz/tenant/Host hypothesis before create_finding")
    if brain.credentials:
        steps.append(
            "Authenticated coverage: execute_nuclei with -var username/password from engagement credentials"
        )
    proven_chains = [h for h in brain.hypotheses if h.status == "proven" and h.source == "map"]
    if proven_chains and not any(h.source == "chain" and h.status == "open" for h in brain.hypotheses):
        steps.append("Call queue_finding_followups on proven findings to enqueue chain cards")
    if not steps:
        steps.append("execute_deep_crawl → sync_engagement_brain to seed hypotheses")
    return steps[:8]


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
    if m and m.group(1).lower() in {"admin", "root", "user", "administrator", "grafana"}:
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
