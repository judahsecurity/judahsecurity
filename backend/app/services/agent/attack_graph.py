"""Entity-centric attack graph built from an agent session's EvoGraph chain.

``evograph.get_session_chain`` returns the agent's run as a tool-by-tool
timeline (chain -> step -> step -> finding). That is the right shape for a
replay, but not for answering "how did the agent get from the internet to
something valuable?".

This module turns the same payload into a layered graph:

    Internet -> host -> endpoint -> [action] -> capability -> [action] -> ...

* Graph nodes are *things*: the attacker origin, hosts, endpoints, and
  capabilities the agent obtained (credentials, privileged identities,
  code execution, data access).
* Actions sit between them as small connector nodes, with the evidence that
  produced them (step, tool, arguments, output summary, the agent's thought).
* Every node carries a validation status:
    - ``proven``   — a published finding for this session that the independent
                     verifier reproduced (``exploit_verified``) or an analyst
                     confirmed. Nothing else can claim this.
    - ``observed`` — a tool ran and the agent reported it, or a published
                     finding that was not runtime-verified
    - ``inferred`` — the step failed, or the agent's wording is speculative
                     ("may be vulnerable", "outdated version")

Repeated sightings of the same issue on the same endpoint are merged, and
past ``MAX_NODES`` the least certain leaf actions are hidden (``meta.hidden``).

Edges are only drawn from a capability to a later action when the later step
actually presents auth material (header, cookie, token, password) against the
same host, or runs in post-exploitation. Otherwise the action hangs off the
endpoint it hit. The graph never invents a chain the evidence does not show.

The builder is pure (safe to unit test); ``load_session_proofs`` is the only
function that touches the database.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from app.services.agent.observability import redact_string

ORIGIN_ID = "origin"

# Capability classification, most specific first. Applied to finding text.
#
# Each rule is (kind, label, strong, weak). A ``strong`` match alone means the
# agent obtained the capability. A ``weak`` noun only counts alongside a
# _GAINED verb, so "missing CSRF token" or "admin panel found" do not become
# stolen credentials or privileged access.
_GAINED = re.compile(
    r"\b(leak\w*|expos\w*|disclos\w*|obtain\w*|captur\w*|harvest\w*|"
    r"stole\w*|stolen|retriev\w*|extract\w*|dump\w*|hard-?coded|"
    r"gain\w*|logged in|authenticated as|accessed|read|download\w*|export\w*|"
    r"enumerat\w*|valid)\b",
    re.I,
)

_CAPABILITY_RULES: List[Tuple[str, str, re.Pattern, Optional[re.Pattern]]] = [
    (
        "rce",
        "Code execution",
        re.compile(
            r"\b(rce|remote code|code execution|command execution|"
            r"command injection|reverse shell|webshell|web shell|"
            r"os command|ssti)\b",
            re.I,
        ),
        None,
    ),
    (
        "credential",
        "Credential",
        re.compile(
            r"(\bAKIA[0-9A-Z]{4,}|\bprivate key\b|\bdefault credentials\b|"
            r"\bcredential stuffing succeeded\b|\bcracked\b)",
            re.I,
        ),
        re.compile(
            r"\b(credentials?|passwords?|api[ _-]?keys?|secrets?|"
            r"access[ _-]?keys?|jwt|bearer token|session (cookie|token)|"
            r"auth(entication)? token)\b",
            re.I,
        ),
    ),
    (
        "identity",
        "Privileged access",
        re.compile(
            r"\b(privilege escalation|escalated privileges?|account takeover|"
            r"auth(entication)? bypass|bypass(ed)? auth\w*|"
            r"assumed? (an? )?(iam )?role|impersonat\w*|idor|"
            r"broken access control|admin access|access as admin)\b",
            re.I,
        ),
        re.compile(r"\b(admin(istrator)?|root|superuser|iam role)\b", re.I),
    ),
    (
        "data",
        "Sensitive data",
        re.compile(
            r"(\bdb dump\b|\bdatabase dump\b|\bexfiltrat\w*|/etc/passwd|"
            r"\blocal file (read|inclusion)\b|\barbitrary file read\b|"
            r"\bpublic(ly)? (readable|listable) (s3 )?bucket\b)",
            re.I,
        ),
        re.compile(
            r"\b(database|pii|ssn|card numbers?|credit cards?|"
            r"customer (data|records)|s3 bucket|bucket|"
            r"sensitive (data|information)|backups?|source code|"
            r"files?|tables?)\b",
            re.I,
        ),
    ),
]

# A later step presenting any of these is evidence it used a captured capability.
_USES_AUTH = re.compile(
    r"(authorization|bearer|cookie|x-api-key|api[_-]?key|access[_-]?token|"
    r"\btoken\b|password|passwd|aws_access|session)",
    re.I,
)

_URL = re.compile(r"https?://[^\s'\"<>,}\]\)]+", re.I)
_HOST_KEY = re.compile(
    r"['\"](?:target|host|hostname|domain|ip|address)['\"]\s*:\s*['\"]([^'\"/\s]+)['\"]",
    re.I,
)


def _clip(text: str, limit: int) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (text or "").lower()).strip()


def classify_capability(text: str) -> Optional[Tuple[str, str]]:
    """Return (kind, label) for what a finding grants, or None."""
    text = text or ""
    gained = bool(_GAINED.search(text))
    for kind, label, strong, weak in _CAPABILITY_RULES:
        if strong.search(text) or (weak is not None and gained and weak.search(text)):
            return kind, label
    return None


def capability_title(text: str, kind: str) -> str:
    """Name the captured thing ("API key", "Card numbers") rather than the action."""
    text = text or ""
    if kind == "credential" and re.search(r"\bAKIA|\baws\b", text, re.I):
        return "AWS access key"
    if kind == "identity":
        for pattern, name in (
            (r"\badmin(istrator)?\b", "Admin access"),
            (r"\b(root|superuser)\b", "Root access"),
            (r"\biam role\b|\bassumed? .*role\b", "IAM role"),
            (r"\baccount takeover\b", "Victim account"),
        ):
            if re.search(pattern, text, re.I):
                return name
        return "Privileged access"
    for rule_kind, label, strong, weak in _CAPABILITY_RULES:
        if rule_kind != kind:
            continue
        for pattern in (weak, strong):
            if pattern is None:
                continue
            match = pattern.search(text)
            if match:
                phrase = " ".join(match.group(0).split())
                return phrase[:1].upper() + phrase[1:]
        return label
    return text


def extract_targets(tool_args: str) -> Tuple[Optional[str], Optional[str]]:
    """Pull (host, path) from a step's stringified tool arguments."""
    raw = tool_args or ""
    match = _URL.search(raw)
    if match:
        parsed = urlparse(match.group(0))
        host = (parsed.hostname or "").lower() or None
        path = parsed.path or ""
        if path in ("", "/"):
            path = ""
        return host, path or None
    match = _HOST_KEY.search(raw)
    if match:
        return match.group(1).lower(), None
    return None, None


# Wording that marks an LLM finding as a guess rather than an observation.
_SPECULATIVE = re.compile(
    r"\b(may|might|could|possibl[ey]|potential(ly)?|likely|appears? to|"
    r"seems? to|suspected|suspicious|unconfirmed|if exploitable|"
    r"version[- ]based|outdated version|vulnerable version)\b",
    re.I,
)

# Above this many nodes, drop the least certain actions first.
MAX_NODES = 60


def step_status(phase: str, success: Any, text: str = "") -> str:
    """Status of something the agent *said* it saw.

    A step's ``success`` only means the tool ran; the finding text is the
    model's reading of the output. So step-derived nodes top out at
    ``observed`` — ``proven`` comes only from published, verified findings
    (see ``proofs`` in :func:`build_attack_graph`).
    """
    if success is True and not _SPECULATIVE.search(text or ""):
        return "observed"
    return "inferred"


def proof_status(proof: Dict[str, Any]) -> Optional[str]:
    """Status for a published finding, or None if it was ruled a false positive."""
    verdict = (proof.get("verdict") or "").lower()
    if verdict == "false_positive":
        return None
    if (proof.get("verification_level") or "") == "exploit_verified" or verdict == "confirmed":
        return "proven"
    return "observed"


_RANK = {"inferred": 0, "observed": 1, "proven": 2}


def _stronger(a: str, b: str) -> str:
    return a if _RANK.get(a, 0) >= _RANK.get(b, 0) else b


def _tokens(text: str) -> set:
    stop = {"the", "a", "an", "in", "on", "of", "to", "via", "and", "or", "with",
            "for", "from", "is", "are", "at", "by", "using", "parameter"}
    return {t for t in _norm(text).split() if len(t) > 2 and t not in stop}


def _similar(a: str, b: str, threshold: float = 0.5) -> bool:
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return False
    return len(ta & tb) / min(len(ta), len(tb)) >= threshold


class _Builder:
    def __init__(self) -> None:
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.order: List[str] = []
        self.edges: Dict[str, Dict[str, Any]] = {}
        # capability ids per host, most recent last; "*" holds credentials,
        # which are commonly reused across hosts.
        self.captured: Dict[str, List[str]] = {}

    def node(self, nid: str, **fields: Any) -> Dict[str, Any]:
        existing = self.nodes.get(nid)
        if existing:
            existing["status"] = _stronger(existing["status"], fields.get("status", "inferred"))
            return existing
        node = {"id": nid, **fields}
        self.nodes[nid] = node
        self.order.append(nid)
        return node

    def edge(self, source: str, target: str, status: str, label: str = "") -> None:
        eid = f"{source}->{target}"
        existing = self.edges.get(eid)
        if existing:
            existing["status"] = _stronger(existing["status"], status)
            return
        self.edges[eid] = {"id": eid, "source": source, "target": target,
                           "status": status, "label": label}

    def promote(self, nid: str, status: str) -> None:
        node = self.nodes.get(nid)
        if node:
            node["status"] = _stronger(node["status"], status)
        # Proof on a node also proves the way in to it.
        if status == "proven":
            for e in self.edges.values():
                if e["target"] == nid and _RANK[e["status"]] < _RANK["proven"]:
                    src = self.nodes.get(e["source"])
                    if src and src["kind"] in ("origin", "host", "endpoint"):
                        e["status"] = "proven"
                        self.promote(e["source"], "proven")

    def anchor(self, host: Optional[str], path: Optional[str], status: str) -> str:
        self.node(ORIGIN_ID, kind="origin", title="Internet",
                  subtitle="Unauthenticated attacker", status="observed")
        if not host:
            return ORIGIN_ID
        host_id = f"host:{host}"
        self.node(host_id, kind="host", title=host, subtitle="Host", status=status)
        self.edge(ORIGIN_ID, host_id, status)
        if not path:
            return host_id
        ep_id = f"endpoint:{host}{path}"
        self.node(ep_id, kind="endpoint", title=_clip(path, 48), subtitle="Endpoint", status=status)
        self.edge(host_id, ep_id, status)
        return ep_id

    def used_capability(self, host: Optional[str], args: str, post_exploitation: bool) -> Optional[str]:
        if not (post_exploitation or _USES_AUTH.search(args or "")):
            return None
        pool = self.captured.get(host or "", []) + self.captured.get("*", [])
        return pool[-1] if pool else None

    def find_action(self, anchor: str, text: str) -> Optional[Dict[str, Any]]:
        for e in self.edges.values():
            if e["source"] != anchor:
                continue
            n = self.nodes.get(e["target"])
            if n and n["kind"] == "action" and _similar(n.get("description") or n["title"], text):
                return n
        return None

    def find_action_on_host(self, host: Optional[str], text: str) -> Optional[Dict[str, Any]]:
        for n in self.nodes.values():
            if n["kind"] != "action" or n.get("finding_id"):
                continue
            if host and n.get("host") not in (host, None):
                continue
            if _similar(n.get("description") or n["title"], text):
                return n
        return None

    def capability(self, action_id: str, text: str, host: Optional[str], status: str) -> None:
        cap = classify_capability(text)
        if not cap:
            return
        kind, label = cap
        title = capability_title(text, kind)
        cap_id = f"{kind}:{host or '*'}:{_norm(title)}"
        self.node(cap_id, kind=kind, title=_clip(title, 40), subtitle=label,
                  description=_clip(text, 500), status=status, host=host)
        self.promote(cap_id, status)
        self.edge(action_id, cap_id, status)
        pool = self.captured.setdefault("*" if kind == "credential" else (host or "*"), [])
        if cap_id in pool:
            pool.remove(cap_id)
        pool.append(cap_id)


def _steps_from_chain(chain: Dict[str, Any]) -> List[Dict[str, Any]]:
    steps = [n for n in (chain.get("nodes") or []) if str(n.get("id", "")).startswith("step-")]
    steps.sort(key=lambda n: (n.get("properties") or {}).get("iteration") or 0)
    return steps


def _add_steps(b: _Builder, steps: List[Dict[str, Any]]) -> int:
    last_host: Optional[str] = None
    failed_attempts = 0
    for step in steps:
        props = step.get("properties") or {}
        iteration = props.get("iteration") or 0
        phase = (props.get("phase") or "").lower()
        tool = props.get("tool_name") or ""
        args = props.get("tool_args") or ""
        findings = [f for f in (props.get("findings") or []) if f.get("type")]
        failed_attempts += len([f for f in (props.get("failures") or []) if f.get("tool")])

        host, path = extract_targets(args)
        host = host or last_host
        if host:
            last_host = host

        relevant = [
            f for f in findings
            if f.get("type") == "vulnerability" or classify_capability(f.get("description") or "")
        ]
        if not relevant:
            continue

        evidence = {
            "iteration": iteration,
            "phase": phase,
            "tool": tool,
            "args": _clip(redact_string(args), 500),
            "output": _clip(redact_string(props.get("output_summary") or ""), 1000),
            "thought": _clip(redact_string(props.get("thought") or ""), 300),
            "success": props.get("success"),
        }

        for idx, finding in enumerate(relevant):
            desc = redact_string(finding.get("description") or "")
            status = step_status(phase, props.get("success"), desc)
            anchor = b.anchor(host, path, status)
            used = b.used_capability(host, args, phase == "post_exploitation")

            existing = b.find_action(anchor, desc)
            if existing:
                # Same issue seen again: merge instead of drawing a duplicate.
                existing["occurrences"] = existing.get("occurrences", 1) + 1
                b.promote(existing["id"], status)
                action_id = existing["id"]
            else:
                action_id = f"action:{iteration}:{idx}"
                b.node(action_id, kind="action", title=_clip(desc, 60) or tool or "Action",
                       subtitle=tool or phase, status=status, severity=finding.get("severity") or "",
                       description=_clip(desc, 500), host=host, evidence=evidence, occurrences=1)
                b.edge(anchor, action_id, status)
            if used:
                b.edge(used, action_id, status, label="uses")
            b.capability(action_id, desc, host, status)
    return failed_attempts


def _proof_target(proof: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], str]:
    """(host, path, joined args) from a published finding's proof chain."""
    host = (proof.get("host") or "").lower() or None
    path: Optional[str] = None
    joined = ""
    for step in proof.get("chain") or []:
        args = str(step.get("args") or "")
        joined += " " + args
        h, p = extract_targets(args)
        if p and (not host or h == host) and not path:
            path = p
            host = host or h
    return host, path, joined


def _add_proofs(b: _Builder, proofs: List[Dict[str, Any]]) -> int:
    added = 0
    for proof in proofs:
        status = proof_status(proof)
        if status is None:
            continue
        title = redact_string(proof.get("title") or "Finding")
        text = " ".join(redact_string(str(proof.get(k) or "")) for k in ("title", "description", "impact"))
        host, path, chain_args = _proof_target(proof)
        anchor = b.anchor(host, path, status)
        chain = proof.get("chain") or []
        evidence = {
            "iteration": 0,
            "phase": "published finding",
            "tool": ", ".join(dict.fromkeys(str(s.get("display_tool") or s.get("tool") or "") for s in chain if s))[:120],
            "args": _clip(redact_string(chain_args), 500),
            "output": _clip(redact_string(" · ".join(str(s.get("outcome") or "") for s in chain if s.get("outcome"))), 1000),
            "thought": _clip(redact_string(proof.get("not_demonstrated") or ""), 300),
            "success": True,
        }
        fields = dict(
            title=_clip(title, 60), severity=proof.get("severity") or "",
            description=_clip(text, 500), finding_id=proof.get("id"),
            verification=proof.get("verification_level") or proof.get("verdict") or "",
        )

        existing = b.find_action(anchor, title) or b.find_action_on_host(host, title)
        if existing:
            existing.update(fields)
            if existing.get("evidence", {}).get("phase") != "published finding":
                existing["step_evidence"] = existing.get("evidence")
            existing["evidence"] = evidence
            b.edge(anchor, existing["id"], status)
            b.promote(existing["id"], status)
            action_id = existing["id"]
        else:
            action_id = f"finding:{proof.get('id')}"
            b.node(action_id, kind="action", subtitle="Published finding", status=status,
                   host=host, evidence=evidence, occurrences=1, **fields)
            b.edge(anchor, action_id, status)
            used = b.used_capability(host, chain_args, False)
            if used:
                b.edge(used, action_id, status, label="uses")
        b.promote(action_id, status)
        # Upstream capability this proof relied on is proven too.
        for e in list(b.edges.values()):
            if e["target"] == action_id and e["label"] == "uses" and status == "proven":
                e["status"] = "proven"
                b.promote(e["source"], "proven")
        b.capability(action_id, text, host, status)
        added += 1
    return added


def _prune(b: _Builder, max_nodes: int) -> int:
    """Drop least-certain leaf actions until the graph fits; returns hidden count."""
    hidden = 0

    def outgoing(nid: str) -> bool:
        return any(e["source"] == nid for e in b.edges.values())

    def remove(nid: str) -> None:
        b.nodes.pop(nid, None)
        b.order.remove(nid)
        for eid in [k for k, e in b.edges.items() if nid in (e["source"], e["target"])]:
            del b.edges[eid]

    for status in ("inferred", "observed"):
        if len(b.nodes) <= max_nodes:
            break
        for nid in [n for n in reversed(b.order)
                    if b.nodes[n]["kind"] == "action" and b.nodes[n]["status"] == status
                    and not b.nodes[n].get("finding_id") and not outgoing(n)]:
            if len(b.nodes) <= max_nodes:
                break
            remove(nid)
            hidden += 1
        # Endpoints/hosts left with nothing behind them go too.
        changed = True
        while changed:
            changed = False
            for nid in list(b.order):
                if b.nodes[nid]["kind"] in ("endpoint", "host") and not outgoing(nid):
                    remove(nid)
                    changed = True
    return hidden


def build_attack_graph(
    chain: Dict[str, Any],
    proofs: Optional[List[Dict[str, Any]]] = None,
    max_nodes: int = MAX_NODES,
) -> Dict[str, Any]:
    """Convert a ``get_session_chain`` payload into an entity attack graph.

    ``proofs`` are the session's published findings (see
    :func:`load_session_proofs`); only those can make a node ``proven``.
    """
    b = _Builder()
    meta = chain.get("meta") or {}
    failed_attempts = _add_steps(b, _steps_from_chain(chain))
    published = _add_proofs(b, proofs or [])
    hidden = _prune(b, max_nodes)

    nodes = [b.nodes[nid] for nid in b.order]
    edges = list(b.edges.values())
    capability_kinds = {"credential", "identity", "rce", "data"}
    return {
        "nodes": nodes,
        "edges": edges,
        "meta": {
            "session_id": meta.get("session_id"),
            "objective": meta.get("objective"),
            "status": meta.get("status"),
            "hosts": sum(1 for n in nodes if n["kind"] == "host"),
            "actions": sum(1 for n in nodes if n["kind"] == "action"),
            "capabilities": sum(1 for n in nodes if n["kind"] in capability_kinds),
            "proven": sum(1 for n in nodes if n["kind"] == "action" and n["status"] == "proven"),
            "published": published,
            "hidden": hidden,
            "failed_attempts": failed_attempts,
        },
    }


def load_session_proofs(db: Any, organization_id: int, session_id: str, limit: int = 200) -> List[Dict[str, Any]]:
    """Published agent findings for one session, shaped for ``build_attack_graph``."""
    from app.models.asset import Asset
    from app.models.vulnerability import Vulnerability

    rows = (
        db.query(Vulnerability)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .filter(
            Asset.organization_id == organization_id,
            Vulnerability.detected_by == "agent",
            Vulnerability.metadata_[("agent_detection", "session_id")].as_string() == str(session_id),
        )
        .order_by(Vulnerability.id.asc())
        .limit(limit)
        .all()
    )
    proofs: List[Dict[str, Any]] = []
    for v in rows:
        meta = v.metadata_ if isinstance(v.metadata_, dict) else {}
        det = meta.get("agent_detection") if isinstance(meta.get("agent_detection"), dict) else {}
        host = ""
        if v.asset is not None:
            value = v.asset.value or ""
            host = (urlparse(value).hostname or "") if "://" in value else value.split("/")[0]
        proofs.append({
            "id": v.id,
            "title": v.title,
            "description": v.description or "",
            "impact": v.impact or "",
            "severity": getattr(v.severity, "value", v.severity) or "",
            "host": host.lower(),
            "verification_level": v.verification_level,
            "verdict": v.last_validation_verdict,
            "not_demonstrated": det.get("not_demonstrated") or "",
            "chain": [s for s in (det.get("chain") or []) if isinstance(s, dict)],
        })
    return proofs


def attach_verified_graph(chain: Dict[str, Any], organization_id: Optional[int],
                          session_id: str, db: Any = None) -> Dict[str, Any]:
    """Rebuild ``chain["attack_graph"]`` with the session's published findings.

    Opens its own session when ``db`` is None. Never raises: on any failure the
    step-only graph (which tops out at ``observed``) is left in place.
    """
    if not organization_id or not session_id:
        return chain
    try:
        if db is not None:
            proofs = load_session_proofs(db, organization_id, session_id)
        else:
            from app.db.database import SessionLocal

            with SessionLocal() as own:
                proofs = load_session_proofs(own, organization_id, session_id)
        if proofs or chain.get("nodes"):
            chain["attack_graph"] = build_attack_graph(chain, proofs=proofs)
    except Exception as e:  # pragma: no cover - defensive
        import logging

        logging.getLogger(__name__).debug(f"attack_graph proofs unavailable: {e}")
    return chain
