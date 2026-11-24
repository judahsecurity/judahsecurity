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
    - ``proven``   — a successful step in an exploitation phase produced it
    - ``observed`` — a successful step saw it, but it was not exploited
    - ``inferred`` — the step failed or did not report success; a hypothesis

Edges are only drawn from a capability to a later action when the later step
actually presents auth material (header, cookie, token, password) against the
same host, or runs in post-exploitation. Otherwise the action hangs off the
endpoint it hit. The graph never invents a chain the evidence does not show.

Pure functions, no I/O: safe to unit test and to call from request handlers.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from app.services.agent.observability import redact_string

ORIGIN_ID = "origin"

EXPLOIT_PHASES = {"exploitation", "post_exploitation"}

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


def step_status(phase: str, success: Any) -> str:
    if success is True:
        return "proven" if (phase or "").lower() in EXPLOIT_PHASES else "observed"
    return "inferred"


_RANK = {"inferred": 0, "observed": 1, "proven": 2}


def _stronger(a: str, b: str) -> str:
    return a if _RANK.get(a, 0) >= _RANK.get(b, 0) else b


class _Builder:
    def __init__(self) -> None:
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.order: List[str] = []
        self.edges: Dict[str, Dict[str, Any]] = {}

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
        self.edges[eid] = {
            "id": eid,
            "source": source,
            "target": target,
            "status": status,
            "label": label,
        }

    def promote(self, nid: str, status: str) -> None:
        node = self.nodes.get(nid)
        if node:
            node["status"] = _stronger(node["status"], status)


def _steps_from_chain(chain: Dict[str, Any]) -> List[Dict[str, Any]]:
    steps = [
        n for n in (chain.get("nodes") or [])
        if str(n.get("id", "")).startswith("step-")
    ]
    steps.sort(key=lambda n: (n.get("properties") or {}).get("iteration") or 0)
    return steps


def build_attack_graph(chain: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a ``get_session_chain`` payload into an entity attack graph."""
    b = _Builder()
    steps = _steps_from_chain(chain)
    meta = chain.get("meta") or {}

    # capability node ids per host, most recent last; "*" holds credentials,
    # which are commonly reused across hosts.
    captured: Dict[str, List[str]] = {}
    last_host: Optional[str] = None
    failed_attempts = 0

    for step in steps:
        props = step.get("properties") or {}
        iteration = props.get("iteration") or 0
        phase = (props.get("phase") or "").lower()
        tool = props.get("tool_name") or ""
        args = props.get("tool_args") or ""
        status = step_status(phase, props.get("success"))
        findings = [f for f in (props.get("findings") or []) if f.get("type")]
        if props.get("failures"):
            failed_attempts += len([f for f in props["failures"] if f.get("tool")])

        host, path = extract_targets(args)
        host = host or last_host
        if host:
            last_host = host

        # Only steps that produced something worth showing become graph structure.
        relevant: List[Tuple[Dict[str, Any], Optional[Tuple[str, str]]]] = []
        for finding in findings:
            cap = classify_capability(finding.get("description") or "")
            if finding.get("type") == "vulnerability" or cap:
                relevant.append((finding, cap))
        if not relevant:
            continue

        if not b.nodes.get(ORIGIN_ID):
            b.node(
                ORIGIN_ID,
                kind="origin",
                title="Internet",
                subtitle="Unauthenticated attacker",
                status="observed",
            )

        anchor = ORIGIN_ID
        if host:
            host_id = f"host:{host}"
            b.node(host_id, kind="host", title=host, subtitle="Host", status=status)
            b.edge(ORIGIN_ID, host_id, status)
            anchor = host_id
            if path:
                ep_id = f"endpoint:{host}{path}"
                b.node(
                    ep_id,
                    kind="endpoint",
                    title=_clip(path, 48),
                    subtitle="Endpoint",
                    status=status,
                )
                b.edge(host_id, ep_id, status)
                anchor = ep_id

        # Did this step use something captured earlier?
        used_cap: Optional[str] = None
        if phase == "post_exploitation" or _USES_AUTH.search(args):
            pool = captured.get(host or "", []) + captured.get("*", [])
            if pool:
                used_cap = pool[-1]
        if used_cap:
            b.promote(used_cap, status)

        evidence = {
            "iteration": iteration,
            "phase": phase,
            "tool": tool,
            "args": _clip(redact_string(args), 500),
            "output": _clip(redact_string(props.get("output_summary") or ""), 1000),
            "thought": _clip(redact_string(props.get("thought") or ""), 300),
            "success": props.get("success"),
        }

        for idx, (finding, cap) in enumerate(relevant):
            desc = redact_string(finding.get("description") or "")
            action_id = f"action:{iteration}:{idx}"
            b.node(
                action_id,
                kind="action",
                title=_clip(desc, 60) or tool or "Action",
                subtitle=tool or phase,
                status=status,
                severity=finding.get("severity") or "",
                description=_clip(desc, 500),
                evidence=evidence,
            )
            b.edge(anchor, action_id, status)
            if used_cap:
                b.edge(used_cap, action_id, status, label="uses")

            if not cap:
                continue
            kind, label = cap
            cap_key = _norm(desc)[:60]
            cap_id = f"{kind}:{host or '*'}:{cap_key}"
            b.node(
                cap_id,
                kind=kind,
                title=_clip(capability_title(desc, kind), 40),
                subtitle=label,
                description=_clip(desc, 500),
                status=status,
                host=host,
            )
            b.edge(action_id, cap_id, status)
            pool_key = "*" if kind == "credential" else (host or "*")
            pool = captured.setdefault(pool_key, [])
            if cap_id in pool:
                pool.remove(cap_id)
            pool.append(cap_id)

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
            "failed_attempts": failed_attempts,
        },
    }
