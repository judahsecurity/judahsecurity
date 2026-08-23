"""Compose Chariot-style attack-path campaigns from demonstrated findings.

Turns agent demonstrated-compromise chains, scanner detections, and CWE→ATT&CK
maps into left-to-right graphs: attacker → technique → host → vulnerability,
with detection-status coloring (tested / logged / undetected / prevented).
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from sqlalchemy.orm import Session, joinedload

from app.models.asset import Asset
from app.models.organization import Organization
from app.models.vulnerability import Vulnerability, VulnerabilityStatus
from app.services.mitre_enrichment_service import ATTACK_TECHNIQUES, CWE_TO_CAPEC

STATUSES = (
    "untested",
    "tested",
    "undetected",
    "logged",
    "alerted",
    "detected",
    "prevented",
)

# Highest-wins when a node has multiple signals.
_STATUS_RANK = {name: i for i, name in enumerate(STATUSES)}

TOOL_TECHNIQUES: Dict[str, str] = {
    "execute_curl": "T1592.004",
    "execute_httpx": "T1592.004",
    "execute_browser": "T1592.004",
    "execute_nuclei": "T1595.002",
    "execute_nikto": "T1595.002",
    "execute_nmap": "T1046",
    "execute_sqlmap": "T1190",
    "execute_commix": "T1190",
    "execute_jwt": "T1550.001",
    "execute_hydra": "T1110",
    "test_credential_spray": "T1110",
    "execute_dalfox": "T1059.007",
    "execute_xsstrike": "T1059.007",
    "execute_ffuf": "T1595.002",
    "execute_feroxbuster": "T1595.002",
    "test_saml_sso": "T1078",
    "execute_interceptor": "T1592.004",
}

_SECRET_RE = re.compile(
    r"hardcoded|hmac|signing secret|api[_ -]?key|private key|credential",
    re.I,
)
_INTEGRITY_RE = re.compile(r"integrity|tamper|signed request|hmac", re.I)
_BRUTE_RE = re.compile(r"brute[- ]?force|lockout|rate[- ]?limit|password spray", re.I)
_QA_RE = re.compile(r"(^|\.)(qa|staging|stg|dev|test|uat)(\.|$)", re.I)
_PROD_RE = re.compile(r"(^|\.)(prod|www|app|api|glms)(\.|$)", re.I)

_FALSE_POSITIVE = VulnerabilityStatus.FALSE_POSITIVE
_PREVENTED = {
    VulnerabilityStatus.RESOLVED,
    VulnerabilityStatus.MITIGATED,
    VulnerabilityStatus.ACCEPTED,
}

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class FindingView:
    id: int
    title: str
    description: str = ""
    impact: str = ""
    severity: str = "medium"
    status: str = "open"
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    host: str = ""
    host_label: str = ""
    env: str = ""
    asset_id: Optional[int] = None
    detected_by: str = ""
    template_id: Optional[str] = None
    has_chain: bool = False
    session_id: Optional[str] = None
    chain_steps: List[Dict[str, Any]] = field(default_factory=list)
    not_demonstrated: str = ""
    oracle_title: str = ""
    oracle_scenario: str = ""
    attack_path_class: str = ""
    validation_verdict: Optional[str] = None
    detected_at: Optional[datetime] = None
    assigned_to: Optional[str] = None

    @property
    def host_key(self) -> str:
        return (self.host or f"asset-{self.asset_id}" or "unknown").lower()


def _enum_val(value: Any) -> str:
    if value is None:
        return ""
    return str(getattr(value, "value", value) or "")


def _host_from_asset(asset: Optional[Asset], fallback: str = "") -> str:
    raw = ""
    if asset is not None:
        raw = (asset.value or asset.name or "") or ""
    raw = raw or fallback
    if "://" in raw:
        parsed = urlparse(raw)
        return (parsed.hostname or parsed.netloc or raw).split(":")[0]
    if "/" in raw and not raw.startswith("/"):
        return raw.split("/")[0].split(":")[0]
    return raw.split(":")[0]


def classify_env(host: str, tags: Optional[Iterable[str]] = None) -> str:
    lower_tags = {str(t).lower() for t in (tags or [])}
    if {"qa", "staging", "stg", "dev", "test", "uat"} & lower_tags:
        if "prod" in lower_tags or "production" in lower_tags:
            return "Production"
        if "qa" in lower_tags:
            return "QA"
        if "staging" in lower_tags or "stg" in lower_tags:
            return "Staging"
        return "Non-prod"
    if _QA_RE.search(host or ""):
        if re.search(r"(^|\.)qa(\.|$)", host or "", re.I):
            return "QA"
        if re.search(r"(^|\.)(staging|stg)(\.|$)", host or "", re.I):
            return "Staging"
        return "Non-prod"
    if "production" in lower_tags or "prod" in lower_tags:
        return "Production"
    if _PROD_RE.search(host or ""):
        return "Production"
    return "Production"


def _normalize_cwe(cwe_id: Optional[str]) -> str:
    if not cwe_id:
        return ""
    cwe = str(cwe_id).upper().strip()
    if cwe.isdigit():
        return f"CWE-{cwe}"
    if not cwe.startswith("CWE-"):
        return f"CWE-{cwe}"
    return cwe


def technique_payload(tech_id: str) -> Dict[str, str]:
    info = ATTACK_TECHNIQUES.get(tech_id) or {}
    name = info.get("name") or tech_id
    return {
        "id": tech_id,
        "name": name,
        "tactic": info.get("tactic") or "",
        "label": f"{tech_id} {name}",
    }


def techniques_for_cwe(cwe_id: Optional[str]) -> List[Dict[str, str]]:
    mapping = CWE_TO_CAPEC.get(_normalize_cwe(cwe_id)) or {}
    out = []
    for tech_id in mapping.get("attack_techniques") or []:
        out.append(technique_payload(tech_id))
    return out


def technique_for_tool(tool: Optional[str]) -> Optional[Dict[str, str]]:
    if not tool:
        return None
    name = str(tool).strip()
    tech_id = TOOL_TECHNIQUES.get(name)
    if not tech_id:
        return None
    return technique_payload(tech_id)


def heuristic_techniques(title: str, description: str = "") -> List[Dict[str, str]]:
    text = f"{title} {description}"
    out: List[Dict[str, str]] = []
    seen = set()
    if _SECRET_RE.search(text):
        out.append(technique_payload("T1552.001"))
        seen.add("T1552.001")
        out.append(technique_payload("T1592.004"))
        seen.add("T1592.004")
    if _INTEGRITY_RE.search(text) and "T1565.002" not in seen:
        out.append(technique_payload("T1565.002"))
    if _BRUTE_RE.search(text):
        out.append(technique_payload("T1110"))
    return out


def _merge_status(current: str, incoming: str) -> str:
    if _STATUS_RANK.get(incoming, 0) >= _STATUS_RANK.get(current, 0):
        return incoming
    return current


def status_for_finding(row: FindingView) -> str:
    if row.status in {s.value for s in _PREVENTED} or row.status in {"resolved", "mitigated", "accepted"}:
        return "prevented"
    has_scanner = bool(row.template_id) or (row.detected_by or "").lower() in {"nuclei", "scanner"}
    confirmed = (row.validation_verdict or "").lower() == "confirmed"
    if row.has_chain and has_scanner:
        return "detected"
    if row.has_chain and not has_scanner:
        return "undetected"
    if confirmed and has_scanner:
        return "detected"
    if row.assigned_to:
        return "alerted"
    if has_scanner:
        return "logged"
    if row.has_chain or confirmed:
        return "tested"
    return "untested"


def _short_title(title: str, limit: int = 48) -> str:
    text = re.sub(r"\s+", " ", (title or "").strip())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def path_title(group: Sequence[FindingView]) -> str:
    demonstrated = [r for r in group if r.has_chain] or list(group)
    ranked = sorted(demonstrated, key=lambda r: (_SEV_RANK.get(r.severity, 0), r.id), reverse=True)
    last = ranked[0]
    if last.oracle_title:
        return last.oracle_title[:140]
    if len({r.title for r in demonstrated}) == 1:
        return demonstrated[0].title[:140]
    first = sorted(demonstrated, key=lambda r: r.detected_at or datetime.min)[0]
    start = _short_title(first.title, 40)
    end = _short_title(last.title, 40)
    if start.lower() != end.lower():
        return f"{start} to {end}"
    return last.title[:140]


def path_summary(group: Sequence[FindingView]) -> str:
    ranked = sorted(group, key=lambda r: (_SEV_RANK.get(r.severity, 0), int(r.has_chain)), reverse=True)
    for row in ranked:
        for candidate in (row.oracle_scenario, row.impact, row.description):
            text = re.sub(r"\s+", " ", (candidate or "").strip())
            if len(text) >= 40:
                return text[:420]
    titles = "; ".join(_short_title(r.title, 60) for r in ranked[:3])
    return f"Demonstrated path across {len(group)} finding(s): {titles}."


def _is_terminal(row: FindingView) -> bool:
    return bool(_BRUTE_RE.search(row.title or "") or _BRUTE_RE.search(row.description or ""))


def group_findings(rows: Sequence[FindingView]) -> List[List[FindingView]]:
    by_session: Dict[str, List[FindingView]] = defaultdict(list)
    ungrouped: List[FindingView] = []
    for row in rows:
        if row.session_id:
            by_session[row.session_id].append(row)
        else:
            ungrouped.append(row)

    groups: List[List[FindingView]] = list(by_session.values())

    by_host: Dict[str, List[FindingView]] = defaultdict(list)
    leftover: List[FindingView] = []
    for row in ungrouped:
        if row.has_chain or row.severity in {"critical", "high"}:
            by_host[row.host_key].append(row)
        else:
            leftover.append(row)
    groups.extend(by_host.values())

    host_to_idx: Dict[str, int] = {}
    for i, group in enumerate(groups):
        for row in group:
            host_to_idx.setdefault(row.host_key, i)

    still: List[FindingView] = []
    for row in leftover:
        idx = host_to_idx.get(row.host_key)
        if idx is not None:
            groups[idx].append(row)
        else:
            still.append(row)

    for row in still:
        if row.severity in {"critical", "high"} or row.detected_by == "agent":
            groups.append([row])

    def sort_key(group: List[FindingView]) -> Tuple:
        max_sev = max((_SEV_RANK.get(r.severity, 0) for r in group), default=0)
        demonstrated = any(r.has_chain for r in group)
        latest = max((r.detected_at or datetime.min for r in group), default=datetime.min)
        return (-int(demonstrated), -max_sev, -latest.timestamp() if latest != datetime.min else 0)

    groups = [g for g in groups if g]
    groups.sort(key=sort_key)
    return groups


def _node(
    nid: str,
    kind: str,
    title: str,
    *,
    subtitle: str = "",
    status: str = "untested",
    mitre_id: str = "",
    finding_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    host: str = "",
    env: str = "",
) -> Dict[str, Any]:
    return {
        "id": nid,
        "kind": kind,
        "title": title,
        "subtitle": subtitle,
        "status": status,
        "mitre_id": mitre_id,
        "finding_id": finding_id,
        "asset_id": asset_id,
        "host": host,
        "env": env,
    }


def _edge(source: str, target: str) -> Dict[str, str]:
    return {"id": f"{source}->{target}", "source": source, "target": target}


def build_graph(group: Sequence[FindingView]) -> Tuple[List[Dict[str, Any]], List[Dict[str, str]], List[Dict[str, Any]]]:
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, str]] = []
    narrative: List[Dict[str, Any]] = []

    any_tested = any(r.has_chain or status_for_finding(r) != "untested" for r in group)
    attacker_status = "tested" if any_tested else "untested"
    nodes["attacker"] = _node(
        "attacker",
        "attacker",
        "External Attacker",
        subtitle="Internet",
        status=attacker_status,
    )
    narrative.append({
        "node_id": "attacker",
        "title": "External Attacker",
        "body": "Untrusted internet actor with no prior foothold.",
        "status": attacker_status,
    })

    recon_tech: Optional[Dict[str, str]] = None
    for row in group:
        for step in row.chain_steps:
            recon_tech = technique_for_tool(step.get("tool") or step.get("display_tool"))
            if recon_tech:
                break
        if recon_tech:
            break
    if recon_tech is None:
        for row in group:
            heur = heuristic_techniques(row.title, row.description)
            recon = next((t for t in heur if t["id"].startswith("T159")), None)
            if recon:
                recon_tech = recon
                break
    if recon_tech is None:
        recon_tech = technique_payload("T1592.004")

    recon_id = f"tech-{recon_tech['id']}"
    recon_status = "tested" if any(r.has_chain for r in group) else "untested"
    nodes[recon_id] = _node(
        recon_id,
        "technique",
        recon_tech["label"],
        subtitle=recon_tech.get("tactic") or "",
        status=recon_status,
        mitre_id=recon_tech["id"],
    )
    edges.append(_edge("attacker", recon_id))
    narrative.append({
        "node_id": recon_id,
        "title": recon_tech["label"],
        "body": "Reconnaissance of publicly reachable client configuration and application surface.",
        "status": recon_status,
    })

    rest = [r for r in group if not _is_terminal(r)]
    terminals = [r for r in group if _is_terminal(r)]
    if not rest:
        rest = list(group)
        terminals = []

    by_host: Dict[str, List[FindingView]] = defaultdict(list)
    for row in rest:
        by_host[row.host_key].append(row)

    host_ids: List[str] = []
    last_ids: List[str] = []

    for host_key, findings in by_host.items():
        sample = findings[0]
        host_id = f"host-{hashlib.sha1(host_key.encode()).hexdigest()[:10]}"
        host_status = "untested"
        for row in findings:
            host_status = _merge_status(host_status, status_for_finding(row))
        env_label = sample.env or classify_env(sample.host)
        platform = ""
        if sample.host_label and sample.host_label != sample.host:
            platform = sample.host_label
        nodes[host_id] = _node(
            host_id,
            "host",
            sample.host or host_key,
            subtitle=f"{platform} ({env_label})" if platform else env_label,
            status=host_status,
            asset_id=sample.asset_id,
            host=sample.host,
            env=env_label,
        )
        edges.append(_edge(recon_id, host_id))
        host_ids.append(host_id)
        narrative.append({
            "node_id": host_id,
            "title": sample.host or host_key,
            "body": f"{env_label} host reached from the external attack surface.",
            "status": host_status,
        })

        prev = host_id
        extra_seen = {recon_tech["id"]}
        outlet_ids: List[str] = []

        for row in findings:
            vuln_id = f"vuln-{row.id}"
            vstatus = status_for_finding(row)
            nodes[vuln_id] = _node(
                vuln_id,
                "vulnerability",
                row.title,
                subtitle=(row.cve_id or _normalize_cwe(row.cwe_id) or row.severity.title()),
                status=vstatus,
                finding_id=row.id,
                asset_id=row.asset_id,
                host=row.host,
                env=env_label,
            )
            edges.append(_edge(prev, vuln_id))
            outlet_ids.append(vuln_id)
            body = row.impact or row.oracle_scenario or row.description or row.title
            if row.chain_steps:
                proof = row.chain_steps[0].get("summary") or row.chain_steps[0].get("outcome")
                if proof:
                    body = f"{_short_title(str(proof), 160)}. {body}"
            narrative.append({
                "node_id": vuln_id,
                "title": row.title,
                "body": re.sub(r"\s+", " ", body)[:420],
                "status": vstatus,
                "finding_id": row.id,
            })
            prev = vuln_id

        extra_tech = None
        extra_status = "tested"
        for row in findings:
            candidates = heuristic_techniques(row.title, f"{row.description} {row.impact}") + techniques_for_cwe(row.cwe_id)
            # Prefer impact techniques (integrity bypass) over the recon duplicate.
            candidates.sort(key=lambda t: 0 if t["id"] == "T1565.002" else 1)
            for tech in candidates:
                if tech["id"] in extra_seen:
                    continue
                extra_tech = tech
                extra_status = status_for_finding(row)
                if extra_status == "logged" and row.has_chain:
                    extra_status = "tested"
                break
            if extra_tech:
                break
        if extra_tech:
            extra_seen.add(extra_tech["id"])
            tech_nid = f"tech-{host_id}-{extra_tech['id']}"
            nodes[tech_nid] = _node(
                tech_nid,
                "technique",
                extra_tech["label"],
                subtitle=extra_tech.get("tactic") or "",
                status=extra_status,
                mitre_id=extra_tech["id"],
                host=sample.host,
                env=env_label,
            )
            for oid in outlet_ids or [host_id]:
                edges.append(_edge(oid, tech_nid))
            narrative.append({
                "node_id": tech_nid,
                "title": extra_tech["label"],
                "body": extra_tech.get("name") or extra_tech["id"],
                "status": extra_status,
            })
            last_ids.append(tech_nid)
        else:
            last_ids.extend(outlet_ids)

    if terminals:
        term = sorted(terminals, key=lambda r: _SEV_RANK.get(r.severity, 0), reverse=True)[0]
        term_id = f"vuln-{term.id}"
        tstatus = status_for_finding(term)
        nodes[term_id] = _node(
            term_id,
            "vulnerability",
            term.title,
            subtitle=term.severity.title(),
            status=tstatus,
            finding_id=term.id,
            asset_id=term.asset_id,
            host=term.host,
            env=term.env,
        )
        sources = last_ids or host_ids or [recon_id]
        for src in sources:
            edges.append(_edge(src, term_id))
        narrative.append({
            "node_id": term_id,
            "title": term.title,
            "body": re.sub(r"\s+", " ", (term.impact or term.description or term.title))[:420],
            "status": tstatus,
            "finding_id": term.id,
        })

    # Dedupe edges
    seen_e = set()
    uniq_edges = []
    for edge in edges:
        key = (edge["source"], edge["target"])
        if key in seen_e:
            continue
        seen_e.add(key)
        uniq_edges.append(edge)

    return list(nodes.values()), uniq_edges, narrative


def _finding_view(vuln: Vulnerability) -> FindingView:
    asset = vuln.asset
    meta = vuln.metadata_ if isinstance(vuln.metadata_, dict) else {}
    agent = meta.get("agent_detection") if isinstance(meta.get("agent_detection"), dict) else {}
    oracle = meta.get("oracle") if isinstance(meta.get("oracle"), dict) else {}
    brief = oracle.get("analyst_brief") if isinstance(oracle.get("analyst_brief"), dict) else {}
    chain = agent.get("chain") if isinstance(agent.get("chain"), list) else []
    host = _host_from_asset(asset)
    tags = list(asset.tags or []) if asset is not None else []
    env = classify_env(host, tags)
    label = ""
    if asset is not None:
        label = (asset.name or "") if asset.name and asset.name != asset.value else ""
    return FindingView(
        id=int(vuln.id),
        title=vuln.title or f"Finding {vuln.id}",
        description=vuln.description or "",
        impact=vuln.impact or "",
        severity=_enum_val(vuln.severity) or "medium",
        status=_enum_val(vuln.status) or "open",
        cwe_id=vuln.cwe_id,
        cve_id=vuln.cve_id,
        host=host,
        host_label=label,
        env=env,
        asset_id=getattr(asset, "id", None) if asset is not None else vuln.asset_id,
        detected_by=vuln.detected_by or "",
        template_id=vuln.template_id,
        has_chain=bool(chain),
        session_id=str(agent["session_id"])[:128] if agent.get("session_id") else None,
        chain_steps=[s for s in chain if isinstance(s, dict)],
        not_demonstrated=str(agent.get("not_demonstrated") or ""),
        oracle_title=str(brief.get("title") or "")[:140],
        oracle_scenario=str(brief.get("attack_scenario") or brief.get("what_is_it") or "")[:800],
        attack_path_class=str(
            oracle.get("attack_path_class") or getattr(vuln, "oracle_attack_path", None) or ""
        ),
        validation_verdict=vuln.last_validation_verdict,
        detected_at=vuln.first_detected or vuln.created_at,
        assigned_to=vuln.assigned_to,
    )


def campaigns_from_views(rows: Sequence[FindingView]) -> List[Dict[str, Any]]:
    campaigns: List[Dict[str, Any]] = []
    for group in group_findings(rows):
        nodes, edges, narrative = build_graph(group)
        counts: Dict[str, int] = {s: 0 for s in STATUSES}
        for node in nodes:
            counts[node["status"]] = counts.get(node["status"], 0) + 1
        ranked = sorted(group, key=lambda r: _SEV_RANK.get(r.severity, 0), reverse=True)
        latest = max((r.detected_at for r in group if r.detected_at), default=None)
        sid = next((r.session_id for r in group if r.session_id), None)
        if sid:
            path_id = f"session-{sid}"
        elif len(group) == 1:
            path_id = f"finding-{group[0].id}"
        else:
            digest = hashlib.sha1(",".join(str(r.id) for r in sorted(group, key=lambda x: x.id)).encode()).hexdigest()[:12]
            path_id = f"cluster-{digest}"
        hosts = sorted({r.host for r in group if r.host})
        campaigns.append({
            "id": path_id,
            "title": path_title(group),
            "summary": path_summary(group),
            "target": hosts[0] if hosts else "",
            "hosts": hosts,
            "timeframe": latest.isoformat() if latest else None,
            "severity": ranked[0].severity if ranked else "medium",
            "demonstrated": any(r.has_chain for r in group),
            "status_counts": counts,
            "finding_ids": [r.id for r in group],
            "session_id": sid,
            "attack_path_class": next((r.attack_path_class for r in ranked if r.attack_path_class), ""),
            "not_demonstrated": next((r.not_demonstrated for r in group if r.not_demonstrated), ""),
            "nodes": nodes,
            "edges": edges,
            "narrative": narrative,
        })
    return campaigns


def _juicy(rows: Sequence[FindingView]) -> List[Dict[str, Any]]:
    fruit = []
    for row in rows:
        if row.severity not in {"critical", "high"}:
            continue
        if not (row.has_chain or row.attack_path_class):
            continue
        fruit.append({
            "finding_id": row.id,
            "title": row.title,
            "host": row.host,
            "severity": row.severity,
            "status": status_for_finding(row),
            "demonstrated": row.has_chain,
            "attack_path_class": row.attack_path_class,
        })
    fruit.sort(key=lambda x: (-_SEV_RANK.get(x["severity"], 0), -int(x["demonstrated"])))
    return fruit[:40]


def _signatures(rows: Sequence[FindingView]) -> List[Dict[str, Any]]:
    by_template: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        tid = (row.template_id or "").strip()
        if not tid:
            continue
        entry = by_template.setdefault(
            tid,
            {"template_id": tid, "count": 0, "hosts": set(), "severity": row.severity},
        )
        entry["count"] += 1
        if row.host:
            entry["hosts"].add(row.host)
        if _SEV_RANK.get(row.severity, 0) > _SEV_RANK.get(entry["severity"], 0):
            entry["severity"] = row.severity
    out = []
    for entry in by_template.values():
        out.append({
            "template_id": entry["template_id"],
            "count": entry["count"],
            "hosts": sorted(entry["hosts"])[:12],
            "severity": entry["severity"],
        })
    out.sort(key=lambda x: (-x["count"], -_SEV_RANK.get(x["severity"], 0)))
    return out[:80]


def _phishing(rows: Sequence[FindingView]) -> List[Dict[str, Any]]:
    out = []
    for row in rows:
        if row.attack_path_class != "phishing_delivery":
            continue
        out.append({
            "finding_id": row.id,
            "title": row.title,
            "host": row.host,
            "severity": row.severity,
            "status": status_for_finding(row),
        })
    return out[:40]


def _capabilities(db: Session, organization_id: int) -> List[Dict[str, Any]]:
    caps: List[Dict[str, Any]] = []
    try:
        from app.models.agent_conversation import AgentConversation
        from app.services.agent.run_snapshot import load_run_snapshot

        convs = (
            db.query(AgentConversation)
            .filter(AgentConversation.organization_id == organization_id)
            .order_by(AgentConversation.updated_at.desc())
            .limit(12)
            .all()
        )
        seen_targets = set()
        for conv in convs:
            snap = load_run_snapshot(organization_id, conv.session_id)
            cmap = snap.get("capability_map") if isinstance(snap, dict) else None
            if not isinstance(cmap, dict):
                continue
            target = str(cmap.get("target") or conv.title or conv.session_id)
            if target in seen_targets:
                continue
            seen_targets.add(target)
            queue = cmap.get("ranked_hunt_queue") or []
            caps.append({
                "session_id": conv.session_id,
                "target": target,
                "quality_score": cmap.get("quality_score"),
                "ready_for_attack": bool(cmap.get("ready_for_attack")),
                "authenticated": cmap.get("authenticated"),
                "capabilities": list(cmap.get("capabilities") or [])[:16],
                "ranked_hunt_queue": queue[:8],
                "updated_at": conv.updated_at.isoformat() if conv.updated_at else None,
            })
    except Exception:
        pass
    return caps


def _red_team(db: Session, organization_id: int) -> List[Dict[str, Any]]:
    try:
        from app.models.pentest_session import PentestSession

        sessions = (
            db.query(PentestSession)
            .filter(PentestSession.organization_id == organization_id)
            .order_by(PentestSession.created_at.desc())
            .limit(20)
            .all()
        )
        out = []
        for s in sessions:
            out.append({
                "id": s.id,
                "name": s.name,
                "target_url": s.target_url,
                "phase": _enum_val(s.phase),
                "total_exploits_confirmed": s.total_exploits_confirmed or 0,
                "total_exploits_attempted": s.total_exploits_attempted or 0,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            })
        return out
    except Exception:
        return []


def build_workspace(db: Session, organization_id: int) -> Dict[str, Any]:
    org = db.query(Organization).filter(Organization.id == organization_id).first()
    if not org:
        return {
            "organization": None,
            "paths": [],
            "capabilities": [],
            "signatures": [],
            "red_team": [],
            "phishing": [],
            "juicy_fruit": [],
        }

    vulns = (
        db.query(Vulnerability)
        .join(Asset)
        .options(joinedload(Vulnerability.asset))
        .filter(Asset.organization_id == organization_id)
        .filter(Asset.in_scope.is_(True))
        .filter(Vulnerability.status != _FALSE_POSITIVE)
        .order_by(Vulnerability.first_detected.desc())
        .limit(400)
        .all()
    )
    rows = [_finding_view(v) for v in vulns]
    return {
        "organization": {"id": org.id, "name": org.name, "domain": org.domain},
        "paths": campaigns_from_views(rows),
        "capabilities": _capabilities(db, organization_id),
        "signatures": _signatures(rows),
        "red_team": _red_team(db, organization_id),
        "phishing": _phishing(rows),
        "juicy_fruit": _juicy(rows),
    }
