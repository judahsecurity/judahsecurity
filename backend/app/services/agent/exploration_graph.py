"""Typed exploration lineage for one agent session.

Prowl records its reasoning across several structures (hypotheses and the
penetration task graph, observation events, follow-up proposals, coverage
cells). Each one answers part of "what was tried, what it produced, and why",
and none links to the others or to assets. This module derives one typed
graph from them, in the shape of ARTEX's exploration graph:

Nodes
  goal      the session objective
  intent    a hypothesis card, or a follow-up assignment on a coverage cell
  fact      an observation event (capture, worker_result, credential, verified_finding)
  finding   a proven hypothesis or a verified finding

Edges (src -rel-> dst)
  goal|intent|finding -spawns-> intent      the card was created from it
  intent -derived_from-> fact               the follow-up was planned from this fact
  intent -yields-> fact                     the work produced this fact
  intent -proves-> finding                  the work proved this finding

It is rebuilt from the brain on every run save (``build``), stored per
session with an asset anchor per node (``persist``), and served to the UI.
Building is pure and cheap; nothing in the planner depends on it.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

MAX_NODES = 1_500
_LABEL = 160


def _t(value: Any, limit: int = 0) -> str:
    out = str(value or "").strip()
    return out[:limit] if limit else out


def _host(value: Any) -> str:
    text = _t(value).lower()
    if "://" in text:
        text = text.split("://", 1)[1]
    return text.split("/")[0].split("@")[-1].split(":")[0].rstrip(".")


def _get(brain: Any, name: str, default: Any) -> Any:
    if isinstance(brain, dict):
        return brain.get(name, default)
    return getattr(brain, name, default)


def _as_dict(row: Any) -> Dict[str, Any]:
    if isinstance(row, dict):
        return row
    to_dict = getattr(row, "to_dict", None)
    return to_dict() if callable(to_dict) else {}


class _Graph:
    def __init__(self) -> None:
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Tuple[str, str, str]] = []
        self._edge_set: set = set()

    def node(self, key: str, kind: str, label: str, **attrs: Any) -> str:
        if key not in self.nodes and len(self.nodes) < MAX_NODES:
            self.nodes[key] = {"key": key, "kind": kind, "label": _t(label, _LABEL) or kind, **{
                k: v for k, v in attrs.items() if v not in (None, "", [])}}
        return key

    def edge(self, src: str, rel: str, dst: str) -> None:
        if src in self.nodes and dst in self.nodes and src != dst and (src, rel, dst) not in self._edge_set:
            self._edge_set.add((src, rel, dst))
            self.edges.append((src, rel, dst))


def build(brain: Any, *, objective: str = "") -> Dict[str, Any]:
    """Derive the lineage graph from an engagement brain (dict or dataclass)."""
    g = _Graph()
    target = _t(_get(brain, "target", ""))
    goal = g.node("goal", "goal", objective or (f"Assess {target}" if target else "Assessment"),
                  host=_host(target), status=_t(_get(brain, "phase", "")))

    hyps = [_as_dict(h) for h in _get(brain, "hypotheses", None) or []]
    task_nodes = (_get(brain, "task_graph", None) or {}).get("nodes") or {}
    cells = [c for c in _get(brain, "coverage_cells", None) or [] if isinstance(c, dict) and c.get("id")]
    cells_by_id = {c["id"]: c for c in cells}
    events = [e for e in _get(brain, "observation_events", None) or [] if isinstance(e, dict) and e.get("id")]

    # --- intents: hypothesis cards -------------------------------------------------
    title_to_intent: Dict[str, str] = {}
    finding_by_title: Dict[str, str] = {}
    for h in hyps:
        if not h.get("id"):
            continue
        key = g.node(f"intent:{h['id']}", "intent", h.get("title") or h["id"],
                     status=_t(h.get("status")), specialist=_t(h.get("specialist")),
                     source=_t(h.get("source")), host=_host(h.get("target") or target),
                     parameter=_t(h.get("parameter")), ref=h["id"])
        title_to_intent[_t(h.get("title")).lower()] = key
        if h.get("status") == "proven":
            fkey = g.node(f"finding:{h['id']}", "finding", h.get("title") or h["id"],
                          status="proven", host=_host(h.get("target") or target),
                          evidence=_t(h.get("evidence"), 300))
            g.edge(key, "proves", fkey)
            finding_by_title[_t(h.get("title")).lower()] = fkey

    for h in hyps:
        if not h.get("id"):
            continue
        key = f"intent:{h['id']}"
        node = task_nodes.get(h["id"]) or {}
        parents = [f"intent:{d}" for d in node.get("depends_on") or [] if f"intent:{d}" in g.nodes]
        parent_finding = _t(h.get("parent_finding")).lower()
        if parent_finding:
            if parent_finding in finding_by_title:
                parents.append(finding_by_title[parent_finding])
            else:
                # A chain card created from a reported finding outside the cards.
                fkey = g.node(f"finding:title:{hashlib.sha1(parent_finding.encode()).hexdigest()[:12]}",
                              "finding", h.get("parent_finding"), status="reported",
                              host=_host(h.get("target") or target))
                finding_by_title[parent_finding] = fkey
                g.edge(goal, "spawns", fkey)
                parents.append(fkey)
        for parent in parents or [goal]:
            g.edge(parent, "spawns", key)
        if node.get("last_failure", "").startswith("Prerequisite refuted"):
            g.nodes[key]["blocked_reason"] = _t(node["last_failure"], 200)

    # --- facts -----------------------------------------------------------------------
    for e in events:
        facts = e.get("facts") or {}
        kind = _t(e.get("kind"))
        label = {
            "capture": f"{facts.get('method', 'GET')} {facts.get('host', '')}{facts.get('path', '')}",
            "worker_result": f"{facts.get('verdict', 'result')}: {facts.get('test_class', '')} "
                             f"{facts.get('path', '')}",
            "credential": f"Identity {facts.get('credential_identity', '')} {facts.get('role', '')}".strip(),
            "verified_finding": f"Verified {facts.get('test_class', '')} {facts.get('path', '')}",
        }.get(kind, kind)
        g.node(e["id"], "fact", label, fact_kind=kind, status=_t(e.get("status")),
               host=_host(facts.get("host") or e.get("scope")),
               evidence_ids=list(e.get("evidence_ids") or [])[:6])

    # --- intents: follow-up assignments on coverage cells ---------------------------
    for cell in cells:
        followup = cell.get("followup") or {}
        if not followup.get("event_ids") and cell.get("source") != "observation_followup":
            continue
        key = g.node(f"followup:{cell['id']}", "intent",
                     f"{cell.get('test_type', 'test')} {cell.get('method', '')} {cell.get('path', '')}"
                     f" [{cell.get('parameter', '')}]",
                     status=_t(cell.get("status")), specialist=_t(cell.get("specialist")),
                     source="followup", host=_host(cell.get("host")), parameter=_t(cell.get("parameter")),
                     reason=_t(followup.get("reason") or cell.get("reason"), 200), ref=cell["id"])
        for event_id in followup.get("event_ids") or []:
            g.edge(key, "derived_from", event_id)

    def _intent_for_cell(cell_id: str) -> Optional[str]:
        if f"followup:{cell_id}" in g.nodes:
            return f"followup:{cell_id}"
        hyp = _t((cells_by_id.get(cell_id) or {}).get("hypothesis_id"))
        return f"intent:{hyp}" if hyp and f"intent:{hyp}" in g.nodes else None

    for e in events:
        facts = e.get("facts") or {}
        intent = _intent_for_cell(_t(facts.get("coverage_cell_id")))
        if not intent:
            continue
        if e.get("kind") == "worker_result":
            g.edge(intent, "yields", e["id"])
        elif e.get("kind") == "verified_finding":
            fkey = g.node(f"finding:{facts.get('finding_id')}", "finding",
                          (cells_by_id.get(facts.get("coverage_cell_id")) or {}).get("finding_title")
                          or f"Finding {facts.get('finding_id')}",
                          status="verified", host=_host(facts.get("host")))
            g.edge(intent, "yields", e["id"])
            g.edge(intent, "proves", fkey)

    return {
        "nodes": list(g.nodes.values()),
        "edges": [{"source": s, "rel": r, "target": d} for s, r, d in g.edges],
        "truncated": len(g.nodes) >= MAX_NODES,
    }


def digest(graph: Dict[str, Any]) -> str:
    return hashlib.sha1(json.dumps(graph, sort_keys=True, default=str).encode()).hexdigest()[:16]


def persist(organization_id: Optional[int], session_id: Optional[str], brain: Any,
            *, objective: str = "", db=None) -> bool:
    """Store the session's lineage graph and node -> asset anchors if it changed."""
    if not organization_id or not session_id or not brain:
        return False
    graph = build(brain, objective=objective)
    if len(graph["nodes"]) <= 1:
        return False
    fingerprint = digest(graph)

    from app.models.agent_exploration import AgentExplorationAnchor, AgentExplorationGraph
    from app.services.agent.test_coverage_store import _resolve_assets

    own = db is None
    if own:
        from app.db.database import SessionLocal
        db = SessionLocal()
    try:
        org_id, sid = int(organization_id), str(session_id)[:128]
        row = db.get(AgentExplorationGraph, sid)
        if row is not None and row.organization_id != org_id:
            return False
        if row is not None and row.digest == fingerprint:
            return False
        assets = _resolve_assets(db, org_id, (n.get("host", "") for n in graph["nodes"]))
        for node in graph["nodes"]:
            if assets.get(node.get("host", "")):
                node["asset_id"] = assets[node["host"]]
        counts: Dict[str, int] = {}
        for node in graph["nodes"]:
            counts[node["kind"]] = counts.get(node["kind"], 0) + 1
        if row is None:
            row = AgentExplorationGraph(session_id=sid, organization_id=org_id)
            db.add(row)
        row.digest = fingerprint
        row.graph = graph
        row.node_counts = counts
        row.updated_at = datetime.utcnow()
        db.query(AgentExplorationAnchor).filter(AgentExplorationAnchor.session_id == sid).delete()
        for node in graph["nodes"]:
            if node.get("asset_id") and node["kind"] in ("intent", "fact", "finding"):
                db.add(AgentExplorationAnchor(
                    session_id=sid, organization_id=org_id, node_key=node["key"][:200],
                    kind=node["kind"], asset_id=node["asset_id"], label=node["label"][:_LABEL],
                    status=_t(node.get("status"), 24),
                ))
        db.commit()
        return True
    except Exception:
        db.rollback()
        raise
    finally:
        if own:
            db.close()
