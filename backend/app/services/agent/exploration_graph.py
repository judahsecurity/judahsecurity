"""Per-run exploration graph: what Prowl observed, hypothesised, tried and proved.

Built read-only from the run snapshot's Engagement Brain. Nodes:

* ``asset``        — a host the run touched, linked to the org asset when known
* ``observation``  — a recon lead (live host, endpoint, technology, CNAME...)
* ``hypothesis``   — a specialist card / task-graph node with its status
* ``candidate``    — a submitted finding candidate, verified or still a lead
* ``finding``      — a published finding

Edges carry the lineage: observation ``spawns`` hypothesis, hypothesis
``depends_on`` / ``derived_from`` hypothesis, finding ``chains_to``
hypothesis, hypothesis ``yields`` candidate, candidate ``proves`` finding,
and every node is ``anchored`` to the asset it is about. Per-asset coverage
counts come from the same anchors.

Nothing here is execution authority; values are redacted and truncated.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional
from urllib.parse import urlsplit

MAX_NODES = 800
_TERMINAL_PROVEN = {"proven", "confirmed", "verified"}
_TERMINAL_KILLED = {"killed", "refuted", "disproven"}


def _redact(value: Any, limit: int = 240) -> str:
    from app.services.agent.observability import redact_string

    return redact_string(str(value or ""))[:limit]


def host_of(target: Any) -> str:
    text = str(target or "").strip()
    if not text:
        return ""
    try:
        parsed = urlsplit(text if "://" in text else f"//{text}")
        return (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _status_bucket(status: str) -> str:
    status = (status or "").lower()
    if status in _TERMINAL_PROVEN:
        return "proven"
    if status in _TERMINAL_KILLED:
        return "killed"
    if status in ("blocked", "inconclusive", "retry"):
        return "blocked"
    if status in ("running", "in_progress", "leased"):
        return "running"
    return "open"


def _verified(candidate: dict, receipts: dict) -> bool:
    from app.services.agent.autonomy_timeline import verified_candidate

    try:
        return bool(verified_candidate(candidate, receipts))
    except Exception:
        return str(candidate.get("status") or "").lower() in ("verified", "confirmed")


class _Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []
        self._edge_keys: set[tuple] = set()
        self.truncated = False

    def node(self, node_id: str, **data) -> Optional[str]:
        if node_id in self.nodes:
            return node_id
        if len(self.nodes) >= MAX_NODES:
            self.truncated = True
            return None
        self.nodes[node_id] = {"id": node_id, **data}
        return node_id

    def edge(self, source: Optional[str], target: Optional[str], kind: str) -> None:
        if not source or not target or source == target:
            return
        if source not in self.nodes or target not in self.nodes:
            return
        key = (source, target, kind)
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        self.edges.append({"source": source, "target": target, "kind": kind})


def build_exploration_graph(
    snapshot: dict,
    *,
    assets: Iterable[tuple[int, str]] = (),
    findings: Iterable[dict] = (),
) -> dict:
    """``assets``: (asset_id, value) for the org; ``findings``: dicts with id, title, severity, status, asset_id."""
    brain = (snapshot or {}).get("engagement_brain") or {}
    graph = _Graph()
    asset_ids = {str(value or "").lower(): asset_id for asset_id, value in assets}
    findings_by_id = {int(f["id"]): f for f in findings if f.get("id") is not None}
    asset_value_by_id = {asset_id: value for value, asset_id in asset_ids.items()}

    def asset_node(target: Any) -> Optional[str]:
        host = host_of(target)
        if not host:
            return None
        asset_id = asset_ids.get(host)
        return graph.node(f"asset:{host}", type="asset", label=host, asset_id=asset_id)

    primary = asset_node(brain.get("target"))
    if primary:
        graph.nodes[primary]["primary"] = True

    # Observations
    observation_ids: dict[str, str] = {}
    for row in (brain.get("recon_observations") or [])[-200:]:
        if not isinstance(row, dict) or not row.get("id"):
            continue
        nid = graph.node(
            f"obs:{row['id']}", type="observation", label=_redact(row.get("value") or row.get("kind"), 120),
            kind=str(row.get("kind") or ""), source=str(row.get("source") or "")[:80],
            target=_redact(row.get("target"), 300), at=row.get("observed_at"),
        )
        if nid:
            observation_ids[str(row["id"])] = nid
            graph.edge(nid, asset_node(row.get("target") or row.get("host")), "anchored")

    # Hypotheses (+ task-graph status and dependencies)
    task_nodes = (brain.get("task_graph") or {}).get("nodes") or {}
    hypotheses = [h for h in (brain.get("hypotheses") or []) if isinstance(h, dict) and h.get("id")]
    hyp_ids: dict[str, str] = {}
    for row in hypotheses[:MAX_NODES]:
        hid = str(row["id"])
        task = task_nodes.get(hid) if isinstance(task_nodes, dict) else None
        task = task if isinstance(task, dict) else {}
        status = str(task.get("status") or row.get("status") or "open")
        nid = graph.node(
            f"hyp:{hid}", type="hypothesis", label=_redact(row.get("title"), 160),
            specialist=str(row.get("specialist") or task.get("specialist") or ""),
            status=status, bucket=_status_bucket(status), priority=str(row.get("priority") or ""),
            source=str(row.get("source") or ""), owasp=str(row.get("owasp") or ""),
            parameter=_redact(row.get("parameter"), 80), identity=_redact(row.get("identity"), 64),
            attempts=int(task.get("attempts") or 0),
            blocked_reason=_redact(task.get("blocked_reason") or task.get("last_failure"), 300),
            target=_redact(row.get("target"), 300), at=row.get("created_at"),
        )
        if nid:
            hyp_ids[hid] = nid
    for row in hypotheses[:MAX_NODES]:
        nid = hyp_ids.get(str(row["id"]))
        if not nid:
            continue
        graph.edge(nid, asset_node(row.get("target") or brain.get("target")), "anchored")
        graph.edge(observation_ids.get(str(row.get("observation_id") or "")), nid, "spawns")
        task = task_nodes.get(str(row["id"])) if isinstance(task_nodes, dict) else None
        if isinstance(task, dict):
            for dep in task.get("depends_on") or []:
                graph.edge(hyp_ids.get(str(dep)), nid, "depends_on")
            graph.edge(hyp_ids.get(str(task.get("parent_hypothesis_id") or "")), nid, "derived_from")
        parent_finding = str(row.get("parent_finding") or (task or {}).get("parent_finding") or "")
        if parent_finding.isdigit() and int(parent_finding) in findings_by_id:
            f = findings_by_id[int(parent_finding)]
            fid = graph.node(f"finding:{f['id']}", type="finding", label=_redact(f.get("title"), 160),
                             severity=f.get("severity"), status=f.get("status"), finding_id=f["id"])
            graph.edge(fid, nid, "chains_to")

    # Candidates and the findings they produced
    receipts = brain.get("verification_receipts") or {}
    for row in (brain.get("candidates") or [])[:200]:
        if not isinstance(row, dict) or not row.get("id"):
            continue
        verified = _verified(row, receipts)
        cid = graph.node(
            f"cand:{row['id']}", type="candidate", label=_redact(row.get("title") or row.get("id"), 160),
            verified=verified, status=str(row.get("status") or ""),
            target=_redact(row.get("target"), 300),
        )
        graph.edge(hyp_ids.get(str(row.get("hypothesis_id") or "")), cid, "yields")
        graph.edge(cid, asset_node(row.get("target")), "anchored")
        finding_id = str(row.get("finding_id") or "")
        if finding_id.isdigit() and int(finding_id) in findings_by_id:
            f = findings_by_id[int(finding_id)]
            fid = graph.node(f"finding:{f['id']}", type="finding", label=_redact(f.get("title"), 160),
                             severity=f.get("severity"), status=f.get("status"), finding_id=f["id"])
            graph.edge(cid, fid, "proves")

    for f in findings_by_id.values():
        fid = f"finding:{f['id']}"
        if fid in graph.nodes:
            value = asset_value_by_id.get(f.get("asset_id"))
            graph.edge(fid, asset_node(value) if value else None, "anchored")

    # Coverage per asset from anchors
    coverage: dict[str, dict] = {}
    for edge in graph.edges:
        if edge["kind"] != "anchored":
            continue
        source = graph.nodes[edge["source"]]
        bucket = coverage.setdefault(edge["target"], {
            "observations": 0, "hypotheses": 0, "proven": 0, "killed": 0, "open": 0,
            "blocked": 0, "running": 0, "candidates": 0, "findings": 0,
        })
        kind = source["type"]
        if kind == "observation":
            bucket["observations"] += 1
        elif kind == "hypothesis":
            bucket["hypotheses"] += 1
            bucket[source["bucket"]] += 1
        elif kind == "candidate":
            bucket["candidates"] += 1
        elif kind == "finding":
            bucket["findings"] += 1
    for asset_id, counts in coverage.items():
        if asset_id in graph.nodes:
            graph.nodes[asset_id]["coverage"] = counts

    nodes = list(graph.nodes.values())
    counts: dict[str, int] = {}
    for node in nodes:
        counts[node["type"]] = counts.get(node["type"], 0) + 1
    return {
        "target": _redact(brain.get("target"), 300),
        "phase": brain.get("phase"),
        "saved_at": (snapshot or {}).get("saved_at"),
        "nodes": nodes,
        "edges": graph.edges,
        "counts": counts,
        "truncated": graph.truncated,
    }


def finding_ids_in_snapshot(snapshot: dict) -> set[int]:
    brain = (snapshot or {}).get("engagement_brain") or {}
    ids: set[int] = set()
    for row in brain.get("candidates") or []:
        value = str((row or {}).get("finding_id") or "") if isinstance(row, dict) else ""
        if value.isdigit():
            ids.add(int(value))
    for row in brain.get("hypotheses") or []:
        value = str((row or {}).get("parent_finding") or "") if isinstance(row, dict) else ""
        if value.isdigit():
            ids.add(int(value))
    return ids


def hosts_in_snapshot(snapshot: dict) -> set[str]:
    brain = (snapshot or {}).get("engagement_brain") or {}
    hosts = {host_of(brain.get("target"))}
    for key in ("recon_observations", "hypotheses", "candidates"):
        for row in brain.get(key) or []:
            if isinstance(row, dict):
                hosts.add(host_of(row.get("target") or row.get("host")))
    hosts.discard("")
    return hosts
