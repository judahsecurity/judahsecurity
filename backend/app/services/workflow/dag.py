"""DAG utilities — topo sort, cycle detection, module expansion."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy.orm import Session

from app.models.workflow import Workflow, WorkflowKind, WorkflowVersion

MAX_MODULE_DEPTH = 5


class DagError(Exception):
    """Invalid workflow graph."""


def _node_map(graph: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {n["id"]: n for n in (graph.get("nodes") or []) if n.get("id")}


def _edge_list(graph: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(graph.get("edges") or [])


def validate_acyclic(graph: Dict[str, Any]) -> None:
    nodes = _node_map(graph)
    edges = _edge_list(graph)
    adj: Dict[str, List[str]] = {nid: [] for nid in nodes}
    for e in edges:
        src, tgt = e.get("source"), e.get("target")
        if src in adj and tgt in nodes:
            adj[src].append(tgt)

    visiting: Set[str] = set()
    visited: Set[str] = set()

    def dfs(n: str) -> None:
        if n in visited:
            return
        if n in visiting:
            raise DagError(f"Cycle detected at node {n}")
        visiting.add(n)
        for nxt in adj.get(n, []):
            dfs(nxt)
        visiting.remove(n)
        visited.add(n)

    for nid in nodes:
        dfs(nid)


def topological_levels(graph: Dict[str, Any]) -> List[List[str]]:
    """Return node ids grouped by execution level (ready-set scheduling)."""
    validate_acyclic(graph)
    nodes = _node_map(graph)
    edges = _edge_list(graph)
    indeg = {nid: 0 for nid in nodes}
    adj: Dict[str, List[str]] = {nid: [] for nid in nodes}
    for e in edges:
        src, tgt = e.get("source"), e.get("target")
        if src in nodes and tgt in nodes:
            adj[src].append(tgt)
            indeg[tgt] += 1

    levels: List[List[str]] = []
    ready = sorted([n for n, d in indeg.items() if d == 0])
    remaining = set(nodes)
    while ready:
        levels.append(list(ready))
        next_ready = []
        for n in ready:
            remaining.discard(n)
            for nxt in adj[n]:
                indeg[nxt] -= 1
                if indeg[nxt] == 0:
                    next_ready.append(nxt)
        ready = sorted(next_ready)
    if remaining:
        raise DagError(f"Unreachable or cyclic nodes: {sorted(remaining)}")
    return levels


def predecessors(graph: Dict[str, Any], node_id: str) -> List[Dict[str, Any]]:
    """Edges targeting node_id."""
    return [e for e in _edge_list(graph) if e.get("target") == node_id]


def expand_modules(
    db: Session,
    graph: Dict[str, Any],
    *,
    organization_id: int,
    depth: int = 0,
    seen_modules: Optional[Set[int]] = None,
) -> Dict[str, Any]:
    """
    Inline module nodes into a flat graph.
    Module node id namespaces child node ids as `{parent}__{child}`.
    Boundary: edges into module connect to matching input_port primitives;
    edges out of module connect from matching sink ports / output ports.
    """
    if depth > MAX_MODULE_DEPTH:
        raise DagError(f"Module nesting exceeds max depth {MAX_MODULE_DEPTH}")

    seen_modules = seen_modules or set()
    nodes = list(graph.get("nodes") or [])
    edges = list(graph.get("edges") or [])

    module_nodes = [n for n in nodes if (n.get("type") == "module" or (n.get("data") or {}).get("node_type") == "module")]
    if not module_nodes:
        validate_acyclic({"nodes": nodes, "edges": edges})
        return {"nodes": nodes, "edges": edges, "viewport": graph.get("viewport")}

    for mod in module_nodes:
        mod_id = mod["id"]
        data = mod.get("data") or {}
        ref_wf_id = data.get("workflow_id") or data.get("module_id")
        if not ref_wf_id:
            raise DagError(f"Module node {mod_id} missing workflow_id")
        ref_wf_id = int(ref_wf_id)
        if ref_wf_id in seen_modules:
            raise DagError(f"Cyclic module reference involving workflow {ref_wf_id}")

        wf = (
            db.query(Workflow)
            .filter(
                Workflow.id == ref_wf_id,
                Workflow.organization_id == organization_id,
                Workflow.kind == WorkflowKind.MODULE,
            )
            .first()
        )
        if not wf or not wf.latest_version_id:
            raise DagError(f"Module workflow {ref_wf_id} not found")
        ver = db.query(WorkflowVersion).filter(WorkflowVersion.id == wf.latest_version_id).first()
        if not ver:
            raise DagError(f"Module version missing for workflow {ref_wf_id}")

        inner = expand_modules(
            db,
            ver.graph or {},
            organization_id=organization_id,
            depth=depth + 1,
            seen_modules=seen_modules | {ref_wf_id},
        )

        # Remove module node; add namespaced inner nodes
        nodes = [n for n in nodes if n["id"] != mod_id]
        id_map: Dict[str, str] = {}
        for n in inner.get("nodes") or []:
            new_id = f"{mod_id}__{n['id']}"
            id_map[n["id"]] = new_id
            cloned = {**n, "id": new_id}
            # shift position slightly for readability
            pos = dict(n.get("position") or {})
            base_pos = mod.get("position") or {}
            cloned["position"] = {
                "x": (base_pos.get("x") or 0) + (pos.get("x") or 0) * 0.5,
                "y": (base_pos.get("y") or 0) + (pos.get("y") or 0) * 0.5,
            }
            nodes.append(cloned)

        # Remap inner edges
        for e in inner.get("edges") or []:
            edges.append(
                {
                    **e,
                    "id": f"{mod_id}__{e.get('id', f'{e.get('source')}-{e.get('target')}')}",
                    "source": id_map.get(e.get("source"), e.get("source")),
                    "target": id_map.get(e.get("target"), e.get("target")),
                }
            )

        # Rewire edges that targeted the module → inner input primitives by port
        input_ports = {p.get("name"): p for p in (ver.input_ports or []) if isinstance(p, dict)}
        output_ports = {p.get("name"): p for p in (ver.output_ports or []) if isinstance(p, dict)}

        # Find inner primitive nodes keyed by port name
        inner_inputs: Dict[str, str] = {}
        inner_outputs: Dict[str, str] = {}
        for n in inner.get("nodes") or []:
            nd = n.get("data") or {}
            ntype = n.get("type")
            port = nd.get("port") or {}
            pname = port.get("name") or nd.get("value_key")
            if ntype == "primitive" and pname:
                inner_inputs[pname] = id_map[n["id"]]
            if ntype == "sink" and pname:
                inner_outputs[pname] = id_map[n["id"]]

        # Also allow tool output ports as module outputs when sinks missing
        if not inner_outputs and output_ports:
            for n in inner.get("nodes") or []:
                if n.get("type") == "tool":
                    # last tool with matching handle — skip; sinks preferred
                    pass

        new_edges = []
        for e in edges:
            if e.get("target") == mod_id:
                handle = e.get("targetHandle") or next(iter(input_ports), None)
                inner_tgt = inner_inputs.get(handle) if handle else None
                if not inner_tgt and inner_inputs:
                    inner_tgt = next(iter(inner_inputs.values()))
                if not inner_tgt:
                    raise DagError(f"Cannot wire into module {mod_id}: no input port {handle}")
                new_edges.append({**e, "target": inner_tgt, "targetHandle": handle or e.get("targetHandle")})
            elif e.get("source") == mod_id:
                handle = e.get("sourceHandle") or next(iter(output_ports), None)
                inner_src = inner_outputs.get(handle) if handle else None
                if not inner_src:
                    # fallback: find any tool producing that handle name among remapped nodes
                    for n in nodes:
                        if not n["id"].startswith(f"{mod_id}__"):
                            continue
                        if n.get("type") == "tool":
                            # use hosts/urls common ports
                            pass
                    # Prefer last sink-less: use last tool node
                    tool_ids = [n["id"] for n in nodes if n["id"].startswith(f"{mod_id}__") and n.get("type") == "tool"]
                    if tool_ids:
                        inner_src = tool_ids[-1]
                if not inner_src:
                    raise DagError(f"Cannot wire out of module {mod_id}: no output port {handle}")
                new_edges.append({**e, "source": inner_src, "sourceHandle": handle or e.get("sourceHandle")})
            else:
                # drop edges that still reference old inner unmapped (already remapped above)
                if e.get("source") in id_map or e.get("target") in id_map:
                    # already handled as inner edges with new ids
                    if e.get("id", "").startswith(f"{mod_id}__"):
                        new_edges.append(e)
                    continue
                new_edges.append(e)
        edges = new_edges

    result = {"nodes": nodes, "edges": edges, "viewport": graph.get("viewport")}
    validate_acyclic(result)
    return result


def resolve_node_type(node: Dict[str, Any]) -> str:
    t = node.get("type") or (node.get("data") or {}).get("node_type") or "tool"
    return t
