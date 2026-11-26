"""Project NetBrain calculated paths without treating them as proven reachability."""

import logging

from app.models.netbrain_path import NetBrainPath
from app.services.graph_service import get_graph_service

logger = logging.getLogger(__name__)


def project_netbrain_path(path: NetBrainPath) -> bool:
    """Return false when Neo4j is unavailable; PostgreSQL remains the evidence store."""
    if path.status != "succeeded":
        return False
    graph = get_graph_service()
    if not graph._connected:
        return False
    key = f"org:{path.organization_id}:netbrain-path:{path.id}"
    hops = [
        {**hop, "key": f"{key}:hop:{hop['hop_id']}"}
        for hop in (path.hop_list or []) if hop.get("hop_id")
    ]
    hop_keys = {hop["hop_id"]: hop["key"] for hop in hops}
    next_edges = [
        {"from_key": hop["key"], "to_key": hop_keys[next_id]}
        for hop in hops for next_id in hop.get("next_hop_ids", []) if next_id in hop_keys
    ]
    props = {
        "key": key, "path_id": path.id, "organization_id": path.organization_id,
        "source_integration_id": path.source_integration_id, "task_id": path.task_id,
        "source_asset_id": path.source_asset_id, "target_asset_id": path.target_asset_id,
        "source_ip": path.source_ip, "target_ip": path.target_ip,
        "source_scope_id": path.source_scope_id, "target_scope_id": path.target_scope_id,
        "tenant_id": path.tenant_id, "domain_id": path.domain_id,
        "gateway_ip": path.gateway_ip, "gateway_device": path.gateway_device,
        "gateway_interface": path.gateway_interface, "protocol": path.protocol,
        "destination_port": path.destination_port, "is_live": path.is_live,
        "evidence_type": "calculated_route", "status": path.status,
        "calculated_at": path.completed_at.isoformat() if path.completed_at else None,
    }
    try:
        with graph.session() as session:
            def write(tx):
                tx.run("""
                    MATCH (source:Asset {asset_id: $source_id, organization_id: $org_id})
                    MATCH (target:Asset {asset_id: $target_id, organization_id: $org_id})
                    MERGE (p:NetworkPath {key: $key})
                    SET p += $props
                    MERGE (source)-[from:HAS_CALCULATED_PATH]->(p)
                    SET from.organization_id = $org_id
                    MERGE (p)-[to:REQUESTED_TARGET]->(target)
                    SET to.organization_id = $org_id
                    RETURN p.key AS key
                """, key=key, props=props, source_id=path.source_asset_id,
                    target_id=path.target_asset_id, org_id=path.organization_id).single(strict=True)
                tx.run("""
                    MATCH (p:NetworkPath {key: $key})
                    UNWIND $hops AS hop
                    MERGE (h:NetworkHop {key: hop.key})
                    SET h += hop, h.organization_id = $org_id, h.path_key = $key
                    MERGE (p)-[rel:HAS_HOP]->(h)
                    SET rel.organization_id = $org_id
                """, key=key, hops=hops, org_id=path.organization_id).consume()
                tx.run("""
                    UNWIND $edges AS edge
                    MATCH (a:NetworkHop {key: edge.from_key})
                    MATCH (b:NetworkHop {key: edge.to_key})
                    MERGE (a)-[rel:NEXT_CALCULATED_HOP]->(b)
                    SET rel.organization_id = $org_id
                """, edges=next_edges, org_id=path.organization_id).consume()
            session.execute_write(write)
        return True
    except Exception:
        logger.exception("Could not project NetBrain path %s", path.id)
        return False
