"""
Graph Database API Routes

Endpoints for querying and visualizing asset relationships
using the Neo4j graph database.
"""

import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from app.api.deps import get_current_user
from app.models.user import User
from app.services.graph_service import get_graph_service
from app.core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/graph", tags=["Graph"])


def _resolve_graph_org(current_user: User, requested_org: Optional[int]) -> Optional[int]:
    """A requested organization must be one the caller may access."""
    if (requested_org is not None and not current_user.is_superuser
            and requested_org != current_user.organization_id):
        raise HTTPException(status_code=403, detail="Organization access denied")
    return requested_org if requested_org is not None else current_user.organization_id


# =============================================================================
# RESPONSE MODELS
# =============================================================================

class GraphNode(BaseModel):
    """A node in the graph."""
    id: int
    labels: List[str]
    properties: dict


class GraphEdge(BaseModel):
    """An edge/relationship in the graph."""
    source: int
    target: int
    type: str


class GraphData(BaseModel):
    """Graph data for visualization."""
    nodes: List[dict]
    edges: List[dict]


class AttackPath(BaseModel):
    """An attack path in the graph."""
    assets: List[str]
    relationships: List[str]
    target_cve: Optional[str] = None
    severity: Optional[str] = None


class VulnerabilityImpact(BaseModel):
    """Impact analysis for a vulnerability."""
    direct: List[dict]
    indirect: List[dict]
    total_impact: int


class SyncResult(BaseModel):
    """Result of a graph sync operation."""
    synced: int
    error: Optional[str] = None


# =============================================================================
# ENDPOINTS
# =============================================================================

@router.get("/status")
async def get_graph_status(current_user: User = Depends(get_current_user)):
    """
    Check if the graph database is available.
    """
    try:
        graph = get_graph_service()
        connected = graph._connected
        
        # Test query
        node_count = 0
        relationship_count = 0
        if connected:
            result = graph.query("RETURN 1 AS test")
            connected = bool(result)
            
            if connected:
                # Tenant users see only graph entities in their organization.
                org_id = current_user.organization_id
                if current_user.is_superuser:
                    node_query = "MATCH (n) RETURN count(n) AS count"
                    rel_query = "MATCH ()-[r]->() RETURN count(r) AS count"
                    params = {}
                elif org_id:
                    node_query = "MATCH (n) WHERE n.organization_id = $org_id RETURN count(n) AS count"
                    rel_query = "MATCH (n)-[r]->() WHERE n.organization_id = $org_id RETURN count(r) AS count"
                    params = {"org_id": org_id}
                else:
                    node_query = rel_query = None
                    params = {}
                node_result = graph.query(node_query, params) if node_query else []
                if node_result:
                    node_count = node_result[0].get("count", 0)

                rel_result = graph.query(rel_query, params) if rel_query else []
                if rel_result:
                    relationship_count = rel_result[0].get("count", 0)
        
        return {
            "connected": connected,
            "enabled": bool(settings.NEO4J_URI),
            "uri": settings.NEO4J_URI if connected and current_user.is_superuser else None,
            "node_count": node_count,
            "relationship_count": relationship_count,
        }
    except Exception as e:
        return {
            "connected": False,
            "enabled": bool(settings.NEO4J_URI),
            "error": str(e)
        }


@router.post("/sync")
async def sync_organization_graph(
    organization_id: Optional[int] = Query(default=None),
    current_user: User = Depends(get_current_user)
):
    """
    Sync organization's assets to the graph database.
    
    This creates nodes and relationships for all assets, vulnerabilities,
    ports, and technologies in the organization. Requires an organization
    to be specified (query param or your default org).
    """
    org_id = _resolve_graph_org(current_user, organization_id)
    if org_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Select an organization to sync. Sync only runs for one organization at a time."
        )
    try:
        graph = get_graph_service()
        result = graph.sync_organization(org_id)
        return {
            "assets_synced": result.get("synced", 0),
            "error": result.get("error"),
        }
    except Exception as e:
        logger.error(f"Graph sync error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/asset/{asset_id}/relationships")
async def get_asset_relationships(
    asset_id: int,
    depth: int = Query(default=2, ge=1, le=5),
    organization_id: Optional[int] = Query(None),
    current_user: User = Depends(get_current_user)
):
    """
    Get all relationships for an asset up to a specified depth.
    
    Returns nodes and relationships suitable for graph visualization.
    """
    org_id = _resolve_graph_org(current_user, organization_id)
    try:
        graph = get_graph_service()
        result = graph.get_asset_relationships(asset_id, depth, org_id)
        
        # Transform to frontend format
        nodes = []
        relationships = []
        seen_nodes = set()
        
        for record in result.get("nodes", []):
            node_id = record.get("id") or record.get("element_id")
            if node_id and node_id not in seen_nodes:
                seen_nodes.add(node_id)
                nodes.append({
                    "id": node_id,
                    "element_id": node_id,
                    "labels": record.get("labels", []),
                    "properties": record.get("properties", {}),
                })
        
        for record in result.get("edges", []):
            relationships.append({
                "source": record.get("source"),
                "target": record.get("target"),
                "start_node": record.get("source"),
                "end_node": record.get("target"),
                "type": record.get("type"),
                "properties": record.get("properties", {}),
            })
        
        return {
            "nodes": nodes,
            "relationships": relationships,
        }
    except Exception as e:
        logger.error(f"Relationship query error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/attack-paths")
async def get_attack_paths(
    source_id: Optional[int] = None,
    target_id: Optional[int] = None,
    organization_id: Optional[int] = None,
    max_paths: int = Query(default=5, ge=1, le=20),
    current_user: User = Depends(get_current_user)
):
    """
    Find potential attack paths between assets.
    
    Attack paths show chains of relationships that could be exploited
    by an attacker to move between assets.
    
    Args:
        source_id: Starting asset (entry point)
        target_id: Ending asset (goal)
        organization_id: Filter by organization
        max_paths: Maximum number of paths to return
    """
    org_id = _resolve_graph_org(current_user, organization_id)
    if not (source_id and target_id) and org_id is None:
        raise HTTPException(status_code=400, detail="Select an organization for attack paths")
    
    try:
        graph = get_graph_service()
        
        # Build query based on parameters
        if source_id and target_id:
            # Find paths between specific assets (graph stores asset_id, not id)
            query = """
            MATCH path = shortestPath((source:Asset {asset_id: $source_id})-[*1..6]-(target:Asset {asset_id: $target_id}))
            WHERE source.organization_id IS NOT NULL
              AND source.organization_id = target.organization_id
              AND ($org_id IS NULL OR source.organization_id = $org_id)
              AND all(n IN nodes(path) WHERE
                  n.organization_id IS NULL OR n.organization_id = source.organization_id)
            RETURN path
            LIMIT $max_paths
            """
            params = {"source_id": source_id, "target_id": target_id,
                      "org_id": org_id, "max_paths": max_paths}
        else:
            # Find paths to vulnerable assets
            query = """
            MATCH path = (entry:Asset {organization_id: $org_id})-[*1..4]->(vuln:Vulnerability)
            WHERE vuln.severity IN ['critical', 'high']
              AND all(n IN nodes(path) WHERE
                  n.organization_id IS NULL OR n.organization_id = $org_id)
            RETURN path
            LIMIT $max_paths
            """
            params = {"org_id": org_id, "max_paths": max_paths}
        
        results = graph.query(query, params)
        
        paths = []
        for record in results:
            path_data = record.get("path")
            if path_data:
                nodes = []
                relationships = []
                
                # Extract nodes and relationships from path
                if hasattr(path_data, 'nodes'):
                    for node in path_data.nodes:
                        nodes.append({
                            "id": node.element_id if hasattr(node, 'element_id') else str(node.id),
                            "labels": list(node.labels) if hasattr(node, 'labels') else [],
                            "properties": dict(node) if node else {},
                        })
                
                if hasattr(path_data, 'relationships'):
                    for rel in path_data.relationships:
                        relationships.append({
                            "type": rel.type if hasattr(rel, 'type') else str(type(rel)),
                            "source": rel.start_node.element_id if hasattr(rel, 'start_node') else None,
                            "target": rel.end_node.element_id if hasattr(rel, 'end_node') else None,
                        })
                
                paths.append({
                    "nodes": nodes,
                    "relationships": relationships,
                })
        
        return {"paths": paths}
    except Exception as e:
        logger.error(f"Attack path query error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/vulnerability/{vuln_id}/impact", response_model=VulnerabilityImpact)
async def get_vulnerability_impact(
    vuln_id: int,
    current_user: User = Depends(get_current_user)
):
    """
    Analyze the potential impact of a vulnerability.
    
    Returns directly affected assets and indirectly affected assets
    through relationship chains.
    """
    org_id = current_user.organization_id if hasattr(current_user, 'organization_id') else None
    if not org_id:
        raise HTTPException(
            status_code=400,
            detail="User must belong to an organization"
        )
    
    try:
        graph = get_graph_service()
        result = graph.get_vulnerability_impact(vuln_id, org_id)
        return VulnerabilityImpact(**result)
    except Exception as e:
        logger.error(f"Impact analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/query")
async def execute_graph_query(
    query: str,
    current_user: User = Depends(get_current_user)
):
    """
    Execute a custom Cypher query (admin only).
    
    The query is automatically filtered by organization_id.
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=403,
            detail="Only admins can execute custom queries"
        )
    
    org_id = current_user.organization_id if hasattr(current_user, 'organization_id') else None
    
    # Add organization filter for safety
    if org_id and "organization_id" not in query.lower():
        # Inject org filter into WHERE clause
        if "WHERE" in query.upper():
            query = query.replace("WHERE", f"WHERE n.organization_id = {org_id} AND ", 1)
        elif "RETURN" in query.upper():
            query = query.replace("RETURN", f"WHERE n.organization_id = {org_id} RETURN", 1)
    
    try:
        graph = get_graph_service()
        results = graph.query(query)
        return {"results": results, "count": len(results)}
    except Exception as e:
        logger.error(f"Custom query error: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/discovery-tree")
async def get_discovery_tree(
    asset_id: int = Query(..., description="Asset ID to trace provenance for"),
    organization_id: Optional[int] = Query(None),
    current_user: User = Depends(get_current_user),
):
    """
    Return the full discovery provenance graph for an asset.

    Shows how the asset was found (DiscoverySource), where it is hosted
    (HostingProvider), what ASN it belongs to, and which subdomains share
    its TLS certificate via SAN expansion.
    """
    org_id = _resolve_graph_org(current_user, organization_id)
    if not org_id:
        raise HTTPException(status_code=400, detail="User must belong to an organization")
    try:
        graph = get_graph_service()
        result = graph.get_discovery_tree(asset_id, org_id)
        nodes = []
        relationships = []
        seen_nodes: set = set()
        for n in result.get("nodes", []):
            nid = n.get("id")
            if nid and nid not in seen_nodes:
                seen_nodes.add(nid)
                nodes.append({
                    "id": nid,
                    "element_id": nid,
                    "labels": n.get("labels", []),
                    "properties": n.get("properties", {}),
                })
        for e in result.get("edges", []):
            relationships.append({
                "source": e.get("source"),
                "target": e.get("target"),
                "start_node": e.get("source"),
                "end_node": e.get("target"),
                "type": e.get("type"),
                "properties": {},
            })
        return {"nodes": nodes, "relationships": relationships}
    except Exception as e:
        logger.error(f"Discovery tree error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/shared-infrastructure")
async def get_shared_infrastructure(
    ip: str = Query(..., description="IP address to find co-hosted assets for"),
    organization_id: Optional[int] = Query(None),
    current_user: User = Depends(get_current_user),
):
    """
    Return all assets that share the same IP, ASN, or hosting provider.

    Useful for answering: "What else is on this IP / network?" and
    identifying shared-infrastructure blast radius.
    """
    org_id = _resolve_graph_org(current_user, organization_id)
    if not org_id:
        raise HTTPException(status_code=400, detail="User must belong to an organization")
    try:
        graph = get_graph_service()
        result = graph.get_shared_infrastructure(ip, org_id)
        return result
    except Exception as e:
        logger.error(f"Shared infrastructure error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/cert-expansion")
async def get_cert_expansion(
    domain: str = Query(..., description="Domain to expand via TLS certificate SANs"),
    organization_id: Optional[int] = Query(None),
    current_user: User = Depends(get_current_user),
):
    """
    Return subdomains that share a TLS certificate with a given domain.

    Traverses SIGNED_BY -> Certificate -> ALSO_COVERS to surface shadow IT
    and related assets discovered via certificate transparency.
    """
    org_id = _resolve_graph_org(current_user, organization_id)
    if not org_id:
        raise HTTPException(status_code=400, detail="User must belong to an organization")
    try:
        graph = get_graph_service()
        result = graph.get_cert_expansion(domain, org_id)
        return result
    except Exception as e:
        logger.error(f"Cert expansion error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/discovery-sources")
async def get_discovery_sources(
    organization_id: Optional[int] = Query(None),
    current_user: User = Depends(get_current_user),
):
    """
    Return asset counts grouped by discovery source.

    Answers: "How many assets did subfinder vs whoxy vs certspotter find?"
    Falls back to PostgreSQL when Neo4j is unavailable.
    """
    org_id = _resolve_graph_org(current_user, organization_id)
    if not org_id:
        raise HTTPException(status_code=400, detail="User must belong to an organization")
    try:
        graph = get_graph_service()
        if graph._connected:
            results = graph.get_discovery_sources_summary(org_id)
            if results:
                return {"sources": results, "source": "neo4j"}

        # PostgreSQL fallback
        from app.db.database import SessionLocal
        from app.models.asset import Asset
        from sqlalchemy import func
        db = SessionLocal()
        try:
            rows = (
                db.query(
                    func.coalesce(Asset.discovery_source, "manual").label("source"),
                    func.count(Asset.id).label("asset_count"),
                )
                .filter(Asset.organization_id == org_id)
                .group_by(func.coalesce(Asset.discovery_source, "manual"))
                .order_by(func.count(Asset.id).desc())
                .all()
            )
            return {
                "sources": [
                    {"source": r.source, "display_name": r.source.replace("_", " ").title(), "asset_count": r.asset_count}
                    for r in rows
                ],
                "source": "postgresql",
            }
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Discovery sources error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/group-by-technology")
async def get_assets_by_technology(
    organization_id: Optional[int] = Query(None, description="Filter by organization"),
    category: Optional[str] = Query(None, description="Filter by technology category (e.g., 'cms', 'web-servers')"),
    current_user: User = Depends(get_current_user)
):
    """
    Group assets by technology for attack surface analysis.
    
    Returns technologies with their associated assets, useful for identifying:
    - All WordPress sites (potential attack vectors)
    - All Apache servers (version-specific vulnerabilities)
    - All jQuery instances (client-side risks)
    """
    org_id = _resolve_graph_org(current_user, organization_id)
    
    try:
        graph = get_graph_service()
        
        # Query for technologies and their associated assets
        if category:
            cypher = """
                MATCH (a:Asset)-[:USES_TECHNOLOGY]->(t:Technology)
                WHERE a.organization_id = $org_id
                  AND t.categories CONTAINS $category
                WITH t, collect(DISTINCT {
                    id: a.asset_id,
                    value: a.value,
                    is_live: a.is_live,
                    risk_score: a.risk_score,
                    has_login_portal: a.has_login_portal
                }) AS assets
                RETURN t.name AS technology,
                       t.categories AS categories,
                       t.cpe AS cpe,
                       size(assets) AS asset_count,
                       assets
                ORDER BY asset_count DESC
            """
            params = {"org_id": org_id, "category": category}
        else:
            cypher = """
                MATCH (a:Asset)-[:USES_TECHNOLOGY]->(t:Technology)
                WHERE a.organization_id = $org_id
                WITH t, collect(DISTINCT {
                    id: a.asset_id,
                    value: a.value,
                    is_live: a.is_live,
                    risk_score: a.risk_score,
                    has_login_portal: a.has_login_portal
                }) AS assets
                RETURN t.name AS technology,
                       t.categories AS categories,
                       t.cpe AS cpe,
                       size(assets) AS asset_count,
                       assets
                ORDER BY asset_count DESC
                LIMIT 50
            """
            params = {"org_id": org_id}
        
        results = graph.query(cypher, params)
        
        # Also get category summary
        category_cypher = """
            MATCH (a:Asset)-[:USES_TECHNOLOGY]->(t:Technology)
            WHERE a.organization_id = $org_id
              AND t.categories IS NOT NULL
            WITH t.categories AS cat, count(DISTINCT a) AS count
            RETURN cat AS category, count
            ORDER BY count DESC
        """
        category_results = graph.query(category_cypher, {"org_id": org_id})
        
        return {
            "technologies": results,
            "categories": category_results,
            "total_technologies": len(results)
        }
    except Exception as e:
        logger.error(f"Technology grouping error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/group-by-port")
async def get_assets_by_port(
    organization_id: Optional[int] = Query(None, description="Filter by organization"),
    risky_only: bool = Query(False, description="Only show risky ports"),
    current_user: User = Depends(get_current_user)
):
    """
    Group assets by open ports for attack surface analysis.
    
    Returns ports with their associated assets, useful for identifying:
    - All assets with SSH (port 22) exposed
    - All assets with RDP (port 3389) exposed
    - All assets with database ports exposed
    """
    org_id = _resolve_graph_org(current_user, organization_id)
    
    try:
        graph = get_graph_service()
        
        # Query for ports and their associated assets
        if risky_only:
            cypher = """
                MATCH (a:Asset)-[:HAS_PORT]->(p:Port)
                WHERE a.organization_id = $org_id
                  AND p.is_risky = true
                WITH p.port AS port_number, p.protocol AS protocol,
                     collect(DISTINCT {
                         id: a.asset_id,
                         value: a.value,
                         is_live: a.is_live,
                         scanned_ip: p.scanned_ip
                     }) AS assets
                OPTIONAL MATCH (p2:Port {port: port_number})-[:RUNS_SERVICE]->(s:Service)
                WITH port_number, protocol, assets, collect(DISTINCT s.name)[0] AS service_name
                RETURN port_number,
                       protocol,
                       service_name,
                       size(assets) AS asset_count,
                       assets,
                       true AS is_risky
                ORDER BY asset_count DESC
            """
        else:
            cypher = """
                MATCH (a:Asset)-[:HAS_PORT]->(p:Port)
                WHERE a.organization_id = $org_id
                WITH p.port AS port_number, p.protocol AS protocol, p.is_risky AS is_risky,
                     collect(DISTINCT {
                         id: a.asset_id,
                         value: a.value,
                         is_live: a.is_live,
                         scanned_ip: p.scanned_ip
                     }) AS assets
                OPTIONAL MATCH (p2:Port {port: port_number})-[:RUNS_SERVICE]->(s:Service)
                WITH port_number, protocol, is_risky, assets, collect(DISTINCT s.name)[0] AS service_name
                RETURN port_number,
                       protocol,
                       service_name,
                       size(assets) AS asset_count,
                       assets,
                       is_risky
                ORDER BY asset_count DESC
                LIMIT 50
            """
        
        results = graph.query(cypher, {"org_id": org_id})
        
        # Get risky port summary
        risky_cypher = """
            MATCH (a:Asset)-[:HAS_PORT]->(p:Port)
            WHERE a.organization_id = $org_id
              AND p.is_risky = true
            RETURN count(DISTINCT p) AS risky_port_count,
                   count(DISTINCT a) AS affected_asset_count
        """
        risky_summary = graph.query(risky_cypher, {"org_id": org_id})
        
        return {
            "ports": results,
            "risky_summary": risky_summary[0] if risky_summary else {"risky_port_count": 0, "affected_asset_count": 0},
            "total_unique_ports": len(results)
        }
    except Exception as e:
        logger.error(f"Port grouping error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/attack-surface-overview")
async def get_attack_surface_overview(
    organization_id: Optional[int] = Query(None, description="Filter by organization"),
    current_user: User = Depends(get_current_user)
):
    """
    Get a comprehensive attack surface overview with groupings.
    
    Returns:
    - Entry points (externally accessible assets)
    - High-value targets (critical assets, login portals)
    - Attack vectors (risky ports, vulnerable technologies)
    - Risk distribution
    """
    org_id = _resolve_graph_org(current_user, organization_id)
    
    try:
        graph = get_graph_service()
        
        # Entry points - live assets with open ports
        entry_points = graph.query("""
            MATCH (a:Asset)-[:HAS_PORT]->(p:Port)
            WHERE a.organization_id = $org_id
              AND a.is_live = true
            WITH a, count(DISTINCT p) AS port_count
            OPTIONAL MATCH (a)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            WHERE v.severity IN ['critical', 'high']
            WITH a, port_count, count(DISTINCT v) AS critical_vulns
            RETURN a.value AS asset,
                   a.asset_type AS type,
                   a.has_login_portal AS has_login,
                   port_count,
                   critical_vulns,
                   a.risk_score AS risk_score
            ORDER BY critical_vulns DESC, port_count DESC
            LIMIT 20
        """, {"org_id": org_id})
        
        # High-value targets - login portals and critical assets
        high_value = graph.query("""
            MATCH (a:Asset)
            WHERE a.organization_id = $org_id
              AND (a.has_login_portal = true OR a.criticality = 'critical')
            OPTIONAL MATCH (a)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            WITH a, collect(DISTINCT v.severity) AS vuln_severities
            RETURN a.value AS asset,
                   a.asset_type AS type,
                   a.has_login_portal AS has_login,
                   a.criticality AS criticality,
                   vuln_severities
            ORDER BY a.risk_score DESC
            LIMIT 20
        """, {"org_id": org_id})
        
        # Technology attack vectors - technologies with known issues
        tech_vectors = graph.query("""
            MATCH (a:Asset)-[:USES_TECHNOLOGY]->(t:Technology)
            WHERE a.organization_id = $org_id
            WITH t.name AS technology, t.categories AS categories, t.cpe AS cpe,
                 count(DISTINCT a) AS usage_count
            WHERE usage_count > 1
            RETURN technology, categories, cpe, usage_count
            ORDER BY usage_count DESC
            LIMIT 15
        """, {"org_id": org_id})
        
        # Port attack vectors - commonly exploited ports
        port_vectors = graph.query("""
            MATCH (a:Asset)-[:HAS_PORT]->(p:Port)
            WHERE a.organization_id = $org_id
              AND p.is_risky = true
            OPTIONAL MATCH (p)-[:RUNS_SERVICE]->(s:Service)
            WITH p.port AS port, s.name AS service, count(DISTINCT a) AS exposure_count
            RETURN port, service, exposure_count
            ORDER BY exposure_count DESC
            LIMIT 15
        """, {"org_id": org_id})
        
        # Risk distribution
        risk_dist = graph.query("""
            MATCH (a:Asset)
            WHERE a.organization_id = $org_id
            RETURN 
                sum(CASE WHEN a.risk_score >= 80 THEN 1 ELSE 0 END) AS critical_risk,
                sum(CASE WHEN a.risk_score >= 60 AND a.risk_score < 80 THEN 1 ELSE 0 END) AS high_risk,
                sum(CASE WHEN a.risk_score >= 40 AND a.risk_score < 60 THEN 1 ELSE 0 END) AS medium_risk,
                sum(CASE WHEN a.risk_score < 40 THEN 1 ELSE 0 END) AS low_risk,
                count(a) AS total_assets
        """, {"org_id": org_id})
        
        # Discovery sources
        discovery_sources = graph.query("""
            MATCH (a:Asset)
            WHERE a.organization_id = $org_id
            WITH CASE 
                WHEN a.discovery_source IS NULL THEN 'manual'
                ELSE a.discovery_source
            END AS source, count(a) AS count
            RETURN source, count
            ORDER BY count DESC
        """, {"org_id": org_id})
        
        return {
            "entry_points": entry_points,
            "high_value_targets": high_value,
            "technology_vectors": tech_vectors,
            "port_vectors": port_vectors,
            "risk_distribution": risk_dist[0] if risk_dist else {},
            "discovery_sources": discovery_sources
        }
    except Exception as e:
        logger.error(f"Attack surface overview error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics")
async def get_graph_statistics(
    current_user: User = Depends(get_current_user)
):
    """
    Get statistics about the graph database.
    """
    org_id = current_user.organization_id if hasattr(current_user, 'organization_id') else None
    if not org_id:
        raise HTTPException(
            status_code=400,
            detail="User must belong to an organization"
        )
    
    try:
        graph = get_graph_service()
        
        # Get node counts by label
        node_counts = graph.query("""
            MATCH (n)
            WHERE n.organization_id = $org_id
            RETURN labels(n)[0] AS label, count(n) AS count
            ORDER BY count DESC
        """, {"org_id": org_id})
        
        # Get relationship counts
        rel_counts = graph.query("""
            MATCH (n)-[r]->(m)
            WHERE n.organization_id = $org_id
            RETURN type(r) AS type, count(r) AS count
            ORDER BY count DESC
        """, {"org_id": org_id})
        
        # Get vulnerability severity distribution
        vuln_dist = graph.query("""
            MATCH (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            WHERE a.organization_id = $org_id
            RETURN v.severity AS severity, count(v) AS count
        """, {"org_id": org_id})
        
        return {
            "nodes": {r.get("label", "Unknown"): r.get("count", 0) for r in node_counts},
            "relationships": {r.get("type", "Unknown"): r.get("count", 0) for r in rel_counts},
            "vulnerabilities_by_severity": {r.get("severity", "Unknown"): r.get("count", 0) for r in vuln_dist},
        }
    except Exception as e:
        logger.error(f"Statistics query error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# POSTGRESQL FALLBACK ENDPOINTS (work without Neo4j)
# =============================================================================

@router.get("/fallback/group-by-technology")
async def get_assets_by_technology_fallback(
    organization_id: Optional[int] = Query(None, description="Filter by organization"),
    current_user: User = Depends(get_current_user)
):
    """
    Group assets by technology using PostgreSQL (works without Neo4j).
    
    Returns technologies with their associated assets for attack surface analysis.
    """
    from app.db.database import SessionLocal
    from app.models.asset import Asset
    from app.models.technology import Technology, asset_technologies
    from sqlalchemy import func
    from sqlalchemy.orm import Session
    
    org_id = _resolve_graph_org(current_user, organization_id)
    
    db = SessionLocal()
    try:
        # Query technologies with asset counts
        tech_query = db.query(
            Technology.name,
            Technology.slug,
            Technology.categories,
            Technology.cpe,
            func.count(Asset.id).label('asset_count')
        ).join(
            asset_technologies,
            Technology.id == asset_technologies.c.technology_id
        ).join(
            Asset,
            Asset.id == asset_technologies.c.asset_id
        )
        
        if org_id:
            tech_query = tech_query.filter(Asset.organization_id == org_id)
        
        tech_results = tech_query.group_by(
            Technology.name,
            Technology.slug,
            Technology.categories,
            Technology.cpe
        ).order_by(func.count(Asset.id).desc()).limit(50).all()
        
        technologies = []
        for tech in tech_results:
            # Get assets for this technology
            assets_query = db.query(
                Asset.id,
                Asset.value,
                Asset.is_live,
                Asset.has_login_portal
            ).join(
                asset_technologies,
                Asset.id == asset_technologies.c.asset_id
            ).join(
                Technology,
                Technology.id == asset_technologies.c.technology_id
            ).filter(Technology.name == tech.name)
            
            if org_id:
                assets_query = assets_query.filter(Asset.organization_id == org_id)
            
            assets = [
                {
                    "id": a.id,
                    "value": a.value,
                    "is_live": a.is_live,
                    "has_login_portal": a.has_login_portal
                }
                for a in assets_query.limit(20).all()
            ]
            
            technologies.append({
                "technology": tech.name,
                "slug": tech.slug,
                "categories": tech.categories,
                "cpe": tech.cpe,
                "asset_count": tech.asset_count,
                "assets": assets
            })
        
        # Get category summary
        category_counts = {}
        for tech in technologies:
            if tech["categories"]:
                for cat in tech["categories"]:
                    category_counts[cat] = category_counts.get(cat, 0) + tech["asset_count"]
        
        return {
            "technologies": technologies,
            "categories": [{"category": k, "count": v} for k, v in sorted(category_counts.items(), key=lambda x: -x[1])],
            "total_technologies": len(technologies),
            "source": "postgresql"  # Indicates this is fallback data
        }
    finally:
        db.close()


@router.get("/fallback/group-by-port")
async def get_assets_by_port_fallback(
    organization_id: Optional[int] = Query(None, description="Filter by organization"),
    risky_only: bool = Query(False, description="Only show risky ports"),
    current_user: User = Depends(get_current_user)
):
    """
    Group assets by open ports using PostgreSQL (works without Neo4j).
    
    Returns ports with their associated assets for attack surface analysis.
    """
    from app.db.database import SessionLocal
    from app.models.asset import Asset
    from app.models.port_service import PortService
    from sqlalchemy import func
    
    org_id = _resolve_graph_org(current_user, organization_id)
    
    db = SessionLocal()
    try:
        # Query ports with asset counts
        port_query = db.query(
            PortService.port,
            PortService.protocol,
            PortService.service_name,
            PortService.is_risky,
            func.count(Asset.id).label('asset_count')
        ).join(
            Asset,
            Asset.id == PortService.asset_id
        )
        
        if org_id:
            port_query = port_query.filter(Asset.organization_id == org_id)
        
        if risky_only:
            port_query = port_query.filter(PortService.is_risky == True)
        
        port_results = port_query.group_by(
            PortService.port,
            PortService.protocol,
            PortService.service_name,
            PortService.is_risky
        ).order_by(func.count(Asset.id).desc()).limit(50).all()
        
        ports = []
        for port in port_results:
            # Get assets for this port
            assets_query = db.query(
                Asset.id,
                Asset.value,
                Asset.is_live,
                PortService.scanned_ip
            ).join(
                PortService,
                Asset.id == PortService.asset_id
            ).filter(
                PortService.port == port.port,
                PortService.protocol == port.protocol
            )
            
            if org_id:
                assets_query = assets_query.filter(Asset.organization_id == org_id)
            
            assets = [
                {
                    "id": a.id,
                    "value": a.value,
                    "is_live": a.is_live,
                    "scanned_ip": a.scanned_ip
                }
                for a in assets_query.limit(20).all()
            ]
            
            ports.append({
                "port_number": port.port,
                "protocol": port.protocol.value if hasattr(port.protocol, 'value') else str(port.protocol),
                "service_name": port.service_name,
                "asset_count": port.asset_count,
                "is_risky": port.is_risky,
                "assets": assets
            })
        
        # Get risky summary
        risky_summary = db.query(
            func.count(func.distinct(PortService.id)).label('risky_port_count'),
            func.count(func.distinct(Asset.id)).label('affected_asset_count')
        ).join(
            Asset,
            Asset.id == PortService.asset_id
        ).filter(PortService.is_risky == True)
        
        if org_id:
            risky_summary = risky_summary.filter(Asset.organization_id == org_id)
        
        risky_result = risky_summary.first()
        
        return {
            "ports": ports,
            "risky_summary": {
                "risky_port_count": risky_result.risky_port_count if risky_result else 0,
                "affected_asset_count": risky_result.affected_asset_count if risky_result else 0
            },
            "total_unique_ports": len(ports),
            "source": "postgresql"
        }
    finally:
        db.close()


@router.get("/fallback/attack-surface-overview")
async def get_attack_surface_overview_fallback(
    organization_id: Optional[int] = Query(None, description="Filter by organization"),
    current_user: User = Depends(get_current_user)
):
    """
    Get attack surface overview using PostgreSQL (works without Neo4j).
    """
    from app.db.database import SessionLocal
    from app.models.asset import Asset, AssetType
    from app.models.port_service import PortService
    from app.models.technology import Technology, asset_technologies
    from app.models.vulnerability import Vulnerability
    from sqlalchemy import func, and_
    
    org_id = _resolve_graph_org(current_user, organization_id)
    
    db = SessionLocal()
    try:
        # Entry points - live assets with open ports
        entry_points_query = db.query(
            Asset.value,
            Asset.asset_type,
            Asset.has_login_portal,
            func.count(PortService.id).label('port_count'),
        ).outerjoin(
            PortService,
            Asset.id == PortService.asset_id
        ).filter(
            Asset.is_live == True
        )
        
        if org_id:
            entry_points_query = entry_points_query.filter(Asset.organization_id == org_id)
        
        entry_points = entry_points_query.group_by(
            Asset.value,
            Asset.asset_type,
            Asset.has_login_portal
        ).order_by(func.count(PortService.id).desc()).limit(20).all()
        
        entry_points_data = [
            {
                "asset": e.value,
                "type": e.asset_type.value if e.asset_type else None,
                "has_login": e.has_login_portal,
                "port_count": e.port_count
            }
            for e in entry_points
        ]
        
        # High-value targets - login portals
        high_value = db.query(
            Asset.value,
            Asset.asset_type,
            Asset.has_login_portal
        ).filter(
            Asset.has_login_portal == True
        )
        
        if org_id:
            high_value = high_value.filter(Asset.organization_id == org_id)
        
        high_value_data = [
            {
                "asset": h.value,
                "type": h.asset_type.value if h.asset_type else None,
                "has_login": h.has_login_portal
            }
            for h in high_value.limit(20).all()
        ]
        
        # Technology vectors
        tech_query = db.query(
            Technology.name,
            Technology.categories,
            func.count(Asset.id).label('usage_count')
        ).join(
            asset_technologies,
            Technology.id == asset_technologies.c.technology_id
        ).join(
            Asset,
            Asset.id == asset_technologies.c.asset_id
        )
        
        if org_id:
            tech_query = tech_query.filter(Asset.organization_id == org_id)
        
        tech_vectors = [
            {
                "technology": t.name,
                "categories": t.categories,
                "usage_count": t.usage_count
            }
            for t in tech_query.group_by(
                Technology.name,
                Technology.categories
            ).order_by(func.count(Asset.id).desc()).limit(15).all()
        ]
        
        # Port vectors - risky ports
        port_query = db.query(
            PortService.port,
            PortService.service_name,
            func.count(Asset.id).label('exposure_count')
        ).join(
            Asset,
            Asset.id == PortService.asset_id
        ).filter(
            PortService.is_risky == True
        )
        
        if org_id:
            port_query = port_query.filter(Asset.organization_id == org_id)
        
        port_vectors = [
            {
                "port": p.port,
                "service": p.service_name,
                "exposure_count": p.exposure_count
            }
            for p in port_query.group_by(
                PortService.port,
                PortService.service_name
            ).order_by(func.count(Asset.id).desc()).limit(15).all()
        ]
        
        # Total counts
        total_assets = db.query(func.count(Asset.id)).filter(Asset.organization_id == org_id).scalar() if org_id else 0
        live_assets = db.query(func.count(Asset.id)).filter(
            Asset.organization_id == org_id,
            Asset.is_live == True
        ).scalar() if org_id else 0
        
        # Risk distribution (so frontend risk cards work without Neo4j)
        risk_distribution = {
            "critical_risk": 0,
            "high_risk": 0,
            "medium_risk": 0,
            "low_risk": 0,
            "total_assets": total_assets or 0,
        }
        if org_id:
            base_filter = Asset.organization_id == org_id
            risk_distribution["critical_risk"] = db.query(Asset).filter(base_filter, Asset.risk_score >= 80).count()
            risk_distribution["high_risk"] = db.query(Asset).filter(
                base_filter, Asset.risk_score >= 60, Asset.risk_score < 80
            ).count()
            risk_distribution["medium_risk"] = db.query(Asset).filter(
                base_filter, Asset.risk_score >= 40, Asset.risk_score < 60
            ).count()
            risk_distribution["low_risk"] = db.query(Asset).filter(
                base_filter, Asset.risk_score < 40
            ).count()
        
        # Discovery sources (so frontend discovery section works without Neo4j)
        discovery_sources = []
        if org_id:
            from sqlalchemy import distinct
            source_query = db.query(
                func.coalesce(Asset.discovery_source, "manual").label("source"),
                func.count(Asset.id).label("count")
            ).filter(Asset.organization_id == org_id).group_by(
                func.coalesce(Asset.discovery_source, "manual")
            ).order_by(func.count(Asset.id).desc()).all()
            discovery_sources = [{"source": r.source, "count": r.count} for r in source_query]
        
        return {
            "entry_points": entry_points_data,
            "high_value_targets": high_value_data,
            "technology_vectors": tech_vectors,
            "port_vectors": port_vectors,
            "summary": {
                "total_assets": total_assets,
                "live_assets": live_assets,
                "login_portals": len(high_value_data)
            },
            "risk_distribution": risk_distribution,
            "discovery_sources": discovery_sources,
            "source": "postgresql"
        }
    finally:
        db.close()
