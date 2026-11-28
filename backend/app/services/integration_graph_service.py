"""Batch projection of imported Wiz and CrowdStrike records into Neo4j.

The SQL inventory remains the source of truth. Stable SQL IDs make every graph
write idempotent, so a failed run can safely restart from the beginning.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta
from typing import Any, Iterable

from sqlalchemy import text
from sqlalchemy.orm import Session, selectinload

from app.db.database import SessionLocal
from app.models.asset import Asset, AssetStatus
from app.models.crowdstrike_integration import CrowdStrikeIntegration
from app.models.vulnerability import Vulnerability
from app.models.wiz_integration import WizApplicationEndpoint, WizIntegration
from app.services.graph_service import get_graph_service

logger = logging.getLogger(__name__)

ASSET_BATCH_SIZE = 500
VULNERABILITY_BATCH_SIZE = 500
ENDPOINT_BATCH_SIZE = 100

ASSET_QUERY = """
UNWIND $rows AS row
MERGE (a:Asset {asset_id: row.id})
SET a += row.props
RETURN count(a) AS written
"""

VULNERABILITY_QUERY = """
UNWIND $rows AS row
MATCH (a:Asset {asset_id: row.asset_id, organization_id: $org_id})
MERGE (v:Vulnerability {vuln_id: row.id})
SET v += row.props
MERGE (a)-[:HAS_VULNERABILITY]->(v)
RETURN count(v) AS written
"""

CVE_QUERY = """
UNWIND $rows AS row
WITH row WHERE row.cve_id IS NOT NULL
MATCH (v:Vulnerability {vuln_id: row.id, organization_id: $org_id})
MERGE (c:CVE {cve_id: row.cve_id})
MERGE (v)-[:REFERENCES]->(c)
"""

ENDPOINT_QUERY = """
UNWIND $rows AS row
MERGE (e:Endpoint {endpoint_id: row.key})
SET e:WizEndpoint, e += row.props
WITH e, row
OPTIONAL MATCH (a:Asset {asset_id: row.asset_id, organization_id: $org_id})
FOREACH (_ IN CASE WHEN a IS NULL THEN [] ELSE [1] END |
    MERGE (a)-[:HAS_ENDPOINT]->(e))
RETURN count(e) AS written
"""

CLEAR_ENDPOINT_LINKS_QUERY = """
UNWIND $keys AS key
MATCH (e:Endpoint {endpoint_id: key})
OPTIONAL MATCH (e)-[r:HAS_DIRECT_ISSUE|EXPOSES_RESOURCE]->()
DELETE r
"""

ISSUE_QUERY = """
UNWIND $rows AS row
MATCH (e:Endpoint {endpoint_id: row.endpoint_key, organization_id: $org_id})
MERGE (i:WizIssue {key: row.issue_key})
SET i.organization_id = $org_id,
    i.wiz_id = row.id,
    i.severity = row.severity,
    i.status = row.status,
    i.url = row.url
MERGE (e)-[:HAS_DIRECT_ISSUE]->(i)
RETURN count(i) AS written
"""

RESOURCE_QUERY = """
UNWIND $rows AS row
MATCH (e:Endpoint {endpoint_id: row.endpoint_key, organization_id: $org_id})
MERGE (r:WizResource {key: row.resource_key})
SET r.organization_id = $org_id,
    r.wiz_id = row.id,
    r.name = row.name,
    r.resource_type = row.type,
    r.provider_unique_id = row.provider_unique_id
MERGE (e)-[:EXPOSES_RESOURCE]->(r)
WITH r, row
OPTIONAL MATCH (a:Asset {organization_id: $org_id, wiz_resource_id: row.id})
WITH r, row, head(collect(a)) AS a
FOREACH (_ IN CASE WHEN a IS NULL THEN [] ELSE [1] END |
    MERGE (r)-[:REPRESENTS]->(a))
RETURN count(r) AS written
"""


def _chunks(values: list[int], size: int) -> Iterable[list[int]]:
    for start in range(0, len(values), size):
        yield values[start:start + size]


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _asset_row(asset: Asset) -> dict[str, Any]:
    metadata = _as_dict(asset.metadata_)
    wiz = _as_dict(metadata.get("wiz"))
    tags = [str(tag) for tag in (asset.tags or []) if tag]
    return {"id": asset.id, "props": {
        "asset_id": asset.id,
        "organization_id": asset.organization_id,
        "name": asset.name,
        "value": asset.value,
        "asset_type": asset.asset_type.value if asset.asset_type else None,
        "discovery_source": asset.discovery_source,
        "sources": [source for source in ("wiz", "crowdstrike") if f"source:{source}" in tags],
        "is_active": asset.status not in (AssetStatus.INACTIVE, AssetStatus.ARCHIVED),
        "is_public": bool(asset.is_public),
        "is_live": bool(asset.is_live),
        "http_status": asset.http_status,
        "http_title": asset.http_title,
        "operating_system": asset.operating_system,
        "hosting_provider": asset.hosting_provider,
        "ip_addresses": [str(ip) for ip in (asset.ip_addresses or []) if ip],
        "wiz_resource_id": str(wiz.get("id")) if wiz.get("id") else None,
        "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
    }}


def _vulnerability_row(vuln: Vulnerability) -> dict[str, Any]:
    return {"id": vuln.id, "asset_id": vuln.asset_id, "cve_id": vuln.cve_id,
            "props": {
                "vuln_id": vuln.id,
                "organization_id": vuln.asset.organization_id,
                "title": vuln.title,
                "severity": vuln.severity.value if vuln.severity else None,
                "status": vuln.status.value if vuln.status else None,
                "description": (vuln.description or "")[:2000],
                "cvss_score": vuln.cvss_score,
                "cve_id": vuln.cve_id,
                "detected_by": vuln.detected_by,
                "template_id": vuln.template_id,
            }}


def _endpoint_rows(endpoint: WizApplicationEndpoint) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    key = f"wiz:{endpoint.organization_id}:{endpoint.integration_id}:{endpoint.wiz_id}"
    data = _as_dict(endpoint.endpoint_data)
    http = _as_dict(data.get("httpResults"))
    technologies = [
        _as_dict(item.get("technology"))
        for item in (data.get("hostedTechnologies") or [])
        if isinstance(item, dict)
    ]
    analytics = _as_dict(data.get("issueAnalytics"))
    row = {"key": key, "asset_id": endpoint.asset_id, "props": {
        "endpoint_id": key,
        "organization_id": endpoint.organization_id,
        "source": "wiz",
        "wiz_id": endpoint.wiz_id,
        "url": endpoint.name,
        "host": endpoint.host,
        "port": endpoint.port,
        "protocols": [str(value) for value in (data.get("protocols") or []) if value],
        "scan_sources": [str(value) for value in (data.get("scanSources") or []) if value],
        "port_status": data.get("portStatus"),
        "title": http.get("pageTitle"),
        "http_status": http.get("statusCode"),
        "http_status_text": http.get("statusText"),
        "content_type": http.get("contentType"),
        "authentication_method": http.get("authenticationMethod"),
        "authentication_service_provider": http.get("authenticationServiceProvider"),
        "screenshot_url": http.get("screenshotUrl"),
        "technology_ids": [str(item["id"]) for item in technologies if item.get("id")],
        "technology_names": [str(item["name"]) for item in technologies if item.get("name")],
        "ai_component_ids": [str(item["id"]) for item in (endpoint.ai_components or [])
                             if isinstance(item, dict) and item.get("id")],
        "exposure_level": endpoint.exposure_level,
        "is_ai": bool(endpoint.is_ai),
        "is_active": bool(endpoint.is_active),
        "related_issue_count": endpoint.related_issue_count or 0,
        "analytics_issue_count": analytics.get("issueCount") or 0,
        "critical_issue_count": analytics.get("criticalSeverityCount") or 0,
        "high_issue_count": analytics.get("highSeverityCount") or 0,
        "medium_issue_count": analytics.get("mediumSeverityCount") or 0,
        "low_issue_count": analytics.get("lowSeverityCount") or 0,
    }}
    issues = [{
        "endpoint_key": key,
        "issue_key": f"wiz:{endpoint.organization_id}:{item['id']}",
        "id": str(item["id"]),
        "severity": item.get("severity"),
        "status": item.get("status"),
        "url": item.get("url"),
    } for item in (endpoint.related_issues or []) if isinstance(item, dict) and item.get("id")]
    resources = [{
        "endpoint_key": key,
        "resource_key": f"wiz:{endpoint.organization_id}:{item['id']}",
        "id": str(item["id"]),
        "name": item.get("name"),
        "type": item.get("type"),
        "provider_unique_id": item.get("providerUniqueId"),
    } for item in (data.get("resources") or []) if isinstance(item, dict) and item.get("id")]
    return row, issues, resources


def _write_count(tx: Any, statement: str, rows: list[dict[str, Any]], org_id: int) -> None:
    if not rows:
        return
    record = tx.run(statement, rows=rows, org_id=org_id).single()
    written = record["written"] if record else 0
    if written != len(rows):
        raise RuntimeError(f"Graph wrote {written} of {len(rows)} source records.")


def _write_asset_batch(tx: Any, rows: list[dict[str, Any]], org_id: int) -> None:
    _write_count(tx, ASSET_QUERY, rows, org_id)


def _write_vulnerability_batch(tx: Any, rows: list[dict[str, Any]], org_id: int) -> None:
    _write_count(tx, VULNERABILITY_QUERY, rows, org_id)
    if any(row["cve_id"] for row in rows):
        tx.run(CVE_QUERY, rows=rows, org_id=org_id).consume()


def _write_endpoint_batch(
    tx: Any, endpoints: list[dict[str, Any]], issues: list[dict[str, Any]],
    resources: list[dict[str, Any]], org_id: int,
) -> None:
    _write_count(tx, ENDPOINT_QUERY, endpoints, org_id)
    tx.run(CLEAR_ENDPOINT_LINKS_QUERY, keys=[row["key"] for row in endpoints]).consume()
    _write_count(tx, ISSUE_QUERY, issues, org_id)
    _write_count(tx, RESOURCE_QUERY, resources, org_id)


def _source_asset_ids(db: Session, organization_id: int, source: str) -> list[int]:
    if source == "wiz":
        statement = text("""
            SELECT id FROM assets WHERE organization_id = :org_id AND
            (discovery_source = 'wiz' OR metadata->'wiz' IS NOT NULL
             OR metadata->'wiz_endpoint_ids' IS NOT NULL)
            ORDER BY id
        """)
    else:
        statement = text("""
            SELECT DISTINCT a.id FROM assets a
            JOIN crowdstrike_asset_links l ON l.asset_id = a.id
            JOIN crowdstrike_integrations c ON c.id = l.integration_id
            WHERE a.organization_id = :org_id AND c.organization_id = :org_id
            ORDER BY a.id
        """)
    return list(db.execute(statement, {"org_id": organization_id}).scalars())


def _source_vulnerability_ids(db: Session, organization_id: int, source: str) -> list[int]:
    return [row[0] for row in db.query(Vulnerability.id).join(Asset, Vulnerability.asset_id == Asset.id).filter(
        Asset.organization_id == organization_id, Vulnerability.detected_by == source
    ).order_by(Vulnerability.id).all()]


def _lock_key(organization_id: int, source: str) -> int:
    digest = hashlib.sha256(f"integration-graph:{organization_id}:{source}".encode()).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


def sync_integration_graph(
    organization_id: int, source: str, *, limit: int | None = None
) -> dict[str, Any]:
    """Reconcile every imported record from one provider, in bounded batches."""
    if source not in {"wiz", "crowdstrike"}:
        raise ValueError("Unsupported integration graph source")
    if limit is not None and limit < 1:
        raise ValueError("Graph projection limit must be positive")
    stats: dict[str, Any] = {"ok": False, "assets": 0, "vulnerabilities": 0,
                             "endpoints": 0, "direct_issue_links": 0, "resource_links": 0,
                             "partial": limit is not None,
                             "attempted_at": datetime.utcnow().isoformat()}
    with SessionLocal() as db:
        engine = db.get_bind()
        with engine.connect() as lock_conn:
            locked = (engine.dialect.name != "postgresql" or bool(lock_conn.execute(
                text("SELECT pg_try_advisory_lock(:key)"), {"key": _lock_key(organization_id, source)}
            ).scalar()))
            if not locked:
                return {**stats, "error": "A graph projection for this source is already running."}
            try:
                graph = get_graph_service()
                if not graph._connected:
                    raise RuntimeError("Neo4j is not connected from this worker.")
                with graph.session() as graph_session:
                    graph_session.run("CREATE INDEX integration_asset_wiz_id IF NOT EXISTS "
                                      "FOR (a:Asset) ON (a.wiz_resource_id)").consume()
                    graph_session.run("CREATE CONSTRAINT wiz_issue_key IF NOT EXISTS "
                                      "FOR (i:WizIssue) REQUIRE i.key IS UNIQUE").consume()
                    graph_session.run("CREATE CONSTRAINT wiz_resource_key IF NOT EXISTS "
                                      "FOR (r:WizResource) REQUIRE r.key IS UNIQUE").consume()
                    asset_ids = _source_asset_ids(db, organization_id, source)
                    vulnerability_ids = _source_vulnerability_ids(db, organization_id, source)
                    endpoint_ids = ([row[0] for row in db.query(WizApplicationEndpoint.id).filter(
                        WizApplicationEndpoint.organization_id == organization_id
                    ).order_by(WizApplicationEndpoint.id).all()] if source == "wiz" else [])
                    if limit:
                        asset_ids = asset_ids[:limit]
                        vulnerability_ids = vulnerability_ids[:limit]
                        endpoint_ids = endpoint_ids[:limit]
                    if limit:
                        dependent_assets = [row[0] for row in db.query(Vulnerability.asset_id).filter(
                            Vulnerability.id.in_(vulnerability_ids)
                        ).all()] if vulnerability_ids else []
                        if endpoint_ids:
                            dependent_assets.extend(row[0] for row in db.query(WizApplicationEndpoint.asset_id).filter(
                                WizApplicationEndpoint.id.in_(endpoint_ids),
                                WizApplicationEndpoint.asset_id.isnot(None),
                            ).all())
                    else:
                        dependent_assets = [row[0] for row in db.query(Vulnerability.asset_id).join(
                            Asset, Vulnerability.asset_id == Asset.id
                        ).filter(Asset.organization_id == organization_id, Vulnerability.detected_by == source).distinct().all()]
                        if source == "wiz":
                            dependent_assets.extend(row[0] for row in db.query(WizApplicationEndpoint.asset_id).filter(
                                WizApplicationEndpoint.organization_id == organization_id,
                                WizApplicationEndpoint.asset_id.isnot(None),
                            ).distinct().all())
                    asset_ids = sorted(set(asset_ids + dependent_assets))
                    for ids in _chunks(asset_ids, ASSET_BATCH_SIZE):
                        assets = db.query(Asset).filter(Asset.id.in_(ids), Asset.organization_id == organization_id).all()
                        rows = [_asset_row(asset) for asset in assets]
                        graph_session.execute_write(_write_asset_batch, rows, organization_id)
                        stats["assets"] += len(rows)
                        if stats["assets"] % 10000 < ASSET_BATCH_SIZE:
                            logger.info("%s graph assets projected for org %s: %s", source, organization_id, stats["assets"])
                    for ids in _chunks(vulnerability_ids, VULNERABILITY_BATCH_SIZE):
                        vulns = db.query(Vulnerability).options(selectinload(Vulnerability.asset)).join(
                            Asset, Vulnerability.asset_id == Asset.id
                        ).filter(
                            Vulnerability.id.in_(ids), Asset.organization_id == organization_id
                        ).all()
                        rows = [_vulnerability_row(vuln) for vuln in vulns]
                        graph_session.execute_write(_write_vulnerability_batch, rows, organization_id)
                        stats["vulnerabilities"] += len(rows)
                    if source == "wiz":
                        for ids in _chunks(endpoint_ids, ENDPOINT_BATCH_SIZE):
                            endpoints = db.query(WizApplicationEndpoint).filter(
                                WizApplicationEndpoint.id.in_(ids),
                                WizApplicationEndpoint.organization_id == organization_id,
                            ).all()
                            rows, issues, resources = [], [], []
                            for endpoint in endpoints:
                                row, endpoint_issues, endpoint_resources = _endpoint_rows(endpoint)
                                rows.append(row)
                                issues.extend(endpoint_issues)
                                resources.extend(endpoint_resources)
                            graph_session.execute_write(
                                _write_endpoint_batch, rows, issues, resources, organization_id
                            )
                            stats["endpoints"] += len(rows)
                            stats["direct_issue_links"] += len(issues)
                            stats["resource_links"] += len(resources)
                stats["ok"] = True
                stats["completed_at"] = datetime.utcnow().isoformat()
                logger.info("%s graph projection for org %s complete: %s", source, organization_id, stats)
            except Exception as exc:
                logger.exception("%s graph projection for org %s failed", source, organization_id)
                stats["error"] = str(exc)[:500]
            finally:
                if engine.dialect.name == "postgresql":
                    lock_conn.execute(text("SELECT pg_advisory_unlock(:key)"),
                                      {"key": _lock_key(organization_id, source)})
    return stats


def project_and_record_graph(organization_id: int, source: str, integration_id: int) -> dict[str, Any]:
    """Project a provider and record graph health separately from API import health."""
    result = sync_integration_graph(organization_id, source)
    model = WizIntegration if source == "wiz" else CrowdStrikeIntegration
    with SessionLocal() as db:
        integration = db.query(model).filter_by(id=integration_id, organization_id=organization_id).first()
        if integration is not None:
            state = dict(integration.last_sync_stats or {})
            state["graph_projection"] = result
            integration.last_sync_stats = state
            db.commit()
    return result


def graph_projection_retry_due(integration: WizIntegration | CrowdStrikeIntegration,
                               now: datetime | None = None) -> bool:
    """Retry a failed graph write without repeating a completed provider pull."""
    if not integration.is_active or not integration.last_sync_ok:
        return False
    state = integration.last_sync_stats or {}
    if state.get("sync_in_progress"):
        return False
    graph_state = state.get("graph_projection") or {}
    if graph_state.get("ok") is not False:
        return False
    try:
        attempted_at = datetime.fromisoformat(graph_state["attempted_at"])
    except (KeyError, TypeError, ValueError):
        return True
    return (now or datetime.utcnow()) >= attempted_at + timedelta(hours=1)
