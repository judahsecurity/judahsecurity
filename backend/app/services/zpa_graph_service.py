"""Project durable ZPA observations into Neo4j without inferring reachability."""

import logging

from sqlalchemy import func

from app.db.database import SessionLocal
from app.models.asset import Asset
from app.models.zpa_integration import ZpaIntegration, ZpaObservation
from app.services.graph_service import get_graph_service

logger = logging.getLogger(__name__)


def project_zpa_integration(integration_id: int, organization_id: int) -> dict:
    """Rebuild one connection's observation edges from PostgreSQL evidence."""
    graph = get_graph_service()
    if not graph._connected:
        return {"ok": False, "error": "Neo4j not connected"}
    db = SessionLocal()
    try:
        integration = db.query(ZpaIntegration).filter(
            ZpaIntegration.id == integration_id,
            ZpaIntegration.organization_id == organization_id,
        ).first()
        if not integration:
            return {"ok": False, "error": "ZPA connection not found"}
        asset_ids = [row[0] for row in db.query(ZpaObservation.destination_asset_id).filter(
            ZpaObservation.integration_id == integration_id,
            ZpaObservation.destination_asset_id.isnot(None),
        ).distinct().all()]
        assets = db.query(Asset).filter(
            Asset.organization_id == organization_id,
            Asset.id.in_(asset_ids),
        ).all() if asset_ids else []
        with graph.session() as session:
            for asset in assets:
                session.execute_write(lambda tx, item=asset: graph._sync_asset(tx, item, organization_id))
            # A full rebuild also repairs interrupted previous projections and
            # removes stale evidence if an observation was deleted.
            session.run(
                "MATCH (s:ZpaSource {integration_id: $integration_id, organization_id: $org_id}) DETACH DELETE s",
                integration_id=integration_id, org_id=organization_id,
            )
            rows = db.query(
                ZpaObservation.source_key,
                func.max(ZpaObservation.source_name),
                ZpaObservation.feed,
                ZpaObservation.destination_asset_id,
                ZpaObservation.destination_port,
                ZpaObservation.protocol,
                ZpaObservation.connected,
                func.count(ZpaObservation.id),
                func.min(ZpaObservation.occurred_at),
                func.max(ZpaObservation.occurred_at),
            ).filter(
                ZpaObservation.integration_id == integration_id,
                ZpaObservation.destination_asset_id.isnot(None),
            ).group_by(
                ZpaObservation.source_key, ZpaObservation.feed,
                ZpaObservation.destination_asset_id, ZpaObservation.destination_port,
                ZpaObservation.protocol, ZpaObservation.connected,
            ).all()
            for source_key, source_name, feed, asset_id, port, protocol, connected, count, first, last in rows:
                edge = ("OBSERVED_OUTBOUND_TO" if connected else "ATTEMPTED_OUTBOUND_TO") if feed == "microsegmentation" else (
                    "OBSERVED_ACCESS_TO" if connected else "REPORTED_ACCESS_TO"
                )
                query = f"""
                    MERGE (s:ZpaSource {{key: $source_key}})
                    SET s.organization_id = $org_id, s.integration_id = $integration_id,
                        s.name = $source_name, s.feed = $feed
                    WITH s
                    MATCH (a:Asset {{asset_id: $asset_id, organization_id: $org_id}})
                    MERGE (s)-[r:{edge} {{port: $port, protocol: $protocol}}]->(a)
                    SET r.source = 'zpa', r.organization_id = $org_id,
                        r.observation_count = $count,
                        r.first_seen = $first_seen, r.last_seen = $last_seen
                """
                session.run(query, source_key=source_key, source_name=source_name,
                            feed=feed, asset_id=asset_id, org_id=organization_id,
                            integration_id=integration_id, port=port or 0,
                            protocol=protocol or "", count=count,
                            first_seen=first.isoformat(), last_seen=last.isoformat())
        return {"ok": True, "assets": len(assets), "edges": len(rows)}
    except Exception as exc:
        logger.exception("ZPA graph projection failed for integration %s", integration_id)
        return {"ok": False, "error": str(exc)}
    finally:
        db.close()
