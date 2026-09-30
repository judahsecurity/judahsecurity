"""Backfill one organization's PostgreSQL assets into Neo4j in bounded batches.

By default, only assets without an inventory node in Neo4j are selected.
Re-running the command resumes from the remaining assets. Use --refresh-existing
to rebuild graph evidence for assets that already have an inventory node.
"""

import argparse
import time

from sqlalchemy.orm import selectinload

from app.db.database import SessionLocal
from app.models.asset import Asset
from app.services.graph_service import get_graph_service


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--organization-id", type=int, required=True)
    parser.add_argument("--batch-size", type=int, default=50)
    parser.add_argument("--max-assets", type=int, default=0,
                        help="Stop after this many assets; 0 means no limit")
    parser.add_argument("--after-id", type=int, default=0,
                        help="Only consider PostgreSQL asset IDs above this value")
    parser.add_argument("--pause-ms", type=int, default=100,
                        help="Pause between batches to reduce production load")
    parser.add_argument("--refresh-existing", action="store_true",
                        help="Rebuild evidence for assets already present in Neo4j")
    args = parser.parse_args()
    if args.organization_id < 1 or not 1 <= args.batch_size <= 200:
        parser.error("Organization ID must be positive and batch size must be 1-200")
    if args.max_assets < 0 or args.after_id < 0 or args.pause_ms < 0:
        parser.error("Limits, after-id, and pause-ms must be nonnegative")

    graph = get_graph_service()
    if not graph._connected:
        parser.exit(1, "Neo4j is not connected\n")

    with SessionLocal() as db:
        asset_ids = [row[0] for row in db.query(Asset.id).filter(
            Asset.organization_id == args.organization_id,
            Asset.id > args.after_id,
        ).order_by(Asset.id).all()]
        if not args.refresh_existing:
            existing = {int(row["asset_id"]) for row in graph.query(
                "MATCH (a:Asset {organization_id: $org_id}) "
                "WHERE a.asset_id IS NOT NULL RETURN a.asset_id AS asset_id",
                {"org_id": args.organization_id},
            )}
            asset_ids = [asset_id for asset_id in asset_ids if asset_id not in existing]
        pending = len(asset_ids)
        if args.max_assets:
            asset_ids = asset_ids[:args.max_assets]
        print(f"organization={args.organization_id} pending={pending} "
              f"selected={len(asset_ids)} refresh_existing={args.refresh_existing}",
              flush=True)

        done = 0
        started = time.monotonic()
        for offset in range(0, len(asset_ids), args.batch_size):
            batch_ids = asset_ids[offset:offset + args.batch_size]
            assets = db.query(Asset).options(
                selectinload(Asset.port_services),
                selectinload(Asset.technologies),
                selectinload(Asset.vulnerabilities),
            ).filter(Asset.organization_id == args.organization_id,
                     Asset.id.in_(batch_ids)).order_by(Asset.id).all()
            with graph.session() as session:
                for asset in assets:
                    try:
                        # One asset per transaction prevents a failed record from
                        # leaving an incomplete Asset node that a resume would skip.
                        session.execute_write(
                            lambda tx, item=asset: graph._sync_asset(
                                tx, item, args.organization_id))
                    except Exception as exc:
                        parser.exit(1, f"Graph backfill failed at asset_id={asset.id}: {exc}\n")
                    done += 1
            print(f"synced={done}/{len(asset_ids)} last_asset_id={batch_ids[-1]} "
                  f"seconds={time.monotonic() - started:.1f}", flush=True)
            if offset + args.batch_size < len(asset_ids) and args.pause_ms:
                time.sleep(args.pause_ms / 1000)

    print(f"complete organization={args.organization_id} synced={done} "
          f"seconds={time.monotonic() - started:.1f}", flush=True)


if __name__ == "__main__":
    main()
