"""Remove legacy tenant observations from shared graph nodes.

Run during a graph maintenance window, then refresh every organization with
backfill_graph.py --refresh-existing. PostgreSQL remains the source of truth.
The command is idempotent and only changes Neo4j when --apply is provided.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.graph_service import get_graph_service


# Each query returns the number changed and stops matching after its cleanup.
# Keeping the batches small avoids one transaction spanning a large graph.
CLEANUPS = (
    ("unsupported service-technology links",
     "MATCH (:Service)-[r:USES_TECHNOLOGY]->(:Technology) "
     "WITH r LIMIT $batch_size DELETE r RETURN count(r) AS changed"),
    ("unsupported technology-finding links",
     "MATCH (:Technology)-[r:HAS_VULNERABILITY]->(:Vulnerability) "
     "WITH r LIMIT $batch_size DELETE r RETURN count(r) AS changed"),
    ("unscoped shared-node links",
     "MATCH (a)-[r:FORWARDS_TO|BELONGS_TO_ASN|HOSTED_BY]->(b) "
     "WHERE r.organization_id IS NULL AND (a:IP OR b:IP) "
     "WITH r LIMIT $batch_size DELETE r RETURN count(r) AS changed"),
    ("IP observations on shared nodes",
     "MATCH (n:IP) WHERE n.organization_id IS NOT NULL OR n.is_cdn IS NOT NULL "
     "OR n.is_live IS NOT NULL OR n.is_internet_facing IS NOT NULL "
     "WITH n LIMIT $batch_size "
     "REMOVE n.organization_id, n.is_cdn, n.is_live, n.is_internet_facing "
     "RETURN count(n) AS changed"),
    ("ASN observations on shared nodes",
     "MATCH (n:ASN) WHERE n.organization_id IS NOT NULL OR n.isp IS NOT NULL "
     "OR n.country IS NOT NULL WITH n LIMIT $batch_size "
     "REMOVE n.organization_id, n.isp, n.country RETURN count(n) AS changed"),
    ("certificate tenant stamps",
     "MATCH (n:Certificate) WHERE n.organization_id IS NOT NULL "
     "WITH n LIMIT $batch_size REMOVE n.organization_id RETURN count(n) AS changed"),
    ("discovery source tenant stamps",
     "MATCH (n:DiscoverySource) WHERE n.organization_id IS NOT NULL "
     "WITH n LIMIT $batch_size REMOVE n.organization_id RETURN count(n) AS changed"),
    ("hosting provider observations on shared nodes",
     "MATCH (n:HostingProvider) WHERE n.organization_id IS NOT NULL "
     "OR n.hosting_type IS NOT NULL WITH n LIMIT $batch_size "
     "REMOVE n.organization_id, n.hosting_type RETURN count(n) AS changed"),
    ("technology observations on shared nodes",
     "MATCH (n:Technology) WHERE n.organization_id IS NOT NULL "
     "OR n.version IS NOT NULL OR n.cpe IS NOT NULL WITH n LIMIT $batch_size "
     "REMOVE n.organization_id, n.version, n.cpe RETURN count(n) AS changed"),
    ("service observations on shared nodes",
     "MATCH (n:Service) WHERE n.version IS NOT NULL OR n.banner IS NOT NULL "
     "OR n.product IS NOT NULL OR n.cpe IS NOT NULL WITH n LIMIT $batch_size "
     "REMOVE n.version, n.banner, n.product, n.cpe RETURN count(n) AS changed"),
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Perform the cleanup")
    parser.add_argument("--batch-size", type=int, default=1000)
    args = parser.parse_args()
    if not 1 <= args.batch_size <= 10000:
        parser.error("batch size must be 1-10000")
    if not args.apply:
        parser.exit(2, "No changes made. Pass --apply after backing up Neo4j.\n")

    graph = get_graph_service()
    if not graph._connected:
        parser.exit(1, "Neo4j is not connected\n")
    with graph.session() as session:
        for name, statement in CLEANUPS:
            total = 0
            while True:
                row = session.run(statement, {"batch_size": args.batch_size}).single()
                changed = int(row["changed"]) if row else 0
                total += changed
                if not changed:
                    break
            print(f"{name}: {total}", flush=True)
    print("Cleanup complete. Refresh every organization from PostgreSQL.", flush=True)


if __name__ == "__main__":
    main()
