#!/usr/bin/env python3
"""
Clean unattributed shared-PaaS assets (e.g. random *.azurewebsites.net) from inventory.

Only hostnames on shared platforms that cannot be attributed to the org via brand
tokens (rockwell, factorytalk, …) or owned corporate domains are affected.

Usage:
  # Dry run
  python scripts/cleanup_unattributed_paas.py --org-id 1

  # Mark out of scope (recommended)
  python scripts/cleanup_unattributed_paas.py --org-id 1 --action out_of_scope --confirm

  # Hard delete
  python scripts/cleanup_unattributed_paas.py --org-name "Rockwell Automation" --action delete --confirm
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.database import SessionLocal
from app.models.organization import Organization
from app.services.asset_cleanup_service import cleanup_unattributed_shared_paas


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--org-id", type=int, help="Organization ID")
    parser.add_argument("--org-name", type=str, help="Organization name (exact or ILIKE)")
    parser.add_argument(
        "--action",
        choices=["preview", "out_of_scope", "delete"],
        default="preview",
        help="preview (default), out_of_scope, or delete",
    )
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="Required for out_of_scope/delete",
    )
    parser.add_argument(
        "--include-out-of-scope",
        action="store_true",
        help="Also process assets already marked out of scope",
    )
    args = parser.parse_args()

    if args.action != "preview" and not args.confirm:
        print("Refusing to modify inventory without --confirm", file=sys.stderr)
        return 2

    db = SessionLocal()
    try:
        org = None
        if args.org_id:
            org = db.query(Organization).filter(Organization.id == args.org_id).first()
        elif args.org_name:
            org = (
                db.query(Organization)
                .filter(Organization.name.ilike(args.org_name))
                .first()
            )
        else:
            print("Provide --org-id or --org-name", file=sys.stderr)
            return 2

        if not org:
            print("Organization not found", file=sys.stderr)
            return 1

        result = cleanup_unattributed_shared_paas(
            db,
            org.id,
            action=args.action,
            include_already_out_of_scope=args.include_out_of_scope,
        )
        print(json.dumps(result.to_dict(), indent=2))
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
