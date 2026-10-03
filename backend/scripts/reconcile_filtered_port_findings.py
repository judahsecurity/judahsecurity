"""One-time repair for active port findings whose latest port state is non-open.

Run inside the backend environment with
``PYTHONPATH=backend python backend/scripts/reconcile_filtered_port_findings.py``.
The default is a dry run; pass --apply to persist changes after deploying the
port-verification fix.
"""

import argparse

from sqlalchemy import and_, or_

import app.models  # noqa: F401 - register all ORM relationships
from app.db.database import SessionLocal
from app.models.port_service import PortService, PortState
from app.services.port_findings_service import PortFindingsService


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="commit the repaired finding statuses")
    args = parser.parse_args()

    non_open_states = (
        PortState.FILTERED, PortState.CLOSED,
        PortState.OPEN_FILTERED, PortState.CLOSED_FILTERED,
    )
    with SessionLocal() as db:
        ports = db.query(PortService).filter(or_(
            PortService.state.in_(non_open_states),
            and_(
                PortService.verified.is_(True),
                PortService.verified_state.in_(tuple(s.value for s in non_open_states)),
            ),
        )).all()
        resolved = sum(PortFindingsService.resolve_findings_for_port(db, port) for port in ports)
        if args.apply:
            db.commit()
        else:
            db.rollback()
        print(f"{len(ports)} non-open ports checked; {resolved} active scanner findings "
              f"{'resolved' if args.apply else 'would be resolved (dry run)'}")


if __name__ == "__main__":
    main()
