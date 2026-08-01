#!/usr/bin/env python3
"""
Set up a recurring DAILY subdomain-enumeration schedule for continuous
attack-surface monitoring.

This creates (idempotently) a `subdomain_enum` scan schedule with NO static
targets, so the schedule worker dynamically targets every in-scope domain and
subdomain in the organization's inventory on each run — including domains added
after the schedule was created (e.g. via reverse-pivot discovery). Run it once
per organization and the daily sweep keeps expanding coverage automatically.

Usage:
    # One organization
    python scripts/setup_daily_subdomain_enum.py --org-id 1

    # Every organization that has assets
    python scripts/setup_daily_subdomain_enum.py --all-orgs

    # Choose the hour of day (UTC, 0-23) the sweep runs (default 3am)
    python scripts/setup_daily_subdomain_enum.py --org-id 1 --hour 3

The script is safe to re-run: if a matching daily subdomain_enum schedule
already exists it is left in place (and re-enabled if it was paused).
"""

import argparse
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.database import SessionLocal
from app.models.organization import Organization
from app.models.scan_schedule import ScanSchedule, ScheduleFrequency

SCHEDULE_NAME = "Daily subdomain enumeration"


def ensure_schedule_for_org(db, organization_id: int, run_at_hour: int) -> str:
    """Create or re-enable the daily subdomain_enum schedule for one org.

    Returns a short status string describing what happened.
    """
    # Idempotency: a dynamic (no explicit targets, no labels) daily
    # subdomain_enum schedule is the one we manage.
    existing = (
        db.query(ScanSchedule)
        .filter(
            ScanSchedule.organization_id == organization_id,
            ScanSchedule.scan_type == "subdomain_enum",
        )
        .all()
    )
    managed = next(
        (
            s
            for s in existing
            if not s.targets and not s.label_ids
        ),
        None,
    )

    if managed:
        changed = False
        if not managed.is_enabled:
            managed.is_enabled = True
            changed = True
        if managed.frequency != ScheduleFrequency.DAILY:
            managed.frequency = ScheduleFrequency.DAILY
            changed = True
        managed.run_at_hour = run_at_hour
        managed.next_run_at = managed.calculate_next_run()
        db.commit()
        return f"org {organization_id}: existing schedule #{managed.id} " + (
            "updated" if changed else "already configured"
        )

    schedule = ScanSchedule(
        name=SCHEDULE_NAME,
        description=(
            "Continuously enumerate subdomains for every in-scope domain to keep "
            "attack-surface coverage current. Targets are resolved dynamically at "
            "run time, so newly discovered domains are picked up automatically."
        ),
        organization_id=organization_id,
        scan_type="subdomain_enum",
        targets=[],          # dynamic: worker targets all in-scope domains
        label_ids=[],
        frequency=ScheduleFrequency.DAILY,
        run_at_hour=run_at_hour,
        timezone="UTC",
        is_enabled=True,
        notify_on_findings=True,
        created_by="setup_daily_subdomain_enum",
    )
    schedule.next_run_at = schedule.calculate_next_run()
    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    return f"org {organization_id}: created schedule #{schedule.id} (next run {schedule.next_run_at} UTC)"


def main():
    parser = argparse.ArgumentParser(description="Set up a daily subdomain-enum schedule.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--org-id", type=int, help="Organization ID to configure")
    group.add_argument("--all-orgs", action="store_true", help="Configure every organization")
    parser.add_argument(
        "--hour",
        type=int,
        default=3,
        help="Hour of day (UTC, 0-23) to run the daily sweep (default: 3)",
    )
    args = parser.parse_args()

    if not (0 <= args.hour <= 23):
        parser.error("--hour must be between 0 and 23")

    db = SessionLocal()
    try:
        if args.all_orgs:
            org_ids = [o.id for o in db.query(Organization.id).all()]
            if not org_ids:
                print("No organizations found.")
                return
        else:
            org = db.query(Organization).filter(Organization.id == args.org_id).first()
            if not org:
                print(f"Organization {args.org_id} not found.")
                sys.exit(1)
            org_ids = [args.org_id]

        for org_id in org_ids:
            print(ensure_schedule_for_org(db, org_id, args.hour))
        print(f"\nDone. Ensure the schedule worker is running so the daily sweep fires.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
