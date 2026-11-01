"""Synchronize the PostgreSQL scan type enum and CommonCrawl settings.

SQLAlchemy persists ScanType member names (for example COMMONCRAWL_ENUM), not
their lowercase Python values. Keep every model member available to scheduled
and direct scans. Safe to run repeatedly.

Usage:
    python scripts/migrate_commoncrawl_enum.py
"""
import os
import sys
import logging

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.models.scan import ScanType

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    logger.error("DATABASE_URL not set")
    sys.exit(1)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)


def add_enum_value():
    """Add every ScanType member name missing from the PostgreSQL enum."""
    with engine.begin() as conn:
        existing = {
            row[0]
            for row in conn.execute(text("""
                SELECT e.enumlabel
                FROM pg_enum e
                JOIN pg_type t ON t.oid = e.enumtypid
                WHERE t.typname = 'scantype'
            """))
        }
        if not existing:
            raise RuntimeError("PostgreSQL scantype enum is missing")

        missing = sorted({member.name for member in ScanType} - existing)
        for label in missing:
            conn.execute(
                text("ALTER TYPE scantype ADD VALUE IF NOT EXISTS :label"),
                {"label": label},
            )

    logger.info("Added %d missing scantype labels", len(missing))


def ensure_commoncrawl_settings():
    """Create the commoncrawl project-settings row for every existing org."""
    from app.models.organization import Organization
    from app.models.project_settings import ProjectSettings

    db = SessionLocal()
    try:
        orgs = db.query(Organization).filter(Organization.is_active == True).all()
        created = 0
        for org in orgs:
            ProjectSettings.ensure_defaults(db, org.id)
            created += 1
        logger.info(f"Ensured commoncrawl settings for {created} organization(s)")
    finally:
        db.close()


if __name__ == "__main__":
    logger.info("Running scan type and CommonCrawl migration...")
    add_enum_value()
    ensure_commoncrawl_settings()
    logger.info("Migration complete.")
