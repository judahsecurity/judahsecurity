#!/usr/bin/env python3
"""
Create sitemap_entries table (Praetorian-style application map).

Run with:
    docker exec asm_backend python /app/scripts/migrate_add_sitemap_entries.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine, text
from app.core.config import settings


def run_migration():
    engine = create_engine(settings.DATABASE_URL)
    statements = [
        """
        CREATE TABLE IF NOT EXISTS sitemap_entries (
            id SERIAL PRIMARY KEY,
            organization_id INTEGER NOT NULL REFERENCES organizations(id),
            asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            kind VARCHAR(20) NOT NULL,
            path_key VARCHAR(64) NOT NULL,
            host VARCHAR(255) NOT NULL DEFAULT '',
            method VARCHAR(16) NOT NULL DEFAULT '',
            path VARCHAR(2048) NOT NULL DEFAULT '/',
            url VARCHAR(2048) NOT NULL DEFAULT '',
            query_template VARCHAR(1024),
            has_secrets BOOLEAN NOT NULL DEFAULT FALSE,
            has_login BOOLEAN NOT NULL DEFAULT FALSE,
            has_sso BOOLEAN NOT NULL DEFAULT FALSE,
            screenshot_count INTEGER NOT NULL DEFAULT 0,
            screenshot_id INTEGER REFERENCES screenshots(id) ON DELETE SET NULL,
            http_status INTEGER,
            response_title VARCHAR(512),
            source VARCHAR(64),
            sources JSON DEFAULT '[]'::json,
            parameters JSON DEFAULT '[]'::json,
            extra JSON DEFAULT '{}'::json,
            first_seen TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            last_seen TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        )
        """,
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_sitemap_asset_path_key ON sitemap_entries (asset_id, path_key)",
        "CREATE INDEX IF NOT EXISTS ix_sitemap_asset_kind ON sitemap_entries (asset_id, kind)",
        "CREATE INDEX IF NOT EXISTS ix_sitemap_org_asset ON sitemap_entries (organization_id, asset_id)",
        "CREATE INDEX IF NOT EXISTS ix_sitemap_login ON sitemap_entries (asset_id, has_login)",
        "CREATE INDEX IF NOT EXISTS ix_sitemap_sso ON sitemap_entries (asset_id, has_sso)",
        "CREATE INDEX IF NOT EXISTS ix_sitemap_secrets ON sitemap_entries (asset_id, has_secrets)",
        "CREATE INDEX IF NOT EXISTS ix_sitemap_entries_asset_id ON sitemap_entries (asset_id)",
        "CREATE INDEX IF NOT EXISTS ix_sitemap_entries_organization_id ON sitemap_entries (organization_id)",
        "CREATE INDEX IF NOT EXISTS ix_sitemap_entries_kind ON sitemap_entries (kind)",
    ]
    with engine.connect() as conn:
        for stmt in statements:
            preview = " ".join(stmt.split())[:80]
            try:
                print(f"Running: {preview}...")
                conn.execute(text(stmt))
                conn.commit()
                print("  ✓ Success")
            except Exception as e:
                if "already exists" in str(e).lower():
                    print("  ⚠ Already exists, skipping")
                else:
                    print(f"  ✗ Error: {e}")
                    raise
    print("\n✓ sitemap_entries table ready")


if __name__ == "__main__":
    run_migration()
