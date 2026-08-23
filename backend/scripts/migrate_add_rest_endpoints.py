#!/usr/bin/env python3
"""Add rest_endpoints + api_specs JSON columns on assets (Vespasian/OpenAPI inventory)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine, text
from app.core.config import settings


def run_migration():
    engine = create_engine(settings.DATABASE_URL)
    statements = [
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS rest_endpoints JSON DEFAULT '[]'::json",
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS api_specs JSON DEFAULT '[]'::json",
    ]
    with engine.connect() as conn:
        for stmt in statements:
            try:
                print(f"Running: {stmt[:70]}...")
                conn.execute(text(stmt))
                conn.commit()
                print("  ✓ Success")
            except Exception as e:
                if "already exists" in str(e).lower():
                    print("  ⚠ Already exists, skipping")
                else:
                    raise
    print("\n✓ Asset REST inventory columns ready")


if __name__ == "__main__":
    run_migration()
