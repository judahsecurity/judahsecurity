"""
CMDB worker — keeps ServiceNow ownership attribution current.

- Every CMDB_SYNC_HOURS (default 24; 0 disables) it runs the full ServiceNow
  CMDB sync for every organization with a ServiceNow integration: business
  applications, application services, the CIs that run them, then asset
  attribution (see app.services.cmdb_sync).
- Every CMDB_ATTRIBUTE_INTERVAL_MINUTES (default 15) it matches newly
  discovered, not-yet-attributed assets against the last synced CMDB data,
  without calling ServiceNow.

The first full sync runs CMDB_SYNC_START_DELAY_MINUTES (default 5) after
the worker starts, so a restart does not hit ServiceNow immediately.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import threading
import time
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

_shutdown = threading.Event()


def _int_env(name: str, default: int, minimum: int) -> int:
    try:
        return max(minimum, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


def _org_ids(session_factory) -> List[int]:
    from app.models.servicenow_integration import ServiceNowIntegration

    db = session_factory()
    try:
        return [row[0] for row in db.query(ServiceNowIntegration.organization_id).distinct()]
    finally:
        db.close()


def sync_all(session_factory) -> Dict[int, Any]:
    """Full CMDB sync for each org with ServiceNow configured. One org's
    failure does not stop the others."""
    from app.services.cmdb_sync import sync_cmdb

    results: Dict[int, Any] = {}
    for org_id in _org_ids(session_factory):
        if _shutdown.is_set():
            break
        db = session_factory()
        try:
            result = asyncio.run(sync_cmdb(db, org_id))
            db.commit()
            results[org_id] = result
            logger.info(
                "CMDB sync org %s: %s business apps, %s services, attribution %s, warnings %d",
                org_id, result.get("business_apps"), result.get("application_services"),
                result.get("attribution"), len(result.get("warnings") or []),
            )
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            results[org_id] = {"error": str(exc)}
            logger.warning("CMDB sync failed for org %s: %s", org_id, exc)
            _record_failure(session_factory, org_id, str(exc))
        finally:
            db.close()
    return results


def _record_failure(session_factory, org_id: int, error: str) -> None:
    from datetime import datetime

    from app.models.servicenow_integration import ServiceNowIntegration

    db = session_factory()
    try:
        integration = db.query(ServiceNowIntegration).filter(ServiceNowIntegration.organization_id == org_id).first()
        if integration is not None:
            integration.last_cmdb_sync_at = datetime.utcnow()
            integration.last_cmdb_sync_result = {"error": error[:500]}
            db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()
    finally:
        db.close()


def attribute_new(session_factory) -> Dict[int, Any]:
    """Match not-yet-attributed assets to the last synced CMDB data."""
    from app.services.cmdb_sync import attribute_assets

    results: Dict[int, Any] = {}
    for org_id in _org_ids(session_factory):
        db = session_factory()
        try:
            stats = attribute_assets(db, org_id, unattributed_only=True)
            db.commit()
            results[org_id] = stats
            if stats["linked"]:
                logger.info("CMDB attribution org %s: %d new asset(s) linked", org_id, stats["linked"])
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            logger.warning("CMDB attribution failed for org %s: %s", org_id, exc)
        finally:
            db.close()
    return results


def _handle_signal(_signum, _frame) -> None:
    _shutdown.set()


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    import app.models  # noqa: F401 — registers models and dirty tracking
    from app.db.database import SessionLocal

    sync_hours = _int_env("CMDB_SYNC_HOURS", 24, 0)
    attribute_every = _int_env("CMDB_ATTRIBUTE_INTERVAL_MINUTES", 15, 1) * 60
    start_delay = _int_env("CMDB_SYNC_START_DELAY_MINUTES", 5, 0) * 60
    next_sync = time.monotonic() + start_delay if sync_hours else None
    logger.info(
        "Starting CMDB worker (full sync every %s, attribution every %dm)",
        f"{sync_hours}h" if sync_hours else "— disabled", attribute_every // 60,
    )

    while not _shutdown.is_set():
        try:
            if next_sync is not None and time.monotonic() >= next_sync:
                sync_all(SessionLocal)
                next_sync = time.monotonic() + sync_hours * 3600
            else:
                attribute_new(SessionLocal)
        except Exception:
            logger.exception("CMDB worker cycle failed")
        _shutdown.wait(attribute_every)
    logger.info("CMDB worker stopped")


if __name__ == "__main__":
    main()
