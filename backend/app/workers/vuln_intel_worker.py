"""Continuously refresh disk-backed vulnerability intelligence indexes."""

from __future__ import annotations

import logging
import os
import signal
import threading
from typing import Any

from app.scripts.refresh_vuln_intel import _resolve_token
from app.services.external_vuln_indexes import (
    refresh_nuclei_cve_index,
    refresh_vulncheck_exploit_index,
)
from app.services.vuln_intel_feeds import (
    fetch_cisa_kev_catalog,
    fetch_enisa_eukev_catalog,
    fetch_vulncheck_kev,
)

logger = logging.getLogger(__name__)
DEFAULT_INTERVAL_SECONDS = 3600
MIN_INTERVAL_SECONDS = 300
_shutdown = threading.Event()


def refresh_interval_seconds() -> int:
    try:
        configured = int(
            os.environ.get("VULN_INTEL_REFRESH_INTERVAL_SECONDS", DEFAULT_INTERVAL_SECONDS)
        )
    except (TypeError, ValueError):
        configured = DEFAULT_INTERVAL_SECONDS
    return max(MIN_INTERVAL_SECONDS, configured)


def refresh_once(*, interval_seconds: int | None = None) -> dict[str, Any]:
    """Refresh all feed caches once, retaining stale data on provider failure."""
    interval = interval_seconds or refresh_interval_seconds()
    refresh_hours = max(interval / 3600.0, MIN_INTERVAL_SECONDS / 3600.0)
    token, token_source = _resolve_token()

    cisa = fetch_cisa_kev_catalog(refresh_hours=refresh_hours)
    enisa = fetch_enisa_eukev_catalog(refresh_hours=refresh_hours)
    if token:
        vulncheck_kev = fetch_vulncheck_kev(token, request_timeout=120)
        vulncheck_exploits = refresh_vulncheck_exploit_index(
            token, refresh_hours=refresh_hours
        )
    else:
        vulncheck_kev = {}
        vulncheck_exploits = {
            "status": "unavailable",
            "cves": 0,
            "error": "missing_token",
        }
    nuclei = refresh_nuclei_cve_index(refresh_hours=refresh_hours)
    result = {
        "cisa_kev": len(cisa),
        "enisa_kev": len(enisa),
        "vulncheck_kev": len(vulncheck_kev),
        "vulncheck_exploits": vulncheck_exploits,
        "nuclei": nuclei,
        "token_configured": bool(token),
        "token_source": token_source,
    }
    logger.info(
        "Vulnerability intelligence refresh complete: CISA=%d ENISA=%d "
        "VulnCheck-KEV=%d VulnCheck-XDB=%s Nuclei=%s",
        result["cisa_kev"],
        result["enisa_kev"],
        result["vulncheck_kev"],
        vulncheck_exploits.get("cves", 0),
        nuclei.get("cves", 0),
    )
    return result


def _handle_signal(_signum, _frame) -> None:
    _shutdown.set()


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    interval = refresh_interval_seconds()
    logger.info("Starting vulnerability intelligence refresher (interval=%ss)", interval)
    while not _shutdown.is_set():
        try:
            refresh_once(interval_seconds=interval)
        except Exception:
            logger.exception("Vulnerability intelligence refresh cycle failed")
        _shutdown.wait(interval)
    logger.info("Vulnerability intelligence refresher stopped")


if __name__ == "__main__":
    main()
