"""Bootstrap / increment VulnCheck KEV (and CISA/ENISA caches) on the host.

Run this on the AWS instance inside the backend container so Vulnerability Intel
has disk-cached data to serve. First run downloads the community KEV backup;
later runs only merge newly added rows.

Usage (on the EC2 host)::

    cd /opt/asm   # or wherever the compose file lives
    sudo docker compose exec backend python -m app.scripts.refresh_vuln_intel
    sudo docker compose exec backend python -m app.scripts.refresh_vuln_intel --force
    sudo docker compose exec backend python -m app.scripts.refresh_vuln_intel --status
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone


def _resolve_token() -> tuple[str, str]:
    """Return (token, source) from env, settings, then api_configs."""
    env = (os.environ.get("VULNCHECK_API_TOKEN") or "").strip()
    if env:
        return env, "env:VULNCHECK_API_TOKEN"

    try:
        from app.core.config import settings

        cfg = (getattr(settings, "VULNCHECK_API_TOKEN", None) or "").strip()
        if cfg:
            return cfg, "settings.VULNCHECK_API_TOKEN"
    except Exception:
        pass

    try:
        from app.db.database import SessionLocal
        from app.models.api_config import ExternalService, resolve_api_key

        db = SessionLocal()
        try:
            key = (resolve_api_key(db, ExternalService.VULNCHECK) or "").strip()
            if key:
                return key, "db:api_configs"
        finally:
            db.close()
    except Exception as exc:
        print(f"note: could not read api_configs ({exc})", file=sys.stderr)

    return "", "none"


def _status() -> int:
    from app.services.vuln_intel_feeds import _cache_dir, fetch_vulncheck_kev, read_json_cache

    cache_dir = _cache_dir()
    print(f"cache dir: {cache_dir}")
    vkev = fetch_vulncheck_kev("", cache_only=True)
    cisa = (read_json_cache("cisa_kev.json") or {}).get("vulnerabilities") or []
    enisa = (read_json_cache("enisa_eukev.json") or {}).get("rows") or []
    print(f"vulncheck_kev: {len(vkev)} entries")
    print(f"cisa_kev:      {len(cisa)} entries")
    print(f"enisa_eukev:   {len(enisa)} entries")
    token, source = _resolve_token()
    print(f"vulncheck token: {'configured' if token else 'MISSING'} ({source})")
    return 0 if (vkev or cisa or enisa) else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Refresh Vulnerability Intel disk caches")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-download the full VulnCheck community backup instead of incremental merge",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Print cache counts and token source; do not fetch",
    )
    args = parser.parse_args(argv)

    if args.status:
        return _status()

    from app.services.vuln_intel_feeds import (
        _cache_dir,
        fetch_cisa_kev_catalog,
        fetch_enisa_eukev_catalog,
        fetch_vulncheck_kev,
    )

    cache_dir = _cache_dir()
    print(f"cache dir: {cache_dir}")
    token, source = _resolve_token()
    if token:
        print(f"vulncheck token: configured ({source})")
    else:
        print("vulncheck token: MISSING — set VULNCHECK_API_TOKEN in .env or Settings")

    started = datetime.now(timezone.utc)
    print("fetching CISA KEV…")
    cisa = fetch_cisa_kev_catalog(force=True)
    print(f"  cisa_kev: {len(cisa)} entries")

    print("fetching ENISA EUKEV…")
    enisa = fetch_enisa_eukev_catalog(force=True)
    print(f"  enisa_eukev: {len(enisa)} entries")

    vkev = {}
    if token:
        print("fetching VulnCheck community KEV (backup if empty, else new rows)…")
        vkev = fetch_vulncheck_kev(token, force=args.force, request_timeout=120)
        print(f"  vulncheck_kev: {len(vkev)} entries")
    else:
        print("skipping VulnCheck (no token)")

    elapsed = (datetime.now(timezone.utc) - started).total_seconds()
    print(f"done in {elapsed:.1f}s")
    if not cisa and not vkev and not enisa:
        print("ERROR: no intel rows cached. Check outbound HTTPS from this host.", file=sys.stderr)
        return 1
    print("Vulnerability Intel can now serve from this cache. Refresh the UI.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
