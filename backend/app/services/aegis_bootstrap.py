"""
aegis_bootstrap — translate platform settings into the shared aegis_praetorium
config and register a SQLAlchemy-backed scope resolver.

Called once at FastAPI startup from ``app.main``. Keeps all platform-specific
glue out of the shared package so ``aegis_praetorium`` stays dependency-free
and works inside the Aegis Vanguard container.

What it does:
  1. Snapshots ``app.core.config.settings.AGENT_*`` into a ``PraetoriumConfig``
     and pushes it into the shared package (``set_config``).
  2. Registers a ``ScopeResolver`` that queries the platform ``Asset`` table
     for the calling org_id (host or root-domain match). When
     ``AGENT_ENFORCE_ORG_SCOPE`` is False the resolver is still installed but
     never consulted (Lictor checks the config flag first).
"""

from __future__ import annotations

import logging
from typing import Optional

from aegis_praetorium import (
    PraetoriumConfig,
    ScopeResolver,
    set_config,
    set_scope_resolver,
)
from app.core.config import settings

logger = logging.getLogger(__name__)


class _AssetTableScopeResolver(ScopeResolver):
    """Scope resolver that consults the platform ``Asset`` table per request.

    Match logic: hostname is in scope for org_id if any ``Asset`` row exists
    for that org with ``value == hostname`` OR ``root_domain == hostname`` OR
    a registered ``root_domain`` is a suffix of hostname.
    """

    def is_in_scope(self, hostname: str, *, org_id: Optional[int] = None) -> bool:
        if not hostname:
            return False
        if org_id is None:
            # Without an org_id we cannot make a tenant-scoped decision.
            # Fail open and let other Lictor hooks (SSRF, destructive flags)
            # carry the load. The platform always passes org_id when it has one.
            return True
        try:
            from app.db.database import SessionLocal
            from app.models.asset import Asset
        except Exception as e:
            logger.error("aegis_bootstrap: asset/db imports failed (%s) — fail-open", e)
            return True

        host = hostname.strip().lower()
        try:
            with SessionLocal() as session:
                # Exact-value or exact root_domain match.
                exact = (
                    session.query(Asset.id)
                    .filter(Asset.organization_id == org_id)
                    .filter((Asset.value == host) | (Asset.root_domain == host))
                    .first()
                )
                if exact:
                    return True
                # Suffix match against any registered root_domain.
                roots = (
                    session.query(Asset.root_domain)
                    .filter(Asset.organization_id == org_id)
                    .filter(Asset.root_domain.isnot(None))
                    .distinct()
                    .all()
                )
                for (rd,) in roots:
                    if not rd:
                        continue
                    rd = rd.strip().lower()
                    if host == rd or host.endswith("." + rd):
                        return True
                return False
        except Exception as e:
            logger.error("aegis_bootstrap: scope query failed (%s) — fail-open", e)
            return True


def bootstrap_aegis_praetorium() -> None:
    """Push platform settings into the shared package and install the resolver."""
    cfg = PraetoriumConfig(
        lictor_enabled=getattr(settings, "AGENT_LICTOR_ENABLED", True),
        censor_enabled=getattr(settings, "AGENT_CENSOR_ENABLED", True),
        augur_enabled=getattr(settings, "AGENT_AUGUR_ENABLED", True),
        augur_verbose=getattr(settings, "AGENT_AUGUR_VERBOSE", False),
        enforce_scope=getattr(settings, "AGENT_ENFORCE_ORG_SCOPE", False),
        rate_capacity=getattr(settings, "AGENT_TOOL_RATE_CAPACITY", 30),
        rate_per_minute=getattr(settings, "AGENT_TOOL_RATE_PER_MINUTE", 30),
    )
    set_config(cfg)
    set_scope_resolver(_AssetTableScopeResolver())
    logger.info(
        "aegis_praetorium configured: lictor=%s censor=%s augur=%s enforce_scope=%s "
        "rate=%d/min (burst %d) — scope resolver: AssetTable",
        cfg.lictor_enabled, cfg.censor_enabled, cfg.augur_enabled,
        cfg.enforce_scope, cfg.rate_per_minute, cfg.rate_capacity,
    )
