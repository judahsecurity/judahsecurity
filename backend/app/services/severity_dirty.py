"""
Mark findings for severity re-evaluation whenever one of their inputs changes.

The severity score is computed by the severity worker (a periodic Python job,
app/workers/severity_worker.py). This module is the "anytime a value changes,
the score re-runs" half: SQLAlchemy flush hooks set ``sev_dirty`` (and
``sev_dirty_at``) on every finding whose inputs changed, and the worker
re-evaluates dirty findings on its next tick.

Inputs watched:
  • the finding itself — scanner fields, status, enrichment in ``metadata_``
    (Oracle, Delphi, analyst overrides; the evaluator's own
    ``severity_eval`` output is ignored so evaluation never re-triggers
    itself), business application link
  • its asset — criticality, exposure, IPs, hosting, netblock, business app
  • IP assets resolved from a domain — they decide the domain's hosting
  • business applications — criticality and name
  • netblocks — the organization's IP inventory decides hosting for all of
    its findings
  • the organization — its name (Network Location rating) and its default
    factor weights

Registered on import from app.models, so writes from any process (API,
scanner workers, integrations) mark findings dirty.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Iterable, Set

from sqlalchemy import event, inspect, or_, select, update
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

VULN_INPUTS = {
    "title", "severity", "cvss_score", "cvss_vector", "cve_id", "cwe_id", "detected_by",
    "template_id", "is_manual", "detection_confidence", "last_validation_verdict",
    "business_app_id", "asset_id", "status",
}
ASSET_INPUTS = {
    "criticality", "is_public", "ip_address", "ip_addresses", "hosting_type", "hosting_provider",
    "netblock_id", "business_app_id", "organization_id", "value", "has_login_portal", "resolved_from",
}
APP_INPUTS = {"criticality_level", "business_criticality", "name", "app_id"}
NETBLOCK_INPUTS = {"cidr_notation", "inetnum", "start_ip", "end_ip", "is_owned", "in_scope", "organization_id"}

_registered = False


def _changed(obj, names: Set[str]) -> bool:
    state = inspect(obj)
    return any(state.attrs[n].history.has_changes() for n in names if n in state.attrs)


def _metadata_input_changed(vuln) -> bool:
    """True when metadata_ changed in anything but the evaluator's own output."""
    hist = inspect(vuln).attrs["metadata_"].history
    if not hist.has_changes():
        return False
    before = dict((hist.deleted or [None])[0] or {})
    after = dict((hist.added or [None])[0] or {})
    before.pop("severity_eval", None)
    after.pop("severity_eval", None)
    # A plain in-place mutation + flag_modified leaves no "before"; be safe.
    return not hist.deleted or before != after


def _is_evaluation_write(vuln) -> bool:
    """The evaluator stamps sev_evaluated_at when it writes; those writes were
    computed from the in-session values, so they don't need a re-run."""
    return inspect(vuln).attrs["sev_evaluated_at"].history.has_changes()


def mark_dirty(conn, where) -> None:
    from app.models.vulnerability import Vulnerability

    conn.execute(
        update(Vulnerability.__table__)
        .where(where)
        .values(sev_dirty=True, sev_dirty_at=datetime.utcnow())
    )


def _collect(session: Session):
    from app.models.asset import Asset
    from app.models.business_application import BusinessApplication
    from app.models.netblock import Netblock
    from app.models.organization import Organization
    from app.models.vulnerability import Vulnerability

    asset_ids: Set[int] = set()
    resolved: Set[tuple] = set()  # (org_id, domain) whose resolved IPs changed
    app_ids: Set[int] = set()
    org_ids: Set[int] = set()

    for obj in list(session.dirty) + list(session.deleted):
        if isinstance(obj, Vulnerability):
            if obj in session.deleted or _is_evaluation_write(obj):
                continue
            if _changed(obj, VULN_INPUTS) or _metadata_input_changed(obj):
                obj.sev_dirty = True
                obj.sev_dirty_at = datetime.utcnow()
        elif isinstance(obj, Asset):
            if obj in session.deleted or _changed(obj, ASSET_INPUTS):
                if obj.id is not None:
                    asset_ids.add(obj.id)
                if obj.resolved_from:
                    resolved.add((obj.organization_id, obj.resolved_from))
        elif isinstance(obj, BusinessApplication):
            if obj in session.deleted or _changed(obj, APP_INPUTS):
                if obj.id is not None:
                    app_ids.add(obj.id)
        elif isinstance(obj, Netblock):
            if obj in session.deleted or _changed(obj, NETBLOCK_INPUTS):
                org_ids.add(obj.organization_id)
        elif isinstance(obj, Organization):
            if _changed(obj, {"name", "risk_weight_defaults"}) and obj.id is not None:
                org_ids.add(obj.id)

    for obj in session.new:
        if isinstance(obj, Netblock):
            org_ids.add(obj.organization_id)
        elif isinstance(obj, Asset) and obj.resolved_from:
            resolved.add((obj.organization_id, obj.resolved_from))
    return asset_ids, resolved, app_ids, org_ids


def register() -> None:
    """Install the flush hooks once per process."""
    global _registered
    if _registered:
        return
    _registered = True

    @event.listens_for(Session, "before_flush")
    def _before_flush(session, flush_context, instances):  # noqa: ARG001
        try:
            session.info["sev_pending"] = _collect(session)
        except Exception:  # noqa: BLE001 — never block a write over scoring
            logger.exception("severity dirty-tracking failed; the nightly sweep will catch up")
            session.info.pop("sev_pending", None)

    @event.listens_for(Session, "after_flush")
    def _after_flush(session, flush_context):  # noqa: ARG001
        pending = session.info.pop("sev_pending", None)
        if not pending:
            return
        asset_ids, resolved, app_ids, org_ids = pending
        if not (asset_ids or resolved or app_ids or org_ids):
            return
        from app.models.asset import Asset
        from app.models.vulnerability import Vulnerability

        vt, at = Vulnerability.__table__, Asset.__table__
        conn = session.connection()
        try:
            if asset_ids:
                mark_dirty(conn, vt.c.asset_id.in_(asset_ids))
            for org_id, domain in resolved:
                domain_assets = select(at.c.id).where(at.c.organization_id == org_id, at.c.value == domain)
                mark_dirty(conn, vt.c.asset_id.in_(domain_assets))
            if app_ids:
                app_assets = select(at.c.id).where(at.c.business_app_id.in_(app_ids))
                mark_dirty(conn, or_(vt.c.business_app_id.in_(app_ids), vt.c.asset_id.in_(app_assets)))
            if org_ids:
                org_assets = select(at.c.id).where(at.c.organization_id.in_(org_ids))
                mark_dirty(conn, vt.c.asset_id.in_(org_assets))
        except Exception:  # noqa: BLE001
            logger.exception("severity dirty-marking failed; the nightly sweep will catch up")


def mark_all_open(db: Session, organization_id: int | None = None) -> int:
    """Queue every open finding (optionally one org's) for re-evaluation."""
    from app.models.asset import Asset
    from app.models.vulnerability import Vulnerability, VulnerabilityStatus

    vt, at = Vulnerability.__table__, Asset.__table__
    where = vt.c.status.in_([VulnerabilityStatus.OPEN, VulnerabilityStatus.IN_PROGRESS])
    if organization_id is not None:
        where = where & vt.c.asset_id.in_(select(at.c.id).where(at.c.organization_id == organization_id))
    result = db.execute(update(vt).where(where).values(sev_dirty=True, sev_dirty_at=datetime.utcnow()))
    return result.rowcount or 0


def mark_all_findings(db: Session) -> int:
    """Queue every finding for a full sweep, including closed findings."""
    from app.models.vulnerability import Vulnerability

    result = db.execute(
        update(Vulnerability.__table__).values(sev_dirty=True, sev_dirty_at=datetime.utcnow())
    )
    return result.rowcount or 0


def clear_dirty(db: Session, vuln_ids: Iterable[int], started: datetime) -> None:
    """Clear the flag unless the finding changed again after ``started``."""
    from app.models.vulnerability import Vulnerability

    vt = Vulnerability.__table__
    ids = list(vuln_ids)
    if not ids:
        return
    db.execute(
        update(vt)
        .where(vt.c.id.in_(ids), or_(vt.c.sev_dirty_at.is_(None), vt.c.sev_dirty_at <= started))
        .values(sev_dirty=False)
    )
