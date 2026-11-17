"""
Host checks — resolve Oracle's ``host_probe`` verification tasks.

Oracle marks a precondition "unknown" when it depends on something only
visible from inside a server (sshd config, installed packages, running
processes). These routes collect or accept that evidence and re-score the
affected findings:

  GET  /host-checks/organizations/{org_id}/pending  findings waiting on host evidence
  POST /host-checks/organizations/{org_id}/run      check every pending asset (background)
  POST /host-checks/assets/{asset_id}/collect       check one asset now over SSH
  POST /host-checks/assets/{asset_id}/facts         push facts from another collector
  GET  /host-checks/assets/{asset_id}/facts         the facts on record

Collectors, in order of preference:
  falcon  the asset is a Falcon host and its CrowdStrike integration has
          ``collect_host_evidence`` on (app/services/falcon_host_evidence.py)
  ssh     the asset matches the org's ``host_ssh`` credential ``targets``
          (fixed read-only probe catalog; app/services/host_evidence_service.py)
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_admin, require_analyst
from app.db.database import SessionLocal
from app.models.asset import Asset
from app.models.user import User
from app.models.vulnerability import Vulnerability, VulnerabilityStatus
from app.services import host_evidence_service as hes

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/host-checks", tags=["host-checks"])


def _check_org(user: User, org_id: int) -> None:
    role = getattr(getattr(user, "role", None), "value", None)
    if role == "admin" or getattr(user, "is_superuser", False):
        return
    if user.organization_id != org_id:
        raise HTTPException(status_code=403, detail="Access denied")


def _asset_or_404(db: Session, asset_id: int, user: User) -> Asset:
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    _check_org(user, asset.organization_id)
    return asset


def _facts_view(asset: Asset) -> Dict[str, Any]:
    record = (asset.metadata_ or {}).get("host_facts") if isinstance(asset.metadata_, dict) else None
    if not record:
        return {"asset_id": asset.id, "collected": False}
    facts = record.get("facts") or {}
    return {
        "asset_id": asset.id,
        "collected": True,
        "collector": record.get("collector"),
        "observed_at": record.get("observed_at"),
        "target": record.get("target"),
        "error": record.get("error"),
        "host_key": record.get("host_key"),
        "probes": {k: {kk: vv for kk, vv in v.items() if kk != "command"} for k, v in (record.get("probes") or {}).items()},
        "fact_count": len(facts),
        "facts": facts,
    }


@router.get("/organizations/{organization_id}/pending")
def pending(
    organization_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> Dict[str, Any]:
    """Open CVE findings with preconditions only a host check can settle."""
    _check_org(current_user, organization_id)
    cred = hes.load_credential(db, organization_id)
    rows = (
        db.query(Vulnerability)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .filter(Asset.organization_id == organization_id, Vulnerability.status == VulnerabilityStatus.OPEN,
                Vulnerability.cve_id.isnot(None))
        .all()
    )
    items: List[Dict[str, Any]] = []
    for v in rows:
        tasks = hes.pending_host_checks(v)
        if not tasks:
            continue
        last = (v.asset.metadata_ or {}).get("host_facts") if isinstance(v.asset.metadata_, dict) else None
        collector, _ = hes.collector_for_asset(db, v.asset, cred)
        items.append({
            "vulnerability_id": v.id,
            "cve_id": v.cve_id,
            "asset_id": v.asset_id,
            "asset": v.asset.value,
            "signals": [t.get("expected_signal_path") for t in tasks],
            "collector": collector or None,  # falcon | ssh | None (nothing can check it)
            "in_target_scope": bool(cred and hes.in_target_scope(v.asset, cred.targets)),
            "last_check": {"observed_at": last.get("observed_at"), "error": last.get("error")} if last else None,
        })
    return {
        "credential_configured": cred is not None,
        "targets": cred.targets if cred else [],
        "pending": items,
    }


def _run_in_background(organization_id: int) -> None:
    db = SessionLocal()
    try:
        summary = hes.run_pending_host_checks(db, organization_id)
        logger.info("host checks org=%s checked=%s failed=%s skipped=%s", organization_id,
                    summary.get("checked"), summary.get("failed"), summary.get("skipped"))
    except Exception:
        logger.exception("host check run failed for org %s", organization_id)
    finally:
        db.close()


@router.post("/organizations/{organization_id}/run")
def run(
    organization_id: int,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> Dict[str, Any]:
    """Check every in-scope asset that has findings waiting on host evidence,
    then re-score those findings. Runs in the background."""
    _check_org(current_user, organization_id)
    assets = hes.assets_needing_host_checks(db, organization_id)
    background.add_task(_run_in_background, organization_id)
    return {"queued": True, "assets": len(assets)}


@router.post("/assets/{asset_id}/collect")
def collect(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> Dict[str, Any]:
    """Check one asset now and return the probe results and the before/after
    verdict for each open CVE finding on it."""
    asset = _asset_or_404(db, asset_id, current_user)
    kind, collector = hes.collector_for_asset(db, asset, hes.load_credential(db, asset.organization_id))
    if collector is None:
        raise HTTPException(status_code=400, detail=(
            "nothing can check this asset: enable host evidence on its CrowdStrike integration, or add it to the "
            f"'{hes.HOST_SSH_SERVICE}' credential's targets"))
    return hes.check_asset(db, asset, collector=collector)


class HostFactsIn(BaseModel):
    source: str = Field(..., min_length=1, max_length=64, description="collector name, e.g. osquery")
    facts: Dict[str, Any] = Field(..., description='host.* keys without the prefix, e.g. {"sshd.logingracetime": "0"}')
    complete_families: List[str] = Field(default_factory=list, description='"package" / "process" when the full list was sent')
    observed_at: Optional[datetime] = None
    reassess: bool = True


@router.post("/assets/{asset_id}/facts")
def push_facts(
    asset_id: int,
    body: HostFactsIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> Dict[str, Any]:
    """Record facts gathered by another collector and re-score the asset's
    findings."""
    asset = _asset_or_404(db, asset_id, current_user)
    if len(body.facts) > 20000:
        raise HTTPException(status_code=413, detail="too many facts")
    try:
        hes.ingest_host_facts(asset, body.facts, source=body.source,
                              complete_families=body.complete_families, observed_at=body.observed_at)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    db.add(asset)
    db.commit()
    out: Dict[str, Any] = {"asset_id": asset.id, "stored": len(body.facts)}
    if body.reassess:
        out["findings"] = hes.reassess_asset(db, asset)
    return out


@router.get("/assets/{asset_id}/facts")
def get_facts(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> Dict[str, Any]:
    return _facts_view(_asset_or_404(db, asset_id, current_user))
