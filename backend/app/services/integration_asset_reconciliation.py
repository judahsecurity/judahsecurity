"""Reconcile provider membership without deleting asset or finding history."""

from __future__ import annotations

from datetime import datetime
from typing import Iterable

from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetStatus
from app.models.crowdstrike_integration import CrowdStrikeAssetLink
from app.models.wiz_integration import WizApplicationEndpoint, WizAssetLink

_PROVIDERS = {"wiz", "crowdstrike"}
_BATCH_SIZE = 500


def mark_asset_seen(asset: Asset, source: str) -> None:
    """Restore an asset only when an integration previously deactivated it."""
    if source not in _PROVIDERS:
        raise ValueError("Unsupported integration asset source")
    tags = list(asset.tags or [])
    tag = f"source:{source}"
    if tag not in tags:
        asset.tags = tags + [tag]
    metadata = dict(asset.metadata_ or {})
    marker = metadata.get("integration_reconciliation") or {}
    if asset.status == AssetStatus.INACTIVE and marker.get("inactive_by") in _PROVIDERS:
        asset.status = AssetStatus.DISCOVERED
        metadata.pop("integration_reconciliation", None)
        asset.metadata_ = metadata


def _chunks(values: Iterable[int]) -> Iterable[list[int]]:
    batch: list[int] = []
    for value in values:
        batch.append(value)
        if len(batch) >= _BATCH_SIZE:
            yield batch
            batch = []
    if batch:
        yield batch


def reconcile_asset_membership(db: Session, source: str, organization_id: int, asset_ids: Iterable[int]) -> int:
    """Remove stale source tags and deactivate only unshared provider assets."""
    if source not in _PROVIDERS:
        raise ValueError("Unsupported integration asset source")
    retired = 0
    for ids in _chunks(sorted(set(asset_ids))):
        wiz_active = {row[0] for row in db.query(WizAssetLink.asset_id).filter(
            WizAssetLink.asset_id.in_(ids), WizAssetLink.is_active.is_(True),
        ).all()}
        wiz_active.update(row[0] for row in db.query(WizApplicationEndpoint.asset_id).filter(
            WizApplicationEndpoint.asset_id.in_(ids), WizApplicationEndpoint.is_active.is_(True),
        ).all())
        crowdstrike_active = {row[0] for row in db.query(CrowdStrikeAssetLink.asset_id).filter(
            CrowdStrikeAssetLink.asset_id.in_(ids), CrowdStrikeAssetLink.is_active.is_(True),
        ).all()}
        for asset in db.query(Asset).filter(
            Asset.id.in_(ids), Asset.organization_id == organization_id,
        ).all():
            active_source = (asset.id in wiz_active if source == "wiz" else asset.id in crowdstrike_active)
            tags = list(asset.tags or [])
            if not active_source:
                tag = f"source:{source}"
                if tag in tags:
                    tags.remove(tag)
                    asset.tags = tags
            has_provider = asset.id in wiz_active or asset.id in crowdstrike_active
            marker = dict((asset.metadata_ or {}).get("integration_reconciliation") or {})
            if has_provider:
                if asset.status == AssetStatus.INACTIVE and marker.get("inactive_by") in _PROVIDERS:
                    asset.status = AssetStatus.DISCOVERED
                    metadata = dict(asset.metadata_ or {})
                    metadata.pop("integration_reconciliation", None)
                    asset.metadata_ = metadata
                continue
            other_source = any(
                tag.startswith("source:") and tag not in {"source:wiz", "source:crowdstrike"}
                for tag in tags
            )
            if (asset.discovery_source not in _PROVIDERS or asset.is_owned or other_source
                    or asset.status in {AssetStatus.INACTIVE, AssetStatus.ARCHIVED}):
                continue
            asset.status = AssetStatus.INACTIVE
            metadata = dict(asset.metadata_ or {})
            metadata["integration_reconciliation"] = {
                "inactive_by": source, "inactive_at": datetime.utcnow().isoformat(),
            }
            asset.metadata_ = metadata
            retired += 1
    return retired
