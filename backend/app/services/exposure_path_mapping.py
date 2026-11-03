"""Resolve provider path nodes to Judah assets using stable source IDs only."""

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.crowdstrike_integration import CrowdStrikeAssetLink, CrowdStrikeIntegration
from app.models.exposure_evidence import ExposurePath


def resolve_crowdstrike_asset_ref(
    db: Session, *, organization_id: int, integration_id: int, source_ref: str | None,
) -> int | None:
    """Return a same-tenant Judah asset for `host:<aid>` or `external:<id>`."""
    if not source_ref or ":" not in source_ref:
        return None
    kind, source_id = source_ref.split(":", 1)
    if kind not in {"host", "external"} or not source_id:
        return None
    integration = db.get(CrowdStrikeIntegration, integration_id)
    if integration is None or integration.organization_id != organization_id:
        return None
    link = db.query(CrowdStrikeAssetLink).filter_by(
        integration_id=integration_id, source_kind=kind, source_id=source_id,
    ).first()
    asset = db.get(Asset, link.asset_id) if link else None
    return asset.id if asset is not None and asset.organization_id == organization_id else None


def map_crowdstrike_path_assets(db: Session, *, integration_id: int, path: ExposurePath) -> int:
    """Attach exact asset matches while retaining unmatched provider node refs."""
    if path.source != "crowdstrike":
        raise ValueError("This mapper accepts CrowdStrike paths only")
    if path.source_instance_id != str(integration_id):
        raise ValueError("Path belongs to a different CrowdStrike connection")
    matched = 0
    for step in path.steps:
        for source_field, asset_field in (
            ("from_source_ref", "from_asset_id"), ("to_source_ref", "to_asset_id"),
        ):
            asset_id = resolve_crowdstrike_asset_ref(
                db, organization_id=path.organization_id, integration_id=integration_id,
                source_ref=getattr(step, source_field),
            )
            setattr(step, asset_field, asset_id)
            if asset_id is not None:
                matched += 1
    return matched
