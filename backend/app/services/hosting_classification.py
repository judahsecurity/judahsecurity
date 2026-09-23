"""
Classify where an asset is hosted, from the organization's own IP inventory.

Used by the risk model's Network Location factor, which scores assets
hosted on the organization's infrastructure higher than those hosted by a
third party. The organization's IP inventory (owned netblocks) is the source
of truth:

  1. The asset is linked to an owned netblock, or one of its IPs falls in one
     → hosted by the organization.
  2. An IP is in a known cloud / CDN provider range → third-party hosted.
  3. All IPs are private → internal only.
  4. The organization has an IP inventory and none of the asset's IPs are in
     it → third-party hosted (outside every range the org owns).
  5. Otherwise the stored ``hosting_type`` from discovery, if any.
  6. Nothing to go on → unknown; the risk model flags it for analyst triage.

Domain assets usually carry no IP of their own, so the IPs are taken from the
IP assets that were resolved from the domain.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetType
from app.models.netblock import Netblock
from app.models.organization import Organization
from app.services.ip_classifier_service import IPClassifierService

_MAX_IPS = 20


def _asset_ips(db: Session, asset: Asset) -> List[str]:
    ips: List[str] = []
    for ip in list(asset.ip_addresses or []) + [asset.ip_address]:
        if ip and ip not in ips:
            ips.append(str(ip))
    asset_type = asset.asset_type.value if isinstance(asset.asset_type, AssetType) else str(asset.asset_type or "")
    if asset_type.upper() == "IP_ADDRESS" and asset.value and asset.value not in ips:
        ips.append(asset.value)
    if not ips and asset.value:
        rows = (
            db.query(Asset.ip_address, Asset.value)
            .filter(Asset.organization_id == asset.organization_id, Asset.resolved_from == asset.value)
            .limit(_MAX_IPS)
            .all()
        )
        for ip, value in rows:
            candidate = ip or value
            if candidate and candidate not in ips:
                ips.append(str(candidate))
    valid = []
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
            valid.append(ip)
        except ValueError:
            continue
    return valid[:_MAX_IPS]


def organization_name(db: Session, organization_id: Optional[int]) -> str:
    if not organization_id:
        return ""
    org = db.query(Organization.name).filter(Organization.id == organization_id).first()
    return (org[0] if org else "") or ""


def classify_asset_hosting(db: Session, asset: Asset) -> Dict[str, Any]:
    """Return ``{hosting_type, hosting_provider, basis, organization_name}``.

    ``hosting_type`` is one of: owned, third_party, internal, unknown.
    """
    org_name = organization_name(db, asset.organization_id)
    org_label = org_name or "the organization"

    def result(hosting_type: str, basis: str, provider: str = "") -> Dict[str, Any]:
        return {
            "hosting_type": hosting_type,
            "hosting_provider": provider,
            "basis": basis,
            "organization_name": org_name,
        }

    if asset.netblock_id:
        nb = db.query(Netblock).filter(Netblock.id == asset.netblock_id).first()
        if nb is not None and nb.is_owned and nb.organization_id == asset.organization_id:
            where = nb.cidr_notation or nb.inetnum
            return result("owned", f"Linked to {org_label}'s netblock {where}")

    ips = _asset_ips(db, asset)
    if ips:
        classifier = IPClassifierService(db)
        classes = [classifier.classify(ip, asset.organization_id) for ip in ips]

        owned = next((c for c in classes if c.hosting_type == "owned"), None)
        if owned is not None:
            return result("owned", f"{owned.ip} is in {org_label}'s IP inventory ({owned.reason})")

        hosted = next((c for c in classes if c.hosting_type in ("cloud", "cdn")), None)
        if hosted is not None:
            return result(
                "third_party",
                f"{hosted.ip} is in {hosted.hosting_provider} {hosted.hosting_type} address space",
                hosted.hosting_provider or "",
            )

        if all(c.hosting_type in ("private", "reserved") for c in classes):
            return result("internal", f"Only private addresses ({', '.join(ips[:3])})")

        owned_blocks = (
            db.query(Netblock.id)
            .filter(
                Netblock.organization_id == asset.organization_id,
                Netblock.is_owned.is_(True),
                Netblock.in_scope.is_(True),
            )
            .count()
        )
        if owned_blocks:
            return result(
                "third_party",
                f"{', '.join(ips[:3])} not in any of {org_label}'s {owned_blocks} owned netblock(s)",
                asset.hosting_provider or "",
            )

    stored = (asset.hosting_type or "").lower()
    if stored == "owned":
        return result("owned", "Classified as organization-owned at discovery")
    if stored in ("cloud", "cdn", "third_party"):
        return result("third_party", f"Classified as {stored} at discovery", asset.hosting_provider or "")

    if not ips:
        return result("unknown", "No IP addresses known for this asset")
    return result("unknown", f"{org_label} has no owned netblocks in its IP inventory to compare against")
