"""
Cleanup unattributed shared-PaaS assets from organization inventory.

Marks out of scope (default) or deletes hostnames on multi-tenant platforms
(azurewebsites.net, herokuapp.com, …) that cannot be attributed to the org.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetType
from app.models.organization import Organization
from app.models.vulnerability import Vulnerability, VulnerabilityStatus
from app.services.platform_attribution import (
    is_shared_paas_hostname,
    iter_unattributed_shared_paas_assets,
    shared_paas_value_match_clause,
    tokens_from_organization,
)

logger = logging.getLogger(__name__)

CleanupAction = Literal["preview", "out_of_scope", "delete"]


@dataclass
class CleanupResult:
    organization_id: int
    action: CleanupAction
    matched: int = 0
    updated: int = 0
    deleted: int = 0
    findings_closed: int = 0
    attribution_tokens: List[str] = field(default_factory=list)
    preview: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "organization_id": self.organization_id,
            "action": self.action,
            "matched": self.matched,
            "updated": self.updated,
            "deleted": self.deleted,
            "findings_closed": self.findings_closed,
            "attribution_tokens": self.attribution_tokens,
            "preview": self.preview,
        }


def _owned_corporate_domains(db: Session, org: Organization) -> List[str]:
    owned: List[str] = []
    if org.domain:
        owned.append(org.domain)
    rows = (
        db.query(Asset.value)
        .filter(
            Asset.organization_id == org.id,
            Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
            Asset.in_scope.is_(True),
        )
        .limit(10000)
        .all()
    )
    for (value,) in rows:
        if value and not is_shared_paas_hostname(value):
            owned.append(value)
    return sorted(set(owned))


def _close_open_findings(db: Session, asset_id: int) -> int:
    open_statuses = [VulnerabilityStatus.OPEN, VulnerabilityStatus.IN_PROGRESS]
    findings = (
        db.query(Vulnerability)
        .filter(
            Vulnerability.asset_id == asset_id,
            Vulnerability.status.in_(open_statuses),
        )
        .all()
    )
    now = datetime.utcnow()
    for f in findings:
        f.status = VulnerabilityStatus.ACCEPTED
        f.resolved_at = now
        f.updated_at = now
        if not f.metadata_:
            f.metadata_ = {}
        f.metadata_["out_of_scope_closed_at"] = now.isoformat()
        f.metadata_["out_of_scope_closed_reason"] = (
            "Unattributed shared PaaS asset removed from scope"
        )
    return len(findings)


def cleanup_unattributed_shared_paas(
    db: Session,
    organization_id: int,
    *,
    action: CleanupAction = "preview",
    include_already_out_of_scope: bool = False,
    limit: int = 20000,
    preview_limit: int = 50,
) -> CleanupResult:
    """
    Find shared-PaaS inventory rows that are not attributable to the org.

    Actions:
      - preview: report only
      - out_of_scope: mark in_scope=False and auto-accept open findings
      - delete: delete assets (cascades findings/ports)
    """
    org = db.query(Organization).filter(Organization.id == organization_id).first()
    if not org:
        raise ValueError(f"Organization {organization_id} not found")

    tokens = tokens_from_organization(org)
    owned = _owned_corporate_domains(db, org)
    result = CleanupResult(
        organization_id=organization_id,
        action=action,
        attribution_tokens=tokens,
    )

    query = db.query(Asset).filter(
        Asset.organization_id == organization_id,
        Asset.asset_type.in_(
            [AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.URL, AssetType.OTHER]
        ),
        shared_paas_value_match_clause(Asset.value),
    )
    if not include_already_out_of_scope:
        query = query.filter(Asset.in_scope.is_(True))

    candidates = query.limit(limit).all()
    rejected = iter_unattributed_shared_paas_assets(
        candidates,
        tokens,
        owned_domains=owned,
    )
    result.matched = len(rejected)

    for asset, decision in rejected[:preview_limit]:
        result.preview.append(
            {
                "id": asset.id,
                "value": asset.value,
                "asset_type": asset.asset_type.value if asset.asset_type else None,
                "in_scope": asset.in_scope,
                "discovery_source": asset.discovery_source,
                "reason": decision.reason,
                "paas_suffix": decision.paas_suffix,
            }
        )

    if action == "preview":
        return result

    for asset, decision in rejected:
        if action == "out_of_scope":
            if asset.in_scope:
                closed = _close_open_findings(db, asset.id)
                result.findings_closed += closed
                asset.in_scope = False
                asset.last_seen = datetime.utcnow()
                tags = list(asset.tags or [])
                if "unattributed-paas" not in tags:
                    tags.append("unattributed-paas")
                asset.tags = tags
                if not asset.association_reason:
                    asset.association_reason = decision.reason
                asset.association_confidence = min(
                    asset.association_confidence or 0, 10
                )
                result.updated += 1
        elif action == "delete":
            # Close findings first for a clean audit trail, then delete.
            result.findings_closed += _close_open_findings(db, asset.id)
            db.delete(asset)
            result.deleted += 1

    db.commit()
    logger.info(
        "Unattributed PaaS cleanup org=%s action=%s matched=%s updated=%s deleted=%s findings_closed=%s",
        organization_id,
        action,
        result.matched,
        result.updated,
        result.deleted,
        result.findings_closed,
    )
    return result
