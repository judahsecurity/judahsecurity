"""Cross-source finding identity.

Every importer (Tenable, Wiz, Nuclei, future CrowdStrike / Censys / ratings
vendors) reports the same real-world problem under its own ID. This module
gives them one way to agree on *what* a finding is, so the platform keeps one
canonical ``Vulnerability`` per problem and one ``FindingObservation`` per
source that reported it.

Lookup order for an incoming source finding (``resolve_canonical``):

1. The source's own observation, ``(org, source, vendor_finding_id)``. This is
   what keeps re-syncs stable after a finding was merged into another source's
   row.
2. The importer's legacy per-source key (handled by the caller, e.g. Tenable's
   ``template_id``), so rows created before this module existed keep updating.
3. A canonical match on the same asset or a related asset (domain <-> resolved
   IP): same ``dedup_key``, or any overlap between CVE sets.

Merging never overwrites another source's title, description or evidence. It
only widens the CVE set, raises severity, and extends ``last_detected``. A
source reporting a fix resolves the canonical row only when every source that
reported it agrees (see ``all_sources_fixed``).
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import String, cast, or_
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.finding_observation import FindingObservation
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# Statuses an analyst set on purpose; merges and source fixes leave them alone.
ANALYST_STATUSES = (
    VulnerabilityStatus.ACCEPTED,
    VulnerabilityStatus.FALSE_POSITIVE,
    VulnerabilityStatus.MITIGATED,
)
_ACTIVE_STATUSES = (VulnerabilityStatus.OPEN, VulnerabilityStatus.IN_PROGRESS)


def normalize_cves(values: Optional[Iterable[Any]]) -> List[str]:
    """Return the distinct, upper-cased, sorted CVE IDs found in ``values``."""
    found = set()
    for value in values or ():
        if value is None:
            continue
        for match in _CVE_RE.findall(str(value)):
            found.add(match.upper())
    return sorted(found)


def make_dedup_key(cves: List[str], source: str, rule_id: Optional[str] = None) -> Optional[str]:
    """Source-independent weakness key.

    CVE-backed findings key on their lowest CVE so every tool agrees; findings
    without a CVE fall back to the source's own rule (Tenable plugin, Wiz rule),
    which only matches the same rule from the same source.
    """
    if cves:
        return f"cve:{cves[0]}"[:255]
    if rule_id:
        return f"{source}:{rule_id}"[:255]
    return None


def finding_cves(vuln: Vulnerability) -> List[str]:
    """All CVEs a stored finding covers, including legacy rows with only ``cve_id``."""
    return normalize_cves(list(vuln.cves or []) + [vuln.cve_id])


def _candidate_asset_ids(db: Session, asset: Asset, include_related: bool) -> List[int]:
    ids = [asset.id]
    if include_related:
        from app.services.finding_deduplication_service import FindingDeduplicationService

        for related in FindingDeduplicationService(db).get_related_assets(asset):
            if related.id not in ids:
                ids.append(related.id)
    return ids


def find_observed(
    db: Session, organization_id: int, source: str, vendor_finding_id: Optional[str]
) -> Optional[Vulnerability]:
    """Canonical finding this source already reported under ``vendor_finding_id``."""
    if not vendor_finding_id:
        return None
    obs = db.query(FindingObservation).filter(
        FindingObservation.organization_id == organization_id,
        FindingObservation.source == source,
        FindingObservation.vendor_finding_id == str(vendor_finding_id)[:255],
    ).first()
    return obs.vulnerability if obs else None


def find_canonical(
    db: Session,
    asset: Asset,
    cves: List[str],
    dedup_key: Optional[str],
    *,
    include_related: bool = True,
    exclude_id: Optional[int] = None,
) -> Optional[Vulnerability]:
    """Existing finding for the same weakness on this asset or a related one.

    Active findings win over closed ones, and findings on ``asset`` itself win
    over findings on related assets.
    """
    if not cves and not dedup_key:
        return None
    asset_ids = _candidate_asset_ids(db, asset, include_related)
    clauses = []
    if dedup_key:
        clauses.append(Vulnerability.dedup_key == dedup_key)
    for cve in cves:
        clauses.append(Vulnerability.cve_id == cve)
        # ``cves`` is a JSON (not JSONB) column; match the encoded array text,
        # as finding_deduplication_service does for ``ip_addresses``.
        clauses.append(cast(Vulnerability.cves, String).like(f'%"{cve}"%'))
    query = db.query(Vulnerability).filter(Vulnerability.asset_id.in_(asset_ids), or_(*clauses))
    if exclude_id is not None:
        query = query.filter(Vulnerability.id != exclude_id)
    candidates = query.all()
    if not candidates:
        return None

    def rank(v: Vulnerability):
        return (
            0 if v.status in _ACTIVE_STATUSES else 1,
            0 if v.asset_id == asset.id else 1,
            v.id,
        )

    return sorted(candidates, key=rank)[0]


def record_observation(
    db: Session,
    organization_id: int,
    vuln: Vulnerability,
    source: str,
    vendor_finding_id: Optional[str],
    *,
    state: str = "open",
    vendor_severity: Optional[str] = None,
    seen_at: Optional[datetime] = None,
    first_seen: Optional[datetime] = None,
    details: Optional[Dict[str, Any]] = None,
) -> Optional[FindingObservation]:
    """Create or refresh this source's observation of ``vuln``."""
    if not vendor_finding_id:
        return None
    vendor_finding_id = str(vendor_finding_id)[:255]
    now = seen_at or datetime.utcnow()
    obs = db.query(FindingObservation).filter(
        FindingObservation.organization_id == organization_id,
        FindingObservation.source == source,
        FindingObservation.vendor_finding_id == vendor_finding_id,
    ).first()
    if obs is None:
        # The vulnerability may not be flushed yet; let the relationship carry it.
        obs = FindingObservation(
            organization_id=organization_id,
            source=source,
            vendor_finding_id=vendor_finding_id,
            first_seen=first_seen or now,
        )
        vuln.observations.append(obs)
        db.add(obs)
    elif obs.vulnerability is not vuln:
        obs.vulnerability = vuln
    obs.state = state
    obs.vendor_severity = vendor_severity
    obs.last_seen = now
    obs.details = details or {}
    return obs


def merge_into(
    vuln: Vulnerability,
    *,
    cves: List[str],
    severity: Optional[Severity] = None,
    last_detected: Optional[datetime] = None,
    source: Optional[str] = None,
) -> None:
    """Fold another source's view into an existing canonical finding.

    Widens the CVE set, keeps the higher severity, and extends
    ``last_detected``. Title, description and evidence stay as the owning
    source wrote them. A resolved finding that another source still sees is
    reopened; analyst decisions are left alone.
    """
    merged = normalize_cves(finding_cves(vuln) + list(cves))
    if merged:
        vuln.cves = merged
        if not vuln.cve_id:
            vuln.cve_id = merged[0][:50]
    if not vuln.dedup_key:
        vuln.dedup_key = make_dedup_key(merged, source or "", None)
    if severity is not None and SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(vuln.severity, 0):
        vuln.severity = severity
    if last_detected and (vuln.last_detected is None or last_detected > vuln.last_detected):
        vuln.last_detected = last_detected
    if vuln.status == VulnerabilityStatus.RESOLVED:
        vuln.status = VulnerabilityStatus.OPEN
        vuln.resolved_at = None
    if source:
        tag = f"source:{source}"
        tags = list(vuln.tags or [])
        if tag not in tags:
            vuln.tags = tags + [tag]


def owning_source(vuln: Vulnerability) -> Optional[str]:
    meta = vuln.metadata_ or {}
    return meta.get("source") or vuln.detected_by


def all_sources_fixed(vuln: Vulnerability, *, owner_aliases: Iterable[str] = ()) -> bool:
    """True when nothing still reports ``vuln`` as present.

    Every observation must be fixed, and the row's owning source must be one
    of the observed sources. A Nuclei-created row that Tenable later also
    reported is not closed by Tenable alone, since Nuclei has no observation
    recording that it stopped seeing it.
    """
    observations = list(vuln.observations or [])
    if not observations or any(o.state != "fixed" for o in observations):
        return False
    observed = {o.source for o in observations} | set(owner_aliases)
    return owning_source(vuln) in observed
