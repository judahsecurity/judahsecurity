"""Normalize source records into atomic targets, identifiers, and evidence."""

import hashlib
import ipaddress
import json
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetStatus, AssetType
from app.models.finding_provenance import (
    FindingEvidence, FindingIdentifier, FindingObservation, FindingObservationTarget,
    FindingTarget,
)
from app.models.vulnerability import Vulnerability
from app.schemas.unified_results import AffectedTarget, UnifiedFinding


def _utc_naive(value: datetime) -> datetime:
    return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value


def _safe_url(value: str | None) -> str | None:
    """Keep endpoint identity, excluding credentials, query, and fragment."""
    if not value:
        return None
    try:
        parsed = urlsplit(value)
        if not parsed.scheme or not parsed.hostname:
            return None
        host = parsed.hostname.lower()
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        netloc = host + (f":{parsed.port}" if parsed.port else "")
        return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", "", ""))[:2048]
    except ValueError:
        return None


def source_record_key(finding: UnifiedFinding) -> str:
    """Stable within one source instance; never used to merge across sources."""
    identity = (
        ["native", finding.id]
        if finding.id
        else [
            "derived", finding.type.value,
            finding.template_id or finding.cve_id or finding.title or "",
            finding.target, finding.url, finding.port, finding.protocol,
        ]
    )
    encoded = json.dumps(identity, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _target_key(asset_id: int, port: int | None, protocol: str | None, url: str | None) -> str:
    if port is None and url is None:
        return f"asset:{asset_id}"
    value = json.dumps([asset_id, port, (protocol or "").lower(), url], separators=(",", ":"))
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _asset_for_target(db: Session, organization_id: int, target: AffectedTarget, primary: Asset, source: str) -> Asset:
    value = target.asset_value.strip()
    if value == primary.value:
        return primary
    if target.asset_type:
        asset_type = AssetType[target.asset_type.upper()]
    else:
        try:
            ipaddress.ip_address(value)
            asset_type = AssetType.IP_ADDRESS
        except ValueError:
            if "/" in value:
                try:
                    ipaddress.ip_network(value, strict=False)
                    asset_type = AssetType.IP_RANGE
                except ValueError:
                    asset_type = AssetType.URL if urlsplit(value).scheme else AssetType.OTHER
            elif urlsplit(value).scheme:
                asset_type = AssetType.URL
            else:
                asset_type = AssetType.DOMAIN if value.count(".") == 1 else AssetType.SUBDOMAIN
    asset = db.query(Asset).filter_by(
        organization_id=organization_id, asset_type=asset_type, value=value,
    ).first()
    if asset is None:
        asset = db.query(Asset).filter_by(organization_id=organization_id, value=value).first()
    if asset is None:
        asset = Asset(
            organization_id=organization_id, asset_type=asset_type,
            name=value, value=value, status=AssetStatus.DISCOVERED,
            discovery_source=f"agent:{source}",
        )
        db.add(asset)
        db.flush()
    return asset


def _upsert_target(
    db: Session, organization_id: int, vulnerability: Vulnerability,
    asset: Asset, target: AffectedTarget, first_seen: datetime, last_seen: datetime,
) -> FindingTarget:
    if asset.organization_id != organization_id:
        raise ValueError("Finding target must stay within one organization")
    url = _safe_url(target.url)
    protocol = target.protocol.lower() if target.protocol else ("tcp" if target.port else None)
    key = _target_key(asset.id, target.port, protocol, url)
    record = db.query(FindingTarget).filter_by(
        vulnerability_id=vulnerability.id, target_key=key,
    ).first()
    if record is None:
        record = FindingTarget(
            organization_id=organization_id, vulnerability_id=vulnerability.id,
            asset_id=asset.id, target_key=key, port=target.port,
            protocol=protocol, service_name=target.service_name,
            url=url, verification="reported", first_seen=first_seen, last_seen=last_seen,
        )
        db.add(record)
        db.flush()
    else:
        record.first_seen = min(record.first_seen, first_seen)
        record.last_seen = max(record.last_seen, last_seen)
        if target.service_name:
            record.service_name = target.service_name
    return record


def record_finding_sighting(
    db: Session, *, organization_id: int, vulnerability: Vulnerability,
    asset: Asset, finding: UnifiedFinding, source_instance: str = "",
) -> FindingObservation:
    """Upsert one native record and link its separately stored targets/proof."""
    if asset.organization_id != organization_id or vulnerability.asset.organization_id != organization_id:
        raise ValueError("Finding provenance must stay within one organization")
    if vulnerability.id is None:
        db.flush()

    first_seen = _utc_naive(finding.first_seen or finding.timestamp or datetime.utcnow())
    last_seen = _utc_naive(finding.last_seen or finding.timestamp or first_seen)
    source = finding.source.strip().lower()
    instance = source_instance.strip()
    if not source:
        raise ValueError("Source name is required")
    if len(source) > 100 or len(instance) > 255:
        raise ValueError("Source name or instance exceeds the supported length")
    key = source_record_key(finding)
    observation = db.query(FindingObservation).filter_by(
        organization_id=organization_id, source=source,
        source_instance=instance, source_record_key=key,
    ).first()
    if observation is not None and observation.vulnerability_id != vulnerability.id:
        raise ValueError("Source record already belongs to another finding")
    if observation is None:
        observation = FindingObservation(
            organization_id=organization_id, vulnerability_id=vulnerability.id,
            scan_id=finding.scan_id, source=source, source_instance=instance,
            source_record_id=str(finding.id)[:500] if finding.id else None,
            source_record_key=key,
            rule_id=(finding.template_id or finding.cve_id or "")[:255] or None,
            title=(finding.title or "")[:500] or None,
            severity=finding.severity.value, confidence=finding.confidence.value,
            description=finding.description,
            first_seen=first_seen, last_seen=last_seen,
        )
        db.add(observation)
        db.flush()
    else:
        observation.first_seen = min(observation.first_seen, first_seen)
        observation.last_seen = max(observation.last_seen, last_seen)
        observation.seen_count += 1
        observation.severity = finding.severity.value
        observation.confidence = finding.confidence.value
        observation.description = finding.description
        observation.scan_id = finding.scan_id or observation.scan_id

    # Explicit target rows replace lists of IPs, ports, or URLs in a text field.
    targets = finding.affected_targets or [AffectedTarget(
        asset_value=asset.value, port=finding.port, protocol=finding.protocol,
        service_name=finding.service_name, url=finding.url,
    )]
    for target_input in targets:
        target_asset = _asset_for_target(db, organization_id, target_input, asset, source)
        target = _upsert_target(
            db, organization_id, vulnerability, target_asset,
            target_input, first_seen, last_seen,
        )
        if db.query(FindingObservationTarget).filter_by(
            observation_id=observation.id, target_id=target.id,
        ).first() is None:
            db.add(FindingObservationTarget(observation_id=observation.id, target_id=target.id))

    for item in finding.evidence_items:
        kind = item.kind.strip().lower()
        target_id = None
        if item.target:
            evidence_asset = _asset_for_target(db, organization_id, item.target, asset, source)
            evidence_target = _upsert_target(
                db, organization_id, vulnerability, evidence_asset,
                item.target, first_seen, last_seen,
            )
            target_id = evidence_target.id
            if db.query(FindingObservationTarget).filter_by(
                observation_id=observation.id, target_id=target_id,
            ).first() is None:
                db.add(FindingObservationTarget(observation_id=observation.id, target_id=target_id))
        value_hash = hashlib.sha256(f"{target_id or ''}\x00{item.value}".encode("utf-8")).hexdigest()
        if db.query(FindingEvidence).filter_by(
            observation_id=observation.id, kind=kind, value_hash=value_hash,
        ).first() is None:
            db.add(FindingEvidence(
                observation_id=observation.id, target_id=target_id, kind=kind,
                value=item.value, value_hash=value_hash,
                observed_at=_utc_naive(item.observed_at) if item.observed_at else None,
            ))

    identifiers = [("cve", finding.cve_id), ("cwe", finding.cwe_id)]
    identifiers.extend((item.kind, item.value) for item in finding.identifiers)
    for kind_raw, value_raw in identifiers:
        kind = (kind_raw or "").strip().lower()
        value = (value_raw or "").strip()
        if kind in {"cve", "cwe", "ghsa"}:
            value = value.upper()
        if not kind or not value:
            continue
        if db.query(FindingIdentifier).filter_by(
            vulnerability_id=vulnerability.id, kind=kind, value=value,
        ).first() is None:
            db.add(FindingIdentifier(vulnerability_id=vulnerability.id, kind=kind, value=value))
    return observation
