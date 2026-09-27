"""Map source records to one finding per endpoint and structured proof."""

import hashlib
import json
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.finding_provenance import FindingEvidence, FindingIdentifier, FindingObservation
from app.models.vulnerability import Vulnerability
from app.schemas.unified_results import AffectedTarget, UnifiedFinding


def _utc_naive(value: datetime) -> datetime:
    return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value


def safe_endpoint_url(value: str | None) -> str | None:
    """Preserve endpoint identity without credentials, query, or fragment."""
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


def endpoint_values(finding: UnifiedFinding, asset: Asset) -> tuple[int | None, str | None, str | None, str | None]:
    """Flat endpoint fields for the one asset attached to this finding."""
    if len(finding.affected_targets) > 1:
        raise ValueError("One finding must describe one endpoint")
    target = finding.affected_targets[0] if finding.affected_targets else AffectedTarget(
        asset_value=asset.value, port=finding.port, protocol=finding.protocol,
        service_name=finding.service_name, url=finding.url,
    )
    if target.asset_value != asset.value:
        raise ValueError("Finding endpoint must match its asset")
    protocol = target.protocol.lower() if target.protocol else ("tcp" if target.port else None)
    return target.port, protocol, target.service_name, safe_endpoint_url(target.url)


def source_record_key(finding: UnifiedFinding) -> str:
    """Source identity includes endpoint so one native report may yield many findings."""
    identity = [
        finding.id or [finding.type.value, finding.template_id or finding.cve_id or finding.title or ""],
        finding.target, finding.port, (finding.protocol or "").lower(), safe_endpoint_url(finding.url),
    ]
    encoded = json.dumps(identity, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def record_finding_sighting(
    db: Session, *, organization_id: int, vulnerability: Vulnerability,
    asset: Asset, finding: UnifiedFinding, source_instance: str = "",
) -> FindingObservation:
    """Upsert provenance and atomic evidence for one canonical endpoint finding."""
    if asset.organization_id != organization_id or vulnerability.asset.organization_id != organization_id:
        raise ValueError("Finding provenance must stay within one organization")
    if vulnerability.asset_id != asset.id:
        raise ValueError("Finding endpoint must match its canonical asset")
    if vulnerability.id is None:
        db.flush()

    port, protocol, service, url = endpoint_values(finding, asset)
    if (vulnerability.target_port, vulnerability.target_protocol, vulnerability.target_url) != (port, protocol, url):
        raise ValueError("Finding endpoint must match its canonical endpoint")
    if service and not vulnerability.target_service_name:
        vulnerability.target_service_name = service

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
            severity=finding.severity.value, confidence=finding.confidence.value,
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
        observation.scan_id = finding.scan_id or observation.scan_id

    for item in finding.evidence_items:
        if item.target:
            evidence_endpoint = (
                item.target.asset_value, item.target.port,
                (item.target.protocol or ("tcp" if item.target.port else None) or "").lower(),
                safe_endpoint_url(item.target.url),
            )
            finding_endpoint = (asset.value, port, protocol or "", url)
            if evidence_endpoint != finding_endpoint:
                raise ValueError("Evidence target must match its finding endpoint")
        kind = item.kind.strip().lower()
        value_hash = hashlib.sha256(item.value.encode("utf-8")).hexdigest()
        if db.query(FindingEvidence).filter_by(
            observation_id=observation.id, kind=kind, value_hash=value_hash,
        ).first() is None:
            db.add(FindingEvidence(
                observation_id=observation.id, kind=kind, value=item.value,
                value_hash=value_hash,
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
        if kind == "cve" and not vulnerability.cve_id:
            vulnerability.cve_id = value
        if kind == "cwe" and not vulnerability.cwe_id:
            vulnerability.cwe_id = value
        if db.query(FindingIdentifier).filter_by(
            vulnerability_id=vulnerability.id, kind=kind, value=value,
        ).first() is None:
            db.add(FindingIdentifier(vulnerability_id=vulnerability.id, kind=kind, value=value))
    return observation
