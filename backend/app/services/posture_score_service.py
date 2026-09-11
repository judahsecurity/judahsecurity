"""Deterministic external security posture score.

The score intentionally includes only demonstrated, internet-facing findings:
agent findings with a live proof chain, validator-confirmed findings, or scanner
findings whose exploit was actively confirmed.  The calculation is pure once
its inputs are assembled so API responses and tests can be reproduced exactly.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy.orm import Session, joinedload

from app.models.asset import Asset, AssetStatus, AssetType
from app.models.scan import Scan, ScanStatus
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus


MODEL_VERSION = "external-posture-v1"

SEVERITY_PARAMETERS: Dict[str, tuple[float, Optional[int]]] = {
    "critical": (10.0, 7),
    "high": (5.0, 30),
    "medium": (2.0, 60),
    "low": (0.5, 90),
    "exposure": (0.1, 45),
    "info": (0.0, None),
    "informational": (0.0, None),
}

COUNTED_STATUSES = {
    VulnerabilityStatus.OPEN,
    VulnerabilityStatus.IN_PROGRESS,
    VulnerabilityStatus.ACCEPTED,
}

# Count addressable perimeter objects, not derivative inventory records such as
# certificates, ports, services, ranges, or email addresses. This prevents the
# denominator from being inflated by child records that are not independent
# attack targets.
EXTERNAL_ASSET_TYPES = {
    AssetType.DOMAIN,
    AssetType.SUBDOMAIN,
    AssetType.IP_ADDRESS,
    AssetType.URL,
    AssetType.CLOUD_RESOURCE,
    AssetType.API_ENDPOINT,
}


@dataclass(frozen=True)
class FindingScoreInput:
    finding_id: int
    title: str
    severity: str
    status: str
    opened_at: datetime
    asset_id: int
    asset_name: str


def _enum_value(value: Any) -> str:
    return str(value.value if hasattr(value, "value") else value or "").lower()


def _naive_utc(value: datetime) -> datetime:
    """Normalize DB timestamps for safe subtraction across drivers."""
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def age_multiplier(age_days: float, sla_days: Optional[int]) -> float:
    """Return 1 at opening, 2 at SLA, and asymptotically approach 3."""
    if not sla_days:
        return 1.0
    ratio = max(0.0, age_days) / float(sla_days)
    return 1.0 + 2.0 * (1.0 - math.pow(2.0, -ratio))


def _round_half_up(value: float) -> int:
    return int(Decimal(str(value)).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def calculate_posture_score(
    findings: Iterable[FindingScoreInput],
    active_asset_count: int,
    *,
    calculated_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Calculate the v1 score from already-authorized and eligible inputs."""
    now = _naive_utc(calculated_at or datetime.utcnow())
    scored: List[Dict[str, Any]] = []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "exposure": 0, "info": 0}

    for finding in findings:
        severity = finding.severity.lower()
        base_weight, sla_days = SEVERITY_PARAMETERS.get(severity, (0.0, None))
        age_days = max(0.0, (now - _naive_utc(finding.opened_at)).total_seconds() / 86400.0)
        multiplier = age_multiplier(age_days, sla_days)
        deduction = base_weight * multiplier
        normalized_severity = "info" if severity == "informational" else severity
        if normalized_severity in severity_counts:
            severity_counts[normalized_severity] += 1
        scored.append({
            "finding_id": finding.finding_id,
            "title": finding.title,
            "severity": normalized_severity,
            "status": finding.status,
            "asset_id": finding.asset_id,
            "asset_name": finding.asset_name,
            "age_days": round(age_days, 1),
            "sla_days": sla_days,
            "overdue": bool(sla_days and age_days > sla_days),
            "age_multiplier": round(multiplier, 4),
            "deduction": round(deduction, 4),
        })

    deductions = sorted((row["deduction"] for row in scored), reverse=True)
    total_deduction = sum(deductions)
    worst_case_deduction = sum(deductions[:10])
    density = total_deduction / max(active_asset_count, 1)
    density_penalty = 100.0 * (1.0 - math.exp(-density / 20.0))
    worst_case_penalty = 100.0 * (1.0 - math.exp(-worst_case_deduction / 80.0))
    raw_score = 100.0 - (0.40 * density_penalty + 0.60 * worst_case_penalty)

    critical = severity_counts["critical"]
    high = severity_counts["high"]
    caps: List[tuple[int, str]] = []
    if critical >= 1:
        caps.append((89, "CRITICAL_CAP"))
    if critical == 0 and high >= 3:
        caps.append((89, "HIGH_COUNT_CAP"))
    if critical >= 2:
        caps.append((79, "MULTIPLE_CRITICAL_CAP"))
    if critical >= 1 and high >= 3:
        caps.append((79, "CRITICAL_HIGH_CAP"))
    if critical >= 5:
        caps.append((69, "SEVERE_CRITICAL_CAP"))
    if critical >= 3 and high >= 5:
        caps.append((69, "SEVERE_MIXED_CAP"))

    applied_cap = min(caps, key=lambda row: row[0]) if caps else None
    capped_score = min(raw_score, float(applied_cap[0])) if applied_cap else raw_score
    final_score = _round_half_up(max(0.0, min(100.0, capped_score)))
    top_drivers = sorted(
        (row for row in scored if row["deduction"] > 0),
        key=lambda row: (-row["deduction"], row["finding_id"]),
    )[:3]

    return {
        "model_version": MODEL_VERSION,
        "raw_score": round(raw_score, 4),
        "score": final_score,
        "grade": _grade(final_score),
        "density_penalty": round(density_penalty, 4),
        "worst_case_penalty": round(worst_case_penalty, 4),
        "total_deduction": round(total_deduction, 4),
        "applicable_cap": applied_cap[0] if applied_cap else None,
        "cap_reason": applied_cap[1] if applied_cap else None,
        "eligible_finding_count": len(scored),
        "finding_counts": severity_counts,
        "top_drivers": top_drivers,
    }


def _is_demonstrated(vulnerability: Vulnerability) -> bool:
    validation_verdict = (vulnerability.last_validation_verdict or "").lower()
    if validation_verdict:
        # The latest explicit validator verdict supersedes older scanner or
        # agent evidence, including an earlier proof chain.
        return validation_verdict == "confirmed"
    if (vulnerability.detection_confidence or "").lower() == "exploit_confirmed":
        return True
    metadata = vulnerability.metadata_ if isinstance(vulnerability.metadata_, dict) else {}
    agent_detection = metadata.get("agent_detection")
    if not isinstance(agent_detection, dict):
        return False
    chain = agent_detection.get("chain")
    return isinstance(chain, list) and len(chain) > 0


def _active_external_assets_query(db: Session, organization_id: int):
    return db.query(Asset).filter(
        Asset.organization_id == organization_id,
        Asset.in_scope.is_(True),
        Asset.is_public.is_(True),
        Asset.is_monitored.is_(True),
        Asset.asset_type.in_(EXTERNAL_ASSET_TYPES),
        Asset.status.notin_([AssetStatus.INACTIVE, AssetStatus.ARCHIVED]),
    )


def _confidence(
    *,
    active_asset_count: int,
    fresh_assessed_asset_count: int,
    recent_assessed_asset_count: int,
    latest_completed_scan_at: Optional[datetime],
    has_inflight_scan: bool,
    now: datetime,
) -> Dict[str, Any]:
    if active_asset_count <= 0:
        return {"rating_status": "unrated", "confidence": None, "reason_code": "NO_ACTIVE_ASSETS"}
    if latest_completed_scan_at is None:
        return {
            "rating_status": "pending" if has_inflight_scan else "unrated",
            "confidence": None,
            "reason_code": "SCAN_IN_PROGRESS" if has_inflight_scan else "NO_COMPLETED_SCAN",
        }

    scan_age_days = max(0.0, (now - _naive_utc(latest_completed_scan_at)).total_seconds() / 86400.0)
    fresh_coverage = fresh_assessed_asset_count / active_asset_count
    recent_coverage = recent_assessed_asset_count / active_asset_count
    if scan_age_days > 30:
        return {"rating_status": "unrated", "confidence": None, "reason_code": "STALE_SCAN"}
    if scan_age_days <= 7 and fresh_coverage >= 0.95:
        confidence = "high"
    elif scan_age_days <= 14 and recent_coverage >= 0.80:
        confidence = "medium"
    else:
        confidence = "low"
    return {"rating_status": "rated", "confidence": confidence, "reason_code": None}


def build_posture_score(db: Session, organization_id: int, *, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Load an organization's eligible inputs and return its customer response."""
    calculated_at = _naive_utc(now or datetime.utcnow())
    active_query = _active_external_assets_query(db, organization_id)
    active_asset_count = active_query.count()

    latest_completed = (
        db.query(Scan)
        .filter(
            Scan.organization_id == organization_id,
            Scan.status == ScanStatus.COMPLETED,
            Scan.completed_at.isnot(None),
        )
        .order_by(Scan.completed_at.desc())
        .first()
    )
    latest_completed_at = latest_completed.completed_at if latest_completed else None
    has_inflight_scan = db.query(Scan.id).filter(
        Scan.organization_id == organization_id,
        Scan.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
    ).first() is not None

    fresh_assessed_asset_count = active_query.filter(
        Asset.last_scan_date >= calculated_at - timedelta(days=7)
    ).count()
    recent_assessed_asset_count = active_query.filter(
        Asset.last_scan_date >= calculated_at - timedelta(days=14)
    ).count()
    confidence = _confidence(
        active_asset_count=active_asset_count,
        fresh_assessed_asset_count=fresh_assessed_asset_count,
        recent_assessed_asset_count=recent_assessed_asset_count,
        latest_completed_scan_at=latest_completed_at,
        has_inflight_scan=has_inflight_scan,
        now=calculated_at,
    )
    confidence_window_days = 7 if confidence.get("confidence") == "high" else 14
    assessed_asset_count = (
        fresh_assessed_asset_count
        if confidence_window_days == 7
        else recent_assessed_asset_count
    )

    base = {
        "enabled": True,
        "organization_id": organization_id,
        "calculated_at": calculated_at.isoformat() + "Z",
        "active_external_asset_count": active_asset_count,
        "assessed_external_asset_count": assessed_asset_count,
        "coverage_percentage": round(100.0 * assessed_asset_count / active_asset_count, 1) if active_asset_count else 0.0,
        "coverage_window_days": confidence_window_days,
        "last_completed_scan_at": _naive_utc(latest_completed_at).isoformat() + "Z" if latest_completed_at else None,
        **confidence,
    }
    if confidence["rating_status"] != "rated":
        return {
            **base,
            "model_version": MODEL_VERSION,
            "raw_score": None,
            "score": None,
            "grade": None,
            "applicable_cap": None,
            "cap_reason": None,
            "eligible_finding_count": 0,
            "finding_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "exposure": 0, "info": 0},
            "top_drivers": [],
        }

    vulnerabilities = (
        db.query(Vulnerability)
        .options(joinedload(Vulnerability.asset))
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .filter(
            Asset.organization_id == organization_id,
            Asset.in_scope.is_(True),
            Asset.is_public.is_(True),
            Asset.is_monitored.is_(True),
            Asset.asset_type.in_(EXTERNAL_ASSET_TYPES),
            Asset.status.notin_([AssetStatus.INACTIVE, AssetStatus.ARCHIVED]),
            Vulnerability.status.in_(COUNTED_STATUSES),
        )
        .all()
    )
    inputs = [
        FindingScoreInput(
            finding_id=vulnerability.id,
            title=vulnerability.title,
            severity=_enum_value(vulnerability.severity),
            status=_enum_value(vulnerability.status),
            opened_at=vulnerability.first_detected or vulnerability.created_at or calculated_at,
            asset_id=vulnerability.asset_id,
            asset_name=(vulnerability.asset.value or vulnerability.asset.name) if vulnerability.asset else "Unknown asset",
        )
        for vulnerability in vulnerabilities
        if _is_demonstrated(vulnerability)
    ]
    return {**base, **calculate_posture_score(inputs, active_asset_count, calculated_at=calculated_at)}
