"""
Detection pattern service.

Turns repeated false-positive signals into an analyst-reviewable suppression
recommendation, keyed on template_id. A template is only ever flagged once its
false-positive signals span at least DETECTION_PATTERN_MIN_HOSTS distinct hosts,
and it is only enforced (future matches auto-marked false_positive at ingest)
after an analyst APPROVES the recommendation.

Signals counted (per organization + template_id):
  1. validator_agent  — FindingValidation.verdict == false_positive
  2. analyst          — DetectionFeedback rows
  3. manual           — Vulnerability.status == false_positive
"""

import logging
from typing import List, Optional

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability, VulnerabilityStatus
from app.models.finding_validation import (
    FindingValidation,
    ValidationStatus,
    ValidationVerdict,
)
from app.models.detection_feedback import DetectionFeedback
from app.models.detection_suppression import DetectionSuppression, SuppressionStatus

logger = logging.getLogger(__name__)


def _min_hosts(threshold: Optional[int]) -> int:
    if threshold is not None:
        return threshold
    return getattr(settings, "DETECTION_PATTERN_MIN_HOSTS", 3)


def collect_fp_signals(db: Session, organization_id: int, template_id: str) -> dict:
    """Collect distinct FP-affected hosts and per-signal counts for a template."""
    # 1. Validator false-positive verdicts
    validator_rows = (
        db.query(Asset.value)
        .join(Vulnerability, Vulnerability.asset_id == Asset.id)
        .join(FindingValidation, FindingValidation.vulnerability_id == Vulnerability.id)
        .filter(
            FindingValidation.organization_id == organization_id,
            FindingValidation.verdict == ValidationVerdict.FALSE_POSITIVE,
            Vulnerability.template_id == template_id,
        )
        .distinct()
        .all()
    )
    validator_hosts = {r[0] for r in validator_rows if r[0]}

    # 3. Manual false-positive status
    manual_rows = (
        db.query(Asset.value)
        .join(Vulnerability, Vulnerability.asset_id == Asset.id)
        .filter(
            Asset.organization_id == organization_id,
            Vulnerability.template_id == template_id,
            Vulnerability.status == VulnerabilityStatus.FALSE_POSITIVE,
        )
        .distinct()
        .all()
    )
    manual_hosts = {r[0] for r in manual_rows if r[0]}

    # 2. Analyst-logged detection feedback
    feedback_rows = (
        db.query(DetectionFeedback)
        .filter(
            DetectionFeedback.organization_id == organization_id,
            DetectionFeedback.template_id == template_id,
        )
        .all()
    )
    analyst_count = len(feedback_rows)
    example_ids = [fb.example_vulnerability_id for fb in feedback_rows if fb.example_vulnerability_id]
    analyst_hosts: set = set()
    if example_ids:
        rows = (
            db.query(Asset.value)
            .join(Vulnerability, Vulnerability.asset_id == Asset.id)
            .filter(Vulnerability.id.in_(example_ids))
            .distinct()
            .all()
        )
        analyst_hosts = {r[0] for r in rows if r[0]}

    all_hosts = validator_hosts | manual_hosts | analyst_hosts
    return {
        "hosts": all_hosts,
        "host_count": len(all_hosts),
        "breakdown": {
            "validator_hosts": len(validator_hosts),
            "manual_hosts": len(manual_hosts),
            "analyst_feedback": analyst_count,
            "hosts": sorted(all_hosts)[:50],
        },
    }


def evaluate_template(
    db: Session,
    organization_id: int,
    template_id: str,
    detected_by: Optional[str] = None,
    threshold: Optional[int] = None,
) -> Optional[DetectionSuppression]:
    """Recompute the FP pattern for one template and upsert its recommendation.

    Best-effort: never raises (callers are ingest/trigger paths). Approved and
    dismissed rows keep their status; only their metrics are refreshed.
    """
    if not template_id:
        return None
    try:
        min_hosts = _min_hosts(threshold)
        signals = collect_fp_signals(db, organization_id, template_id)
        host_count = signals["host_count"]

        existing = (
            db.query(DetectionSuppression)
            .filter(
                DetectionSuppression.organization_id == organization_id,
                DetectionSuppression.template_id == template_id,
            )
            .first()
        )

        from datetime import datetime
        now = datetime.utcnow()

        if existing:
            existing.host_count = host_count
            existing.signal_breakdown = signals["breakdown"]
            existing.last_evaluated_at = now
            if detected_by and not existing.detected_by:
                existing.detected_by = detected_by
            db.commit()
            return existing

        # No row yet — only create one once the pattern threshold is crossed.
        if host_count >= min_hosts:
            suppression = DetectionSuppression(
                organization_id=organization_id,
                template_id=template_id,
                detected_by=detected_by,
                status=SuppressionStatus.RECOMMENDED,
                host_count=host_count,
                threshold=min_hosts,
                signal_breakdown=signals["breakdown"],
                first_flagged_at=now,
                last_evaluated_at=now,
            )
            db.add(suppression)
            db.commit()
            db.refresh(suppression)
            logger.info(
                "Detection pattern flagged: template=%s org=%s hosts=%d (>=%d)",
                template_id, organization_id, host_count, min_hosts,
            )
            return suppression

        return None
    except Exception as e:  # never break the calling path
        logger.warning("evaluate_template failed for %s: %s", template_id, e)
        try:
            db.rollback()
        except Exception:
            pass
        return None


def evaluate_all(db: Session, organization_id: int, threshold: Optional[int] = None) -> List[DetectionSuppression]:
    """Recompute patterns across every template with any FP signal in the org."""
    template_ids: set = set()

    validator_tids = (
        db.query(Vulnerability.template_id)
        .join(FindingValidation, FindingValidation.vulnerability_id == Vulnerability.id)
        .filter(
            FindingValidation.organization_id == organization_id,
            FindingValidation.verdict == ValidationVerdict.FALSE_POSITIVE,
            Vulnerability.template_id.isnot(None),
        )
        .distinct()
        .all()
    )
    template_ids.update(t[0] for t in validator_tids if t[0])

    fb_tids = (
        db.query(DetectionFeedback.template_id)
        .filter(DetectionFeedback.organization_id == organization_id)
        .distinct()
        .all()
    )
    template_ids.update(t[0] for t in fb_tids if t[0])

    manual_tids = (
        db.query(Vulnerability.template_id)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .filter(
            Asset.organization_id == organization_id,
            Vulnerability.status == VulnerabilityStatus.FALSE_POSITIVE,
            Vulnerability.template_id.isnot(None),
        )
        .distinct()
        .all()
    )
    template_ids.update(t[0] for t in manual_tids if t[0])

    results: List[DetectionSuppression] = []
    for tid in template_ids:
        row = evaluate_template(db, organization_id, tid, threshold=threshold)
        if row is not None:
            results.append(row)
    return results


def is_template_suppressed(db: Session, organization_id: int, template_id: Optional[str]) -> bool:
    """True only if an analyst has APPROVED suppression for this template."""
    if not template_id:
        return False
    return (
        db.query(DetectionSuppression.id)
        .filter(
            DetectionSuppression.organization_id == organization_id,
            DetectionSuppression.template_id == template_id,
            DetectionSuppression.status == SuppressionStatus.APPROVED,
        )
        .first()
        is not None
    )


def get_template_validation_coverage(db: Session, organization_id: int, template_id: str) -> dict:
    """Return validation coverage for the open findings of a template."""
    open_findings = (
        db.query(Vulnerability.id)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .filter(
            Asset.organization_id == organization_id,
            Vulnerability.template_id == template_id,
            Vulnerability.status == VulnerabilityStatus.OPEN,
        )
        .all()
    )
    open_ids = [r[0] for r in open_findings]
    if not open_ids:
        return {"open": 0, "validated": 0, "pending": 0}

    validated = (
        db.query(FindingValidation.vulnerability_id)
        .filter(
            FindingValidation.vulnerability_id.in_(open_ids),
            FindingValidation.status == ValidationStatus.COMPLETED,
        )
        .distinct()
        .count()
    )
    return {"open": len(open_ids), "validated": validated, "pending": len(open_ids) - validated}


def queue_sample_validations(
    db: Session,
    organization_id: int,
    template_id: str,
    requested_by_user_id: Optional[int] = None,
    limit: Optional[int] = None,
) -> List[int]:
    """Queue validator-agent runs for open, not-yet-validated findings of a template.

    Returns the list of created FindingValidation ids. Findings that already have
    a queued/running validation are skipped. The scanner worker picks these up
    via its DB poller (and via SQS when configured).
    """
    if limit is None:
        limit = getattr(settings, "DETECTION_PATTERN_VALIDATE_SAMPLE", 5)

    open_findings = (
        db.query(Vulnerability)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .filter(
            Asset.organization_id == organization_id,
            Vulnerability.template_id == template_id,
            Vulnerability.status == VulnerabilityStatus.OPEN,
        )
        .order_by(Vulnerability.id.asc())
        .all()
    )

    created_ids: List[int] = []
    for vuln in open_findings:
        if len(created_ids) >= limit:
            break
        in_flight = (
            db.query(FindingValidation.id)
            .filter(
                FindingValidation.vulnerability_id == vuln.id,
                FindingValidation.status.in_([ValidationStatus.QUEUED, ValidationStatus.RUNNING]),
            )
            .first()
        )
        if in_flight:
            continue
        validation = FindingValidation(
            vulnerability_id=vuln.id,
            organization_id=organization_id,
            status=ValidationStatus.QUEUED,
            requested_by_user_id=requested_by_user_id,
        )
        db.add(validation)
        vuln.validation_status = "queued"
        db.flush()
        created_ids.append(validation.id)

    db.commit()

    # Best-effort SQS enqueue for responsiveness (DB poll is the fallback).
    if created_ids:
        try:
            from app.api.routes.vulnerabilities import send_validation_to_sqs
            for vid in created_ids:
                v = db.query(FindingValidation).filter(FindingValidation.id == vid).first()
                if v:
                    send_validation_to_sqs(v)
        except Exception as e:
            logger.debug("SQS enqueue for sample validations skipped: %s", e)

    return created_ids
