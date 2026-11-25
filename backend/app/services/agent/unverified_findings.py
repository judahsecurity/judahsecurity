"""Unverified findings tier and verifier verdict log.

The independent verifier only confirms a candidate when a class-specific proof
recipe passes. Real bugs that no recipe covers used to end as ``inconclusive``
and never reached the findings table. This module gives them a home:

* An inconclusive candidate that carries hunter evidence is published as a
  finding with ``verification_level="unverified"``, capped at medium severity.
  Default findings lists, dashboards and reports exclude it; analysts review it
  in its own view and promote it (``analyst_verified``) or dismiss it.
* A later confirmed publication supersedes the unverified row, and a later
  refuted verdict (which needs counterevidence) closes it as a false positive.
* Every verdict is appended to ``agent_verdict_log`` so operators can see which
  classes and recipes reject candidates most often.

Nothing here changes what counts as ``exploit_verified``.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

UNVERIFIED = "unverified"
ANALYST_VERIFIED = "analyst_verified"
SUPERSEDED = "superseded"
# Verification levels left out of default findings lists, dashboards and reports.
HIDDEN_BY_DEFAULT = (UNVERIFIED, SUPERSEDED)
UNVERIFIED_SEVERITY_CAP = "medium"
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def unverified_tier_enabled() -> bool:
    from app.core.config import settings

    return bool(getattr(settings, "AGENT_UNVERIFIED_FINDINGS", True))


def cap_unverified_severity(severity: Optional[str]) -> str:
    normalized = (severity or "info").strip().lower()
    if normalized not in _SEVERITY_RANK:
        normalized = "info"
    if _SEVERITY_RANK[normalized] > _SEVERITY_RANK[UNVERIFIED_SEVERITY_CAP]:
        return UNVERIFIED_SEVERITY_CAP
    return normalized


def candidate_class(candidate: Any) -> str:
    explicit = str(getattr(candidate, "vulnerability_class", "") or "").strip().lower()
    if explicit:
        return explicit[:64]
    try:
        from app.services.agent.proof_policy import inferred_vulnerability_class

        return (inferred_vulnerability_class(candidate) or "unclassified")[:64]
    except Exception:  # noqa: BLE001 - classification is best effort
        return "unclassified"


def visible_level_clause(model):
    """SQL condition for findings shown by default (not unverified/superseded)."""
    from sqlalchemy import or_

    return or_(model.verification_level.is_(None),
               model.verification_level.notin_(HIDDEN_BY_DEFAULT))


def exclude_hidden_levels(query, model):
    """Filter a Vulnerability query down to findings shown by default."""
    return query.filter(visible_level_clause(model))


def is_visible(vuln: Any) -> bool:
    return getattr(vuln, "verification_level", None) not in HIDDEN_BY_DEFAULT


def _org_and_session() -> tuple[Optional[int], str]:
    try:
        from app.services.agent.tools import current_session_id, get_tenant_context

        _, org_id = get_tenant_context()
        return org_id, str(current_session_id.get() or "")
    except Exception:  # noqa: BLE001
        return None, ""


def record_verdict(candidate: Any, verdict: str, *, proof_kind: str = "",
                   reason: str = "", hunter_evidence_count: int = 0,
                   finding_id: Optional[int] = None) -> None:
    """Append one verdict row. Never raises; skipped outside a tenant context."""
    org_id, session_id = _org_and_session()
    if not org_id:
        return
    try:
        from app.db.database import SessionLocal
        from app.models.agent_verdict_log import AgentVerdictLog
        from app.services.agent.action_ledger import active_run_id, safe_target
        from app.services.agent.observability import redact_string

        with SessionLocal() as db:
            db.add(AgentVerdictLog(
                organization_id=org_id,
                session_id=session_id[:64],
                run_id=active_run_id.get(),
                candidate_id=str(getattr(candidate, "id", "") or "")[:64],
                revision=int(getattr(candidate, "revision", 1) or 1),
                vulnerability_class=candidate_class(candidate),
                verdict=verdict[:24],
                proof_kind=str(proof_kind or "")[:64],
                reason=redact_string(reason or "")[:1000],
                target=safe_target(getattr(candidate, "target", "")),
                hunter_evidence_count=hunter_evidence_count,
                finding_id=finding_id,
            ))
            db.commit()
    except Exception:  # noqa: BLE001 - logging must not break verification
        logger.debug("verdict log write failed", exc_info=True)
    logger.info(
        "agent_verdict class=%s verdict=%s proof_kind=%s candidate=%s",
        candidate_class(candidate), verdict, proof_kind or "-",
        getattr(candidate, "id", ""),
    )


def _description(candidate: Any) -> str:
    gap = getattr(candidate, "proof_gap", None) or {}
    parts = [str(getattr(candidate, "description", "") or "").strip()]
    parts.append(
        "Not independently verified. The hunter reported this with evidence, but the "
        "independent verifier could not reproduce it with a supported proof."
    )
    if gap.get("reason"):
        parts.append(f"Verifier gap: {gap['reason']}")
    if gap.get("next_step"):
        parts.append(f"Suggested next step: {gap['next_step']}")
    return "\n\n".join(p for p in parts if p)[:10000]


def _lead_metadata(candidate: Any, requested: str, published: str, session_id: str) -> Dict[str, Any]:
    gap = getattr(candidate, "proof_gap", None) or {}
    return {
        "candidate_id": getattr(candidate, "id", ""),
        "revision": getattr(candidate, "revision", 1),
        "vulnerability_class": candidate_class(candidate),
        "session_id": session_id,
        "hunter_evidence_ids": list(getattr(candidate, "evidence_ids", None) or [])[:32],
        "verifier_run_id": getattr(candidate, "verifier_run_id", ""),
        "verifier_summary": str(getattr(candidate, "verifier_summary", "") or "")[:2000],
        "proof_gap": dict(gap),
        "requested_severity": requested,
        "published_severity": published,
        "published_at": datetime.utcnow().isoformat(),
    }


def publish_unverified_candidate(tools_manager: Any, candidate: Any) -> Optional[int]:
    """Create or refresh the unverified finding for an inconclusive candidate."""
    org_id, session_id = _org_and_session()
    if not org_id or not getattr(candidate, "target", ""):
        return None
    get_asset = getattr(tools_manager, "_get_or_create_asset", None)
    if get_asset is None:
        return None
    from app.db.database import SessionLocal
    from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus

    requested = (getattr(candidate, "severity", "") or "medium").strip().lower()
    published = cap_unverified_severity(requested)
    lead = _lead_metadata(candidate, requested, published, session_id)
    try:
        with SessionLocal() as db:
            existing_id = int(getattr(candidate, "unverified_finding_id", 0) or 0)
            vuln = db.query(Vulnerability).filter(Vulnerability.id == existing_id).first() if existing_id else None
            if vuln is not None and vuln.verification_level == UNVERIFIED:
                # Refresh the gap; keep any analyst edits to status or severity.
                meta = dict(vuln.metadata_ or {})
                meta["unverified_lead"] = lead
                vuln.metadata_ = meta
                vuln.description = _description(candidate)
                vuln.last_detected = datetime.utcnow()
                db.commit()
                return vuln.id
            if vuln is not None:
                # Analyst already promoted or dismissed it; do not reopen.
                return vuln.id
            asset = get_asset(db, org_id, candidate.target)
            db.flush()
            vuln = Vulnerability(
                title=(getattr(candidate, "title", "") or "Unverified agent lead")[:500],
                description=_description(candidate),
                severity=Severity(published),
                asset_id=asset.id,
                detected_by="agent",
                evidence=(str(getattr(candidate, "evidence", "") or "")[:5000] or None),
                steps_to_reproduce=(str(getattr(candidate, "claimed_request", "") or "")[:10000] or None),
                affected_component=(str(getattr(candidate, "parameter", "") or "")[:500] or None),
                detection_confidence=UNVERIFIED,
                verification_level=UNVERIFIED,
                status=VulnerabilityStatus.OPEN,
                tags=["unverified"],
                metadata_={
                    "verification_level": UNVERIFIED,
                    "unverified_lead": lead,
                    "severity_cap": {
                        "requested": requested, "published": published,
                        "reason": "unverified findings are capped at medium until "
                                  "an analyst or a runtime proof confirms them",
                    } if published != requested else None,
                    "trace": {"candidate_id": getattr(candidate, "id", "")},
                },
            )
            db.add(vuln)
            db.commit()
            from app.services.agent.tools import _emit_finding_to_sink

            _emit_finding_to_sink(
                title=vuln.title, description=vuln.description or "", severity=published,
                target=candidate.target, host=asset.value,
                evidence=getattr(candidate, "evidence", "") or None,
                poc=getattr(candidate, "claimed_request", "") or None,
                confirmed=False, verification_level=UNVERIFIED,
            )
            return vuln.id
    except Exception:  # noqa: BLE001 - publication must not break verification
        logger.warning("unverified finding publication failed", exc_info=True)
        return None


def close_unverified_finding(finding_id: int, *, superseded_by: Optional[int] = None,
                             refuted_reason: str = "") -> None:
    """Supersede (confirmed elsewhere) or close (refuted) an unverified finding."""
    if not finding_id:
        return
    from app.db.database import SessionLocal
    from app.models.vulnerability import Vulnerability, VulnerabilityStatus

    try:
        with SessionLocal() as db:
            vuln = db.query(Vulnerability).filter(Vulnerability.id == finding_id).first()
            if vuln is None or vuln.verification_level != UNVERIFIED:
                return
            meta = dict(vuln.metadata_ or {})
            if superseded_by:
                vuln.verification_level = SUPERSEDED
                vuln.status = VulnerabilityStatus.RESOLVED
                vuln.resolved_at = datetime.utcnow()
                meta["superseded_by"] = superseded_by
            else:
                vuln.status = VulnerabilityStatus.FALSE_POSITIVE
                meta["refuted"] = {"reason": refuted_reason[:2000],
                                   "at": datetime.utcnow().isoformat()}
            vuln.metadata_ = meta
            db.commit()
    except Exception:  # noqa: BLE001
        logger.warning("closing unverified finding %s failed", finding_id, exc_info=True)


def after_verdict(tools_manager: Any, brain: Any, candidate: Any, verdict: str, *,
                  proof_kind: str = "", hunter_evidence_count: int = 0) -> None:
    """Publish, close and log after apply_verdict settled a candidate."""
    finding_id: Optional[int] = None
    from app.services.agent.verification_profile import unverified_tier_allowed

    if verdict == "inconclusive" and candidate.review_status == "needs_analyst_review" \
            and unverified_tier_enabled() and unverified_tier_allowed(tools_manager):
        finding_id = publish_unverified_candidate(tools_manager, candidate)
        if finding_id and finding_id != candidate.unverified_finding_id:
            candidate.unverified_finding_id = finding_id
            for raw in brain.candidates or []:
                if isinstance(raw, dict) and raw.get("id") == candidate.id:
                    raw["unverified_finding_id"] = finding_id
    elif verdict == "refuted" and candidate.unverified_finding_id:
        close_unverified_finding(
            candidate.unverified_finding_id,
            refuted_reason=candidate.verifier_summary or "Refuted by the independent verifier",
        )
    reason = (candidate.proof_gap or {}).get("reason", "") if verdict == "inconclusive" \
        else candidate.verifier_summary
    record_verdict(candidate, verdict, proof_kind=proof_kind, reason=reason,
                   hunter_evidence_count=hunter_evidence_count, finding_id=finding_id)


def promote_finding(vuln: Any, user: Any, *, severity: Optional[str] = None, note: str = "") -> None:
    """Analyst confirms an unverified finding; restores the requested severity."""
    from app.models.vulnerability import Severity

    if vuln.verification_level != UNVERIFIED:
        raise ValueError("Only unverified findings can be promoted")
    meta = dict(vuln.metadata_ or {})
    lead = meta.get("unverified_lead") or {}
    target = (severity or lead.get("requested_severity") or vuln.severity.value).strip().lower()
    if target not in _SEVERITY_RANK:
        raise ValueError(f"Unknown severity: {target}")
    vuln.severity = Severity(target)
    vuln.verification_level = ANALYST_VERIFIED
    vuln.detection_confidence = ANALYST_VERIFIED
    vuln.tags = [t for t in (vuln.tags or []) if t != "unverified"]
    meta["verification_level"] = ANALYST_VERIFIED
    meta["analyst_review"] = {
        "action": "promote", "by": getattr(user, "email", None) or getattr(user, "id", None),
        "at": datetime.utcnow().isoformat(), "note": note[:2000], "severity": target,
    }
    vuln.metadata_ = meta


def dismiss_finding(vuln: Any, user: Any, *, note: str = "") -> None:
    from app.models.vulnerability import VulnerabilityStatus

    if vuln.verification_level != UNVERIFIED:
        raise ValueError("Only unverified findings can be dismissed here")
    meta = dict(vuln.metadata_ or {})
    meta["analyst_review"] = {
        "action": "dismiss", "by": getattr(user, "email", None) or getattr(user, "id", None),
        "at": datetime.utcnow().isoformat(), "note": note[:2000],
    }
    vuln.metadata_ = meta
    vuln.status = VulnerabilityStatus.FALSE_POSITIVE


def verdict_summary(db: Any, organization_id: int, *, days: int = 30,
                    top_reasons: int = 3) -> Dict[str, Any]:
    """Verdict counts per vulnerability class, with the most common gap reasons.

    ``rejection_rate`` is the share of a class's verdicts that were not
    confirmed. A high rate with many inconclusive verdicts points at a proof
    recipe that may be stricter than the bugs it is meant to confirm.
    """
    from datetime import timedelta

    from sqlalchemy import func

    from app.models.agent_verdict_log import AgentVerdictLog

    since = datetime.utcnow() - timedelta(days=days)
    base = db.query(AgentVerdictLog).filter(
        AgentVerdictLog.organization_id == organization_id,
        AgentVerdictLog.created_at >= since,
    )
    counts = (
        base.with_entities(AgentVerdictLog.vulnerability_class, AgentVerdictLog.verdict,
                           func.count(AgentVerdictLog.id))
        .group_by(AgentVerdictLog.vulnerability_class, AgentVerdictLog.verdict)
        .all()
    )
    classes: Dict[str, Dict[str, Any]] = {}
    for cls, verdict, n in counts:
        row = classes.setdefault(cls, {"vulnerability_class": cls, "confirmed": 0,
                                       "refuted": 0, "inconclusive": 0, "total": 0})
        if verdict in row:
            row[verdict] += n
        row["total"] += n
    reasons = (
        base.filter(AgentVerdictLog.verdict == "inconclusive")
        .with_entities(AgentVerdictLog.vulnerability_class, AgentVerdictLog.reason,
                       func.count(AgentVerdictLog.id))
        .group_by(AgentVerdictLog.vulnerability_class, AgentVerdictLog.reason)
        .order_by(func.count(AgentVerdictLog.id).desc())
        .all()
    )
    for cls, reason, n in reasons:
        row = classes.get(cls)
        if row is None:
            continue
        top = row.setdefault("top_inconclusive_reasons", [])
        if len(top) < top_reasons:
            top.append({"reason": (reason or "")[:300], "count": n})
    rows = []
    for row in classes.values():
        row.setdefault("top_inconclusive_reasons", [])
        row["rejection_rate"] = round(1 - row["confirmed"] / row["total"], 3) if row["total"] else 0.0
        rows.append(row)
    rows.sort(key=lambda r: (-r["inconclusive"], -r["total"], r["vulnerability_class"]))
    return {"days": days, "classes": rows,
            "totals": {k: sum(r[k] for r in rows)
                       for k in ("confirmed", "refuted", "inconclusive", "total")}}


def publish_external_unverified(db: Any, *, organization_id: int, asset_id: int,
                                session_id: str, run_id: str, candidate: Dict[str, Any],
                                recipe: str, reason: str) -> Optional[int]:
    """Unverified finding for a Prowl service candidate its verifier did not confirm.

    Deduplicated per service candidate. Hidden from default views like any
    other unverified finding; the service's own publication stays the only
    route to exploit_verified.
    """
    from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus

    candidate_id = str(candidate.get("candidate_id") or "")
    if not candidate_id or not unverified_tier_enabled():
        return None
    title = str(candidate.get("title") or f"Unverified Prowl lead ({recipe})")[:500]
    existing = (db.query(Vulnerability)
                .filter(Vulnerability.asset_id == asset_id,
                        Vulnerability.detected_by == "PROWL",
                        Vulnerability.title == title,
                        Vulnerability.verification_level.in_((UNVERIFIED, ANALYST_VERIFIED)))
                .all())
    for row in existing:
        if (row.metadata_ or {}).get("unverified_lead", {}).get("candidate_id") == candidate_id:
            return row.id
    requested = str(candidate.get("severity") or "medium").strip().lower()
    published = cap_unverified_severity(requested)
    lead = {
        "candidate_id": candidate_id, "prowl_run_id": run_id, "session_id": session_id,
        "vulnerability_class": str(candidate.get("vulnerability_class") or recipe)[:64],
        "verifier_recipe": recipe, "requested_severity": requested,
        "published_severity": published,
        "proof_gap": {"reason": reason[:2000],
                      "next_step": "Retry the service verifier or review the hunter evidence"},
        "hunter_evidence_ids": [str(x)[:64] for x in (candidate.get("evidence_ids") or [])][:32],
        "published_at": datetime.utcnow().isoformat(),
    }
    vuln = Vulnerability(
        title=title, severity=Severity(published), asset_id=asset_id, detected_by="PROWL",
        description=(str(candidate.get("description") or "").strip() + "\n\nNot independently "
                     "verified: the Prowl service verifier did not reproduce this claim.").strip()[:10000],
        detection_confidence=UNVERIFIED, verification_level=UNVERIFIED,
        status=VulnerabilityStatus.OPEN, tags=["unverified"],
        metadata_={"verification_level": UNVERIFIED, "unverified_lead": lead,
                   "prowl_run_id": run_id, "prowl_candidate_id": candidate_id},
    )
    db.add(vuln)
    db.commit()
    return vuln.id
