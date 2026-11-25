"""Org-scoped impact of one CVE: which assets have it, which are exposed,
and how far the agent got in validating it.

Backs the threat-intel incident page ("Am I affected?"). Everything here
comes from the organization's own findings and assets — no external calls.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.vulnerability import Vulnerability

OPEN_STATUSES = {"open", "in_progress"}

# Strongest validation wins when an asset has several findings for the CVE.
VALIDATION_RANK = {"detected": 0, "demonstrated": 1, "exploit_verified": 2}


def _enum(value: Any) -> str:
    return str(getattr(value, "value", value) or "").lower()


def finding_validation(v: Vulnerability) -> str:
    """exploit_verified > demonstrated (agent chain attached) > detected."""
    verdict = (v.last_validation_verdict or "").lower()
    if verdict == "false_positive":
        return "detected"
    if (v.verification_level or "") == "exploit_verified" or verdict == "confirmed":
        return "exploit_verified"
    meta = v.metadata_ if isinstance(v.metadata_, dict) else {}
    det = meta.get("agent_detection") if isinstance(meta.get("agent_detection"), dict) else {}
    if det.get("chain"):
        return "demonstrated"
    return "detected"


def asset_exposure(a: Optional[Asset]) -> str:
    if a is None:
        return "unknown"
    if getattr(a, "is_public", False) and getattr(a, "is_live", False):
        return "internet_exposed"
    if getattr(a, "is_public", False):
        return "public_not_live"
    return "internal"


def build_cve_impact(db: Session, organization_id: int, cve_id: str, limit: int = 500) -> Dict[str, Any]:
    cve = (cve_id or "").strip().upper()
    rows: List[Vulnerability] = (
        db.query(Vulnerability)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .filter(Asset.organization_id == organization_id, func.upper(Vulnerability.cve_id) == cve)
        .order_by(Vulnerability.id.desc())
        .limit(limit)
        .all()
    )

    by_asset: Dict[int, Dict[str, Any]] = {}
    sessions: Dict[str, Dict[str, Any]] = {}
    for v in rows:
        status = _enum(v.status)
        if status == "false_positive":
            continue
        a = v.asset
        validation = finding_validation(v)
        entry = by_asset.get(v.asset_id)
        if entry is None:
            entry = by_asset[v.asset_id] = {
                "asset_id": v.asset_id,
                "asset": a.value if a is not None else f"asset-{v.asset_id}",
                "asset_type": _enum(getattr(a, "asset_type", "")),
                "exposure": asset_exposure(a),
                "validation": validation,
                "open": False,
                "severity": _enum(v.severity),
                "finding_ids": [],
                "first_detected": None,
            }
        entry["finding_ids"].append(v.id)
        if status in OPEN_STATUSES:
            entry["open"] = True
        if VALIDATION_RANK[validation] > VALIDATION_RANK[entry["validation"]]:
            entry["validation"] = validation
        seen = v.first_detected or v.created_at
        if seen and (entry["first_detected"] is None or seen.isoformat() < entry["first_detected"]):
            entry["first_detected"] = seen.isoformat()

        meta = v.metadata_ if isinstance(v.metadata_, dict) else {}
        det = meta.get("agent_detection") if isinstance(meta.get("agent_detection"), dict) else {}
        sid = det.get("session_id")
        if sid:
            s = sessions.setdefault(str(sid), {"session_id": str(sid), "finding_ids": [], "validation": "detected"})
            s["finding_ids"].append(v.id)
            if VALIDATION_RANK[validation] > VALIDATION_RANK[s["validation"]]:
                s["validation"] = validation

    assets = sorted(
        by_asset.values(),
        key=lambda e: (
            not e["open"],
            -VALIDATION_RANK[e["validation"]],
            e["exposure"] != "internet_exposed",
            e["asset"],
        ),
    )
    open_assets = [e for e in assets if e["open"]]
    return {
        "cve_id": cve,
        "counts": {
            "affected": len(open_assets),
            "exposed": sum(1 for e in open_assets if e["exposure"] == "internet_exposed"),
            "exploit_verified": sum(1 for e in open_assets if e["validation"] == "exploit_verified"),
            "demonstrated": sum(1 for e in open_assets if e["validation"] == "demonstrated"),
            "resolved": len(assets) - len(open_assets),
        },
        "assets": assets,
        "sessions": list(sessions.values()),
    }
