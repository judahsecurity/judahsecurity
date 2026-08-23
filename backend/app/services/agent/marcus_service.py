"""On-demand Marcus RA — Ask Marcus from the findings UI.

Runs a bounded agent session against the published packet. No live retest.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)


async def run_marcus_for_finding(
    *,
    finding_id: int,
    user_id: int,
    organization_id: int,
) -> Dict[str, Any]:
    from app.db.database import SessionLocal
    from app.models.asset import Asset
    from app.models.vulnerability import Vulnerability
    from app.services.agent.risk_assessment import (
        attach_to_vulnerability,
        finding_packet_for_marcus,
        marcus_question,
    )
    from app.services.agent.orchestrator import get_agent_orchestrator
    from app.services.agent.tools import set_tenant_context

    db = SessionLocal()
    try:
        vuln = db.query(Vulnerability).filter(Vulnerability.id == finding_id).first()
        if not vuln:
            return {"ok": False, "error": "finding not found"}
        asset = db.query(Asset).filter(Asset.id == vuln.asset_id).first()
        host = asset.value if asset else None
        meta = dict(vuln.metadata_ or {})
        ra = dict(meta.get("risk_assessment") or {})
        ra["status"] = "in_progress"
        attach_to_vulnerability(vuln, ra)
        db.commit()
        packet = finding_packet_for_marcus(vuln, host=host)
    finally:
        db.close()

    set_tenant_context(user_id, organization_id, session_id=f"marcus-{finding_id}")
    orch = await get_agent_orchestrator()
    result = await orch.invoke(
        question=marcus_question(packet, finding_id),
        user_id=str(user_id),
        organization_id=organization_id,
        session_id=f"marcus-{finding_id}",
        mode="agent",
        max_iterations=8,
    )

    db = SessionLocal()
    try:
        vuln = db.query(Vulnerability).filter(Vulnerability.id == finding_id).first()
        if not vuln:
            return {"ok": False, "error": "finding disappeared"}
        ra = (vuln.metadata_ or {}).get("risk_assessment") or {}
        if ra.get("status") != "complete":
            ra = dict(ra)
            ra["status"] = "failed"
            ra["error"] = (getattr(result, "error", None) or "Marcus did not persist a complete RA")[:400]
            attach_to_vulnerability(vuln, ra)
            db.commit()
            return {"ok": False, "error": ra["error"], "answer": (getattr(result, "answer", None) or "")[:1500]}
        return {"ok": True, "risk_assessment": ra}
    finally:
        db.close()
