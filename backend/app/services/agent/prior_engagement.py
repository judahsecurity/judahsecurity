"""Read-only reuse of the previous engagement against the same target.

A repeat assessment of a customer's app should not start from nothing. This
module finds the most recent saved run of the same organization against the
same origin (another session) and summarizes, read-only:

* findings already filed on that asset, with their status;
* what was proven and what tested clean (killed hypotheses);
* guarded (auth-gated) and other observed surfaces;
* the earlier engagement goals and how they ended.

It is one level deep: it reads the earlier run's saved state, never that
run's own prior runs, and it never changes the current brain. The planner
decides what to retest; ``prior_engagement(detail="surfaces")`` returns the
earlier paths for ``ingest_urls_into_map`` if it wants them in the map.
"""

from __future__ import annotations

import logging
from typing import Any, Optional
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

MAX_SNAPSHOT_FILES = 60


def _origin(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    parts = urlsplit(text if "://" in text else f"https://{text}")
    if not parts.hostname:
        return ""
    return f"{parts.scheme}://{parts.netloc}".lower()


def _host(value: Any) -> str:
    text = str(value or "").strip()
    parts = urlsplit(text if "://" in text else f"https://{text}")
    return (parts.hostname or "").lower()


def _snapshot_origin(snapshot: dict) -> str:
    cmap = snapshot.get("capability_map") if isinstance(snapshot.get("capability_map"), dict) else {}
    brain = snapshot.get("engagement_brain") if isinstance(snapshot.get("engagement_brain"), dict) else {}
    return _origin(cmap.get("scope") or cmap.get("target") or brain.get("target"))


def find_prior_snapshot(organization_id: int, current_session_id: str,
                        target: str) -> tuple[str, dict]:
    """Most recent saved run of this organization against the same origin."""
    from app.services.agent import run_snapshot

    origin = _origin(target)
    if not organization_id or not origin:
        return "", {}
    candidates: list[tuple[float, str, dict]] = []
    prefix = f"{int(organization_id)}_"
    current_name = run_snapshot._path(int(organization_id), current_session_id).name
    try:
        files = sorted(
            (p for p in run_snapshot._DIR.glob(f"{prefix}*.json") if p.name != current_name),
            key=lambda p: p.stat().st_mtime, reverse=True,
        )[:MAX_SNAPSHOT_FILES]
    except OSError:
        files = []
    for path in files:
        session_id = path.stem[len(prefix):]
        snapshot = run_snapshot.load_run_snapshot(int(organization_id), session_id)
        if snapshot and _snapshot_origin(snapshot) == origin:
            candidates.append((float(snapshot.get("saved_at") or 0), session_id, snapshot))
            break
    try:  # scheduled runs keep their snapshots in the database
        from app.db.database import SessionLocal
        from app.models.agent_autonomy_work import AgentRunSnapshot

        with SessionLocal() as db:
            rows = (db.query(AgentRunSnapshot)
                    .filter(AgentRunSnapshot.organization_id == int(organization_id),
                            AgentRunSnapshot.session_id != str(current_session_id))
                    .order_by(AgentRunSnapshot.updated_at.desc()).limit(MAX_SNAPSHOT_FILES).all())
            for row in rows:
                snapshot = run_snapshot._validated_snapshot(dict(row.payload or {}))
                if snapshot and _snapshot_origin(snapshot) == origin:
                    candidates.append((float(snapshot.get("saved_at") or 0), row.session_id, snapshot))
                    break
    except Exception:
        logger.debug("scheduled prior snapshot lookup skipped", exc_info=True)
    if not candidates:
        return "", {}
    _, session_id, snapshot = max(candidates, key=lambda item: item[0])
    return session_id, snapshot


def prior_findings(organization_id: int, target: str, limit: int = 25) -> list[dict]:
    """Findings already filed on this asset (any source), newest first."""
    host = _host(target)
    if not organization_id or not host:
        return []
    try:
        from app.db.database import SessionLocal
        from app.models.asset import Asset
        from app.models.vulnerability import Vulnerability

        with SessionLocal() as db:
            rows = (db.query(Vulnerability)
                    .join(Asset, Asset.id == Vulnerability.asset_id)
                    .filter(Asset.organization_id == int(organization_id), Asset.value == host)
                    .order_by(Vulnerability.id.desc()).limit(limit).all())
            return [{
                "id": row.id,
                "title": (row.title or "")[:200],
                "severity": row.severity.value if row.severity else None,
                "status": row.status.value if row.status else None,
                "detected_by": row.detected_by,
                "verification_level": row.verification_level,
                "affected_component": (row.affected_component or "")[:200],
            } for row in rows]
    except Exception:
        logger.debug("prior findings lookup skipped", exc_info=True)
        return []


def summarize(snapshot: dict, *, limit: int = 20) -> dict:
    brain = snapshot.get("engagement_brain") if isinstance(snapshot.get("engagement_brain"), dict) else {}
    hypotheses = [h for h in brain.get("hypotheses") or [] if isinstance(h, dict)]
    surfaces = [s for s in brain.get("surfaces") or [] if isinstance(s, dict)]

    def card(h: dict) -> dict:
        return {"title": str(h.get("title") or "")[:160], "specialist": h.get("specialist"),
                "evidence": str(h.get("evidence") or "")[:200]}

    return {
        "saved_at": snapshot.get("saved_at"),
        "objective": str(snapshot.get("original_objective") or "")[:400],
        "proven": [card(h) for h in hypotheses if h.get("status") == "proven"][:limit],
        "tested_clean": [card(h) for h in hypotheses if h.get("status") == "killed"][:limit],
        "confirmed_candidates": [
            {"title": str(c.get("title") or "")[:160], "finding_id": c.get("finding_id") or ""}
            for c in brain.get("candidates") or []
            if isinstance(c, dict) and c.get("status") == "confirmed"
        ][:limit],
        "auth_gated_surfaces": [
            f"{s.get('method', 'GET')} {s.get('path')}" for s in surfaces if s.get("auth_gated")
        ][:limit],
        "surface_count": len(surfaces),
        "goals": [
            {"text": g.get("text"), "status": g.get("status")}
            for g in brain.get("engagement_goals") or [] if isinstance(g, dict)
        ][:10],
    }


def surfaces(snapshot: dict, origin: str, limit: int = 150) -> list[str]:
    """Earlier observed in-origin URLs (no query values), for ingest_urls_into_map."""
    brain = snapshot.get("engagement_brain") if isinstance(snapshot.get("engagement_brain"), dict) else {}
    host = urlsplit(origin).netloc
    out: list[str] = []
    for row in brain.get("surfaces") or []:
        if not isinstance(row, dict) or str(row.get("host") or "").lower() != host.lower():
            continue
        path = str(row.get("path") or "")
        if path.startswith("/") and not path.startswith("//"):
            url = origin + path
            if url not in out:
                out.append(url)
        if len(out) >= limit:
            break
    return out
