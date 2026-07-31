"""
Recon bridge API.

Lets an out-of-harness recon run (e.g. the standalone
``python -m app.services.interceptor_recon`` driving the operator's real,
logged-in Interceptor browser session on their desktop) POST its normalised
result back into the harness. We persist it as an ``AgentKnowledge`` document so
the in-app agent's retrieval picks up the authenticated attack surface it could
never reach from a headless Linux crawl.

The normalised ``recon`` payload is the shared contract emitted by both
``interceptor_recon.to_normalized_dict`` and the Playwright ``deep_crawl`` engine.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from urllib.parse import urlparse

from app.db.database import get_db
from app.models.user import User
from app.models.organization import Organization
from app.models.agent_knowledge import AgentKnowledge
from app.api.deps import require_analyst

router = APIRouter(tags=["Recon"])


class ReconIngest(BaseModel):
    """Normalised recon result from an external driver (Interceptor or deep_crawl)."""
    organization_id: Optional[int] = Field(
        None, description="Org to attach the recon to (None = global; superuser only)"
    )
    recon: Dict[str, Any] = Field(..., description="Normalised recon contract")


class ReconIngestResponse(BaseModel):
    knowledge_id: int
    organization_id: Optional[int]
    title: str
    endpoints_ingested: int
    js_files_ingested: int


def _check_org_access(current_user: User, org_id: Optional[int], db: Session) -> None:
    if org_id is None:
        if not getattr(current_user, "is_superuser", False):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only superusers can ingest global recon",
            )
        return
    if not current_user.is_superuser and getattr(current_user, "organization_id", None) != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized for this organization",
        )
    if not db.query(Organization).filter(Organization.id == org_id).first():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")


def _format_recon(d: Dict[str, Any]) -> str:
    """Render the normalised recon contract into an agent-readable document."""
    lines: List[str] = []
    target = d.get("target", "")
    scope = d.get("scope", "")
    engine = d.get("engine", "unknown")
    lines.append(f"# Recon surface for {target}")
    lines.append(f"Engine: {engine}  |  Scope: {scope}")

    pages = d.get("pages_visited") or []
    lines.append(f"\n## Pages visited ({len(pages)})")
    lines += [f"- {p}" for p in pages[:40]]

    api_calls = d.get("api_calls") or {}
    total = sum(len(v) for v in api_calls.values())
    if api_calls:
        lines.append(f"\n## First-party API / XHR endpoints ({total})")
        for host in sorted(api_calls):
            lines.append(f"### {host}")
            for key in list(api_calls[host])[:150]:
                lines.append(f"- {key}")

    for label, keyname, cap in (
        ("WebSocket channels", "websockets", 40),
        ("SSE streams", "sse", 40),
        ("JavaScript files", "js_files", 120),
        ("Source maps exposed", "source_maps", 40),
        ("Endpoints from JS", "endpoints_from_js", 200),
        ("Third-party hosts", "third_party", 60),
    ):
        vals = d.get(keyname) or []
        if vals:
            lines.append(f"\n## {label} ({len(vals)})")
            lines += [f"- {v}" for v in vals[:cap]]

    auth_headers = d.get("auth_headers") or []
    if auth_headers:
        lines.append(f"\n## Auth / CSRF header surface\n- {', '.join(auth_headers)}")

    return "\n".join(lines)


@router.post("/recon/ingest", response_model=ReconIngestResponse)
def ingest_recon(
    body: ReconIngest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Ingest a normalised recon result and persist it as agent knowledge."""
    _check_org_access(current_user, body.organization_id, db)

    recon = body.recon or {}
    target = str(recon.get("target") or "").strip()
    if not target:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="recon.target is required")

    host = urlparse(target).netloc or target
    engine = str(recon.get("engine") or "recon")
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    title = f"Recon: {host} ({engine}) {ts}"[:512]

    api_calls = recon.get("api_calls") or {}
    endpoints_ingested = sum(len(v) for v in api_calls.values()) + len(recon.get("endpoints_from_js") or [])
    js_files_ingested = len(recon.get("js_files") or [])

    doc = AgentKnowledge(
        organization_id=body.organization_id,
        title=title,
        content=_format_recon(recon),
        tags=["recon", engine, host],
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)

    return ReconIngestResponse(
        knowledge_id=doc.id,
        organization_id=doc.organization_id,
        title=doc.title,
        endpoints_ingested=endpoints_ingested,
        js_files_ingested=js_files_ingested,
    )
