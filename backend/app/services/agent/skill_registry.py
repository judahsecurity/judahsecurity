"""Persist and approve versioned skill manifests."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models.agent_runtime import AgentSkillVersion
from app.services.agent.skills_service import SKILLS, manifest_for_skill


def sync_builtin_skills(
    db: Session,
    *,
    organization_id: Optional[int] = None,
    approved_by: Optional[str] = None,
    enable: bool = False,
) -> list[AgentSkillVersion]:
    rows: list[AgentSkillVersion] = []
    for skill in SKILLS:
        manifest = manifest_for_skill(skill)
        query = db.query(AgentSkillVersion).filter(
            AgentSkillVersion.skill_id == skill.id,
            AgentSkillVersion.version == manifest["version"],
        )
        if organization_id is None:
            query = query.filter(AgentSkillVersion.organization_id.is_(None))
        else:
            query = query.filter(AgentSkillVersion.organization_id == organization_id)
        row = query.first()
        if row is None:
            row = AgentSkillVersion(
                organization_id=organization_id,
                skill_id=skill.id,
                version=manifest["version"],
                manifest=manifest,
                content_hash=manifest["digest"],
                enabled=enable,
                approved_by=approved_by if enable else None,
            )
            db.add(row)
        else:
            row.manifest = manifest
            row.content_hash = manifest["digest"]
            if enable:
                row.enabled = True
                row.approved_by = approved_by
            row.updated_at = datetime.utcnow()
        rows.append(row)
    db.flush()
    return rows


def enabled_manifest(
    db: Session,
    *,
    organization_id: int,
    skill_id: str,
) -> Optional[dict]:
    row = (
        db.query(AgentSkillVersion)
        .filter(
            or_(
                AgentSkillVersion.organization_id == organization_id,
                AgentSkillVersion.organization_id.is_(None),
            ),
            AgentSkillVersion.skill_id == skill_id,
            AgentSkillVersion.enabled.is_(True),
        )
        .order_by(AgentSkillVersion.organization_id.desc().nullslast(), AgentSkillVersion.id.desc())
        .first()
    )
    return dict(row.manifest or {}) if row else None
