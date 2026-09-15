"""
Agent skills registry + ``/skill`` chat prefix resolver.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.deps import require_analyst
from app.models.user import User, UserRole
from app.services.agent import skills_service

router = APIRouter(prefix="/agent/skills", tags=["agent-skills"])


class ResolvePayload(BaseModel):
    message: str
    use_llm_fallback: bool = False


@router.get("")
def list_skills(current_user: User = Depends(require_analyst)):
    return skills_service.list_skills()


@router.post("/sync")
def sync_skills(
    enable: bool = False,
    current_user: User = Depends(require_analyst),
):
    """Snapshot built-in manifests for review or explicitly enable them for an org."""
    from app.db.database import SessionLocal
    from app.services.agent.skill_registry import sync_builtin_skills

    org_id = getattr(current_user, "organization_id", None)
    if enable and not (
        getattr(current_user, "is_superuser", False)
        or getattr(current_user, "role", None) == UserRole.ADMIN
    ):
        raise HTTPException(status_code=403, detail="admin approval required to enable skills")
    if not org_id:
        return {"synced": 0, "enabled": False, "reason": "organization_required"}
    db = SessionLocal()
    try:
        rows = sync_builtin_skills(
            db,
            organization_id=int(org_id),
            approved_by=str(current_user.id),
            enable=bool(enable),
        )
        db.commit()
        return {"synced": len(rows), "enabled": bool(enable)}
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


@router.post("/resolve")
async def resolve_prefix(
    payload: ResolvePayload,
    current_user: User = Depends(require_analyst),
):
    """Parse a chat message for a ``/skill`` prefix. If no prefix is present and
    ``use_llm_fallback`` is set, ask the default LLM to classify the intent.
    """
    result = skills_service.resolve(payload.message)
    if result.get("matched") or not payload.use_llm_fallback:
        return result

    # LLM fallback intent routing
    try:
        from langchain_anthropic import ChatAnthropic
        llm = ChatAnthropic(model="claude-sonnet-4-6", temperature=0)
    except Exception:
        try:
            from langchain_openai import ChatOpenAI
            llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
        except Exception:
            return result

    routed = await skills_service.route_by_intent(payload.message, llm)
    if not routed:
        return result
    skill = routed["skill"]
    return {
        "matched": True,
        "source": "intent",
        "confidence": routed["confidence"],
        "why": routed["why"],
        "skill": {
            "id": skill.id,
            "title": skill.title,
            "description": skill.description,
            "scan_type": skill.scan_type,
            "playbook_id": skill.playbook_id,
            "required_inputs": skill.required_inputs,
        },
        "args": {},
        "free_text": payload.message,
        "system_context": skills_service.build_skill_context(skill, {}, payload.message),
    }
