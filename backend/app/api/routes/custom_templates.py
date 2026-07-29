"""
Custom Nuclei Templates API

CRUD management for analyst-written and AI-generated Nuclei templates.
Includes an AI generation endpoint that takes a CVE ID or vulnerability
description and produces a ready-to-review Nuclei YAML template using
the configured LLM (Claude or GPT-4).

Endpoints:
  GET    /nuclei-templates/                   list templates
  POST   /nuclei-templates/                   create (manual upload)
  GET    /nuclei-templates/{id}               get single
  PUT    /nuclei-templates/{id}               update
  DELETE /nuclei-templates/{id}               delete
  POST   /nuclei-templates/{id}/activate      set status=active
  POST   /nuclei-templates/{id}/disable       set status=disabled
  POST   /nuclei-templates/generate           AI generation
"""

import logging
from datetime import datetime
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user, get_db
from app.core.config import settings
from app.models.custom_nuclei_template import CustomNucleiTemplate
from app.models.api_config import ExternalService, resolve_api_key
from app.services.custom_template_store import remove_template_file, sync_template_file
from app.services import custom_template_ai as ai

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/nuclei-templates", tags=["nuclei-templates"])

# ── Pydantic schemas ──────────────────────────────────────────────────────────

class TemplateCreate(BaseModel):
    organization_id: int
    template_id: str
    name: str
    description: Optional[str] = None
    template_yaml: str
    cve_ids: list[str] = []
    severity: Optional[str] = None
    tags: list[str] = []
    template_type: Optional[str] = None
    status: str = "draft"


class TemplateUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    template_yaml: Optional[str] = None
    cve_ids: Optional[list[str]] = None
    severity: Optional[str] = None
    tags: Optional[list[str]] = None
    template_type: Optional[str] = None
    status: Optional[str] = None
    validated: Optional[bool] = None


class GenerateRequest(BaseModel):
    organization_id: int
    # Provide ONE of: cve_id or description
    cve_id: Optional[str] = None
    vulnerability_description: Optional[str] = None
    # Optional context from an existing finding
    affected_url: Optional[str] = None
    affected_product: Optional[str] = None
    detection_evidence: Optional[str] = None  # e.g. error message, response body snippet
    # If False (default), generation is blocked when a template already exists for
    # this CVE (official Nuclei repo, PDCP, or an existing custom template). Set True
    # to deliberately generate a duplicate/secondary template anyway.
    force: bool = False


class RefineRequest(BaseModel):
    """Produce a more accurate template from a confirmed mis-detection.

    Provide the mis-detection diagnosis (`template_logic_issue`, typically from the
    Aegis Vanguard validator) plus either the original `template_yaml` or a `template_id`
    that can be resolved to its YAML (custom DB template or local official catalog).
    """
    organization_id: int
    template_logic_issue: str
    template_id: Optional[str] = None
    original_yaml: Optional[str] = None
    target: Optional[str] = None                # known false-positive target (for re-check)
    evidence: Optional[str] = None              # benign response that mis-fired
    reasoning: Optional[str] = None             # validator reasoning
    cve_ids: Optional[list[str]] = None
    vulnerability_id: Optional[int] = None      # example finding that mis-fired
    recheck: bool = True                        # re-run the refined template against target


def _template_response(t: CustomNucleiTemplate) -> dict:
    return {
        "id": t.id,
        "organization_id": t.organization_id,
        "template_id": t.template_id,
        "name": t.name,
        "description": t.description,
        "template_yaml": t.template_yaml,
        "cve_ids": t.cve_ids or [],
        "severity": t.severity,
        "tags": t.tags or [],
        "template_type": t.template_type,
        "source": t.source,
        "ai_model": t.ai_model,
        "status": t.status,
        "validated": t.validated,
        "times_matched": t.times_matched,
        "last_run_at": t.last_run_at.isoformat() if t.last_run_at else None,
        "last_match_at": t.last_match_at.isoformat() if t.last_match_at else None,
        "created_at": t.created_at.isoformat() if t.created_at else None,
        "updated_at": t.updated_at.isoformat() if t.updated_at else None,
    }


# ── CRUD ──────────────────────────────────────────────────────────────────────

@router.get("")
def list_templates(
    organization_id: int = Query(...),
    status: Optional[str] = Query(None),
    cve_id: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    _user=Depends(get_current_active_user),
):
    q = db.query(CustomNucleiTemplate).filter(
        CustomNucleiTemplate.organization_id == organization_id
    )
    if status:
        q = q.filter(CustomNucleiTemplate.status == status)
    if source:
        q = q.filter(CustomNucleiTemplate.source == source)
    if cve_id:
        # JSON array contains search — works in SQLite and Postgres
        q = q.filter(CustomNucleiTemplate.cve_ids.contains([cve_id.upper()]))
    templates = q.order_by(CustomNucleiTemplate.created_at.desc()).all()
    return [_template_response(t) for t in templates]


@router.post("")
def create_template(
    payload: TemplateCreate,
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    t = CustomNucleiTemplate(
        organization_id=payload.organization_id,
        template_id=payload.template_id,
        name=payload.name,
        description=payload.description,
        template_yaml=payload.template_yaml,
        cve_ids=[c.upper() for c in payload.cve_ids],
        severity=payload.severity,
        tags=payload.tags,
        template_type=payload.template_type,
        status=payload.status,
        source="manual",
        created_by_user_id=getattr(user, "id", None),
    )
    db.add(t)
    db.commit()
    db.refresh(t)
    sync_template_file(t)  # write to disk if active
    return _template_response(t)


@router.get("/{template_id}")
def get_template(
    template_id: int,
    db: Session = Depends(get_db),
    _user=Depends(get_current_active_user),
):
    t = db.query(CustomNucleiTemplate).filter(CustomNucleiTemplate.id == template_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Template not found")
    return _template_response(t)


@router.put("/{template_id}")
def update_template(
    template_id: int,
    payload: TemplateUpdate,
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    t = db.query(CustomNucleiTemplate).filter(CustomNucleiTemplate.id == template_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Template not found")

    for field, val in payload.model_dump(exclude_none=True).items():
        if field == "cve_ids" and val:
            val = [c.upper() for c in val]
        if field == "validated" and val and not t.validated:
            t.validated_at = datetime.utcnow()
            t.validated_by_user_id = getattr(user, "id", None)
        setattr(t, field, val)

    t.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(t)
    sync_template_file(t)  # reflect current status/YAML on disk
    return _template_response(t)


@router.delete("/{template_id}")
def delete_template(
    template_id: int,
    db: Session = Depends(get_db),
    _user=Depends(get_current_active_user),
):
    t = db.query(CustomNucleiTemplate).filter(CustomNucleiTemplate.id == template_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Template not found")
    org_id, tid = t.organization_id, t.template_id
    db.delete(t)
    db.commit()
    remove_template_file(org_id, tid)
    return {"deleted": True}


@router.post("/{template_id}/activate")
async def activate_template(
    template_id: int,
    skip_validation: bool = False,
    db: Session = Depends(get_db),
    _user=Depends(get_current_active_user),
):
    """Activate a template so it is materialized to disk and run by the scanner.

    The template's YAML is validated with `nuclei -validate` first; activation is
    blocked if validation fails. Pass `skip_validation=true` to override (e.g. when
    nuclei is unavailable in this environment and you accept the risk). If the
    nuclei binary is not installed, validation fails open with a warning.
    """
    t = db.query(CustomNucleiTemplate).filter(CustomNucleiTemplate.id == template_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Template not found")

    if not skip_validation:
        v = await ai.validate_template_yaml(t.template_yaml)
        if v.get("ran") and not v.get("valid"):
            raise HTTPException(
                status_code=422,
                detail={
                    "error": "template_validation_failed",
                    "message": "nuclei -validate rejected this template; fix it before activating.",
                    "validation_output": v.get("output"),
                    "hint": "Pass skip_validation=true to activate anyway.",
                },
            )
        if not v.get("ran"):
            logger.warning(
                "Activating template %s without validation (%s)",
                t.template_id, v.get("error"),
            )

    t.status = "active"
    t.updated_at = datetime.utcnow()
    db.commit()
    sync_template_file(t)  # write active template to disk for scanning
    return {"status": "active"}


@router.post("/{template_id}/disable")
def disable_template(
    template_id: int,
    db: Session = Depends(get_db),
    _user=Depends(get_current_active_user),
):
    t = db.query(CustomNucleiTemplate).filter(CustomNucleiTemplate.id == template_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Template not found")
    t.status = "disabled"
    t.updated_at = datetime.utcnow()
    db.commit()
    remove_template_file(t.organization_id, t.template_id)  # exclude from scanning
    return {"status": "disabled"}


# ── AI generation ─────────────────────────────────────────────────────────────

async def _fetch_cve_context(cve_id: str, db: Session) -> dict:
    """Fetch CVE context from PDCP for use in the generation prompt."""
    pdcp_key = resolve_api_key(db, ExternalService.PDCP) or ""
    if not pdcp_key or not cve_id:
        return {}
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://api.projectdiscovery.io/v1/vulnerability/{cve_id.upper()}",
                headers={"X-Api-Key": pdcp_key, "Accept": "application/json"},
                timeout=15.0,
            )
            if resp.status_code == 200:
                return resp.json() or {}
    except Exception:
        pass
    return {}


def _build_generation_prompt(req: GenerateRequest, cve_ctx: dict) -> str:
    parts = []

    if req.cve_id:
        parts.append(f"Generate a Nuclei detection template for: {req.cve_id.upper()}")
    else:
        parts.append("Generate a Nuclei detection template for the following vulnerability:")

    if cve_ctx:
        parts.append(f"\n## CVE Enrichment Data")
        if cve_ctx.get("name"):
            parts.append(f"Name: {cve_ctx['name']}")
        if cve_ctx.get("description"):
            parts.append(f"Description: {cve_ctx['description']}")
        if cve_ctx.get("severity"):
            parts.append(f"Severity: {cve_ctx['severity']}")
        if cve_ctx.get("cvss_score"):
            parts.append(f"CVSS Score: {cve_ctx['cvss_score']}")
        if cve_ctx.get("cvss_vector"):
            parts.append(f"CVSS Vector: {cve_ctx['cvss_vector']}")
        if cve_ctx.get("tags"):
            parts.append(f"Tags: {', '.join(cve_ctx['tags'][:10])}")
        if cve_ctx.get("affected_products"):
            prods = cve_ctx["affected_products"][:3]
            prod_strs = [p.get('vendor', '') + '/' + p.get('product', '') for p in prods]
            parts.append(f"Affected Products: {', '.join(prod_strs)}")
        if cve_ctx.get("is_remote"):
            parts.append("Remotely exploitable: yes")
        if cve_ctx.get("is_poc"):
            parts.append("Public PoC: available")

    if req.vulnerability_description:
        parts.append(f"\n## Vulnerability Description\n{req.vulnerability_description}")

    if req.affected_url:
        path_pattern = ai.url_to_path_pattern(req.affected_url)
        parts.append(
            "\n## Affected Path Pattern\n"
            f"The vulnerability was observed at path `{path_pattern}` on an example host. "
            "Use this ONLY to derive the request path relative to `{{BaseURL}}` "
            "(e.g. `{{BaseURL}}" + path_pattern + "`). "
            "Do NOT hardcode the example host — the template must run against any target."
        )

    if req.affected_product:
        parts.append(f"\n## Affected Product\n{req.affected_product}")

    if req.detection_evidence:
        parts.append(f"\n## Detection Evidence (response snippet / error message observed)\n{req.detection_evidence}")

    parts.append(
        "\n## Instructions\n"
        "Generate a complete, production-ready Nuclei YAML template.\n"
        "Focus on ACTIVE DETECTION — a request that gets a different response from vulnerable vs. patched systems.\n"
        "Return ONLY the raw YAML. No markdown, no explanation."
    )

    return "\n".join(parts)


def _find_existing_nuclei_template(
    cve_id: str,
    organization_id: int,
    cve_ctx: dict,
    db: Session,
) -> Optional[dict]:
    """Check whether a Nuclei template already exists for this CVE.

    Runs cheap→expensive: existing custom templates (DB) → PDCP `is_template`
    flag (already fetched) → local official template catalog on disk. Returns a
    dict describing the first match found, or None if no template exists yet.
    """
    cve = (cve_id or "").upper()
    if not cve:
        return None

    # 1) An existing custom template in this org already covers the CVE.
    org_templates = (
        db.query(CustomNucleiTemplate)
        .filter(CustomNucleiTemplate.organization_id == organization_id)
        .all()
    )
    for t in org_templates:
        if cve in {c.upper() for c in (t.cve_ids or [])}:
            return {
                "source": "custom",
                "template_id": t.template_id,
                "status": t.status,
                "message": f"A custom template ({t.template_id}, status={t.status}) already covers {cve} in this organization.",
            }

    # 2) PDCP reports an official Nuclei template exists (authoritative, host-independent).
    if cve_ctx and (cve_ctx.get("is_template") or cve_ctx.get("nuclei_templates")):
        return {
            "source": "official",
            "template_id": cve_ctx.get("filename") or cve.lower(),
            "message": (
                f"An official Nuclei template already exists for {cve}"
                + (f" ({cve_ctx.get('filename')})" if cve_ctx.get("filename") else "")
                + ". Use the community template instead of generating a duplicate."
            ),
        }

    # 3) Local official template catalog on disk (best-effort; path may vary by deploy).
    try:
        from app.services.nuclei_template_parser_service import find_matching_nuclei_template
        match = find_matching_nuclei_template(cve)
        if match:
            return {
                "source": "official_local",
                "template_id": match.id,
                "path": match.template_path,
                "message": f"An official Nuclei template for {cve} is present on disk ({match.template_path}).",
            }
    except Exception as e:
        logger.debug("Local official template lookup failed for %s: %s", cve, e)

    return None


@router.post("/generate")
async def generate_template(
    req: GenerateRequest,
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """
    Generate a Nuclei YAML detection template using the configured LLM.

    Provide either `cve_id` (will fetch PDCP enrichment automatically) or
    `vulnerability_description` with optional `affected_url`, `affected_product`,
    and `detection_evidence` for richer context.

    The generated template is saved as `status=draft` pending analyst review.
    Use POST /{id}/activate to enable it for scanning.
    """
    if not req.cve_id and not req.vulnerability_description:
        raise HTTPException(
            status_code=422,
            detail="Provide either cve_id or vulnerability_description",
        )

    # Fetch CVE context from PDCP for richer generation
    cve_ctx = {}
    if req.cve_id:
        cve_ctx = await _fetch_cve_context(req.cve_id.upper(), db)

    # Pre-flight: don't waste an LLM call generating a template that already exists.
    if req.cve_id and not req.force:
        existing = _find_existing_nuclei_template(
            req.cve_id, req.organization_id, cve_ctx, db
        )
        if existing:
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "template_already_exists",
                    "message": existing["message"],
                    "existing": existing,
                    "hint": "Set force=true to generate a custom/secondary template anyway.",
                },
            )

    # Build prompt and call LLM
    prompt = _build_generation_prompt(req, cve_ctx)
    raw_yaml = await ai.call_llm(ai.NUCLEI_SYSTEM_PROMPT, prompt)
    clean_yaml = ai.extract_yaml_from_response(raw_yaml)
    # Safety net: ensure the finding's specific host never leaks into the template
    clean_yaml = ai.strip_hardcoded_host(clean_yaml, req.affected_url)

    # Extract metadata from the generated YAML
    meta = ai.parse_yaml_metadata(clean_yaml)

    # Determine template_id — use YAML id or generate one
    template_id = meta.get("template_id") or ""
    if not template_id:
        if req.cve_id:
            template_id = req.cve_id.lower().replace("_", "-")
        else:
            template_id = f"custom-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"

    # Ensure uniqueness within org by suffixing
    existing = db.query(CustomNucleiTemplate).filter(
        CustomNucleiTemplate.organization_id == req.organization_id,
        CustomNucleiTemplate.template_id == template_id,
    ).first()
    if existing:
        template_id = f"{template_id}-{datetime.utcnow().strftime('%H%M%S')}"

    # Merge CVE IDs: from YAML + from request
    cve_ids = list({c.upper() for c in (meta.get("cve_ids") or []) + ([req.cve_id.upper()] if req.cve_id else [])})

    ai_model = getattr(settings, "AI_MODEL", None) or (
        "claude-sonnet-4-6" if getattr(settings, "AI_PROVIDER", "openai") == "anthropic" else "gpt-4o"
    )

    t = CustomNucleiTemplate(
        organization_id=req.organization_id,
        template_id=template_id,
        name=cve_ctx.get("name") or template_id,
        description=cve_ctx.get("description") or req.vulnerability_description,
        template_yaml=clean_yaml,
        cve_ids=cve_ids,
        severity=meta.get("severity") or cve_ctx.get("severity"),
        tags=meta.get("tags") or [],
        template_type=meta.get("template_type", "http"),
        source="ai_generated",
        ai_model=ai_model,
        ai_generation_context=prompt[:4000],  # store context for reproducibility
        status="draft",
        created_by_user_id=getattr(user, "id", None),
    )
    db.add(t)
    db.commit()
    db.refresh(t)

    return {
        **_template_response(t),
        "generation_note": (
            "Template saved as draft. Review the YAML carefully before activating — "
            "AI-generated templates should be validated against a known-vulnerable target."
        ),
    }


@router.post("/refine")
async def refine_template_endpoint(
    req: RefineRequest,
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Generate a more accurate template from a confirmed mis-detection.

    Closes the validate → diagnose → refine loop: given the original template and
    the reason it produced a false positive (e.g. from the Aegis Vanguard validator), the
    LLM produces a tightened template saved as a draft. If `recheck` is set and a
    `target` is provided, the refined template is re-run against that known
    false-positive target; if it still fires, the response flags it so the analyst
    does not blindly trust it.
    """
    if not req.template_logic_issue or not req.template_logic_issue.strip():
        raise HTTPException(status_code=422, detail="template_logic_issue is required")
    if not req.original_yaml and not req.template_id:
        raise HTTPException(status_code=422, detail="Provide original_yaml or template_id")

    try:
        t = await ai.refine_template(
            db,
            organization_id=req.organization_id,
            template_logic_issue=req.template_logic_issue,
            original_yaml=req.original_yaml,
            template_id=req.template_id,
            target=req.target,
            evidence=req.evidence,
            reasoning=req.reasoning,
            cve_ids=req.cve_ids,
            created_by_user_id=getattr(user, "id", None),
            example_vulnerability_id=req.vulnerability_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    recheck = None
    if req.recheck and req.target:
        recheck = await ai.recheck_template_against_target(t.template_yaml, req.target)

    note = (
        "Refined template saved as draft. Review the tightened matchers before activating."
    )
    if recheck and recheck.get("ran"):
        if recheck.get("still_fires"):
            note = (
                "WARNING: the refined template STILL fired on the known false-positive "
                "target. Review and tighten further before activating."
            )
        else:
            note = (
                "Refined template no longer fires on the known false-positive target. "
                "Review, then activate to use it in scans."
            )

    return {
        **_template_response(t),
        "recheck": recheck,
        "refinement_note": note,
    }
