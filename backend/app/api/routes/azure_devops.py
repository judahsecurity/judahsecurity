"""Azure DevOps Boards integration routes (/integrations/azure-devops)."""

import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session, joinedload

from app.api.deps import get_current_active_user, require_analyst
from app.api.routes.integrations import _resolve_org_for_vulnerability, _resolve_org_id
from app.db.database import get_db
from app.models.azure_devops_integration import (
    AUTH_METHOD_ENTRA,
    AUTH_METHOD_PAT,
    AzureDevOpsIntegration,
    AzureDevOpsTemplate,
    AzureDevOpsWorkItem,
)
from app.models.user import User
from app.schemas.azure_devops_schemas import (
    AssociateAzureDevOpsWorkItemRequest,
    AzureDevOpsIntegrationCreate,
    AzureDevOpsIntegrationResponse,
    AzureDevOpsIntegrationUpdate,
    AzureDevOpsProjectsResponse,
    AzureDevOpsSyncResult,
    AzureDevOpsTemplateCreate,
    AzureDevOpsTemplateResponse,
    AzureDevOpsTemplateUpdate,
    AzureDevOpsTestConnectionResponse,
    AzureDevOpsWorkItemResponse,
    AzureDevOpsWorkItemTypesResponse,
    CreateAzureDevOpsWorkItemRequest,
)
from app.services import azure_devops_service as ado
from app.services.azure_devops_service import AzureDevOpsClient, AzureDevOpsError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/integrations/azure-devops", tags=["Integrations", "Azure DevOps"])


# ── helpers ──────────────────────────────────────────────────────────────────

def _get_integration(db: Session, org_id: int) -> AzureDevOpsIntegration:
    integration = (
        db.query(AzureDevOpsIntegration)
        .filter(AzureDevOpsIntegration.organization_id == org_id)
        .first()
    )
    if not integration:
        raise HTTPException(status_code=404, detail="Azure DevOps integration not configured for this organization.")
    return integration


def _get_template(db: Session, integration: AzureDevOpsIntegration, template_id: int) -> AzureDevOpsTemplate:
    template = (
        db.query(AzureDevOpsTemplate)
        .filter(AzureDevOpsTemplate.id == template_id, AzureDevOpsTemplate.integration_id == integration.id)
        .first()
    )
    if not template:
        raise HTTPException(status_code=404, detail="Template not found.")
    return template


def _client(integration: AzureDevOpsIntegration) -> AzureDevOpsClient:
    try:
        return AzureDevOpsClient.from_integration(integration)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


def _ado_http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, AzureDevOpsError) and exc.status_code == 404:
        return HTTPException(status_code=404, detail=str(exc))
    return HTTPException(status_code=502, detail=str(exc))


def _validate_credentials(integration: AzureDevOpsIntegration) -> None:
    if integration.auth_method == AUTH_METHOD_PAT:
        if not integration.has_pat:
            raise HTTPException(status_code=400, detail="A Personal Access Token is required.")
    elif integration.auth_method == AUTH_METHOD_ENTRA:
        if not (integration.tenant_id and integration.client_id and integration.has_client_secret):
            raise HTTPException(
                status_code=400,
                detail="Tenant ID, client (application) ID and client secret are required for Entra ID auth.",
            )
    else:
        raise HTTPException(status_code=400, detail="auth_method must be 'pat' or 'entra_id'.")


def _normalize_url_or_400(url: str) -> str:
    try:
        return ado.normalize_organization_url(url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


def _link_for_user(
    db: Session, user: User, link_id: int, org_id_override: Optional[int]
) -> AzureDevOpsWorkItem:
    link = (
        db.query(AzureDevOpsWorkItem)
        .options(joinedload(AzureDevOpsWorkItem.integration))
        .filter(AzureDevOpsWorkItem.id == link_id)
        .first()
    )
    if not link or not link.integration:
        raise HTTPException(status_code=404, detail="Work item link not found.")
    org = link.integration.organization_id
    if org_id_override is not None:
        if _resolve_org_id(user, org_id_override) != org:
            raise HTTPException(status_code=404, detail="Work item link not found.")
    elif not user.is_superuser and user.organization_id != org:
        raise HTTPException(status_code=403, detail="Access denied.")
    return link


def _active_links(db: Session, integration_id: int, vulnerability_id: int) -> List[AzureDevOpsWorkItem]:
    return (
        db.query(AzureDevOpsWorkItem)
        .filter(
            AzureDevOpsWorkItem.integration_id == integration_id,
            AzureDevOpsWorkItem.vulnerability_id == vulnerability_id,
            AzureDevOpsWorkItem.disconnected_at.is_(None),
        )
        .order_by(AzureDevOpsWorkItem.created_at.desc())
        .all()
    )


# ── connection ───────────────────────────────────────────────────────────────

@router.get("", response_model=AzureDevOpsIntegrationResponse)
def get_azure_devops_integration(
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    return _get_integration(db, _resolve_org_id(current_user, org_id))


@router.post("", response_model=AzureDevOpsIntegrationResponse, status_code=status.HTTP_201_CREATED)
async def create_azure_devops_integration(
    payload: AzureDevOpsIntegrationCreate,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    resolved = _resolve_org_id(current_user, org_id)
    if db.query(AzureDevOpsIntegration).filter(AzureDevOpsIntegration.organization_id == resolved).first():
        raise HTTPException(status_code=409, detail="Azure DevOps integration already exists. Use PUT to update.")

    integration = AzureDevOpsIntegration(
        organization_id=resolved,
        organization_url=_normalize_url_or_400(payload.organization_url),
        auth_method=payload.auth_method,
        tenant_id=(payload.tenant_id or "").strip() or None,
        client_id=(payload.client_id or "").strip() or None,
        sync_enabled=payload.sync_enabled,
        remote_closed_states=[s.strip() for s in payload.remote_closed_states if s.strip()],
        accept_close_as=payload.accept_close_as,
        close_state=(payload.close_state or "").strip() or None,
        reopen_state=(payload.reopen_state or "").strip() or None,
        notify_severity_change=payload.notify_severity_change,
        is_active=True,
    )
    integration.set_pat((payload.pat or "").strip() or None)
    integration.set_client_secret((payload.client_secret or "").strip() or None)
    _validate_credentials(integration)

    result = await _client(integration).test_connection()
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result["message"])
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = True

    db.add(integration)
    db.commit()
    db.refresh(integration)
    return integration


@router.put("", response_model=AzureDevOpsIntegrationResponse)
async def update_azure_devops_integration(
    payload: AzureDevOpsIntegrationUpdate,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    integration = _get_integration(db, _resolve_org_id(current_user, org_id))
    data = payload.model_dump(exclude_unset=True)

    pat = (data.pop("pat", None) or "").strip()
    secret = (data.pop("client_secret", None) or "").strip()
    if "organization_url" in data and data["organization_url"]:
        data["organization_url"] = _normalize_url_or_400(data["organization_url"])
    if "remote_closed_states" in data and data["remote_closed_states"] is not None:
        data["remote_closed_states"] = [s.strip() for s in data["remote_closed_states"] if s.strip()]
    for key in ("close_state", "reopen_state", "tenant_id", "client_id"):
        if key in data:
            data[key] = (data[key] or "").strip() or None

    for field, value in data.items():
        if value is None and field in ("organization_url", "auth_method", "sync_enabled",
                                       "accept_close_as", "notify_severity_change", "is_active",
                                       "remote_closed_states"):
            continue
        setattr(integration, field, value)
    if pat:
        integration.set_pat(pat)
    if secret:
        integration.set_client_secret(secret)
    _validate_credentials(integration)

    result = await _client(integration).test_connection()
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]
    if not result["ok"]:
        db.rollback()
        raise HTTPException(status_code=400, detail=result["message"])
    db.commit()
    db.refresh(integration)
    return integration


@router.delete("", status_code=status.HTTP_204_NO_CONTENT)
def delete_azure_devops_integration(
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    integration = _get_integration(db, _resolve_org_id(current_user, org_id))
    db.delete(integration)
    db.commit()


@router.post("/test", response_model=AzureDevOpsTestConnectionResponse)
async def test_azure_devops_connection(
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    integration = _get_integration(db, _resolve_org_id(current_user, org_id))
    result = await _client(integration).test_connection()
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]
    integration.last_error = None if result["ok"] else result["message"][:1000]
    db.commit()
    return AzureDevOpsTestConnectionResponse(**result)


# ── metadata ─────────────────────────────────────────────────────────────────

@router.get("/projects", response_model=AzureDevOpsProjectsResponse)
async def list_azure_devops_projects(
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    integration = _get_integration(db, _resolve_org_id(current_user, org_id))
    try:
        projects = await _client(integration).list_projects()
    except Exception as exc:
        raise _ado_http_error(exc)
    return AzureDevOpsProjectsResponse(projects=projects)


@router.get("/projects/{project}/work-item-types", response_model=AzureDevOpsWorkItemTypesResponse)
async def list_azure_devops_work_item_types(
    project: str,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    integration = _get_integration(db, _resolve_org_id(current_user, org_id))
    try:
        types = await _client(integration).list_work_item_types(project)
    except Exception as exc:
        raise _ado_http_error(exc)
    return AzureDevOpsWorkItemTypesResponse(work_item_types=types)


# ── templates ────────────────────────────────────────────────────────────────

@router.get("/templates", response_model=List[AzureDevOpsTemplateResponse])
def list_azure_devops_templates(
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    integration = _get_integration(db, _resolve_org_id(current_user, org_id))
    return (
        db.query(AzureDevOpsTemplate)
        .filter(AzureDevOpsTemplate.integration_id == integration.id)
        .order_by(AzureDevOpsTemplate.name)
        .all()
    )


@router.post("/templates", response_model=AzureDevOpsTemplateResponse, status_code=status.HTTP_201_CREATED)
def create_azure_devops_template(
    payload: AzureDevOpsTemplateCreate,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    integration = _get_integration(db, _resolve_org_id(current_user, org_id))
    data = payload.model_dump()
    data["extra_tags"] = [t.strip() for t in data.get("extra_tags") or [] if t.strip()]
    template = AzureDevOpsTemplate(integration_id=integration.id, **data)
    db.add(template)
    db.commit()
    db.refresh(template)
    return template


@router.put("/templates/{template_id}", response_model=AzureDevOpsTemplateResponse)
def update_azure_devops_template(
    template_id: int,
    payload: AzureDevOpsTemplateUpdate,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    integration = _get_integration(db, _resolve_org_id(current_user, org_id))
    template = _get_template(db, integration, template_id)
    data = payload.model_dump(exclude_unset=True)
    if "extra_tags" in data and data["extra_tags"] is not None:
        data["extra_tags"] = [t.strip() for t in data["extra_tags"] if t.strip()]
    for field, value in data.items():
        if value is None and field in ("name", "project", "work_item_type", "auto_create_enabled", "is_active"):
            continue
        setattr(template, field, value)
    db.commit()
    db.refresh(template)
    return template


@router.delete("/templates/{template_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_azure_devops_template(
    template_id: int,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    integration = _get_integration(db, _resolve_org_id(current_user, org_id))
    template = _get_template(db, integration, template_id)
    db.query(AzureDevOpsWorkItem).filter(AzureDevOpsWorkItem.template_id == template.id).update(
        {AzureDevOpsWorkItem.template_id: None}, synchronize_session=False
    )
    db.delete(template)
    db.commit()


# ── work items ───────────────────────────────────────────────────────────────

@router.post(
    "/vulnerabilities/{vulnerability_id}/work-item",
    response_model=AzureDevOpsWorkItemResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_azure_devops_work_item(
    vulnerability_id: int,
    payload: CreateAzureDevOpsWorkItemRequest,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    resolved, vuln = _resolve_org_for_vulnerability(db, current_user, vulnerability_id, org_id)
    integration = _get_integration(db, resolved)

    template: Optional[AzureDevOpsTemplate] = None
    if payload.template_id is not None:
        template = _get_template(db, integration, payload.template_id)
        project, wit = template.project, template.work_item_type
    else:
        project, wit = (payload.project or "").strip(), (payload.work_item_type or "").strip()
        if not project or not wit:
            raise HTTPException(status_code=400, detail="Provide template_id, or both project and work_item_type.")

    existing = (
        db.query(AzureDevOpsWorkItem)
        .filter(
            AzureDevOpsWorkItem.integration_id == integration.id,
            AzureDevOpsWorkItem.vulnerability_id == vulnerability_id,
            AzureDevOpsWorkItem.project == project,
            AzureDevOpsWorkItem.disconnected_at.is_(None),
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Work item #{existing.work_item_id} already exists for this finding in project {project}.",
        )

    try:
        return await ado.create_for_vulnerability(db, integration, vuln, project, wit, template)
    except AzureDevOpsError as exc:
        raise _ado_http_error(exc)


@router.post(
    "/vulnerabilities/{vulnerability_id}/associate",
    response_model=AzureDevOpsWorkItemResponse,
    status_code=status.HTTP_201_CREATED,
)
async def associate_azure_devops_work_item(
    vulnerability_id: int,
    payload: AssociateAzureDevOpsWorkItemRequest,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    resolved, vuln = _resolve_org_for_vulnerability(db, current_user, vulnerability_id, org_id)
    integration = _get_integration(db, resolved)

    dup = (
        db.query(AzureDevOpsWorkItem)
        .filter(
            AzureDevOpsWorkItem.integration_id == integration.id,
            AzureDevOpsWorkItem.vulnerability_id == vulnerability_id,
            AzureDevOpsWorkItem.work_item_id == payload.work_item_id,
            AzureDevOpsWorkItem.disconnected_at.is_(None),
        )
        .first()
    )
    if dup:
        raise HTTPException(status_code=409, detail=f"Work item #{payload.work_item_id} is already linked.")

    try:
        info = await _client(integration).get_work_item(payload.work_item_id)
    except AzureDevOpsError as exc:
        raise _ado_http_error(exc)

    link = AzureDevOpsWorkItem(
        integration_id=integration.id,
        vulnerability_id=vuln.id,
        work_item_id=info["id"],
        work_item_url=info["url"],
        project=info.get("project"),
        work_item_type=info.get("work_item_type"),
        state=info.get("state"),
        assigned_to=info.get("assigned_to"),
        last_synced_at=datetime.utcnow(),
        last_notified_severity=ado._vuln_severity(vuln),
        is_associated=True,
    )
    db.add(link)
    db.commit()
    db.refresh(link)
    return link


@router.get(
    "/vulnerabilities/{vulnerability_id}/work-items",
    response_model=List[AzureDevOpsWorkItemResponse],
)
def list_azure_devops_work_items(
    vulnerability_id: int,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    resolved, _vuln = _resolve_org_for_vulnerability(db, current_user, vulnerability_id, org_id)
    integration = _get_integration(db, resolved)
    return _active_links(db, integration.id, vulnerability_id)


@router.post("/work-items/{link_id}/refresh", response_model=AzureDevOpsWorkItemResponse)
async def refresh_azure_devops_work_item(
    link_id: int,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Pull latest state/assignee. Closes the finding if the work item is closed and sync is on."""
    link = _link_for_user(db, current_user, link_id, org_id)
    try:
        await ado.refresh_links(db, link.integration, [link], apply_remote_close=True)
    except AzureDevOpsError as exc:
        raise _ado_http_error(exc)
    db.refresh(link)
    return link


@router.delete("/work-items/{link_id}", status_code=status.HTTP_200_OK)
def disconnect_azure_devops_work_item(
    link_id: int,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Unlink (soft-delete). The work item in Azure DevOps is untouched."""
    link = _link_for_user(db, current_user, link_id, org_id)
    link.disconnected_at = datetime.utcnow()
    db.commit()
    return {"ok": True, "message": f"Work item #{link.work_item_id} disconnected."}


@router.post("/pull", response_model=AzureDevOpsSyncResult)
async def pull_azure_devops_work_items(
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Refresh every linked work item for the org (Azure DevOps → ASM)."""
    integration = _get_integration(db, _resolve_org_id(current_user, org_id))
    result = await ado.pull_integration(db, integration)
    return AzureDevOpsSyncResult(**result)
