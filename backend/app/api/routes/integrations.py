"""Integrations router — Jira, ServiceNow, Censys, HackerOne, Akamai, Panorama, F5,
FortiGate, Check Point, Cloudflare."""

import logging
from datetime import datetime
from typing import List

from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy import or_
from sqlalchemy.orm import Session, joinedload

logger = logging.getLogger(__name__)

from app.api.deps import get_current_active_user, require_analyst
from app.db.database import get_db
from app.models.jira_integration import JiraIntegration, JiraTicket
from app.models.servicenow_integration import ServiceNowDelivery, ServiceNowIntegration
from app.models.censys_integration import CensysAsmIntegration
from app.models.hackerone_integration import HackerOneIntegration, HackerOneReportLink
from app.models.akamai_integration import AkamaiWafIntegration
from app.models.panorama_integration import (
    CONNECTION_MODE_API,
    CONNECTION_MODE_CONFIG_EXPORT,
    PanoramaIntegration,
)
from app.models.f5_integration import F5Integration
from app.models.fortigate_integration import FortiGateIntegration
from app.models.checkpoint_integration import CheckPointIntegration
from app.models.cloudflare_integration import CloudflareWafIntegration
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.models.asset import Asset
from app.schemas.jira_schemas import (
    AssociateJiraTicketRequest,
    CreateJiraTicketRequest,
    JiraIntegrationCreate,
    JiraIntegrationResponse,
    JiraIntegrationUpdate,
    JiraIssueTypesResponse,
    JiraProjectsResponse,
    JiraTestConnectionResponse,
    JiraTicketResponse,
    JiraTransitionsResponse,
    JiraSyncResult,
)
from app.schemas.servicenow_schemas import (
    AssociateServiceNowDeliveryRequest,
    CreateServiceNowDeliveryRequest,
    ServiceNowDeliveryResponse,
    ServiceNowIntegrationCreate,
    ServiceNowIntegrationResponse,
    ServiceNowIntegrationUpdate,
    ServiceNowSyncResult,
    ServiceNowTestConnectionResponse,
)
from app.schemas.censys_schemas import (
    CensysIntegrationCreate,
    CensysIntegrationResponse,
    CensysIntegrationUpdate,
    CensysSyncResult,
    CensysTestConnectionResponse,
)
from app.schemas.hackerone_schemas import (
    AssociateHackerOneReportRequest,
    HackerOneIntegrationCreate,
    HackerOneIntegrationResponse,
    HackerOneIntegrationUpdate,
    HackerOneReportLinkResponse,
    HackerOneSyncResult,
    HackerOneTestConnectionResponse,
)
from app.schemas.akamai_schemas import (
    AkamaiIntegrationCreate,
    AkamaiIntegrationResponse,
    AkamaiIntegrationUpdate,
    AkamaiSyncResult,
    AkamaiTestConnectionResponse,
)
from app.schemas.panorama_schemas import (
    PanoramaIntegrationCreate,
    PanoramaIntegrationResponse,
    PanoramaIntegrationUpdate,
    PanoramaSyncResult,
    PanoramaTestConnectionResponse,
    PanoramaUploadResponse,
)
from app.schemas.f5_schemas import (
    F5IntegrationCreate,
    F5IntegrationResponse,
    F5IntegrationUpdate,
    F5SyncResult,
    F5TestConnectionResponse,
)
from app.schemas.fortigate_schemas import (
    FortiGateIntegrationCreate,
    FortiGateIntegrationResponse,
    FortiGateIntegrationUpdate,
    FortiGateSyncResult,
    FortiGateTestConnectionResponse,
)
from app.schemas.checkpoint_schemas import (
    CheckPointIntegrationCreate,
    CheckPointIntegrationResponse,
    CheckPointIntegrationUpdate,
    CheckPointSyncResult,
    CheckPointTestConnectionResponse,
)
from app.schemas.cloudflare_schemas import (
    CloudflareIntegrationCreate,
    CloudflareIntegrationResponse,
    CloudflareIntegrationUpdate,
    CloudflareSyncResult,
    CloudflareTestConnectionResponse,
)
from app.services import (
    jira_service,
    censys_asm_service,
    hackerone_service,
    akamai_waf_service,
    panorama_service,
    f5_service,
    fortigate_service,
    checkpoint_service,
    cloudflare_waf_service,
    servicenow_service,
)

router = APIRouter(prefix="/integrations", tags=["Integrations"])


def _get_org_id(user: User) -> int:
    if not user.organization_id:
        raise HTTPException(status_code=400, detail="User has no associated organization.")
    return user.organization_id


def _resolve_org_id(user: User, org_id_override: Optional[int] = None) -> int:
    """
    Return the effective org_id for an integration request.

    Admins (is_superuser) may pass an explicit org_id to manage any
    organization's integration.  Regular users always use their own org.
    """
    if org_id_override is not None:
        if not user.is_superuser:
            raise HTTPException(
                status_code=403,
                detail="Admin access required to manage another organization's integrations.",
            )
        return org_id_override
    if not user.organization_id:
        raise HTTPException(
            status_code=400,
            detail=(
                "User has no associated organization. "
                "Pass org_id for the client organization (e.g. Rockwell), "
                "or assign this user to an organization."
            ),
        )
    return user.organization_id


def _resolve_org_for_vulnerability(
    db: Session,
    user: User,
    vulnerability_id: int,
    org_id_override: Optional[int] = None,
) -> tuple[int, Vulnerability]:
    """
    Resolve the org for a vulnerability-scoped Jira action.

    Priority:
      1. Explicit org_id query param (superuser only)
      2. The vulnerability's asset.organization_id (works for admin accounts
         that have no organization_id of their own)
      3. The user's organization_id
    """
    vuln = (
        db.query(Vulnerability)
        .options(joinedload(Vulnerability.asset))
        .filter(Vulnerability.id == vulnerability_id)
        .first()
    )
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found.")

    if org_id_override is not None:
        resolved = _resolve_org_id(user, org_id_override)
    elif vuln.asset and vuln.asset.organization_id:
        resolved = vuln.asset.organization_id
        # Non-superusers may only act on findings in their own org
        if not user.is_superuser and user.organization_id and user.organization_id != resolved:
            raise HTTPException(status_code=403, detail="Access denied.")
    else:
        resolved = _resolve_org_id(user, None)

    if vuln.asset and vuln.asset.organization_id != resolved and not user.is_superuser:
        raise HTTPException(status_code=403, detail="Access denied.")

    return resolved, vuln


def _get_integration(db: Session, org_id: int) -> JiraIntegration:
    integration = (
        db.query(JiraIntegration)
        .filter(JiraIntegration.organization_id == org_id)
        .first()
    )
    if not integration:
        raise HTTPException(status_code=404, detail="Jira integration not configured for this organization.")
    return integration


def _active_tickets_for_vuln(db: Session, integration_id: int, vulnerability_id: int) -> List[JiraTicket]:
    return (
        db.query(JiraTicket)
        .filter(
            JiraTicket.vulnerability_id == vulnerability_id,
            JiraTicket.integration_id == integration_id,
            JiraTicket.disconnected_at.is_(None),
        )
        .order_by(JiraTicket.created_at.desc())
        .all()
    )


# ── Jira configuration ───────────────────────────────────────────────────────

@router.get("/jira", response_model=JiraIntegrationResponse)
def get_jira_integration(
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    resolved = _resolve_org_id(current_user, org_id)
    return _get_integration(db, resolved)


@router.post("/jira", response_model=JiraIntegrationResponse, status_code=status.HTTP_201_CREATED)
async def create_jira_integration(
    payload: JiraIntegrationCreate,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    resolved = _resolve_org_id(current_user, org_id)
    if db.query(JiraIntegration).filter(JiraIntegration.organization_id == resolved).first():
        raise HTTPException(status_code=409, detail="Jira integration already exists. Use PUT to update.")

    result = await jira_service.test_connection(payload.hostname, payload.email, payload.api_token)
    integration = JiraIntegration(
        organization_id=resolved,
        **payload.model_dump(exclude={"api_token"}),
        api_token=payload.api_token,
        is_active=True,
        last_tested_at=datetime.utcnow(),
        last_test_ok=result["ok"],
    )
    db.add(integration)
    db.commit()
    db.refresh(integration)
    return integration


@router.put("/jira", response_model=JiraIntegrationResponse)
async def update_jira_integration(
    payload: JiraIntegrationUpdate,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    resolved = _resolve_org_id(current_user, org_id)
    integration = _get_integration(db, resolved)

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(integration, field, value)

    result = await jira_service.test_connection(integration.hostname, integration.email, integration.api_token)
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]

    db.commit()
    db.refresh(integration)
    return integration


@router.delete("/jira", status_code=status.HTTP_204_NO_CONTENT)
def delete_jira_integration(
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    resolved = _resolve_org_id(current_user, org_id)
    integration = _get_integration(db, resolved)
    db.delete(integration)
    db.commit()


# ── Test connection ──────────────────────────────────────────────────────────

@router.post("/jira/test", response_model=JiraTestConnectionResponse)
async def test_jira_connection(
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    resolved = _resolve_org_id(current_user, org_id)
    integration = _get_integration(db, resolved)
    result = await jira_service.test_connection(integration.hostname, integration.email, integration.api_token)
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]
    db.commit()
    return JiraTestConnectionResponse(**result)


# ── Projects / issue types / transitions ─────────────────────────────────────

@router.get("/jira/projects", response_model=JiraProjectsResponse)
async def list_jira_projects(
    org_id: Optional[int] = Query(None),
    query: Optional[str] = Query(None, description="Filter by project name or key (e.g. ITVM)"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    resolved = _resolve_org_id(current_user, org_id)
    integration = _get_integration(db, resolved)
    try:
        projects = await jira_service.get_projects(
            integration.hostname, integration.email, integration.api_token, query=query
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Jira API error: {exc}")
    return JiraProjectsResponse(projects=projects)


@router.get("/jira/projects/{project_key}/issue-types", response_model=JiraIssueTypesResponse)
async def list_jira_issue_types(
    project_key: str,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    resolved = _resolve_org_id(current_user, org_id)
    integration = _get_integration(db, resolved)
    try:
        issue_types = await jira_service.get_issue_types(
            integration.hostname, integration.email, integration.api_token, project_key
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Jira API error: {exc}")
    return JiraIssueTypesResponse(issue_types=issue_types)


@router.get("/jira/issues/{issue_key}/transitions", response_model=JiraTransitionsResponse)
async def list_jira_transitions(
    issue_key: str,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Return available transitions from the current state of a Jira issue."""
    resolved = _resolve_org_id(current_user, org_id)
    integration = _get_integration(db, resolved)
    try:
        transitions = await jira_service.get_issue_transitions(
            integration.hostname, integration.email, integration.api_token, issue_key
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Jira API error: {exc}")
    return JiraTransitionsResponse(transitions=transitions)


# ── Ticket creation ──────────────────────────────────────────────────────────

@router.post(
    "/jira/vulnerabilities/{vulnerability_id}/ticket",
    response_model=JiraTicketResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_jira_ticket_for_vulnerability(
    vulnerability_id: int,
    payload: CreateJiraTicketRequest,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    resolved, vuln = _resolve_org_for_vulnerability(db, current_user, vulnerability_id, org_id)
    integration = _get_integration(db, resolved)

    existing = (
        db.query(JiraTicket)
        .filter(
            JiraTicket.vulnerability_id == vulnerability_id,
            JiraTicket.integration_id == integration.id,
            JiraTicket.jira_project_key == payload.project_key,
            JiraTicket.disconnected_at.is_(None),
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"A Jira ticket already exists for this vulnerability: {existing.jira_issue_key}",
        )

    try:
        result = await jira_service.create_jira_ticket(
            integration=integration,
            vuln=vuln,
            project_key=payload.project_key,
            issue_type=payload.issue_type,
            include_description=payload.include_description,
            include_evidence=payload.include_evidence,
            include_remediation=payload.include_remediation,
            include_references=payload.include_references,
            include_enrichment=payload.include_enrichment,
            assignee_account_id=payload.assignee_account_id,
            extra_labels=payload.extra_labels,
        )
    except ValueError as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    ticket = JiraTicket(
        integration_id=integration.id,
        vulnerability_id=vulnerability_id,
        jira_issue_key=result["key"],
        jira_issue_url=result["url"],
        jira_project_key=payload.project_key,
        jira_issue_type=payload.issue_type,
    )
    db.add(ticket)
    db.commit()
    db.refresh(ticket)
    return ticket


# ── Associate existing ticket ────────────────────────────────────────────────

@router.post(
    "/jira/vulnerabilities/{vulnerability_id}/associate",
    response_model=JiraTicketResponse,
    status_code=status.HTTP_201_CREATED,
)
async def associate_existing_jira_ticket(
    vulnerability_id: int,
    payload: AssociateJiraTicketRequest,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Link an existing Jira ticket to a vulnerability without creating a new one."""
    resolved, vuln = _resolve_org_for_vulnerability(db, current_user, vulnerability_id, org_id)
    integration = _get_integration(db, resolved)

    # Verify the issue exists in Jira and fetch its current status
    try:
        detail = await jira_service.get_issue_detail(
            integration.hostname, integration.email, integration.api_token, payload.issue_key
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Could not verify Jira issue {payload.issue_key}: {exc}")

    # Derive project key from the issue key (e.g. "SEC-123" → "SEC")
    project_key = payload.project_key or payload.issue_key.rsplit("-", 1)[0]

    ticket = JiraTicket(
        integration_id=integration.id,
        vulnerability_id=vulnerability_id,
        jira_issue_key=payload.issue_key,
        jira_issue_url=jira_service._issue_url(integration.hostname, payload.issue_key),
        jira_project_key=project_key,
        jira_status=detail.get("status"),
        jira_assignee=detail.get("assignee"),
        is_associated=True,
    )
    db.add(ticket)
    db.commit()
    db.refresh(ticket)
    return ticket


# ── List tickets ─────────────────────────────────────────────────────────────

@router.get(
    "/jira/vulnerabilities/{vulnerability_id}/tickets",
    response_model=List[JiraTicketResponse],
)
def list_jira_tickets_for_vulnerability(
    vulnerability_id: int,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    resolved, _vuln = _resolve_org_for_vulnerability(db, current_user, vulnerability_id, org_id)
    integration = _get_integration(db, resolved)
    return _active_tickets_for_vuln(db, integration.id, vulnerability_id)


# ── Disconnect a ticket ──────────────────────────────────────────────────────

def _ticket_and_integration_for_user(
    db: Session,
    user: User,
    ticket_id: int,
    org_id_override: Optional[int] = None,
) -> tuple[JiraTicket, JiraIntegration]:
    """Load a ticket and verify the caller can access its integration's org."""
    ticket = (
        db.query(JiraTicket)
        .options(joinedload(JiraTicket.integration))
        .filter(JiraTicket.id == ticket_id)
        .first()
    )
    if not ticket or not ticket.integration:
        raise HTTPException(status_code=404, detail="Ticket not found.")

    integration = ticket.integration
    if org_id_override is not None:
        resolved = _resolve_org_id(user, org_id_override)
        if integration.organization_id != resolved:
            raise HTTPException(status_code=404, detail="Ticket not found.")
    elif not user.is_superuser:
        if not user.organization_id or user.organization_id != integration.organization_id:
            raise HTTPException(status_code=403, detail="Access denied.")
    # Superusers without org_id may act on any ticket via the ticket's own org

    return ticket, integration


@router.delete("/jira/tickets/{ticket_id}", status_code=status.HTTP_200_OK)
def disconnect_jira_ticket(
    ticket_id: int,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Unlink a Jira ticket from the vulnerability.
    The ticket is soft-deleted (disconnected_at set); the Jira issue is untouched.
    """
    ticket, _integration = _ticket_and_integration_for_user(db, current_user, ticket_id, org_id)
    ticket.disconnected_at = datetime.utcnow()
    db.commit()
    return {"ok": True, "message": f"Ticket {ticket.jira_issue_key} disconnected."}


# ── Refresh ticket status from Jira ─────────────────────────────────────────

@router.post("/jira/tickets/{ticket_id}/refresh", response_model=JiraTicketResponse)
async def refresh_jira_ticket_status(
    ticket_id: int,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Pull the latest status and assignee from Jira and update our record."""
    ticket, integration = _ticket_and_integration_for_user(db, current_user, ticket_id, org_id)

    try:
        detail = await jira_service.get_issue_detail(
            integration.hostname, integration.email, integration.api_token, ticket.jira_issue_key
        )
        ticket.jira_status = detail.get("status")
        ticket.jira_assignee = detail.get("assignee")
        db.commit()
        db.refresh(ticket)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Jira API error: {exc}")

    return ticket


# ── Manual status sync ───────────────────────────────────────────────────────

@router.post(
    "/jira/vulnerabilities/{vulnerability_id}/sync",
    response_model=JiraSyncResult,
)
async def manually_sync_vulnerability_status(
    vulnerability_id: int,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Manually trigger a Jira ticket status sync for the current vulnerability status."""
    resolved, vuln = _resolve_org_for_vulnerability(db, current_user, vulnerability_id, org_id)
    integration = _get_integration(db, resolved)

    tickets = _active_tickets_for_vuln(db, integration.id, vulnerability_id)
    if not tickets:
        raise HTTPException(status_code=404, detail="No active Jira tickets linked to this vulnerability.")

    ticket = tickets[0]
    new_status = vuln.status.value if vuln.status else "open"
    result = await jira_service.sync_ticket_for_status_change(
        integration=integration,
        ticket=ticket,
        old_status="open",  # treat as transition from open when manually triggered
        new_status=new_status,
        changed_by=current_user.email or current_user.username or "unknown",
    )

    if result.get("transitions_executed") or result.get("comment_added"):
        ticket.jira_status = new_status
        db.commit()

    return JiraSyncResult(**result)


# ══════════════════════════════════════════════════════════════════════════════
# Censys ASM integration — read-only import of risks & assets from a workspace
# ══════════════════════════════════════════════════════════════════════════════


def _get_censys_integration(db: Session, org_id: int, integration_id: int) -> CensysAsmIntegration:
    integration = (
        db.query(CensysAsmIntegration)
        .filter(
            CensysAsmIntegration.id == integration_id,
            CensysAsmIntegration.organization_id == org_id,
        )
        .first()
    )
    if not integration:
        raise HTTPException(status_code=404, detail="Censys ASM connection not found.")
    return integration


@router.get("/censys", response_model=List[CensysIntegrationResponse])
def list_censys_integrations(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    org_id = _get_org_id(current_user)
    return (
        db.query(CensysAsmIntegration)
        .filter(CensysAsmIntegration.organization_id == org_id)
        .order_by(CensysAsmIntegration.created_at.desc())
        .all()
    )


@router.post("/censys", response_model=CensysIntegrationResponse, status_code=status.HTTP_201_CREATED)
async def create_censys_integration(
    payload: CensysIntegrationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)

    existing = (
        db.query(CensysAsmIntegration)
        .filter(
            CensysAsmIntegration.organization_id == org_id,
            CensysAsmIntegration.workspace_name == payload.workspace_name,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"A Censys ASM connection named '{payload.workspace_name}' already exists.",
        )

    result = await censys_asm_service.test_connection(payload.api_key)

    integration = CensysAsmIntegration(
        organization_id=org_id,
        workspace_name=payload.workspace_name,
        import_vulnerabilities=payload.import_vulnerabilities,
        import_assets=payload.import_assets,
        continuous_sync_enabled=payload.continuous_sync_enabled,
        sync_interval_minutes=payload.sync_interval_minutes,
        is_active=True,
        last_tested_at=datetime.utcnow(),
        last_test_ok=result["ok"],
    )
    integration.set_api_key(payload.api_key)
    db.add(integration)
    db.commit()
    db.refresh(integration)
    return integration


@router.put("/censys/{integration_id}", response_model=CensysIntegrationResponse)
async def update_censys_integration(
    integration_id: int,
    payload: CensysIntegrationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)
    integration = _get_censys_integration(db, org_id, integration_id)

    data = payload.model_dump(exclude_unset=True)
    new_key = data.pop("api_key", None)
    for field, value in data.items():
        setattr(integration, field, value)
    if new_key:
        integration.set_api_key(new_key)

    # Re-validate whenever the key changes (or on any edit for freshness).
    result = await censys_asm_service.test_connection(integration.get_api_key())
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]

    db.commit()
    db.refresh(integration)
    return integration


@router.delete("/censys/{integration_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_censys_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)
    integration = _get_censys_integration(db, org_id, integration_id)
    db.delete(integration)
    db.commit()


@router.post("/censys/{integration_id}/test", response_model=CensysTestConnectionResponse)
async def test_censys_connection(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    org_id = _get_org_id(current_user)
    integration = _get_censys_integration(db, org_id, integration_id)
    result = await censys_asm_service.test_connection(integration.get_api_key())
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]
    db.commit()
    return CensysTestConnectionResponse(**result)


@router.post("/censys/{integration_id}/sync", response_model=CensysSyncResult)
async def sync_censys_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Pull the latest risks and/or assets from Censys ASM and import them."""
    org_id = _get_org_id(current_user)
    integration = _get_censys_integration(db, org_id, integration_id)
    if not integration.is_active:
        raise HTTPException(status_code=400, detail="This Censys ASM connection is disabled.")

    result = await censys_asm_service.sync_integration(db, integration)
    return CensysSyncResult(**result)


# ══════════════════════════════════════════════════════════════════════════════
# HackerOne — read-only import of bug bounty reports & program scopes
# ══════════════════════════════════════════════════════════════════════════════


def _get_hackerone_integration(
    db: Session, org_id: int, integration_id: int
) -> HackerOneIntegration:
    integration = (
        db.query(HackerOneIntegration)
        .filter(
            HackerOneIntegration.id == integration_id,
            HackerOneIntegration.organization_id == org_id,
        )
        .first()
    )
    if not integration:
        raise HTTPException(status_code=404, detail="HackerOne connection not found.")
    return integration


@router.get("/hackerone", response_model=List[HackerOneIntegrationResponse])
def list_hackerone_integrations(
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    if org_id is not None:
        if current_user.is_superuser:
            resolved = org_id
        elif current_user.organization_id == org_id:
            resolved = org_id
        else:
            raise HTTPException(status_code=403, detail="Access denied.")
    else:
        resolved = _get_org_id(current_user)
    return (
        db.query(HackerOneIntegration)
        .filter(HackerOneIntegration.organization_id == resolved)
        .order_by(HackerOneIntegration.created_at.desc())
        .all()
    )


@router.post(
    "/hackerone",
    response_model=HackerOneIntegrationResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_hackerone_integration(
    payload: HackerOneIntegrationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)

    existing = (
        db.query(HackerOneIntegration)
        .filter(
            HackerOneIntegration.organization_id == org_id,
            HackerOneIntegration.connection_name == payload.connection_name,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"A HackerOne connection named '{payload.connection_name}' already exists.",
        )

    result = await hackerone_service.test_connection(
        payload.api_identifier, payload.api_token
    )
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result["message"])

    integration = HackerOneIntegration(
        organization_id=org_id,
        connection_name=payload.connection_name,
        api_identifier=payload.api_identifier.strip(),
        import_vulnerabilities=payload.import_vulnerabilities,
        import_scopes=payload.import_scopes,
        continuous_sync_enabled=payload.continuous_sync_enabled,
        sync_interval_minutes=payload.sync_interval_minutes,
        is_active=True,
        last_tested_at=datetime.utcnow(),
        last_test_ok=True,
    )
    integration.set_api_token(payload.api_token)
    db.add(integration)
    db.commit()
    db.refresh(integration)
    return integration


@router.put("/hackerone/{integration_id}", response_model=HackerOneIntegrationResponse)
async def update_hackerone_integration(
    integration_id: int,
    payload: HackerOneIntegrationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)
    integration = _get_hackerone_integration(db, org_id, integration_id)

    data = payload.model_dump(exclude_unset=True)
    new_token = data.pop("api_token", None)
    for field, value in data.items():
        setattr(integration, field, value)
    if new_token:
        integration.set_api_token(new_token)

    result = await hackerone_service.test_connection(
        integration.api_identifier, integration.get_api_token()
    )
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]

    db.commit()
    db.refresh(integration)
    return integration


@router.delete("/hackerone/{integration_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_hackerone_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)
    integration = _get_hackerone_integration(db, org_id, integration_id)
    db.delete(integration)
    db.commit()


@router.post(
    "/hackerone/{integration_id}/test",
    response_model=HackerOneTestConnectionResponse,
)
async def test_hackerone_connection(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    org_id = _get_org_id(current_user)
    integration = _get_hackerone_integration(db, org_id, integration_id)
    result = await hackerone_service.test_connection(
        integration.api_identifier, integration.get_api_token()
    )
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]
    db.commit()
    return HackerOneTestConnectionResponse(**result)


@router.post("/hackerone/{integration_id}/sync", response_model=HackerOneSyncResult)
async def sync_hackerone_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Pull the latest reports and/or scopes from HackerOne and import them."""
    org_id = _get_org_id(current_user)
    integration = _get_hackerone_integration(db, org_id, integration_id)
    if not integration.is_active:
        raise HTTPException(status_code=400, detail="This HackerOne connection is disabled.")

    result = await hackerone_service.sync_integration(db, integration)
    return HackerOneSyncResult(**result)


def _get_active_hackerone_integration(
    db: Session,
    org_id: int,
    integration_id: Optional[int] = None,
) -> HackerOneIntegration:
    """Resolve an active HackerOne connection for the org (optional explicit id)."""
    query = db.query(HackerOneIntegration).filter(
        HackerOneIntegration.organization_id == org_id,
        HackerOneIntegration.is_active == True,  # noqa: E712
    )
    if integration_id is not None:
        query = query.filter(HackerOneIntegration.id == integration_id)
    integration = query.order_by(HackerOneIntegration.created_at.desc()).first()
    if not integration:
        raise HTTPException(
            status_code=404,
            detail="No active HackerOne connection found. Configure one on the Integrations page.",
        )
    return integration


def _active_h1_links_for_vuln(
    db: Session, organization_id: int, vulnerability_id: int
) -> List[HackerOneReportLink]:
    return (
        db.query(HackerOneReportLink)
        .join(HackerOneIntegration)
        .filter(
            HackerOneReportLink.vulnerability_id == vulnerability_id,
            HackerOneReportLink.disconnected_at.is_(None),
            HackerOneIntegration.organization_id == organization_id,
        )
        .order_by(HackerOneReportLink.created_at.desc())
        .all()
    )


def _h1_link_and_integration_for_user(
    db: Session,
    user: User,
    link_id: int,
    org_id_override: Optional[int] = None,
) -> tuple:
    link = (
        db.query(HackerOneReportLink)
        .options(joinedload(HackerOneReportLink.integration))
        .filter(HackerOneReportLink.id == link_id)
        .first()
    )
    if not link or not link.integration:
        raise HTTPException(status_code=404, detail="HackerOne report link not found.")

    integration = link.integration
    if org_id_override is not None:
        resolved = _resolve_org_id(user, org_id_override)
        if integration.organization_id != resolved:
            raise HTTPException(status_code=404, detail="HackerOne report link not found.")
    elif not user.is_superuser:
        if not user.organization_id or user.organization_id != integration.organization_id:
            raise HTTPException(status_code=403, detail="Access denied.")
    return link, integration


@router.post(
    "/hackerone/vulnerabilities/{vulnerability_id}/associate",
    response_model=HackerOneReportLinkResponse,
    status_code=status.HTTP_201_CREATED,
)
async def associate_hackerone_report(
    vulnerability_id: int,
    payload: AssociateHackerOneReportRequest,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Link an existing HackerOne report to a finding (read-only; does not modify H1)."""
    resolved, vuln = _resolve_org_for_vulnerability(db, current_user, vulnerability_id, org_id)
    integration = _get_active_hackerone_integration(db, resolved, payload.integration_id)

    report_id = hackerone_service.parse_report_id(payload.report_id_or_url)
    if not report_id:
        raise HTTPException(
            status_code=400,
            detail="Could not parse a HackerOne report ID. Use a numeric ID or https://hackerone.com/reports/{id}.",
        )

    # Verify the report exists via the HackerOne API
    client = hackerone_service.HackerOneClient(
        integration.api_identifier, integration.get_api_token()
    )
    fetched = await client.get_report(report_id)
    if not fetched:
        raise HTTPException(
            status_code=502,
            detail=f"Could not verify HackerOne report {report_id}. Check the ID and API token permissions.",
        )
    report, included = fetched
    summary = hackerone_service.summarize_report(report, included)

    # Reject duplicate active link for this vuln+report
    existing = (
        db.query(HackerOneReportLink)
        .filter(
            HackerOneReportLink.vulnerability_id == vulnerability_id,
            HackerOneReportLink.hackerone_report_id == report_id,
            HackerOneReportLink.disconnected_at.is_(None),
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Report {report_id} is already linked to this finding.",
        )

    link = hackerone_service.upsert_report_link(
        db,
        integration,
        vulnerability_id,
        report_id=report_id,
        report_url=summary.get("report_url"),
        program=summary.get("program"),
        title=summary.get("title"),
        state=summary.get("state"),
        severity=summary.get("severity"),
        reporter=summary.get("reporter"),
        is_associated=True,
    )

    # Mirror into vulnerability metadata + references for visibility elsewhere
    meta = dict(vuln.metadata_ or {})
    meta.update(
        {
            "hackerone_report_id": report_id,
            "hackerone_report_url": summary.get("report_url"),
            "hackerone_state": summary.get("state"),
            "hackerone_program": summary.get("program"),
            "hackerone_reporter": summary.get("reporter"),
            "source": meta.get("source") or "hackerone",
        }
    )
    vuln.metadata_ = meta
    report_url = summary.get("report_url")
    if report_url:
        refs = list(vuln.references or [])
        if report_url not in refs:
            refs.append(report_url)
            vuln.references = refs

    # Optionally align finding status with HackerOne state
    if summary.get("state"):
        mapped = hackerone_service._map_status(summary["state"])
        vuln.status = mapped
        if mapped.value == "resolved" and not vuln.resolved_at:
            vuln.resolved_at = datetime.utcnow()

    db.commit()
    db.refresh(link)
    return link


@router.get(
    "/hackerone/vulnerabilities/{vulnerability_id}/reports",
    response_model=List[HackerOneReportLinkResponse],
)
def list_hackerone_reports_for_vulnerability(
    vulnerability_id: int,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    resolved, _vuln = _resolve_org_for_vulnerability(db, current_user, vulnerability_id, org_id)
    return _active_h1_links_for_vuln(db, resolved, vulnerability_id)


@router.delete("/hackerone/reports/{link_id}", status_code=status.HTTP_200_OK)
def disconnect_hackerone_report(
    link_id: int,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Unlink a HackerOne report from the finding (does not modify HackerOne)."""
    link, _integration = _h1_link_and_integration_for_user(db, current_user, link_id, org_id)
    if link.disconnected_at:
        return {"ok": True, "message": "Report link already disconnected."}
    link.disconnected_at = datetime.utcnow()
    db.commit()
    return {"ok": True, "message": f"Disconnected HackerOne report {link.hackerone_report_id}."}


@router.post(
    "/hackerone/reports/{link_id}/refresh",
    response_model=HackerOneReportLinkResponse,
)
async def refresh_hackerone_report(
    link_id: int,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Refresh report state/severity from HackerOne and update the linked finding status."""
    link, integration = _h1_link_and_integration_for_user(db, current_user, link_id, org_id)
    if link.disconnected_at:
        raise HTTPException(status_code=400, detail="This report link is disconnected.")

    client = hackerone_service.HackerOneClient(
        integration.api_identifier, integration.get_api_token()
    )
    fetched = await client.get_report(link.hackerone_report_id)
    if not fetched:
        raise HTTPException(
            status_code=502,
            detail=f"Could not refresh HackerOne report {link.hackerone_report_id}.",
        )
    report, included = fetched
    summary = hackerone_service.summarize_report(report, included)

    link.hackerone_state = summary.get("state")
    link.hackerone_severity = summary.get("severity")
    link.hackerone_reporter = summary.get("reporter") or link.hackerone_reporter
    link.hackerone_program = summary.get("program") or link.hackerone_program
    link.hackerone_title = summary.get("title") or link.hackerone_title
    link.hackerone_report_url = summary.get("report_url") or link.hackerone_report_url
    link.updated_at = datetime.utcnow()

    vuln = (
        db.query(Vulnerability)
        .filter(Vulnerability.id == link.vulnerability_id)
        .first()
    )
    if vuln and summary.get("state"):
        mapped = hackerone_service._map_status(summary["state"])
        vuln.status = mapped
        if mapped.value == "resolved" and not vuln.resolved_at:
            vuln.resolved_at = datetime.utcnow()
        meta = dict(vuln.metadata_ or {})
        meta["hackerone_state"] = summary.get("state")
        meta["hackerone_report_id"] = link.hackerone_report_id
        meta["hackerone_report_url"] = link.hackerone_report_url
        vuln.metadata_ = meta

    db.commit()
    db.refresh(link)
    return link


# ══════════════════════════════════════════════════════════════════════════════
# Palo Alto Panorama — read-only import of firewall address objects as assets
# ══════════════════════════════════════════════════════════════════════════════


def _get_panorama_integration(db: Session, org_id: int, integration_id: int) -> PanoramaIntegration:
    integration = (
        db.query(PanoramaIntegration)
        .filter(
            PanoramaIntegration.id == integration_id,
            PanoramaIntegration.organization_id == org_id,
        )
        .first()
    )
    if not integration:
        raise HTTPException(status_code=404, detail="Panorama connection not found.")
    return integration


@router.get("/panorama", response_model=List[PanoramaIntegrationResponse])
def list_panorama_integrations(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    org_id = _get_org_id(current_user)
    return (
        db.query(PanoramaIntegration)
        .filter(PanoramaIntegration.organization_id == org_id)
        .order_by(PanoramaIntegration.created_at.desc())
        .all()
    )


@router.post("/panorama", response_model=PanoramaIntegrationResponse, status_code=status.HTTP_201_CREATED)
async def create_panorama_integration(
    payload: PanoramaIntegrationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)

    existing = (
        db.query(PanoramaIntegration)
        .filter(
            PanoramaIntegration.organization_id == org_id,
            PanoramaIntegration.name == payload.name,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"A Panorama connection named '{payload.name}' already exists.",
        )

    mode = payload.connection_mode or CONNECTION_MODE_API
    last_test_ok = None
    last_tested_at = None

    if mode == CONNECTION_MODE_API:
        result = await panorama_service.test_connection(
            payload.panorama_host or "",
            payload.api_key or "",
            api_version=payload.api_version,
            device_group=payload.device_group,
            verify_ssl=payload.verify_ssl,
        )
        if not result["ok"]:
            raise HTTPException(status_code=400, detail=result["message"])
        last_test_ok = True
        last_tested_at = datetime.utcnow()

    integration = PanoramaIntegration(
        organization_id=org_id,
        name=payload.name,
        connection_mode=mode,
        panorama_host=payload.panorama_host,
        device_group=payload.device_group,
        api_version=payload.api_version,
        verify_ssl=payload.verify_ssl,
        continuous_sync_enabled=payload.continuous_sync_enabled,
        sync_interval_minutes=payload.sync_interval_minutes,
        is_active=True,
        last_tested_at=last_tested_at,
        last_test_ok=last_test_ok,
    )
    if payload.api_key:
        integration.set_api_key(payload.api_key)
    db.add(integration)
    db.commit()
    db.refresh(integration)
    return integration


@router.put("/panorama/{integration_id}", response_model=PanoramaIntegrationResponse)
async def update_panorama_integration(
    integration_id: int,
    payload: PanoramaIntegrationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)
    integration = _get_panorama_integration(db, org_id, integration_id)

    data = payload.model_dump(exclude_unset=True)
    new_key = data.pop("api_key", None)

    # Allow clearing device_group by sending empty string / null.
    if "device_group" in data:
        dg = data["device_group"]
        data["device_group"] = dg.strip() if isinstance(dg, str) and dg.strip() else None

    for field, value in data.items():
        setattr(integration, field, value)
    if new_key:
        integration.set_api_key(new_key)

    mode = integration.connection_mode or CONNECTION_MODE_API
    if mode == CONNECTION_MODE_CONFIG_EXPORT:
        result = panorama_service.test_config_export(integration)
    else:
        result = await panorama_service.test_connection(
            integration.panorama_host or "",
            integration.get_api_key() or "",
            api_version=integration.api_version or "v11.1",
            device_group=integration.device_group,
            verify_ssl=bool(integration.verify_ssl),
        )
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]

    db.commit()
    db.refresh(integration)
    return integration


@router.delete("/panorama/{integration_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_panorama_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)
    integration = _get_panorama_integration(db, org_id, integration_id)
    # Best-effort cleanup of stored export files.
    if integration.export_file_path:
        try:
            from pathlib import Path

            path = Path(integration.export_file_path)
            if path.is_file():
                path.unlink()
            parent = path.parent
            if parent.is_dir() and not any(parent.iterdir()):
                parent.rmdir()
        except OSError:
            pass
    db.delete(integration)
    db.commit()


@router.post("/panorama/{integration_id}/test", response_model=PanoramaTestConnectionResponse)
async def test_panorama_connection(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    org_id = _get_org_id(current_user)
    integration = _get_panorama_integration(db, org_id, integration_id)
    if (integration.connection_mode or CONNECTION_MODE_API) == CONNECTION_MODE_CONFIG_EXPORT:
        result = panorama_service.test_config_export(integration)
    else:
        result = await panorama_service.test_connection(
            integration.panorama_host or "",
            integration.get_api_key() or "",
            api_version=integration.api_version or "v11.1",
            device_group=integration.device_group,
            verify_ssl=bool(integration.verify_ssl),
        )
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]
    db.commit()
    return PanoramaTestConnectionResponse(**result)


@router.post("/panorama/{integration_id}/upload", response_model=PanoramaUploadResponse)
async def upload_panorama_config_export(
    integration_id: int,
    file: UploadFile = File(...),
    sync: bool = Query(True, description="Import address objects immediately after upload."),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Upload a Panorama configuration export (.gz / .tgz / .xml) for air-gapped sync."""
    org_id = _get_org_id(current_user)
    integration = _get_panorama_integration(db, org_id, integration_id)

    raw = await file.read()
    try:
        stored = panorama_service.store_export_file(
            integration,
            filename=file.filename or "panorama-config-export.gz",
            data=raw,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    db.commit()
    db.refresh(integration)

    sync_result = None
    if sync:
        if not integration.is_active:
            raise HTTPException(status_code=400, detail="This Panorama connection is disabled.")
        sync_result = PanoramaSyncResult(**(await panorama_service.sync_integration(db, integration)))

    return PanoramaUploadResponse(
        ok=True,
        message=stored["message"],
        filename=stored.get("filename"),
        file_size=stored.get("file_size"),
        address_count=stored.get("address_count"),
        address_groups_count=stored.get("address_groups_count"),
        sync=sync_result,
    )


@router.post("/panorama/{integration_id}/sync", response_model=PanoramaSyncResult)
async def sync_panorama_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Import address objects from Panorama REST or a stored configuration export."""
    org_id = _get_org_id(current_user)
    integration = _get_panorama_integration(db, org_id, integration_id)
    if not integration.is_active:
        raise HTTPException(status_code=400, detail="This Panorama connection is disabled.")

    result = await panorama_service.sync_integration(db, integration)
    return PanoramaSyncResult(**result)


# ══════════════════════════════════════════════════════════════════════════════
# F5 BIG-IP — read-only VIP → pool-member reachability import
# ══════════════════════════════════════════════════════════════════════════════


def _get_f5_integration(db: Session, org_id: int, integration_id: int) -> F5Integration:
    integration = (
        db.query(F5Integration)
        .filter(
            F5Integration.id == integration_id,
            F5Integration.organization_id == org_id,
        )
        .first()
    )
    if not integration:
        raise HTTPException(status_code=404, detail="F5 connection not found.")
    return integration


@router.get("/f5", response_model=List[F5IntegrationResponse])
def list_f5_integrations(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    org_id = _get_org_id(current_user)
    return (
        db.query(F5Integration)
        .filter(F5Integration.organization_id == org_id)
        .order_by(F5Integration.created_at.desc())
        .all()
    )


@router.post("/f5", response_model=F5IntegrationResponse, status_code=status.HTTP_201_CREATED)
async def create_f5_integration(
    payload: F5IntegrationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)

    existing = (
        db.query(F5Integration)
        .filter(
            F5Integration.organization_id == org_id,
            F5Integration.name == payload.name,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"An F5 connection named '{payload.name}' already exists.",
        )

    result = await f5_service.test_connection(
        payload.bigip_host,
        payload.username,
        payload.password,
        partition=payload.partition,
        verify_ssl=payload.verify_ssl,
    )
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result["message"])

    integration = F5Integration(
        organization_id=org_id,
        name=payload.name,
        bigip_host=payload.bigip_host,
        partition=payload.partition,
        verify_ssl=payload.verify_ssl,
        continuous_sync_enabled=payload.continuous_sync_enabled,
        sync_interval_minutes=payload.sync_interval_minutes,
        is_active=True,
        last_tested_at=datetime.utcnow(),
        last_test_ok=True,
    )
    integration.set_username(payload.username)
    integration.set_password(payload.password)
    db.add(integration)
    db.commit()
    db.refresh(integration)
    return integration


@router.put("/f5/{integration_id}", response_model=F5IntegrationResponse)
async def update_f5_integration(
    integration_id: int,
    payload: F5IntegrationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)
    integration = _get_f5_integration(db, org_id, integration_id)

    data = payload.model_dump(exclude_unset=True)
    new_username = data.pop("username", None)
    new_password = data.pop("password", None)

    if "partition" in data:
        part = data["partition"]
        data["partition"] = part.strip() if isinstance(part, str) and part.strip() else None

    for field, value in data.items():
        setattr(integration, field, value)
    if new_username:
        integration.set_username(new_username)
    if new_password:
        integration.set_password(new_password)

    result = await f5_service.test_connection(
        integration.bigip_host or "",
        integration.get_username() or "",
        integration.get_password() or "",
        partition=integration.partition,
        verify_ssl=bool(integration.verify_ssl),
    )
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]

    db.commit()
    db.refresh(integration)
    return integration


@router.delete("/f5/{integration_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_f5_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)
    integration = _get_f5_integration(db, org_id, integration_id)
    db.delete(integration)
    db.commit()


@router.post("/f5/{integration_id}/test", response_model=F5TestConnectionResponse)
async def test_f5_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)
    integration = _get_f5_integration(db, org_id, integration_id)
    result = await f5_service.test_connection(
        integration.bigip_host or "",
        integration.get_username() or "",
        integration.get_password() or "",
        partition=integration.partition,
        verify_ssl=bool(integration.verify_ssl),
    )
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]
    if not result["ok"]:
        integration.last_error = result["message"]
    else:
        integration.last_error = None
    db.commit()
    return F5TestConnectionResponse(**result)


@router.post("/f5/{integration_id}/sync", response_model=F5SyncResult)
async def sync_f5_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Import VIP → pool-member reachability mappings from F5 BIG-IP."""
    org_id = _get_org_id(current_user)
    integration = _get_f5_integration(db, org_id, integration_id)
    if not integration.is_active:
        raise HTTPException(status_code=400, detail="This F5 connection is disabled.")

    result = await f5_service.sync_integration(db, integration)
    return F5SyncResult(**result)


# ══════════════════════════════════════════════════════════════════════════════
# Fortinet FortiGate — read-only firewall address-object inventory import
# ══════════════════════════════════════════════════════════════════════════════


def _get_fortigate_integration(db: Session, org_id: int, integration_id: int) -> FortiGateIntegration:
    integration = (
        db.query(FortiGateIntegration)
        .filter(
            FortiGateIntegration.id == integration_id,
            FortiGateIntegration.organization_id == org_id,
        )
        .first()
    )
    if not integration:
        raise HTTPException(status_code=404, detail="FortiGate connection not found.")
    return integration


@router.get("/fortigate", response_model=List[FortiGateIntegrationResponse])
def list_fortigate_integrations(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    org_id = _get_org_id(current_user)
    return (
        db.query(FortiGateIntegration)
        .filter(FortiGateIntegration.organization_id == org_id)
        .order_by(FortiGateIntegration.created_at.desc())
        .all()
    )


@router.post("/fortigate", response_model=FortiGateIntegrationResponse, status_code=status.HTTP_201_CREATED)
async def create_fortigate_integration(
    payload: FortiGateIntegrationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)

    existing = (
        db.query(FortiGateIntegration)
        .filter(
            FortiGateIntegration.organization_id == org_id,
            FortiGateIntegration.name == payload.name,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"A FortiGate connection named '{payload.name}' already exists.",
        )

    result = await fortigate_service.test_connection(
        payload.fortigate_host,
        payload.api_token,
        vdom=payload.vdom,
        verify_ssl=payload.verify_ssl,
    )
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result["message"])

    integration = FortiGateIntegration(
        organization_id=org_id,
        name=payload.name,
        fortigate_host=payload.fortigate_host,
        vdom=payload.vdom,
        verify_ssl=payload.verify_ssl,
        continuous_sync_enabled=payload.continuous_sync_enabled,
        sync_interval_minutes=payload.sync_interval_minutes,
        is_active=True,
        last_tested_at=datetime.utcnow(),
        last_test_ok=True,
    )
    integration.set_api_token(payload.api_token)
    db.add(integration)
    db.commit()
    db.refresh(integration)
    return integration


@router.put("/fortigate/{integration_id}", response_model=FortiGateIntegrationResponse)
async def update_fortigate_integration(
    integration_id: int,
    payload: FortiGateIntegrationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)
    integration = _get_fortigate_integration(db, org_id, integration_id)

    data = payload.model_dump(exclude_unset=True)
    new_token = data.pop("api_token", None)

    if "vdom" in data:
        vdom = data["vdom"]
        data["vdom"] = vdom.strip() if isinstance(vdom, str) and vdom.strip() else None

    for field, value in data.items():
        setattr(integration, field, value)
    if new_token:
        integration.set_api_token(new_token)

    result = await fortigate_service.test_connection(
        integration.fortigate_host or "",
        integration.get_api_token() or "",
        vdom=integration.vdom,
        verify_ssl=bool(integration.verify_ssl),
    )
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]

    db.commit()
    db.refresh(integration)
    return integration


@router.delete("/fortigate/{integration_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_fortigate_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)
    integration = _get_fortigate_integration(db, org_id, integration_id)
    db.delete(integration)
    db.commit()


@router.post("/fortigate/{integration_id}/test", response_model=FortiGateTestConnectionResponse)
async def test_fortigate_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)
    integration = _get_fortigate_integration(db, org_id, integration_id)
    result = await fortigate_service.test_connection(
        integration.fortigate_host or "",
        integration.get_api_token() or "",
        vdom=integration.vdom,
        verify_ssl=bool(integration.verify_ssl),
    )
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]
    integration.last_error = None if result["ok"] else result["message"]
    db.commit()
    return FortiGateTestConnectionResponse(**result)


@router.post("/fortigate/{integration_id}/sync", response_model=FortiGateSyncResult)
async def sync_fortigate_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Import firewall address objects from the FortiGate REST API."""
    org_id = _get_org_id(current_user)
    integration = _get_fortigate_integration(db, org_id, integration_id)
    if not integration.is_active:
        raise HTTPException(status_code=400, detail="This FortiGate connection is disabled.")

    result = await fortigate_service.sync_integration(db, integration)
    return FortiGateSyncResult(**result)


# ══════════════════════════════════════════════════════════════════════════════
# Check Point — read-only import of host / network / address-range objects
# ══════════════════════════════════════════════════════════════════════════════


def _get_checkpoint_integration(db: Session, org_id: int, integration_id: int) -> CheckPointIntegration:
    integration = (
        db.query(CheckPointIntegration)
        .filter(
            CheckPointIntegration.id == integration_id,
            CheckPointIntegration.organization_id == org_id,
        )
        .first()
    )
    if not integration:
        raise HTTPException(status_code=404, detail="Check Point connection not found.")
    return integration


@router.get("/checkpoint", response_model=List[CheckPointIntegrationResponse])
def list_checkpoint_integrations(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    org_id = _get_org_id(current_user)
    return (
        db.query(CheckPointIntegration)
        .filter(CheckPointIntegration.organization_id == org_id)
        .order_by(CheckPointIntegration.created_at.desc())
        .all()
    )


@router.post("/checkpoint", response_model=CheckPointIntegrationResponse, status_code=status.HTTP_201_CREATED)
async def create_checkpoint_integration(
    payload: CheckPointIntegrationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)

    existing = (
        db.query(CheckPointIntegration)
        .filter(
            CheckPointIntegration.organization_id == org_id,
            CheckPointIntegration.name == payload.name,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"A Check Point connection named '{payload.name}' already exists.",
        )

    result = await checkpoint_service.test_connection(
        payload.management_host,
        payload.username,
        payload.password,
        domain=payload.domain,
        verify_ssl=payload.verify_ssl,
    )
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result["message"])

    integration = CheckPointIntegration(
        organization_id=org_id,
        name=payload.name,
        management_host=payload.management_host,
        domain=payload.domain,
        verify_ssl=payload.verify_ssl,
        continuous_sync_enabled=payload.continuous_sync_enabled,
        sync_interval_minutes=payload.sync_interval_minutes,
        is_active=True,
        last_tested_at=datetime.utcnow(),
        last_test_ok=True,
    )
    integration.set_username(payload.username)
    integration.set_password(payload.password)
    db.add(integration)
    db.commit()
    db.refresh(integration)
    return integration


@router.put("/checkpoint/{integration_id}", response_model=CheckPointIntegrationResponse)
async def update_checkpoint_integration(
    integration_id: int,
    payload: CheckPointIntegrationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)
    integration = _get_checkpoint_integration(db, org_id, integration_id)

    data = payload.model_dump(exclude_unset=True)
    new_username = data.pop("username", None)
    new_password = data.pop("password", None)

    if "domain" in data:
        dom = data["domain"]
        data["domain"] = dom.strip() if isinstance(dom, str) and dom.strip() else None

    for field, value in data.items():
        setattr(integration, field, value)
    if new_username:
        integration.set_username(new_username)
    if new_password:
        integration.set_password(new_password)

    result = await checkpoint_service.test_connection(
        integration.management_host or "",
        integration.get_username() or "",
        integration.get_password() or "",
        domain=integration.domain,
        verify_ssl=bool(integration.verify_ssl),
    )
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]

    db.commit()
    db.refresh(integration)
    return integration


@router.delete("/checkpoint/{integration_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_checkpoint_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)
    integration = _get_checkpoint_integration(db, org_id, integration_id)
    db.delete(integration)
    db.commit()


@router.post("/checkpoint/{integration_id}/test", response_model=CheckPointTestConnectionResponse)
async def test_checkpoint_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)
    integration = _get_checkpoint_integration(db, org_id, integration_id)
    result = await checkpoint_service.test_connection(
        integration.management_host or "",
        integration.get_username() or "",
        integration.get_password() or "",
        domain=integration.domain,
        verify_ssl=bool(integration.verify_ssl),
    )
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]
    integration.last_error = None if result["ok"] else result["message"]
    db.commit()
    return CheckPointTestConnectionResponse(**result)


@router.post("/checkpoint/{integration_id}/sync", response_model=CheckPointSyncResult)
async def sync_checkpoint_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Import host / network / address-range objects from Check Point."""
    org_id = _get_org_id(current_user)
    integration = _get_checkpoint_integration(db, org_id, integration_id)
    if not integration.is_active:
        raise HTTPException(status_code=400, detail="This Check Point connection is disabled.")

    result = await checkpoint_service.sync_integration(db, integration)
    return CheckPointSyncResult(**result)


# ══════════════════════════════════════════════════════════════════════════════
# Akamai WAF — read-only import of Application Security configs & hostnames
# ══════════════════════════════════════════════════════════════════════════════


def _get_akamai_integration(db: Session, org_id: int, integration_id: int) -> AkamaiWafIntegration:
    integration = (
        db.query(AkamaiWafIntegration)
        .filter(
            AkamaiWafIntegration.id == integration_id,
            AkamaiWafIntegration.organization_id == org_id,
        )
        .first()
    )
    if not integration:
        raise HTTPException(status_code=404, detail="Akamai WAF connection not found.")
    return integration


@router.get("/akamai", response_model=List[AkamaiIntegrationResponse])
def list_akamai_integrations(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    org_id = _get_org_id(current_user)
    return (
        db.query(AkamaiWafIntegration)
        .filter(AkamaiWafIntegration.organization_id == org_id)
        .order_by(AkamaiWafIntegration.created_at.desc())
        .all()
    )


@router.post("/akamai", response_model=AkamaiIntegrationResponse, status_code=status.HTTP_201_CREATED)
async def create_akamai_integration(
    payload: AkamaiIntegrationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)

    existing = (
        db.query(AkamaiWafIntegration)
        .filter(
            AkamaiWafIntegration.organization_id == org_id,
            AkamaiWafIntegration.connection_name == payload.connection_name,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"An Akamai WAF connection named '{payload.connection_name}' already exists.",
        )

    result = await akamai_waf_service.test_connection(
        payload.api_host,
        payload.client_token,
        payload.client_secret,
        payload.access_token,
    )
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result["message"])

    integration = AkamaiWafIntegration(
        organization_id=org_id,
        connection_name=payload.connection_name,
        api_host=payload.api_host,
        import_configurations=payload.import_configurations,
        import_hostnames=payload.import_hostnames,
        continuous_sync_enabled=payload.continuous_sync_enabled,
        sync_interval_minutes=payload.sync_interval_minutes,
        is_active=True,
        last_tested_at=datetime.utcnow(),
        last_test_ok=True,
    )
    integration.set_credentials(
        client_token=payload.client_token,
        client_secret=payload.client_secret,
        access_token=payload.access_token,
    )
    db.add(integration)
    db.commit()
    db.refresh(integration)
    return integration


@router.put("/akamai/{integration_id}", response_model=AkamaiIntegrationResponse)
async def update_akamai_integration(
    integration_id: int,
    payload: AkamaiIntegrationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)
    integration = _get_akamai_integration(db, org_id, integration_id)

    data = payload.model_dump(exclude_unset=True)
    new_client_token = data.pop("client_token", None)
    new_client_secret = data.pop("client_secret", None)
    new_access_token = data.pop("access_token", None)

    for field, value in data.items():
        setattr(integration, field, value)

    integration.set_credentials(
        client_token=new_client_token,
        client_secret=new_client_secret,
        access_token=new_access_token,
    )

    result = await akamai_waf_service.test_connection(
        integration.api_host,
        integration.get_client_token() or "",
        integration.get_client_secret() or "",
        integration.get_access_token() or "",
    )
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]

    db.commit()
    db.refresh(integration)
    return integration


@router.delete("/akamai/{integration_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_akamai_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)
    integration = _get_akamai_integration(db, org_id, integration_id)
    db.delete(integration)
    db.commit()


@router.post("/akamai/{integration_id}/test", response_model=AkamaiTestConnectionResponse)
async def test_akamai_connection(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    org_id = _get_org_id(current_user)
    integration = _get_akamai_integration(db, org_id, integration_id)
    result = await akamai_waf_service.test_connection(
        integration.api_host,
        integration.get_client_token() or "",
        integration.get_client_secret() or "",
        integration.get_access_token() or "",
    )
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]
    db.commit()
    return AkamaiTestConnectionResponse(**result)


@router.post("/akamai/{integration_id}/sync", response_model=AkamaiSyncResult)
async def sync_akamai_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Pull WAF configurations, policies, and protected hostnames from Akamai."""
    org_id = _get_org_id(current_user)
    integration = _get_akamai_integration(db, org_id, integration_id)
    if not integration.is_active:
        raise HTTPException(status_code=400, detail="This Akamai WAF connection is disabled.")

    result = await akamai_waf_service.sync_integration(db, integration)
    return AkamaiSyncResult(**result)


# ══════════════════════════════════════════════════════════════════════════════
# Cloudflare WAF — manage scanner whitelist skip rules on Cloudflare zones
# ══════════════════════════════════════════════════════════════════════════════


def _cloudflare_response(integration: CloudflareWafIntegration) -> CloudflareIntegrationResponse:
    return CloudflareIntegrationResponse(
        id=integration.id,
        organization_id=integration.organization_id,
        connection_name=integration.connection_name,
        zones=integration.zones or [],
        scanner_ips=integration.scanner_ips or [],
        scan_header_name=integration.scan_header_name
        or cloudflare_waf_service.DEFAULT_HEADER_NAME,
        is_active=bool(integration.is_active),
        continuous_sync_enabled=bool(integration.continuous_sync_enabled),
        sync_interval_minutes=integration.sync_interval_minutes or 1440,
        last_tested_at=integration.last_tested_at,
        last_test_ok=integration.last_test_ok,
        last_sync_at=integration.last_sync_at,
        last_sync_ok=integration.last_sync_ok,
        next_sync_at=integration.next_sync_at,
        last_sync_stats=integration.last_sync_stats,
        last_error=integration.last_error,
        created_at=integration.created_at,
        updated_at=integration.updated_at,
        **cloudflare_waf_service.enrichment_for_response(integration),
    )


def _get_cloudflare_integration(
    db: Session, org_id: int, integration_id: int
) -> CloudflareWafIntegration:
    integration = (
        db.query(CloudflareWafIntegration)
        .filter(
            CloudflareWafIntegration.id == integration_id,
            CloudflareWafIntegration.organization_id == org_id,
        )
        .first()
    )
    if not integration:
        raise HTTPException(status_code=404, detail="Cloudflare WAF connection not found.")
    return integration


@router.get("/cloudflare", response_model=List[CloudflareIntegrationResponse])
def list_cloudflare_integrations(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    org_id = _get_org_id(current_user)
    rows = (
        db.query(CloudflareWafIntegration)
        .filter(CloudflareWafIntegration.organization_id == org_id)
        .order_by(CloudflareWafIntegration.created_at.desc())
        .all()
    )
    return [_cloudflare_response(r) for r in rows]


@router.post(
    "/cloudflare",
    response_model=CloudflareIntegrationResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_cloudflare_integration(
    payload: CloudflareIntegrationCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)

    existing = (
        db.query(CloudflareWafIntegration)
        .filter(
            CloudflareWafIntegration.organization_id == org_id,
            CloudflareWafIntegration.connection_name == payload.connection_name,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"A Cloudflare WAF connection named '{payload.connection_name}' already exists.",
        )

    result = await cloudflare_waf_service.test_connection(payload.api_token)
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result["message"])

    integration = CloudflareWafIntegration(
        organization_id=org_id,
        connection_name=payload.connection_name,
        zones=payload.zones or [],
        scanner_ips=payload.scanner_ips or [],
        scan_header_name=cloudflare_waf_service.DEFAULT_HEADER_NAME,
        continuous_sync_enabled=payload.continuous_sync_enabled,
        sync_interval_minutes=payload.sync_interval_minutes,
        is_active=True,
        last_tested_at=datetime.utcnow(),
        last_test_ok=True,
    )
    integration.set_api_token(payload.api_token)
    integration.set_scan_header_secret(cloudflare_waf_service.generate_scan_header_secret())
    db.add(integration)
    db.commit()
    db.refresh(integration)

    # Kick off whitelist sync immediately (Praetorian behavior).
    background_tasks.add_task(_bg_sync_cloudflare, integration.id)

    return _cloudflare_response(integration)


async def _bg_sync_cloudflare(integration_id: int) -> None:
    from app.db.database import SessionLocal

    db = SessionLocal()
    try:
        integration = db.query(CloudflareWafIntegration).filter(
            CloudflareWafIntegration.id == integration_id
        ).first()
        if integration and integration.is_active:
            await cloudflare_waf_service.sync_integration(db, integration)
    except Exception as exc:  # noqa: BLE001
        import logging
        logging.getLogger(__name__).error(
            "Background Cloudflare WAF sync failed for %s: %s", integration_id, exc
        )
    finally:
        db.close()


@router.put("/cloudflare/{integration_id}", response_model=CloudflareIntegrationResponse)
async def update_cloudflare_integration(
    integration_id: int,
    payload: CloudflareIntegrationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)
    integration = _get_cloudflare_integration(db, org_id, integration_id)

    data = payload.model_dump(exclude_unset=True)
    new_token = data.pop("api_token", None)
    for field, value in data.items():
        setattr(integration, field, value)
    if new_token:
        integration.set_api_token(new_token)

    result = await cloudflare_waf_service.test_connection(integration.get_api_token() or "")
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]

    db.commit()
    db.refresh(integration)
    return _cloudflare_response(integration)


@router.delete("/cloudflare/{integration_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_cloudflare_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Disconnect the integration. Cloudflare skip rules are left in place for
    manual cleanup (same as Praetorian — disconnect does not auto-delete rules).
    """
    org_id = _get_org_id(current_user)
    integration = _get_cloudflare_integration(db, org_id, integration_id)
    db.delete(integration)
    db.commit()


@router.post("/cloudflare/{integration_id}/test", response_model=CloudflareTestConnectionResponse)
async def test_cloudflare_connection(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    org_id = _get_org_id(current_user)
    integration = _get_cloudflare_integration(db, org_id, integration_id)
    result = await cloudflare_waf_service.test_connection(integration.get_api_token() or "")
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]
    db.commit()
    return CloudflareTestConnectionResponse(**result)


@router.post("/cloudflare/{integration_id}/sync", response_model=CloudflareSyncResult)
async def sync_cloudflare_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Create or update the managed scanner whitelist skip rule on each zone."""
    org_id = _get_org_id(current_user)
    integration = _get_cloudflare_integration(db, org_id, integration_id)
    if not integration.is_active:
        raise HTTPException(status_code=400, detail="This Cloudflare WAF connection is disabled.")

    result = await cloudflare_waf_service.sync_integration(db, integration)
    return CloudflareSyncResult(**result)


# ── ServiceNow configuration ─────────────────────────────────────────────────

def _get_servicenow_integration(db: Session, org_id: int) -> ServiceNowIntegration:
    integration = (
        db.query(ServiceNowIntegration)
        .filter(ServiceNowIntegration.organization_id == org_id)
        .first()
    )
    if not integration:
        raise HTTPException(
            status_code=404,
            detail="ServiceNow integration not configured for this organization.",
        )
    return integration


def _active_snow_deliveries_for_vuln(
    db: Session, integration_id: int, vulnerability_id: int
) -> List[ServiceNowDelivery]:
    return (
        db.query(ServiceNowDelivery)
        .filter(
            ServiceNowDelivery.vulnerability_id == vulnerability_id,
            ServiceNowDelivery.integration_id == integration_id,
            ServiceNowDelivery.disconnected_at.is_(None),
        )
        .order_by(ServiceNowDelivery.created_at.desc())
        .all()
    )


@router.get("/servicenow", response_model=ServiceNowIntegrationResponse)
def get_servicenow_integration(
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    resolved = _resolve_org_id(current_user, org_id)
    integration = _get_servicenow_integration(db, resolved)
    return ServiceNowIntegrationResponse(**servicenow_service.to_response_dict(integration))


@router.post(
    "/servicenow",
    response_model=ServiceNowIntegrationResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_servicenow_integration(
    payload: ServiceNowIntegrationCreate,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    resolved = _resolve_org_id(current_user, org_id)
    if (
        db.query(ServiceNowIntegration)
        .filter(ServiceNowIntegration.organization_id == resolved)
        .first()
    ):
        raise HTTPException(
            status_code=409,
            detail="ServiceNow integration already exists. Use PUT to update.",
        )

    username = (payload.username or "").strip() or None
    integration = ServiceNowIntegration(
        organization_id=resolved,
        webhook_url=payload.webhook_url,
        username=username,
        auto_create_enabled=payload.auto_create_enabled,
        auto_create_min_severity=payload.auto_create_min_severity or "high",
        sync_enabled=payload.sync_enabled,
        table_name=payload.table_name or "incident",
        close_state=payload.close_state or "6",
        reopen_state=payload.reopen_state or "2",
        remote_closed_states=payload.remote_closed_states or ["6", "7"],
        validate_on_remote_close=payload.validate_on_remote_close,
        accept_close_as=payload.accept_close_as or "resolved",
        is_active=True,
    )
    if payload.password:
        integration.set_password(payload.password)

    result = await servicenow_service.test_connection(integration)
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]
    if not result["ok"]:
        integration.last_error = result["message"]

    db.add(integration)
    db.commit()
    db.refresh(integration)
    return ServiceNowIntegrationResponse(**servicenow_service.to_response_dict(integration))


@router.put("/servicenow", response_model=ServiceNowIntegrationResponse)
async def update_servicenow_integration(
    payload: ServiceNowIntegrationUpdate,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    resolved = _resolve_org_id(current_user, org_id)
    integration = _get_servicenow_integration(db, resolved)

    data = payload.model_dump(exclude_unset=True)
    password = data.pop("password", None)
    if "username" in data:
        data["username"] = (data["username"] or "").strip() or None
    for field, value in data.items():
        setattr(integration, field, value)
    if password is not None:
        if password == "":
            integration.password_encrypted = None
        else:
            integration.set_password(password)

    result = await servicenow_service.test_connection(integration)
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]
    integration.last_error = None if result["ok"] else result["message"]

    db.commit()
    db.refresh(integration)
    return ServiceNowIntegrationResponse(**servicenow_service.to_response_dict(integration))


@router.delete("/servicenow", status_code=status.HTTP_204_NO_CONTENT)
def delete_servicenow_integration(
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    resolved = _resolve_org_id(current_user, org_id)
    integration = _get_servicenow_integration(db, resolved)
    db.delete(integration)
    db.commit()


@router.post("/servicenow/test", response_model=ServiceNowTestConnectionResponse)
async def test_servicenow_connection(
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    resolved = _resolve_org_id(current_user, org_id)
    integration = _get_servicenow_integration(db, resolved)
    result = await servicenow_service.test_connection(integration)
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]
    integration.last_error = None if result["ok"] else result["message"]
    db.commit()
    return ServiceNowTestConnectionResponse(**result)


@router.post(
    "/servicenow/vulnerabilities/{vulnerability_id}/push",
    response_model=ServiceNowDeliveryResponse,
    status_code=status.HTTP_201_CREATED,
)
async def push_vulnerability_to_servicenow(
    vulnerability_id: int,
    payload: CreateServiceNowDeliveryRequest,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Manually push a vulnerability finding to ServiceNow."""
    resolved, vuln = _resolve_org_for_vulnerability(
        db, current_user, vulnerability_id, org_id
    )
    integration = _get_servicenow_integration(db, resolved)
    if not integration.is_active:
        raise HTTPException(status_code=400, detail="ServiceNow integration is disabled.")

    existing = _active_snow_deliveries_for_vuln(db, integration.id, vulnerability_id)
    if existing:
        label = existing[0].snow_number or existing[0].snow_sys_id or f"#{existing[0].id}"
        raise HTTPException(
            status_code=409,
            detail=f"A ServiceNow delivery already exists for this vulnerability: {label}",
        )

    try:
        result = await servicenow_service.push_vulnerability(
            integration,
            vuln,
            include_description=payload.include_description,
            include_evidence=payload.include_evidence,
            include_remediation=payload.include_remediation,
            include_references=payload.include_references,
            include_enrichment=payload.include_enrichment,
        )
    except ValueError as exc:
        integration.last_error = str(exc)[:1000]
        db.commit()
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        integration.last_error = str(exc)[:1000]
        db.commit()
        raise HTTPException(status_code=502, detail=f"ServiceNow webhook error: {exc}")

    delivery = ServiceNowDelivery(
        integration_id=integration.id,
        vulnerability_id=vulnerability_id,
        snow_sys_id=result.get("snow_sys_id"),
        snow_number=result.get("snow_number"),
        snow_url=result.get("snow_url"),
        snow_state=result.get("snow_state"),
        snow_state_label=result.get("snow_state_label"),
        http_status=result.get("http_status"),
        response_body=result.get("response_body"),
    )
    integration.last_delivery_at = datetime.utcnow()
    integration.last_error = None
    db.add(delivery)
    db.commit()
    db.refresh(delivery)
    return delivery


@router.post(
    "/servicenow/vulnerabilities/{vulnerability_id}/associate",
    response_model=ServiceNowDeliveryResponse,
    status_code=status.HTTP_201_CREATED,
)
async def associate_servicenow_record(
    vulnerability_id: int,
    payload: AssociateServiceNowDeliveryRequest,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Link an existing ServiceNow incident to a vulnerability for sync."""
    if not payload.sys_id and not payload.number:
        raise HTTPException(status_code=400, detail="Provide sys_id or number.")

    resolved, vuln = _resolve_org_for_vulnerability(
        db, current_user, vulnerability_id, org_id
    )
    integration = _get_servicenow_integration(db, resolved)

    try:
        detail = await servicenow_service.get_record(
            integration,
            sys_id=payload.sys_id,
            number=payload.number if not payload.sys_id else None,
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"ServiceNow Table API error: {exc}")

    delivery = ServiceNowDelivery(
        integration_id=integration.id,
        vulnerability_id=vuln.id,
        snow_sys_id=detail.get("sys_id"),
        snow_number=detail.get("number"),
        snow_url=detail.get("url"),
        snow_state=detail.get("state"),
        snow_state_label=detail.get("state_label"),
        last_synced_at=datetime.utcnow(),
        http_status=200,
    )
    db.add(delivery)
    db.commit()
    db.refresh(delivery)
    return delivery


@router.get(
    "/servicenow/vulnerabilities/{vulnerability_id}/deliveries",
    response_model=List[ServiceNowDeliveryResponse],
)
def list_servicenow_deliveries_for_vulnerability(
    vulnerability_id: int,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    resolved, _vuln = _resolve_org_for_vulnerability(
        db, current_user, vulnerability_id, org_id
    )
    try:
        integration = _get_servicenow_integration(db, resolved)
    except HTTPException:
        return []
    return _active_snow_deliveries_for_vuln(db, integration.id, vulnerability_id)


@router.post(
    "/servicenow/vulnerabilities/{vulnerability_id}/sync",
    response_model=ServiceNowSyncResult,
)
async def sync_servicenow_vulnerability_status(
    vulnerability_id: int,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Push the current ASM status to linked ServiceNow records (ASM → ServiceNow)."""
    resolved, vuln = _resolve_org_for_vulnerability(
        db, current_user, vulnerability_id, org_id
    )
    integration = _get_servicenow_integration(db, resolved)
    if not integration.sync_enabled:
        raise HTTPException(status_code=400, detail="ServiceNow sync is not enabled.")

    deliveries = _active_snow_deliveries_for_vuln(db, integration.id, vulnerability_id)
    if not deliveries:
        raise HTTPException(status_code=404, detail="No active ServiceNow deliveries for this finding.")

    delivery = deliveries[0]
    new_status = vuln.status.value if vuln.status else "open"
    result = await servicenow_service.sync_delivery_for_status_change(
        integration=integration,
        delivery=delivery,
        old_status="open",
        new_status=new_status,
        changed_by=current_user.email or current_user.username or "unknown",
    )
    if result.get("state_updated"):
        delivery.snow_state = result.get("snow_state")
        delivery.snow_state_label = result.get("snow_state_label")
        delivery.last_synced_at = datetime.utcnow()
        db.commit()
    return ServiceNowSyncResult(**result)


@router.post(
    "/servicenow/deliveries/{delivery_id}/refresh",
    response_model=ServiceNowSyncResult,
)
async def refresh_servicenow_delivery(
    delivery_id: int,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Pull ServiceNow state (ServiceNow → ASM). May queue close-claim validation."""
    delivery = (
        db.query(ServiceNowDelivery)
        .options(joinedload(ServiceNowDelivery.integration))
        .filter(ServiceNowDelivery.id == delivery_id)
        .first()
    )
    if not delivery:
        raise HTTPException(status_code=404, detail="Delivery not found.")

    resolved = _resolve_org_id(current_user, org_id)
    if delivery.integration.organization_id != resolved and not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Access denied.")

    integration = delivery.integration
    try:
        result = await servicenow_service.refresh_delivery(
            db, integration, delivery, apply_remote_close=True
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"ServiceNow refresh failed: {exc}")

    integration.last_pull_at = datetime.utcnow()
    db.commit()
    return ServiceNowSyncResult(**result)


@router.post("/servicenow/pull", response_model=ServiceNowSyncResult)
async def pull_all_servicenow_deliveries(
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Refresh all active ServiceNow deliveries for the org (ServiceNow → ASM)."""
    resolved = _resolve_org_id(current_user, org_id)
    integration = _get_servicenow_integration(db, resolved)
    if not integration.sync_enabled:
        raise HTTPException(status_code=400, detail="ServiceNow sync is not enabled.")

    deliveries = (
        db.query(ServiceNowDelivery)
        .filter(
            ServiceNowDelivery.integration_id == integration.id,
            ServiceNowDelivery.disconnected_at.is_(None),
            or_(
                ServiceNowDelivery.snow_sys_id.isnot(None),
                ServiceNowDelivery.snow_number.isnot(None),
            ),
        )
        .all()
    )

    validated = 0
    refreshed = 0
    errors = 0
    for delivery in deliveries:
        try:
            result = await servicenow_service.refresh_delivery(
                db, integration, delivery, apply_remote_close=True
            )
            refreshed += 1
            if result.get("validation_queued"):
                validated += 1
        except Exception:
            errors += 1
            logger.exception("ServiceNow pull failed for delivery %s", delivery.id)

    integration.last_pull_at = datetime.utcnow()
    db.commit()
    return ServiceNowSyncResult(
        ok=errors == 0,
        message=(
            f"Refreshed {refreshed} delivery(ies); "
            f"{validated} close-claim validation(s) queued; {errors} error(s)."
        ),
        validation_queued=validated > 0,
    )


@router.delete("/servicenow/deliveries/{delivery_id}", status_code=status.HTTP_200_OK)
def disconnect_servicenow_delivery(
    delivery_id: int,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    delivery = (
        db.query(ServiceNowDelivery)
        .options(joinedload(ServiceNowDelivery.integration))
        .filter(ServiceNowDelivery.id == delivery_id)
        .first()
    )
    if not delivery:
        raise HTTPException(status_code=404, detail="Delivery not found.")

    resolved = _resolve_org_id(current_user, org_id)
    if delivery.integration.organization_id != resolved and not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Access denied.")

    delivery.disconnected_at = datetime.utcnow()
    db.commit()
    label = delivery.snow_number or delivery.snow_sys_id or f"#{delivery.id}"
    return {"ok": True, "message": f"ServiceNow delivery {label} disconnected."}
