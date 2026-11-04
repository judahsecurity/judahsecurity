"""GitHub source-code-manager integration routes.

Mounted at ``/integrations/github``. Supports the platform GitHub App
(recommended) and personal access tokens.
"""

import logging
from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session, joinedload

from app.core.config import settings
from app.api.deps import get_current_active_user, require_analyst
from app.db.database import get_db
from app.models.github_integration import (
    AUTH_METHOD_PAT,
    GitHubAppInstallRequest,
    GitHubIntegration,
)
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.schemas.github_schemas import (
    GitHubAppCallbackRequest,
    GitHubAppCallbackResponse,
    GitHubAppInstallStart,
    GitHubAppInstallStartResponse,
    GitHubAppStatus,
    GitHubIntegrationResponse,
    GitHubIntegrationUpdate,
    GitHubPatIntegrationCreate,
    GitHubPullRequestCreate,
    GitHubPullRequestResponse,
    GitHubSyncResult,
    GitHubTestConnectionResponse,
)
from app.services import github_integration_service as github
from app.services.github_integration_service import GitHubApiError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/integrations/github", tags=["Integrations", "GitHub"])


def _org_id(user: User) -> int:
    if not user.organization_id:
        raise HTTPException(status_code=400, detail="User has no associated organization.")
    return user.organization_id


def _http_error(exc: GitHubApiError) -> HTTPException:
    code = exc.status_code if exc.status_code in (400, 403, 404, 409) else 400
    return HTTPException(status_code=code, detail=str(exc))


def _get(db: Session, org_id: int, integration_id: int) -> GitHubIntegration:
    integration = db.query(GitHubIntegration).filter(
        GitHubIntegration.id == integration_id,
        GitHubIntegration.organization_id == org_id,
    ).first()
    if not integration:
        raise HTTPException(status_code=404, detail="GitHub connection not found.")
    return integration


# ── Status & listing ─────────────────────────────────────────────────────────


@router.get("/app", response_model=GitHubAppStatus)
def github_app_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    org_id = _org_id(current_user)
    now = datetime.utcnow()
    pending = db.query(GitHubAppInstallRequest).filter(
        GitHubAppInstallRequest.organization_id == org_id,
        GitHubAppInstallRequest.status == "requested",
        GitHubAppInstallRequest.expires_at > now,
    ).order_by(GitHubAppInstallRequest.created_at.desc()).all()
    return GitHubAppStatus(
        app_configured=github.app_configured(),
        app_slug=settings.GITHUB_APP_SLUG,
        app_install_url=github.app_install_url(),
        pending_requests=[
            {
                "id": item.id,
                "github_login": item.github_login,
                "requested_at": item.requested_at or item.created_at,
                "expires_at": item.expires_at,
            }
            for item in pending
        ],
    )


@router.get("", response_model=List[GitHubIntegrationResponse])
def list_github_integrations(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    org_id = _org_id(current_user)
    return db.query(GitHubIntegration).filter(
        GitHubIntegration.organization_id == org_id
    ).order_by(GitHubIntegration.created_at.desc()).all()


# ── GitHub App install ───────────────────────────────────────────────────────


@router.post("/app/install", response_model=GitHubAppInstallStartResponse)
def start_github_app_install(
    payload: GitHubAppInstallStart,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    try:
        url, expires_at = github.start_app_install(
            db,
            organization_id=_org_id(current_user),
            user_id=current_user.id,
            options=payload.model_dump(),
        )
    except GitHubApiError as exc:
        raise _http_error(exc)
    return GitHubAppInstallStartResponse(install_url=url, expires_at=expires_at)


@router.post("/app/callback", response_model=GitHubAppCallbackResponse)
async def complete_github_app_install(
    payload: GitHubAppCallbackRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Finish an install after GitHub redirects back to the platform.

    The installation is linked only once the user's GitHub authorization proves
    they own or administer the installation's account.
    """
    try:
        result = await github.handle_app_callback(
            db,
            organization_id=_org_id(current_user),
            user_id=current_user.id,
            state=payload.state,
            installation_id=payload.installation_id,
            setup_action=payload.setup_action,
            code=payload.code,
        )
    except GitHubApiError as exc:
        raise _http_error(exc)
    return GitHubAppCallbackResponse(**result)


@router.post("/app/reconcile")
async def reconcile_github_app_requests(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Check whether owners approved pending install requests."""
    _org_id(current_user)
    try:
        linked = await github.reconcile_install_requests(db)
    except GitHubApiError as exc:
        raise _http_error(exc)
    return {"linked": linked}


# ── Personal access token ────────────────────────────────────────────────────


@router.post("/pat", response_model=GitHubIntegrationResponse, status_code=status.HTTP_201_CREATED)
async def create_github_pat_integration(
    payload: GitHubPatIntegrationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _org_id(current_user)
    try:
        login = github.parse_account_login(payload.organization_url)
    except GitHubApiError as exc:
        raise _http_error(exc)
    result = await github.test_pat(payload.token, login)
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result["message"])
    account_login = result["account_login"]
    existing = db.query(GitHubIntegration).filter(
        GitHubIntegration.organization_id == org_id,
        GitHubIntegration.auth_method == AUTH_METHOD_PAT,
        GitHubIntegration.account_login == account_login,
    ).first()
    if existing:
        raise HTTPException(
            status_code=409, detail=f"A token connection for {account_login} already exists. Edit it instead."
        )
    integration = GitHubIntegration(
        organization_id=org_id,
        auth_method=AUTH_METHOD_PAT,
        account_login=account_login,
        account_type=result["account_type"],
        account_id=result.get("account_id"),
        installed_by_user_id=current_user.id,
        import_member_repos=payload.import_member_repos,
        scan_secrets=payload.scan_secrets,
        allow_fix_pull_requests=payload.allow_fix_pull_requests,
        continuous_sync_enabled=payload.continuous_sync_enabled,
        sync_interval_minutes=payload.sync_interval_minutes,
        is_active=True,
        last_tested_at=datetime.utcnow(),
        last_test_ok=True,
    )
    integration.set_token(payload.token)
    db.add(integration)
    db.commit()
    db.refresh(integration)
    return integration


# ── Per-connection actions ───────────────────────────────────────────────────


@router.put("/{integration_id}", response_model=GitHubIntegrationResponse)
async def update_github_integration(
    integration_id: int,
    payload: GitHubIntegrationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    integration = _get(db, _org_id(current_user), integration_id)
    data = payload.model_dump(exclude_unset=True)
    token = data.pop("token", None)
    if integration.auth_method != AUTH_METHOD_PAT:
        if token:
            raise HTTPException(status_code=400, detail="GitHub App connections don't use a token.")
        if data.get("allow_fix_pull_requests"):
            raise HTTPException(
                status_code=400,
                detail="The GitHub App is read-only and can't open fix pull requests yet. Use a token connection.",
            )
    for field, value in data.items():
        setattr(integration, field, value)
    if token:
        result = await github.test_pat(token, integration.account_login)
        if not result["ok"]:
            db.rollback()
            raise HTTPException(status_code=400, detail=result["message"])
        integration.set_token(token)
        integration.last_tested_at = datetime.utcnow()
        integration.last_test_ok = True
    db.commit()
    db.refresh(integration)
    return integration


@router.delete("/{integration_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_github_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    integration = _get(db, _org_id(current_user), integration_id)
    db.delete(integration)
    db.commit()


@router.post("/{integration_id}/test", response_model=GitHubTestConnectionResponse)
async def test_github_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    integration = _get(db, _org_id(current_user), integration_id)
    result = await github.test_integration(integration)
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]
    db.commit()
    return GitHubTestConnectionResponse(
        **{key: value for key, value in result.items() if key in GitHubTestConnectionResponse.model_fields}
    )


@router.post("/{integration_id}/sync", response_model=GitHubSyncResult)
async def sync_github_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    integration = _get(db, _org_id(current_user), integration_id)
    if not integration.is_active:
        raise HTTPException(status_code=400, detail="This GitHub connection is disabled.")
    return GitHubSyncResult(**(await github.sync_integration(db, integration)))


@router.post(
    "/{integration_id}/pull-requests",
    response_model=GitHubPullRequestResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_github_fix_pull_request(
    integration_id: int,
    payload: GitHubPullRequestCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Open a pull request with a patch for a finding. The platform never merges it."""
    org_id = _org_id(current_user)
    integration = _get(db, org_id, integration_id)
    vulnerability = db.query(Vulnerability).options(joinedload(Vulnerability.asset)).filter(
        Vulnerability.id == payload.vulnerability_id
    ).first()
    if not vulnerability or not vulnerability.asset or vulnerability.asset.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Finding not found.")
    try:
        result = await github.create_fix_pull_request(
            db,
            integration,
            vulnerability,
            repository=payload.repository,
            title=payload.title,
            body=payload.body,
            base_branch=payload.base_branch,
            commit_message=payload.commit_message,
            changes=[change.model_dump() for change in payload.changes],
        )
    except GitHubApiError as exc:
        raise _http_error(exc)
    return GitHubPullRequestResponse(**result)
