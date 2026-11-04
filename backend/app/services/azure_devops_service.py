"""Azure DevOps Services source code manager integration.

Read-only. Enumerates projects and Git repositories in an Azure DevOps
organization (or one project), imports active non-fork repositories as
``REPOSITORY`` assets, and queues a TruffleHog secret scan that clones each
repository and scans its full commit history.

Only Azure DevOps Services (``https://dev.azure.com``) is supported; Azure
DevOps Server / TFS and legacy ``*.visualstudio.com`` URLs are rejected.

Authentication:

* ``entra_id`` — OAuth2 client-credentials exchange against Microsoft Entra ID
  for the Azure DevOps resource. The service principal must be added as a user
  in the Azure DevOps organization and granted access to each project.
* ``pat`` — a Personal Access Token with Code (Read) and Project and Team (Read).

Credentials are only ever sent to ``dev.azure.com`` (and
``login.microsoftonline.com`` for the token exchange). For ``git clone`` they
are passed through ``GIT_CONFIG_*`` environment variables as an HTTP header, so
they never appear in a process's argument list or in a stored remote URL.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import re
import shutil
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote, unquote, urlparse, urlunparse

import httpx
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetStatus, AssetType
from app.models.scm_integration import (
    AUTH_METHOD_ENTRA_ID,
    AUTH_METHOD_PAT,
    PROVIDER_AZURE_DEVOPS,
    SourceCodeManagerIntegration,
)

logger = logging.getLogger(__name__)

DISCOVERY_SOURCE = "azure_devops"
ADO_HOST = "dev.azure.com"
ADO_BASE_URL = f"https://{ADO_HOST}"
API_VERSION = "7.1"
ENTRA_TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
# Well-known application ID of the Azure DevOps resource in Entra ID.
AZURE_DEVOPS_RESOURCE_SCOPE = "499b84ac-1321-427f-aa17-267ca6975798/.default"

PROJECT_PAGE_SIZE = 100
MAX_PAGES = 200
ENUMERATION_CONCURRENCY = 25
MAX_RATE_LIMIT_RETRIES = 5
DEFAULT_RETRY_AFTER_SECONDS = 10
MAX_RETRY_AFTER_SECONDS = 120

SCAN_CONCURRENCY = int(os.environ.get("SCM_SCAN_CONCURRENCY", "3"))
CLONE_TIMEOUT_SECONDS = int(os.environ.get("SCM_CLONE_TIMEOUT", "900"))
SCAN_TIMEOUT_SECONDS = int(os.environ.get("SCM_SCAN_TIMEOUT", "1800"))
# Azure DevOps reports repository size in bytes; skip anything unreasonably large.
MAX_REPOSITORY_BYTES = int(os.environ.get("SCM_MAX_REPO_BYTES", str(5 * 1024 ** 3)))

INVALID_URL_MESSAGE = (
    "Enter a valid Azure DevOps organization or project URL, such as "
    "https://dev.azure.com/your-org or https://dev.azure.com/your-org/your-project."
)
TOKEN_REJECTED_MESSAGE = (
    "Azure DevOps rejected the supplied access token. For Entra ID, verify the service "
    "principal has been added under Organization Settings > Users; for a PAT, check it "
    "has not expired and has the Code (Read) and Project and Team (Read) scopes."
)

_ORG_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,48}[A-Za-z0-9])?$")


class AzureDevOpsError(RuntimeError):
    """A safe, user-displayable Azure DevOps error."""


# ══════════════════════════════════════════════════════════════════════════════
# Scope URL parsing
# ══════════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class AzureDevOpsScope:
    organization: str
    project: Optional[str] = None

    @property
    def url(self) -> str:
        base = f"{ADO_BASE_URL}/{quote(self.organization, safe='')}"
        return f"{base}/{quote(self.project, safe='')}" if self.project else base


def parse_scope_url(value: str) -> AzureDevOpsScope:
    """Parse an organization, project, or repository URL into a scan scope.

    A repository URL (``/{org}/{project}/_git/{repo}``) scopes to its project:
    every repository in that project is scanned.
    """
    raw = (value or "").strip()
    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()
    if host.endswith(".visualstudio.com"):
        raise AzureDevOpsError(
            "Legacy visualstudio.com URLs are not supported. Use the "
            "https://dev.azure.com/{organization} form of the URL."
        )
    if (
        parsed.scheme != "https"
        or host != ADO_HOST
        or parsed.username
        or parsed.password
        or parsed.port not in (None, 443)
    ):
        raise AzureDevOpsError(INVALID_URL_MESSAGE)

    segments = [unquote(part) for part in parsed.path.split("/") if part]
    if not segments or not _ORG_NAME_RE.match(segments[0]):
        raise AzureDevOpsError(INVALID_URL_MESSAGE)
    organization = segments[0]
    project: Optional[str] = None
    if len(segments) > 1 and not segments[1].startswith("_"):
        project = segments[1].strip()
        if not project or len(project) > 64 or any(ch in project for ch in '\\/:*?"<>|#$%&{}'):
            raise AzureDevOpsError(INVALID_URL_MESSAGE)
    return AzureDevOpsScope(organization=organization, project=project)


# ══════════════════════════════════════════════════════════════════════════════
# Authentication
# ══════════════════════════════════════════════════════════════════════════════


class _PatAuth:
    def __init__(self, token: str) -> None:
        if not token:
            raise AzureDevOpsError("No Personal Access Token is stored for this connection.")
        self._header = "Basic " + base64.b64encode(f":{token}".encode()).decode()

    async def authorization(self) -> str:
        return self._header


class _EntraIdAuth:
    """Client-credentials token exchange with expiry-aware caching."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        *,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        if not (tenant_id and client_id and client_secret):
            raise AzureDevOpsError(
                "Entra ID authentication needs a tenant ID, application (client) ID and client secret."
            )
        if not re.match(r"^[A-Za-z0-9.-]{1,255}$", tenant_id):
            raise AzureDevOpsError("The Entra ID tenant ID is not valid.")
        self.tenant_id = tenant_id
        self.client_id = client_id
        self._client_secret = client_secret
        self._transport = transport
        self._token: Optional[str] = None
        self._expires_at = 0.0

    async def authorization(self) -> str:
        if self._token and time.monotonic() < self._expires_at:
            return f"Bearer {self._token}"
        try:
            async with httpx.AsyncClient(timeout=30.0, transport=self._transport) as client:
                response = await client.post(
                    ENTRA_TOKEN_URL.format(tenant=self.tenant_id),
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self.client_id,
                        "client_secret": self._client_secret,
                        "scope": AZURE_DEVOPS_RESOURCE_SCOPE,
                    },
                    headers={"Accept": "application/json"},
                )
        except httpx.HTTPError as exc:
            raise AzureDevOpsError(f"Could not reach Microsoft Entra ID: {exc.__class__.__name__}") from exc
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        if response.status_code != 200 or not payload.get("access_token"):
            detail = str(payload.get("error_description") or payload.get("error") or "").split("\r\n")[0]
            raise AzureDevOpsError(
                f"Entra ID token exchange failed (HTTP {response.status_code})"
                + (f": {detail[:300]}" if detail else ".")
            )
        self._token = str(payload["access_token"])
        # Refresh five minutes before the advertised expiry.
        lifetime = int(payload.get("expires_in") or 3600)
        self._expires_at = time.monotonic() + max(60, lifetime - 300)
        return f"Bearer {self._token}"


def auth_for(
    auth_method: str,
    *,
    personal_access_token: Optional[str] = None,
    tenant_id: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    transport: Optional[httpx.AsyncBaseTransport] = None,
):
    if auth_method == AUTH_METHOD_PAT:
        return _PatAuth(personal_access_token or "")
    if auth_method == AUTH_METHOD_ENTRA_ID:
        return _EntraIdAuth(tenant_id or "", client_id or "", client_secret or "", transport=transport)
    raise AzureDevOpsError(f"Unsupported authentication method '{auth_method}'.")


def auth_for_integration(integration: SourceCodeManagerIntegration, **kwargs):
    return auth_for(
        integration.auth_method,
        personal_access_token=integration.get_access_token(),
        tenant_id=integration.tenant_id,
        client_id=integration.client_id,
        client_secret=integration.get_client_secret(),
        **kwargs,
    )


# ══════════════════════════════════════════════════════════════════════════════
# REST client
# ══════════════════════════════════════════════════════════════════════════════


def _retry_after_seconds(value: Optional[str]) -> float:
    """Seconds to wait after HTTP 429: Retry-After, else 10s, capped at 120s."""
    if not value:
        return DEFAULT_RETRY_AFTER_SECONDS
    value = value.strip()
    try:
        seconds = float(value)
    except ValueError:
        try:
            when = parsedate_to_datetime(value)
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            seconds = (when - datetime.now(timezone.utc)).total_seconds()
        except (TypeError, ValueError):
            return DEFAULT_RETRY_AFTER_SECONDS
    return float(min(MAX_RETRY_AFTER_SECONDS, max(0.0, seconds)))


class AzureDevOpsClient:
    """Minimal read-only Azure DevOps REST client (API version 7.1)."""

    def __init__(
        self,
        organization: str,
        auth,
        *,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if not _ORG_NAME_RE.match(organization or ""):
            raise AzureDevOpsError(INVALID_URL_MESSAGE)
        self.organization = organization
        self._auth = auth
        self._transport = transport
        self._sleep = sleep
        self._http: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "AzureDevOpsClient":
        self._http = httpx.AsyncClient(
            base_url=ADO_BASE_URL,
            timeout=30.0,
            transport=self._transport,
            follow_redirects=False,
        )
        return self

    async def __aexit__(self, *exc_info) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    async def authorization(self) -> str:
        return await self._auth.authorization()

    async def _get(
        self, path: str, params: Optional[Dict[str, Any]] = None, *, project: Optional[str] = None
    ) -> Tuple[Dict[str, Any], httpx.Headers]:
        if self._http is None:
            raise RuntimeError("AzureDevOpsClient must be used as an async context manager")
        query = {"api-version": API_VERSION, **(params or {})}
        for attempt in range(MAX_RATE_LIMIT_RETRIES + 1):
            headers = {"Authorization": await self.authorization(), "Accept": "application/json"}
            try:
                response = await self._http.get(path, params=query, headers=headers)
            except httpx.HTTPError as exc:
                if attempt >= 2:
                    raise AzureDevOpsError(
                        f"Could not reach Azure DevOps: {exc.__class__.__name__}"
                    ) from exc
                await self._sleep(2 ** attempt)
                continue

            status_code = response.status_code
            if status_code == 429 or (status_code in (502, 503, 504) and attempt < 2):
                if attempt >= MAX_RATE_LIMIT_RETRIES:
                    raise AzureDevOpsError(
                        "Azure DevOps kept rate limiting requests (HTTP 429). Try again later."
                    )
                await self._sleep(_retry_after_seconds(response.headers.get("Retry-After")))
                continue
            # An invalid PAT gets a 203 sign-in page (HTML) or a redirect, not a 401.
            content_type = response.headers.get("content-type", "")
            if status_code == 401 or status_code in (203, 302) or (
                status_code == 200 and "json" not in content_type
            ):
                raise AzureDevOpsError(TOKEN_REJECTED_MESSAGE)
            if status_code in (403, 404):
                if project:
                    raise AzureDevOpsError(
                        f"Project '{project}' was not found in Azure DevOps organization "
                        f"'{self.organization}', or the authenticated identity is not a member of it. "
                        "Grant access under Organization Settings > Users > Manage access."
                    )
                raise AzureDevOpsError(
                    f"The Azure DevOps token authenticated successfully but cannot access "
                    f"organization '{self.organization}'. Add the identity to the organization "
                    "and grant it access to each project under Organization Settings > Users > Manage access."
                )
            if status_code != 200:
                raise AzureDevOpsError(f"Azure DevOps request failed (HTTP {status_code}).")
            try:
                payload = response.json()
            except ValueError as exc:
                raise AzureDevOpsError("Azure DevOps returned an invalid JSON response.") from exc
            if not isinstance(payload, dict):
                raise AzureDevOpsError("Azure DevOps returned an unexpected response.")
            return payload, response.headers
        raise AzureDevOpsError("Azure DevOps request failed after retries.")

    def _org_path(self, *parts: str) -> str:
        encoded = [quote(self.organization, safe="")] + [quote(part, safe="") for part in parts]
        return "/" + "/".join(encoded)

    async def list_projects(self, *, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """``GET /{org}/_apis/projects`` — paginated via continuation token."""
        projects: List[Dict[str, Any]] = []
        token: Optional[str] = None
        for _ in range(MAX_PAGES):
            params: Dict[str, Any] = {"$top": min(PROJECT_PAGE_SIZE, limit or PROJECT_PAGE_SIZE)}
            if token:
                params["continuationToken"] = token
            payload, headers = await self._get(self._org_path("_apis", "projects"), params)
            batch = payload.get("value") or []
            projects.extend(item for item in batch if isinstance(item, dict))
            if limit and len(projects) >= limit:
                return projects[:limit]
            token = headers.get("x-ms-continuationtoken") or payload.get("continuationToken")
            if not token or not batch:
                break
        return projects

    async def get_project(self, project: str) -> Dict[str, Any]:
        """``GET /{org}/_apis/projects/{project}``."""
        payload, _ = await self._get(self._org_path("_apis", "projects", project), project=project)
        return payload

    async def list_repositories(self, project: str) -> List[Dict[str, Any]]:
        """``GET /{org}/{project}/_apis/git/repositories`` (paginated)."""
        repositories: List[Dict[str, Any]] = []
        token: Optional[str] = None
        for _ in range(MAX_PAGES):
            params: Dict[str, Any] = {}
            if token:
                params["continuationToken"] = token
            payload, headers = await self._get(
                self._org_path(project, "_apis", "git", "repositories"), params, project=project
            )
            batch = payload.get("value") or []
            repositories.extend(item for item in batch if isinstance(item, dict))
            token = headers.get("x-ms-continuationtoken")
            if not token or not batch:
                break
        return repositories


# ══════════════════════════════════════════════════════════════════════════════
# Discovery
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class DiscoveryResult:
    projects: List[Dict[str, Any]]
    repositories: List[Dict[str, Any]]
    forks_skipped: int = 0
    disabled_skipped: int = 0


def is_fork(repository: Dict[str, Any]) -> bool:
    return bool(repository.get("isFork"))


def is_disabled(repository: Dict[str, Any]) -> bool:
    return bool(repository.get("isDisabled")) or bool(repository.get("isInMaintenance"))


def repository_web_url(organization: str, repository: Dict[str, Any]) -> Optional[str]:
    """The repository's canonical web URL — used as the asset identity."""
    candidate = str(repository.get("webUrl") or "").strip()
    project = (repository.get("project") or {}).get("name")
    if not candidate and project and repository.get("name"):
        candidate = (
            f"{ADO_BASE_URL}/{quote(organization, safe='')}/{quote(project, safe='')}"
            f"/_git/{quote(str(repository['name']), safe='')}"
        )
    parsed = urlparse(candidate)
    if parsed.scheme != "https" or (parsed.hostname or "").lower() != ADO_HOST:
        return None
    # Drop any userinfo (``org@dev.azure.com``), query and fragment.
    return urlunparse(("https", ADO_HOST, parsed.path.rstrip("/"), "", "", ""))


def safe_clone_url(organization: str, repository: Dict[str, Any]) -> Optional[str]:
    """An HTTPS clone URL on dev.azure.com inside ``organization``, without userinfo."""
    candidate = str(repository.get("remoteUrl") or "").strip() or (repository_web_url(organization, repository) or "")
    parsed = urlparse(candidate)
    if parsed.scheme != "https" or (parsed.hostname or "").lower() != ADO_HOST or parsed.port not in (None, 443):
        return None
    segments = [unquote(part) for part in parsed.path.split("/") if part]
    if len(segments) < 4 or segments[0].lower() != organization.lower() or "_git" not in segments:
        return None
    return urlunparse(("https", ADO_HOST, parsed.path, "", "", ""))


async def discover_repositories(
    client: AzureDevOpsClient, project: Optional[str] = None
) -> DiscoveryResult:
    if project:
        projects = [await client.get_project(project)]
    else:
        projects = await client.list_projects()

    semaphore = asyncio.Semaphore(ENUMERATION_CONCURRENCY)

    async def _repos(proj: Dict[str, Any]) -> List[Dict[str, Any]]:
        ident = str(proj.get("id") or proj.get("name") or "")
        if not ident:
            return []
        async with semaphore:
            repos = await client.list_repositories(ident)
        for repo in repos:
            repo.setdefault("project", {})
            repo["project"].setdefault("name", proj.get("name"))
            repo["project"].setdefault("id", proj.get("id"))
            repo["project"].setdefault("visibility", proj.get("visibility"))
        return repos

    batches = await asyncio.gather(*(_repos(proj) for proj in projects))
    result = DiscoveryResult(projects=projects, repositories=[])
    seen: set[str] = set()
    for repo in (repo for batch in batches for repo in batch):
        key = str(repo.get("id") or repo.get("webUrl") or "")
        if key in seen:
            continue
        seen.add(key)
        if is_fork(repo):
            result.forks_skipped += 1
            continue
        if is_disabled(repo):
            result.disabled_skipped += 1
            continue
        result.repositories.append(repo)
    return result


async def test_connection(
    scope_url: str,
    auth_method: str,
    *,
    personal_access_token: Optional[str] = None,
    tenant_id: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    transport: Optional[httpx.AsyncBaseTransport] = None,
) -> Dict[str, Any]:
    """Validate the credentials by listing projects (or fetching the scoped project)."""
    try:
        scope = parse_scope_url(scope_url)
        auth = auth_for(
            auth_method,
            personal_access_token=personal_access_token,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            transport=transport,
        )
        async with AzureDevOpsClient(scope.organization, auth, transport=transport) as client:
            if scope.project:
                project = await client.get_project(scope.project)
                return {
                    "ok": True,
                    "message": f"Connected to Azure DevOps project '{project.get('name') or scope.project}'.",
                    "projects_accessible": 1,
                }
            projects = await client.list_projects(limit=PROJECT_PAGE_SIZE)
            if not projects:
                return {
                    "ok": False,
                    "message": (
                        f"The Azure DevOps token authenticated successfully but cannot access any project "
                        f"in organization '{scope.organization}'. Grant the identity access to each project "
                        "under Organization Settings > Users > Manage access."
                    ),
                    "projects_accessible": 0,
                }
            count = f"{len(projects)}+" if len(projects) >= PROJECT_PAGE_SIZE else str(len(projects))
            return {
                "ok": True,
                "message": f"Connected to Azure DevOps organization '{scope.organization}' ({count} project(s) visible).",
                "projects_accessible": len(projects),
            }
    except AzureDevOpsError as exc:
        return {"ok": False, "message": str(exc), "projects_accessible": 0}


# ══════════════════════════════════════════════════════════════════════════════
# Asset import
# ══════════════════════════════════════════════════════════════════════════════


def _upsert_repository_asset(
    db: Session,
    integration: SourceCodeManagerIntegration,
    repository: Dict[str, Any],
    web_url: str,
) -> bool:
    """Create or refresh the repository asset. Returns True when created."""
    project = repository.get("project") or {}
    now = datetime.utcnow()
    details = {
        "integration_id": integration.id,
        "organization": integration.scm_organization,
        "project": project.get("name"),
        "project_id": project.get("id"),
        "project_visibility": project.get("visibility"),
        "repository_id": repository.get("id"),
        "repository_name": repository.get("name"),
        "default_branch": repository.get("defaultBranch"),
        "size_bytes": repository.get("size"),
        "remote_url": safe_clone_url(integration.scm_organization, repository),
        "web_url": web_url,
    }
    name = f"{project.get('name') or integration.scm_organization}/{repository.get('name') or web_url}"[:255]
    asset = (
        db.query(Asset)
        .filter(Asset.organization_id == integration.organization_id, Asset.value == web_url[:500])
        .first()
    )
    if asset:
        metadata = dict(asset.metadata_ or {})
        metadata["azure_devops"] = details
        asset.metadata_ = metadata
        asset.name = name
        asset.last_seen = now
        if asset.status == AssetStatus.INACTIVE:
            asset.status = AssetStatus.DISCOVERED
        tags = list(asset.tags or [])
        for tag in ("source:azure_devops", "repository"):
            if tag not in tags:
                tags.append(tag)
        asset.tags = tags
        return False
    db.add(
        Asset(
            name=name,
            asset_type=AssetType.REPOSITORY,
            value=web_url[:500],
            organization_id=integration.organization_id,
            status=AssetStatus.DISCOVERED,
            discovery_source=DISCOVERY_SOURCE,
            association_reason=(
                f"Git repository in Azure DevOps organization '{integration.scm_organization}' "
                f"imported by the '{integration.connection_name}' source code manager connection"
            ),
            association_confidence=100,
            tags=["source:azure_devops", "repository"],
            metadata_={"azure_devops": details},
            # Public-project repositories are not yet flagged as public.
            is_public=False,
            first_seen=now,
            last_seen=now,
        )
    )
    return True


def _queue_secret_scan(
    db: Session,
    integration: SourceCodeManagerIntegration,
    repositories: List[Dict[str, str]],
    started_by: Optional[str],
):
    from app.models.scan import Scan, ScanStatus, ScanType

    scan = Scan(
        name=f"Azure DevOps secret scan — {integration.connection_name}"[:255],
        scan_type=ScanType.TRUFFLEHOG_SCAN,
        organization_id=integration.organization_id,
        targets=[repo["web_url"] for repo in repositories],
        config={
            "scm_integration_id": integration.id,
            "scm_provider": PROVIDER_AZURE_DEVOPS,
            # Clone URLs and names only — never credentials.
            "repositories": repositories,
            "only_verified": not integration.include_unverified_secrets,
            "include_unverified": bool(integration.include_unverified_secrets),
        },
        status=ScanStatus.PENDING,
        started_by=started_by or "azure_devops_sync",
    )
    db.add(scan)
    db.flush()
    return scan


def _notify_worker(scan) -> None:
    try:
        from app.api.routes.scans import send_scan_to_sqs

        send_scan_to_sqs(scan)
    except Exception as exc:  # noqa: BLE001 — the worker also polls PENDING scans
        logger.debug("SQS notification for SCM scan %s skipped: %s", getattr(scan, "id", None), exc)


async def sync_integration(
    db: Session,
    integration: SourceCodeManagerIntegration,
    *,
    started_by: Optional[str] = None,
    transport: Optional[httpx.AsyncBaseTransport] = None,
) -> Dict[str, Any]:
    """Re-enumerate the configured scope, import repositories, queue a secret scan."""
    stats: Dict[str, Any] = {
        "projects_seen": 0,
        "repositories_seen": 0,
        "repositories_created": 0,
        "repositories_updated": 0,
        "forks_skipped": 0,
        "disabled_skipped": 0,
    }
    try:
        auth = auth_for_integration(integration, transport=transport)
        async with AzureDevOpsClient(integration.scm_organization, auth, transport=transport) as client:
            discovery = await discover_repositories(client, integration.scm_project)

        stats["projects_seen"] = len(discovery.projects)
        stats["forks_skipped"] = discovery.forks_skipped
        stats["disabled_skipped"] = discovery.disabled_skipped

        scan_targets: List[Dict[str, str]] = []
        for repository in discovery.repositories:
            web_url = repository_web_url(integration.scm_organization, repository)
            if not web_url:
                continue
            stats["repositories_seen"] += 1
            if _upsert_repository_asset(db, integration, repository, web_url):
                stats["repositories_created"] += 1
            else:
                stats["repositories_updated"] += 1
            clone_url = safe_clone_url(integration.scm_organization, repository)
            if clone_url:
                scan_targets.append(
                    {
                        "web_url": web_url,
                        "clone_url": clone_url,
                        "name": str(repository.get("name") or "")[:255],
                        "project": str((repository.get("project") or {}).get("name") or "")[:255],
                        "size": int(repository.get("size") or 0),
                    }
                )

        scan = None
        if integration.secret_scanning_enabled and scan_targets:
            scan = _queue_secret_scan(db, integration, scan_targets, started_by)
            integration.last_scan_id = scan.id

        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = True
        integration.last_error = None
        integration.last_sync_stats = stats
        db.commit()
        if scan is not None:
            _notify_worker(scan)

        message = (
            f"Discovered {stats['repositories_seen']} repositor"
            f"{'y' if stats['repositories_seen'] == 1 else 'ies'} across {stats['projects_seen']} project(s) "
            f"({stats['repositories_created']} new)."
        )
        if scan is not None:
            message += f" Secret scan #{scan.id} queued."
        elif stats["repositories_seen"] == 0:
            message += (
                " No active, non-fork repositories are visible; check the identity has access to each project."
            )
        return {"ok": True, "message": message, "scan_id": scan.id if scan is not None else None, **stats}
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        safe = str(exc) if isinstance(exc, AzureDevOpsError) else "Unexpected error while syncing Azure DevOps."
        if not isinstance(exc, AzureDevOpsError):
            logger.exception("Azure DevOps sync failed for integration %s", integration.id)
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = safe[:1000]
        db.commit()
        return {"ok": False, "message": f"Sync failed: {safe}", "scan_id": None, **stats}


# ══════════════════════════════════════════════════════════════════════════════
# Secret scanning (runs in the scanner worker)
# ══════════════════════════════════════════════════════════════════════════════


def _git_env(authorization: str) -> Dict[str, str]:
    """Environment for a non-interactive git clone authenticated by HTTP header."""
    env = {
        key: value
        for key, value in os.environ.items()
        if key in ("PATH", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy", "GIT_SSL_CAINFO")
    }
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "/bin/true",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_COUNT": "2",
            "GIT_CONFIG_KEY_0": "http.extraHeader",
            "GIT_CONFIG_VALUE_0": f"Authorization: {authorization}",
            "GIT_CONFIG_KEY_1": "credential.helper",
            "GIT_CONFIG_VALUE_1": "",
            "HOME": tempfile.gettempdir(),
        }
    )
    return env


async def clone_repository(clone_url: str, destination: str, authorization: str) -> None:
    """Bare-clone every branch so TruffleHog can scan the full history."""
    parsed = urlparse(clone_url)
    if parsed.scheme != "https" or (parsed.hostname or "").lower() != ADO_HOST or parsed.username:
        raise AzureDevOpsError("Refusing to clone a repository outside https://dev.azure.com.")
    proc = await asyncio.create_subprocess_exec(
        "git", "clone", "--bare", "--quiet", "--", clone_url, destination,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
        env=_git_env(authorization),
    )
    try:
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=CLONE_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise AzureDevOpsError(f"git clone timed out after {CLONE_TIMEOUT_SECONDS}s")
    if proc.returncode != 0:
        detail = (stderr or b"").decode(errors="ignore").strip().splitlines()
        message = detail[-1] if detail else f"exit code {proc.returncode}"
        raise AzureDevOpsError(f"git clone failed: {message[:300]}")


async def run_repository_secret_scan(
    db: Session,
    scan_id: int,
    organization_id: int,
    config: Dict[str, Any],
    progress: Optional[Callable[[int, str], Awaitable[None]]] = None,
) -> Dict[str, Any]:
    """Clone each discovered repository and scan it with TruffleHog.

    Findings are attached to the repository asset (keyed by web URL). Clones
    are deleted as soon as each scan finishes.
    """
    from app.services.trufflehog_service import persist_trufflehog_findings, run_trufflehog

    integration = (
        db.query(SourceCodeManagerIntegration)
        .filter(
            SourceCodeManagerIntegration.id == config.get("scm_integration_id"),
            SourceCodeManagerIntegration.organization_id == organization_id,
        )
        .first()
    )
    if integration is None:
        raise AzureDevOpsError("The Azure DevOps connection for this scan no longer exists.")
    if not integration.is_active:
        raise AzureDevOpsError("The Azure DevOps connection for this scan is disabled.")

    auth = auth_for_integration(integration)
    only_verified = bool(config.get("only_verified", True))
    include_unverified = bool(config.get("include_unverified", False))
    repositories = [
        repo for repo in (config.get("repositories") or [])
        if isinstance(repo, dict) and repo.get("web_url") and repo.get("clone_url")
    ]
    summary: Dict[str, Any] = {
        "provider": PROVIDER_AZURE_DEVOPS,
        "integration_id": integration.id,
        "repositories_total": len(repositories),
        "repositories_scanned": 0,
        "repositories_failed": 0,
        "repositories_skipped": 0,
        "findings": 0,
        "persisted": 0,
        "errors": [],
        "per_repository": [],
    }
    semaphore = asyncio.Semaphore(max(1, SCAN_CONCURRENCY))
    work_root = tempfile.mkdtemp(prefix="scm-scan-")

    async def _scan_one(index: int, repo: Dict[str, Any]):
        web_url = str(repo["web_url"])
        if MAX_REPOSITORY_BYTES and int(repo.get("size") or 0) > MAX_REPOSITORY_BYTES:
            return repo, None, f"skipped: repository larger than {MAX_REPOSITORY_BYTES} bytes"
        clone_url = safe_clone_url(integration.scm_organization, {"remoteUrl": repo["clone_url"]})
        if not clone_url:
            return repo, None, "skipped: clone URL is outside the connected organization"
        async with semaphore:
            destination = os.path.join(work_root, f"repo-{index}.git")
            try:
                await clone_repository(clone_url, destination, await auth.authorization())
                result = await run_trufflehog(
                    source_type="git",
                    source_name=f"file://{destination}",
                    only_verified=only_verified,
                    include_unverified=include_unverified,
                    timeout=SCAN_TIMEOUT_SECONDS,
                )
                # Report findings against the repository, not the temporary clone.
                result.source_name = web_url
                for finding in result.findings:
                    finding.source_name = web_url
                    if finding.extras.get("repository"):
                        finding.extras["repository"] = web_url
                return repo, result, None
            except AzureDevOpsError as exc:
                return repo, None, str(exc)
            except Exception as exc:  # noqa: BLE001
                logger.warning("SCM scan of %s failed: %s", web_url, exc, exc_info=True)
                return repo, None, f"scan failed: {exc.__class__.__name__}"
            finally:
                shutil.rmtree(destination, ignore_errors=True)

    tasks: List[asyncio.Task] = []
    try:
        tasks = [asyncio.create_task(_scan_one(i, repo)) for i, repo in enumerate(repositories)]
        completed = 0
        for next_done in asyncio.as_completed(tasks):
            repo, result, error = await next_done
            completed += 1
            entry: Dict[str, Any] = {"repository": repo["web_url"], "findings": 0}
            if result is None:
                entry["error"] = error
                if error and error.startswith("skipped"):
                    summary["repositories_skipped"] += 1
                else:
                    summary["repositories_failed"] += 1
                    summary["errors"].append(f"{repo['web_url']}: {error}")
            else:
                if not result.binary_available:
                    raise AzureDevOpsError("TruffleHog is not installed on this scanner worker.")
                summary["repositories_scanned"] += 1
                entry["findings"] = len(result.findings)
                entry["errors"] = result.errors
                summary["findings"] += len(result.findings)
                summary["persisted"] += persist_trufflehog_findings(
                    db, organization_id, scan_id, result, asset_value=repo["web_url"]
                )
            summary["per_repository"].append(entry)
            if progress:
                await progress(
                    5 + int(90 * completed / max(1, len(repositories))),
                    f"Scanned {completed}/{len(repositories)} Azure DevOps repositories",
                )
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        shutil.rmtree(work_root, ignore_errors=True)

    summary["errors"] = summary["errors"][:50]
    return summary
