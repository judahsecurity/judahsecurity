"""GitHub source-code-manager integration.

Discovers a GitHub organization's (or user's) repositories as ``REPOSITORY``
assets, optionally imports public repositories owned by organization members
as ``PENDING`` assets, scans repository contents for secrets, and — only for
personal-access-token connections that opted in — opens fix pull requests.

Authentication
--------------
* **GitHub App** — the platform signs a short JWT with the App's private key
  and exchanges it for a one-hour installation access token. Only the
  installation ID is stored per customer. Before an installation is linked,
  the installing user authorizes the App (user-to-server OAuth) so the
  platform can confirm they own or administer the installation's account.
* **Personal access token** — stored encrypted, validated before saving.

All calls go to ``api.github.com``; no customer-supplied host is ever used.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import re
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote, urlencode, urlparse

import httpx
from jose import jwt
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.asset import Asset, AssetStatus, AssetType
from app.models.github_integration import (
    AUTH_METHOD_APP,
    AUTH_METHOD_PAT,
    INSTALL_REQUEST_TTL,
    GitHubAppInstallRequest,
    GitHubIntegration,
)
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus
from app.services.github_secret_service import SECRET_PATTERNS, is_likely_secret

logger = logging.getLogger(__name__)

API_BASE = "https://api.github.com"
WEB_BASE = "https://github.com"
API_VERSION = "2022-11-28"
DISCOVERY_SOURCE = "github"
SECRET_DETECTOR = "github_secret_scanner"
SECRET_TEMPLATE_PREFIX = "github-secret:"

MAX_PAGES = 100  # 100 items/page → 10k repositories per listing
MAX_MEMBERS = 2000
MAX_MEMBER_REPO_PAGES = 5
MAX_REPOS_SCANNED_PER_SYNC = 200
MAX_FILES_PER_REPO = 2000
# Blob fetches across all repositories in one sync. Installation tokens and
# PATs get 5,000 requests/hour; this leaves headroom for discovery calls.
MAX_BLOBS_PER_SYNC = 3500
MAX_BLOB_BYTES = 512 * 1024
BLOB_CONCURRENCY = 8

_LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_REPO_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")
_SKIP_DIRS = {
    "node_modules", "vendor", ".git", "__pycache__", "dist", "build",
    ".venv", "venv", "third_party", "bower_components", ".next",
}
_SCAN_NAMES = {
    ".env", ".npmrc", ".pypirc", ".netrc", ".dockercfg", ".git-credentials",
    "credentials", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "dockerfile",
}
_SCAN_EXTENSIONS = (
    ".env", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".config",
    ".properties", ".xml", ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".rb", ".go", ".java", ".kt", ".cs", ".php", ".sh", ".bash", ".ps1", ".tf",
    ".tfvars", ".pem", ".key", ".sql", ".ipynb", ".swift", ".rs", ".scala",
)
_SECRET_REGEXES = {name: re.compile(cfg["pattern"]) for name, cfg in SECRET_PATTERNS.items()}


class GitHubApiError(RuntimeError):
    """A safe, user-displayable GitHub API error."""

    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.status_code = status_code


# ══════════════════════════════════════════════════════════════════════════════
# Input normalization
# ══════════════════════════════════════════════════════════════════════════════


def parse_account_login(value: str) -> str:
    """Accept ``github.com/<login>``, a full URL, or a bare login."""
    raw = (value or "").strip()
    if not raw:
        raise GitHubApiError("Enter a GitHub organization or user URL, e.g. github.com/acme.")
    if "://" not in raw and raw.lower().startswith(("github.com/", "www.github.com/")):
        raw = f"https://{raw}"
    if "://" in raw:
        parsed = urlparse(raw)
        host = (parsed.hostname or "").lower()
        if parsed.scheme not in ("http", "https") or host not in ("github.com", "www.github.com"):
            raise GitHubApiError("Only github.com organization or user URLs are supported.")
        parts = [part for part in parsed.path.split("/") if part]
        if not parts:
            raise GitHubApiError("The URL must name a GitHub organization or user.")
        if parts[0].lower() == "orgs" and len(parts) > 1:
            parts = parts[1:]
        raw = parts[0]
    if not _LOGIN_RE.match(raw):
        raise GitHubApiError(f"'{raw[:60]}' is not a valid GitHub organization or user name.")
    return raw


def repo_asset_value(full_name: str) -> str:
    return f"{WEB_BASE}/{full_name}".lower()


def validate_repo_path(path: str) -> str:
    """Reject paths that escape the repository or touch git internals."""
    clean = (path or "").strip()
    parts = clean.split("/")
    if (
        not clean
        or clean.startswith("/")
        or "\\" in clean
        or "\x00" in clean
        or any(part in ("", ".", "..") for part in parts)
        or parts[0] == ".git"
    ):
        raise GitHubApiError(f"Invalid file path in change set: {path[:200]!r}")
    return clean


# ══════════════════════════════════════════════════════════════════════════════
# HTTP client
# ══════════════════════════════════════════════════════════════════════════════


class GitHubClient:
    """Minimal async REST client for api.github.com with retry and pagination."""

    def __init__(
        self,
        token: str,
        *,
        scheme: str = "token",
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        if not token:
            raise GitHubApiError("No GitHub credential is available for this connection.")
        self._headers = {
            "Authorization": f"{scheme} {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "judah-security-asm",
        }
        self._transport = transport
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "GitHubClient":
        self._client = httpx.AsyncClient(
            base_url=API_BASE, headers=self._headers, timeout=30.0, transport=self._transport,
            follow_redirects=False,
        )
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json: Any = None,
        allow: Iterable[int] = (),
    ) -> httpx.Response:
        if self._client is None:
            raise RuntimeError("GitHubClient must be used as an async context manager")
        if path.startswith("http"):
            # Pagination links must stay on the API host.
            if urlparse(path).hostname != "api.github.com":
                raise GitHubApiError("GitHub returned a pagination link to an unexpected host.")
        allowed = set(allow)
        for attempt in range(4):
            try:
                response = await self._client.request(method, path, params=params, json=json)
            except httpx.HTTPError as exc:
                if attempt == 3:
                    raise GitHubApiError(f"Could not reach GitHub: {exc}") from exc
                await asyncio.sleep(2**attempt)
                continue
            status = response.status_code
            if status < 300 or status in allowed:
                return response
            remaining = response.headers.get("x-ratelimit-remaining")
            retry_after = response.headers.get("retry-after")
            if status == 403 and remaining == "0":
                reset = response.headers.get("x-ratelimit-reset")
                when = (
                    datetime.fromtimestamp(int(reset), tz=timezone.utc).strftime("%H:%M UTC")
                    if reset and reset.isdigit() else "later"
                )
                raise GitHubApiError(f"GitHub API rate limit exhausted; it resets at {when}.", 403)
            if (status in (429, 502, 503, 504) or (status == 403 and retry_after)) and attempt < 3:
                delay = min(int(retry_after), 30) if retry_after and retry_after.isdigit() else 2**attempt
                await asyncio.sleep(delay)
                continue
            raise GitHubApiError(_error_message(response), status)
        raise GitHubApiError("GitHub request failed after retries.")

    async def get_json(self, path: str, **kwargs: Any) -> Any:
        return (await self.request("GET", path, **kwargs)).json()

    async def paginate(
        self,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        items_key: Optional[str] = None,
        max_pages: int = MAX_PAGES,
    ) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        url: Optional[str] = path
        query: Optional[Dict[str, Any]] = {"per_page": 100, **(params or {})}
        for _ in range(max_pages):
            if url is None:
                break
            response = await self.request("GET", url, params=query)
            payload = response.json()
            batch = payload.get(items_key, []) if items_key else payload
            if not isinstance(batch, list):
                raise GitHubApiError("GitHub returned an unexpected list payload.")
            items.extend(item for item in batch if isinstance(item, dict))
            url = response.links.get("next", {}).get("url")
            query = None  # the next link already carries the query string
        return items


def _error_message(response: httpx.Response) -> str:
    status = response.status_code
    try:
        detail = str(response.json().get("message") or "")[:300]
    except ValueError:
        detail = ""
    if status == 401:
        return "GitHub rejected the credential (HTTP 401). Check that the token is valid and not expired."
    if status == 403:
        return f"GitHub denied access (HTTP 403){': ' + detail if detail else ''}."
    if status == 404:
        return f"GitHub resource not found or not accessible with this credential (HTTP 404)."
    return f"GitHub request failed (HTTP {status}){': ' + detail if detail else ''}."


# ══════════════════════════════════════════════════════════════════════════════
# GitHub App authentication
# ══════════════════════════════════════════════════════════════════════════════


def _load_private_key() -> Optional[str]:
    if settings.GITHUB_APP_PRIVATE_KEY:
        return settings.GITHUB_APP_PRIVATE_KEY.replace("\\n", "\n")
    if settings.GITHUB_APP_PRIVATE_KEY_PATH:
        try:
            return Path(settings.GITHUB_APP_PRIVATE_KEY_PATH).read_text()
        except OSError as exc:
            logger.error("Cannot read GitHub App private key: %s", exc)
    return None


def app_configured() -> bool:
    return bool(
        settings.GITHUB_APP_ID
        and settings.GITHUB_APP_SLUG
        and settings.GITHUB_APP_CLIENT_ID
        and settings.GITHUB_APP_CLIENT_SECRET
        and _load_private_key()
    )


def app_install_url(state: Optional[str] = None) -> Optional[str]:
    if not settings.GITHUB_APP_SLUG:
        return None
    base = f"{WEB_BASE}/apps/{quote(settings.GITHUB_APP_SLUG)}/installations/new"
    return f"{base}?{urlencode({'state': state})}" if state else base


def app_authorize_url(state: str) -> str:
    return f"{WEB_BASE}/login/oauth/authorize?" + urlencode(
        {"client_id": settings.GITHUB_APP_CLIENT_ID, "state": state}
    )


def _app_jwt() -> str:
    key = _load_private_key()
    if not (settings.GITHUB_APP_ID and key):
        raise GitHubApiError("The GitHub App is not configured on this platform.")
    now = int(time.time())
    # Backdate iat for clock drift; GitHub caps exp at 10 minutes.
    return jwt.encode(
        {"iat": now - 60, "exp": now + 540, "iss": str(settings.GITHUB_APP_ID)},
        key,
        algorithm="RS256",
    )


def _app_client() -> GitHubClient:
    return GitHubClient(_app_jwt(), scheme="Bearer")


async def create_installation_token(installation_id: int) -> str:
    """Mint a one-hour installation access token scoped to the installation."""
    async with _app_client() as client:
        response = await client.request("POST", f"/app/installations/{int(installation_id)}/access_tokens")
    token = response.json().get("token")
    if not token:
        raise GitHubApiError("GitHub did not return an installation access token.")
    return str(token)


async def get_app_installation(installation_id: int) -> Dict[str, Any]:
    async with _app_client() as client:
        return await client.get_json(f"/app/installations/{int(installation_id)}")


async def exchange_oauth_code(code: str) -> str:
    """Exchange a user-authorization code for a user-to-server token."""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{WEB_BASE}/login/oauth/access_token",
                data={
                    "client_id": settings.GITHUB_APP_CLIENT_ID,
                    "client_secret": settings.GITHUB_APP_CLIENT_SECRET,
                    "code": code,
                },
                headers={"Accept": "application/json"},
            )
    except httpx.HTTPError as exc:
        raise GitHubApiError(f"Could not reach GitHub to complete authorization: {exc}") from exc
    try:
        payload = response.json()
    except ValueError:
        payload = {}
    token = payload.get("access_token")
    if response.status_code != 200 or not token:
        raise GitHubApiError(
            "GitHub authorization failed"
            + (f": {payload.get('error_description')}" if payload.get("error_description") else ".")
            + " Start the install again from the Integrations page."
        )
    return str(token)


async def verify_installer(user_token: str, installation_id: int) -> Tuple[str, Dict[str, Any]]:
    """Confirm the authorizing user owns or administers the installation.

    Returns the user's GitHub login and the installation payload. Raises if the
    user cannot see the installation, or is not the owner of a user-account
    installation, or is not an active admin of an organization installation.
    """
    async with GitHubClient(user_token, scheme="Bearer") as client:
        user = await client.get_json("/user")
        installations = await client.paginate("/user/installations", items_key="installations", max_pages=20)
        installation = next(
            (item for item in installations if int(item.get("id") or 0) == int(installation_id)), None
        )
        if installation is None:
            raise GitHubApiError(
                "Your GitHub account cannot access this installation, so it can't be linked."
            )
        account = installation.get("account") or {}
        if account.get("type") == "User":
            if int(account.get("id") or -1) != int(user.get("id") or -2):
                raise GitHubApiError("Only the account owner can link a GitHub App installation on a user account.")
        else:
            membership = await client.request(
                "GET", f"/user/memberships/orgs/{quote(str(account.get('login', '')))}", allow=(403, 404)
            )
            data = membership.json() if membership.status_code == 200 else {}
            if data.get("state") != "active" or data.get("role") != "admin":
                raise GitHubApiError(
                    f"Only an owner of the {account.get('login')} organization can link this installation."
                )
    return str(user.get("login")), installation


# ══════════════════════════════════════════════════════════════════════════════
# Install flow
# ══════════════════════════════════════════════════════════════════════════════


def _digest(state: str) -> str:
    return hashlib.sha256(state.encode()).hexdigest()


def start_app_install(db: Session, *, organization_id: int, user_id: int, options: Dict[str, Any]) -> Tuple[str, datetime]:
    if not app_configured():
        raise GitHubApiError("The GitHub App is not configured on this platform. Use a personal access token instead.")
    state = secrets.token_urlsafe(32)
    request = GitHubAppInstallRequest(
        state_digest=_digest(state),
        organization_id=organization_id,
        user_id=user_id,
        status="started",
        options=options,
        expires_at=datetime.utcnow() + INSTALL_REQUEST_TTL,
    )
    db.add(request)
    db.commit()
    return app_install_url(state) or "", request.expires_at


def _integration_from_installation(
    db: Session,
    request: GitHubAppInstallRequest,
    installation: Dict[str, Any],
    github_login: Optional[str],
) -> GitHubIntegration:
    installation_id = int(installation["id"])
    account = installation.get("account") or {}
    existing = db.query(GitHubIntegration).filter(GitHubIntegration.installation_id == installation_id).first()
    if existing and existing.organization_id != request.organization_id:
        raise GitHubApiError("This GitHub App installation is already linked to another account.", 409)
    integration = existing or db.query(GitHubIntegration).filter(
        GitHubIntegration.organization_id == request.organization_id,
        GitHubIntegration.auth_method == AUTH_METHOD_APP,
        GitHubIntegration.account_login == account.get("login"),
    ).first()
    options = request.options or {}
    if integration is None:
        integration = GitHubIntegration(
            organization_id=request.organization_id,
            auth_method=AUTH_METHOD_APP,
            account_login=str(account.get("login")),
            import_member_repos=bool(options.get("import_member_repos", True)),
            scan_secrets=bool(options.get("scan_secrets", True)),
            continuous_sync_enabled=bool(options.get("continuous_sync_enabled", True)),
            sync_interval_minutes=int(options.get("sync_interval_minutes", 1440)),
            allow_fix_pull_requests=False,
            is_active=True,
        )
        db.add(integration)
    integration.installation_id = installation_id
    integration.account_login = str(account.get("login"))
    integration.account_type = str(account.get("type") or "Organization")
    integration.account_id = account.get("id")
    integration.repository_selection = installation.get("repository_selection")
    integration.installed_by_user_id = request.user_id
    integration.installed_by_github_login = github_login
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = True
    integration.last_error = None
    db.flush()
    request.status = "linked"
    request.integration_id = integration.id
    request.installation_id = installation_id
    return integration


async def handle_app_callback(
    db: Session,
    *,
    organization_id: int,
    user_id: int,
    state: str,
    installation_id: Optional[int],
    setup_action: Optional[str],
    code: Optional[str],
) -> Dict[str, Any]:
    request = db.query(GitHubAppInstallRequest).filter(
        GitHubAppInstallRequest.state_digest == _digest(state)
    ).first()
    if (
        request is None
        or request.user_id != user_id
        or request.organization_id != organization_id
    ):
        raise GitHubApiError("This GitHub install link is invalid. Start the install again from Integrations.", 400)
    if request.status == "linked":
        return {"status": "connected", "message": "GitHub is already connected.", "integration_id": request.integration_id}
    if request.status == "expired" or request.is_expired():
        request.status = "expired"
        db.commit()
        raise GitHubApiError("This GitHub install link has expired. Start the install again from Integrations.", 400)

    if installation_id and request.installation_id is None:
        request.installation_id = int(installation_id)
    if setup_action == "request":
        request.status = "requested"
        request.requested_at = request.requested_at or datetime.utcnow()

    if request.status == "requested" and request.installation_id is None:
        # A non-owner sent an install request. Capture their GitHub login so
        # the installation can be attributed once an owner approves it.
        if not code:
            db.commit()
            return {
                "status": "authorize",
                "message": "Authorize the App so the platform can link the installation once it is approved.",
                "authorize_url": app_authorize_url(state),
            }
        user_token = await exchange_oauth_code(code)
        async with GitHubClient(user_token, scheme="Bearer") as client:
            request.github_login = str((await client.get_json("/user")).get("login") or "") or None
        db.commit()
        return {
            "status": "requested",
            "message": (
                "Your install request was sent to the organization's owners. The platform links the "
                "installation when an owner approves it within 7 days."
            ),
        }

    if request.installation_id is None:
        raise GitHubApiError("GitHub did not return an installation. Start the install again from Integrations.", 400)
    if not code:
        db.commit()
        return {
            "status": "authorize",
            "message": "Authorize the App so the platform can confirm you own the installation.",
            "authorize_url": app_authorize_url(state),
        }

    user_token = await exchange_oauth_code(code)
    github_login, installation = await verify_installer(user_token, request.installation_id)
    try:
        integration = _integration_from_installation(db, request, installation, github_login)
        db.commit()
    except Exception:
        db.rollback()
        raise
    return {
        "status": "connected",
        "message": f"Connected GitHub {integration.account_type.lower()} {integration.account_login}.",
        "integration_id": integration.id,
    }


async def reconcile_install_requests(db: Session) -> int:
    """Link installations that owners approved after a member's request.

    An approved request creates an installation that nobody returned to the
    platform with. A pending request is matched to a new, unlinked installation
    when the requester is a member of the installation's organization and the
    installation was created after the request. Ambiguous matches (requests
    from more than one platform organization) are left for a manual restart.
    """
    now = datetime.utcnow()
    stale = db.query(GitHubAppInstallRequest).filter(
        GitHubAppInstallRequest.status.in_(("started", "requested")),
        GitHubAppInstallRequest.expires_at <= now,
    ).all()
    for request in stale:
        request.status = "expired"
    pending = db.query(GitHubAppInstallRequest).filter(
        GitHubAppInstallRequest.status == "requested",
        GitHubAppInstallRequest.github_login.isnot(None),
        GitHubAppInstallRequest.expires_at > now,
    ).all()
    db.commit()
    if not pending or not app_configured():
        return 0

    linked_ids = {
        row[0] for row in db.query(GitHubIntegration.installation_id).filter(
            GitHubIntegration.installation_id.isnot(None)
        ).all()
    }
    async with _app_client() as client:
        installations = await client.paginate("/app/installations", max_pages=50)

    earliest = min(request.requested_at or request.created_at for request in pending)
    linked = 0
    for installation in installations:
        installation_id = int(installation.get("id") or 0)
        account = installation.get("account") or {}
        created = _parse_datetime(installation.get("created_at"))
        if (
            not installation_id
            or installation_id in linked_ids
            or account.get("type") != "Organization"
            or created is None
            or created < earliest
        ):
            continue
        candidates = [
            request for request in pending
            if request.status == "requested" and (request.requested_at or request.created_at) <= created
        ]
        if not candidates:
            continue
        try:
            token = await create_installation_token(installation_id)
            matches = []
            async with GitHubClient(token) as client:
                for request in candidates:
                    response = await client.request(
                        "GET",
                        f"/orgs/{quote(str(account.get('login')))}/members/{quote(request.github_login)}",
                        allow=(302, 404),
                    )
                    if response.status_code == 204:
                        matches.append(request)
        except GitHubApiError as exc:
            logger.warning("GitHub install reconcile skipped installation %s: %s", installation_id, exc)
            continue
        if not matches:
            continue
        if len({request.organization_id for request in matches}) > 1:
            logger.warning(
                "GitHub installation %s matches install requests from several organizations; not linking.",
                installation_id,
            )
            continue
        request = matches[0]
        try:
            _integration_from_installation(db, request, installation, request.github_login)
            for other in matches[1:]:
                other.status = "linked"
                other.integration_id = request.integration_id
            db.commit()
            linked_ids.add(installation_id)
            linked += 1
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            logger.warning("Could not link GitHub installation %s: %s", installation_id, exc)
    return linked


# ══════════════════════════════════════════════════════════════════════════════
# Connection tests
# ══════════════════════════════════════════════════════════════════════════════


async def _token_for(integration: GitHubIntegration) -> str:
    if integration.auth_method == AUTH_METHOD_APP:
        if not integration.installation_id:
            raise GitHubApiError("This GitHub App connection has no installation.")
        return await create_installation_token(int(integration.installation_id))
    token = integration.get_token()
    if not token:
        raise GitHubApiError("No personal access token is stored for this connection.")
    return token


async def test_pat(token: str, account_login: str) -> Dict[str, Any]:
    """Validate a PAT against the target organization or user."""
    try:
        async with GitHubClient(token) as client:
            viewer = await client.get_json("/user")
            account = await client.get_json(f"/users/{quote(account_login)}")
            account_type = str(account.get("type") or "User")
            repos_path, params = _pat_repos_listing(account_type, account_login, str(viewer.get("login") or ""))
            await client.request("GET", repos_path, params={**params, "per_page": 1})
            members_accessible = False
            if account_type == "Organization":
                members = await client.request(
                    "GET", f"/orgs/{quote(account_login)}/members", params={"per_page": 1}, allow=(403, 404)
                )
                members_accessible = members.status_code == 200
        message = f"Connected to GitHub {account_type.lower()} {account.get('login')}."
        if account_type == "Organization" and not members_accessible:
            message += " The token can't list members, so member-owned repositories will be skipped."
        return {
            "ok": True,
            "message": message,
            "account_type": account_type,
            "account_login": str(account.get("login") or account_login),
            "account_id": account.get("id"),
            "repos_accessible": True,
            "members_accessible": members_accessible,
        }
    except GitHubApiError as exc:
        return {"ok": False, "message": str(exc), "repos_accessible": False, "members_accessible": False}


async def test_integration(integration: GitHubIntegration) -> Dict[str, Any]:
    if integration.auth_method == AUTH_METHOD_PAT:
        return await test_pat(integration.get_token() or "", integration.account_login)
    try:
        installation = await get_app_installation(int(integration.installation_id or 0))
        token = await create_installation_token(int(integration.installation_id or 0))
        async with GitHubClient(token) as client:
            await client.request("GET", "/installation/repositories", params={"per_page": 1})
        integration.repository_selection = installation.get("repository_selection")
        if installation.get("suspended_at"):
            return {"ok": False, "message": "The GitHub App installation is suspended.", "repos_accessible": False}
        return {
            "ok": True,
            "message": f"GitHub App installation on {integration.account_login} is active.",
            "account_type": integration.account_type,
            "repos_accessible": True,
            "members_accessible": "members" in (installation.get("permissions") or {}),
            "can_write": False,
        }
    except GitHubApiError as exc:
        message = str(exc)
        if exc.status_code == 404:
            message = "The GitHub App is no longer installed on this account. Install it again or remove the connection."
        return {"ok": False, "message": message, "repos_accessible": False}


# ══════════════════════════════════════════════════════════════════════════════
# Repository discovery
# ══════════════════════════════════════════════════════════════════════════════


def _pat_repos_listing(account_type: str, login: str, viewer_login: str) -> Tuple[str, Dict[str, Any]]:
    if account_type == "Organization":
        return f"/orgs/{quote(login)}/repos", {"type": "all"}
    if viewer_login and viewer_login.lower() == login.lower():
        # The token's own account: include private repositories.
        return "/user/repos", {"affiliation": "owner", "visibility": "all"}
    return f"/users/{quote(login)}/repos", {"type": "owner"}


def _parse_datetime(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


class _Stats:
    def __init__(self) -> None:
        self.repos_seen = 0
        self.assets_created = 0
        self.assets_updated = 0
        self.member_repos_seen = 0
        self.members_skipped = False
        self.repos_scanned = 0
        self.repos_scan_skipped = 0
        self.repos_scan_partial = 0
        self.files_scanned = 0
        self.secrets_created = 0
        self.secrets_updated = 0
        self.secrets_resolved = 0

    def as_dict(self) -> Dict[str, Any]:
        return vars(self).copy()


def _repo_metadata(repo: Dict[str, Any], integration: GitHubIntegration, *, member_owned: bool) -> Dict[str, Any]:
    owner = repo.get("owner") or {}
    return {
        "id": repo.get("id"),
        "full_name": repo.get("full_name"),
        "owner": owner.get("login"),
        "owner_type": owner.get("type"),
        "private": bool(repo.get("private")),
        "visibility": repo.get("visibility") or ("private" if repo.get("private") else "public"),
        "default_branch": repo.get("default_branch"),
        "archived": bool(repo.get("archived")),
        "fork": bool(repo.get("fork")),
        "language": repo.get("language"),
        "size_kb": repo.get("size"),
        "pushed_at": repo.get("pushed_at"),
        "html_url": repo.get("html_url"),
        "integration_id": integration.id,
        "auth_method": integration.auth_method,
        "member_owned": member_owned,
    }


def upsert_repository_asset(
    db: Session,
    integration: GitHubIntegration,
    repo: Dict[str, Any],
    stats: _Stats,
    *,
    member_owned: bool = False,
) -> Optional[Asset]:
    full_name = str(repo.get("full_name") or "").strip()
    if not _REPO_RE.match(full_name):
        return None
    value = repo_asset_value(full_name)
    asset = db.query(Asset).filter(
        Asset.organization_id == integration.organization_id, Asset.value == value
    ).first()
    metadata = dict(asset.metadata_ or {}) if asset else {}
    previous = metadata.get("github") or {}
    github_meta = _repo_metadata(repo, integration, member_owned=member_owned)
    # Preserve secret-scan bookkeeping across syncs.
    for key in ("last_scanned_pushed_at", "last_scan_complete", "last_scanned_at"):
        if key in previous:
            github_meta[key] = previous[key]
    metadata["github"] = github_meta
    is_public = not bool(repo.get("private"))
    if asset:
        asset.name = full_name[:255]
        asset.last_seen = datetime.utcnow()
        asset.is_public = is_public
        asset.metadata_ = metadata
        tags = list(asset.tags or [])
        if "source:github" not in tags:
            asset.tags = tags + ["source:github"]
        stats.assets_updated += 1
        return asset
    asset = Asset(
        name=full_name[:255],
        asset_type=AssetType.REPOSITORY,
        value=value,
        organization_id=integration.organization_id,
        # Member-owned repositories need review before they count as the org's.
        status=AssetStatus.PENDING if member_owned else AssetStatus.DISCOVERED,
        discovery_source=DISCOVERY_SOURCE,
        association_reason=(
            f"Public repository owned by a member of the {integration.account_login} GitHub organization"
            if member_owned
            else f"Repository in the {integration.account_login} GitHub {integration.account_type.lower()}"
        ),
        association_confidence=50 if member_owned else 100,
        tags=["source:github"] + (["github:member-owned"] if member_owned else []),
        metadata_=metadata,
        is_public=is_public,
    )
    db.add(asset)
    db.flush()
    stats.assets_created += 1
    return asset


async def list_repositories(client: GitHubClient, integration: GitHubIntegration) -> List[Dict[str, Any]]:
    if integration.auth_method == AUTH_METHOD_APP:
        return await client.paginate("/installation/repositories", items_key="repositories")
    viewer_login = ""
    if integration.account_type != "Organization":
        viewer_login = str((await client.get_json("/user")).get("login") or "")
    path, params = _pat_repos_listing(integration.account_type, integration.account_login, viewer_login)
    return await client.paginate(path, params=params)


async def list_member_repositories(
    client: GitHubClient, integration: GitHubIntegration
) -> Tuple[List[Dict[str, Any]], bool]:
    """Return public repos owned by org members, and whether members were skipped."""
    try:
        members = await client.paginate(
            f"/orgs/{quote(integration.account_login)}/members",
            max_pages=MAX_MEMBERS // 100,
        )
    except GitHubApiError as exc:
        if exc.status_code in (403, 404):
            logger.info("GitHub: cannot list members of %s; skipping member repos", integration.account_login)
            return [], True
        raise
    repos: List[Dict[str, Any]] = []
    for member in members[:MAX_MEMBERS]:
        login = str(member.get("login") or "")
        if not _LOGIN_RE.match(login):
            continue
        try:
            repos.extend(
                await client.paginate(
                    f"/users/{quote(login)}/repos", params={"type": "owner"}, max_pages=MAX_MEMBER_REPO_PAGES
                )
            )
        except GitHubApiError as exc:
            if exc.status_code in (403, 404):
                continue
            raise
    return [repo for repo in repos if not repo.get("private")], False


# ══════════════════════════════════════════════════════════════════════════════
# Secret scanning
# ══════════════════════════════════════════════════════════════════════════════


def _should_scan_path(path: str, size: int) -> bool:
    if size > MAX_BLOB_BYTES:
        return False
    parts = path.split("/")
    if any(part in _SKIP_DIRS for part in parts[:-1]):
        return False
    name = parts[-1].lower()
    return name in _SCAN_NAMES or name.startswith(".env") or name.endswith(_SCAN_EXTENSIONS)


_HIGH_RISK_EXTENSIONS = (".env", ".pem", ".key", ".tfvars", ".ipynb")
_CONFIG_EXTENSIONS = (
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".config",
    ".properties", ".xml", ".tf", ".sh", ".bash", ".ps1",
)


def _scan_priority(path: str) -> int:
    """Lower scans first, so a capped scan covers the likeliest secret files."""
    name = path.rsplit("/", 1)[-1].lower()
    if name in _SCAN_NAMES or name.startswith(".env") or name.endswith(_HIGH_RISK_EXTENSIONS):
        return 0
    if name.endswith(_CONFIG_EXTENSIONS) or "config" in name or "secret" in name or "settings" in name:
        return 1
    return 2 + path.count("/")  # shallower source files before deeply nested ones


def find_secrets(content: str, path: str) -> List[Dict[str, Any]]:
    """Return secret matches in one file's text, with full matched values."""
    findings: List[Dict[str, Any]] = []
    seen: set = set()
    for secret_type, regex in _SECRET_REGEXES.items():
        for match in regex.finditer(content):
            matched = match.group()
            if not is_likely_secret(matched, secret_type):
                continue
            key = (secret_type, matched)
            if key in seen:
                continue
            seen.add(key)
            config = SECRET_PATTERNS[secret_type]
            findings.append({
                "type": secret_type,
                "description": config["description"],
                "severity": config["severity"],
                "file": path,
                "line": content.count("\n", 0, match.start()) + 1,
                "match": matched,
            })
    return findings


async def scan_repository(
    client: GitHubClient, repo: Dict[str, Any], *, max_files: int = MAX_FILES_PER_REPO
) -> Tuple[List[Dict[str, Any]], bool, int]:
    """Scan a repository's default branch.

    Returns findings, whether every candidate file was scanned, and how many
    files were fetched. Files are scanned in risk order, so a capped scan still
    covers ``.env``/key/config files first.
    """
    full_name = str(repo["full_name"])
    branch = str(repo.get("default_branch") or "")
    if not branch:
        return [], True, 0
    response = await client.request(
        "GET",
        f"/repos/{full_name}/git/trees/{quote(branch, safe='')}",
        params={"recursive": "1"},
        allow=(404, 409),  # 409: empty repository
    )
    if response.status_code != 200:
        return [], response.status_code == 409, 0
    tree = response.json()
    candidates = sorted(
        (
            entry for entry in tree.get("tree") or []
            if entry.get("type") == "blob"
            and _should_scan_path(str(entry.get("path") or ""), int(entry.get("size") or 0))
        ),
        key=lambda entry: (_scan_priority(str(entry["path"])), str(entry["path"])),
    )
    selected = candidates[:max(0, max_files)]
    complete = not tree.get("truncated") and len(selected) == len(candidates)
    semaphore = asyncio.Semaphore(BLOB_CONCURRENCY)

    async def scan_blob(entry: Dict[str, Any]) -> List[Dict[str, Any]]:
        async with semaphore:
            blob = await client.get_json(f"/repos/{full_name}/git/blobs/{entry['sha']}")
        if blob.get("encoding") != "base64":
            return []
        raw = base64.b64decode(blob.get("content") or "")
        if b"\x00" in raw[:8000]:
            return []  # binary
        path = str(entry["path"])
        results = find_secrets(raw.decode("utf-8", errors="ignore"), path)
        for item in results:
            item["url"] = f"{WEB_BASE}/{full_name}/blob/{quote(branch)}/{quote(path)}#L{item['line']}"
            item["blob_sha"] = entry.get("sha")
        return results

    findings: List[Dict[str, Any]] = []
    for result in await asyncio.gather(
        *(scan_blob(entry) for entry in selected), return_exceptions=True
    ):
        if isinstance(result, GitHubApiError):
            complete = False
            logger.debug("GitHub blob fetch failed in %s: %s", full_name, result)
        elif isinstance(result, Exception):
            raise result
        else:
            findings.extend(result)
    return findings, complete, len(selected)


def _secret_template_id(finding: Dict[str, Any]) -> str:
    digest = hashlib.sha256(f"{finding['file']}\0{finding['match']}".encode()).hexdigest()[:24]
    return f"{SECRET_TEMPLATE_PREFIX}{finding['type']}:{digest}"[:255]


def store_secret_findings(
    db: Session,
    asset: Asset,
    repo: Dict[str, Any],
    findings: List[Dict[str, Any]],
    *,
    complete: bool,
    stats: _Stats,
) -> None:
    now = datetime.utcnow()
    full_name = str(repo.get("full_name"))
    existing = {
        vuln.template_id: vuln
        for vuln in db.query(Vulnerability).filter(
            Vulnerability.asset_id == asset.id,
            Vulnerability.detected_by == SECRET_DETECTOR,
            Vulnerability.template_id.like(f"{SECRET_TEMPLATE_PREFIX}%"),
        ).all()
    }
    seen: set = set()
    for finding in findings:
        template_id = _secret_template_id(finding)
        if template_id in seen:
            continue
        seen.add(template_id)
        severity: Severity = finding["severity"]
        evidence = (
            f"Matched value: {finding['match']}\n"
            f"Repository: {full_name}\nFile: {finding['file']}\nLine: {finding['line']}\n"
            f"URL: {finding.get('url')}"
        )
        metadata = {
            "source": DISCOVERY_SOURCE,
            "secret_type": finding["type"],
            "repository": full_name,
            "branch": repo.get("default_branch"),
            "file": finding["file"],
            "line": finding["line"],
            "url": finding.get("url"),
            "blob_sha": finding.get("blob_sha"),
            "contains_secret_value": True,
        }
        vuln = existing.get(template_id)
        if vuln is not None:
            vuln.last_detected = now
            vuln.evidence = evidence
            vuln.metadata_ = {**(vuln.metadata_ or {}), **metadata}
            if vuln.status in (VulnerabilityStatus.RESOLVED,):
                vuln.status = VulnerabilityStatus.OPEN
                vuln.resolved_at = None
            stats.secrets_updated += 1
            continue
        db.add(Vulnerability(
            title=f"Exposed {finding['description']} in {full_name}"[:500],
            description=(
                f"A {finding['description']} was found in {finding['file']} (line {finding['line']}) "
                f"on the default branch of the GitHub repository {full_name}."
            ),
            severity=severity,
            asset_id=asset.id,
            detected_by=SECRET_DETECTOR,
            template_id=template_id,
            status=VulnerabilityStatus.OPEN,
            evidence=evidence,
            affected_component=f"{full_name}:{finding['file']}"[:500],
            references=[finding["url"]] if finding.get("url") else [],
            remediation=(
                "1. Rotate or revoke the exposed credential immediately; assume it is compromised.\n"
                "2. Remove the secret from the repository and its history (git filter-repo or BFG).\n"
                "3. Load the value from a secret manager or environment variable instead.\n"
                "4. Enable push protection / pre-commit secret scanning to stop it recurring."
            ),
            first_detected=now,
            last_detected=now,
            tags=["source:github", "secret"],
            metadata_=metadata,
        ))
        stats.secrets_created += 1
    if complete:
        # Full coverage of the default branch: secrets no longer present are resolved.
        for template_id, vuln in existing.items():
            if template_id not in seen and vuln.status == VulnerabilityStatus.OPEN:
                vuln.status = VulnerabilityStatus.RESOLVED
                vuln.resolved_at = now
                stats.secrets_resolved += 1


# ══════════════════════════════════════════════════════════════════════════════
# Sync
# ══════════════════════════════════════════════════════════════════════════════


async def sync_integration(db: Session, integration: GitHubIntegration) -> Dict[str, Any]:
    stats = _Stats()
    try:
        token = await _token_for(integration)
        async with GitHubClient(token) as client:
            repos = await list_repositories(client, integration)
            stats.repos_seen = len(repos)
            owned: List[Tuple[Asset, Dict[str, Any]]] = []
            owned_values = set()
            for repo in repos:
                asset = upsert_repository_asset(db, integration, repo, stats)
                if asset is not None:
                    owned.append((asset, repo))
                    owned_values.add(asset.value)
            db.commit()

            if integration.import_member_repos and integration.account_type == "Organization":
                member_repos, stats.members_skipped = await list_member_repositories(client, integration)
                for repo in member_repos:
                    if repo_asset_value(str(repo.get("full_name") or "")) in owned_values:
                        continue
                    if upsert_repository_asset(db, integration, repo, stats, member_owned=True) is not None:
                        stats.member_repos_seen += 1
                db.commit()

            if integration.scan_secrets:
                for asset, repo in owned:
                    github_meta = (asset.metadata_ or {}).get("github") or {}
                    unchanged = (
                        github_meta.get("last_scan_complete")
                        and github_meta.get("last_scanned_pushed_at") == repo.get("pushed_at")
                    )
                    budget = MAX_BLOBS_PER_SYNC - stats.files_scanned
                    if unchanged or stats.repos_scanned >= MAX_REPOS_SCANNED_PER_SYNC or budget <= 0:
                        # Unchanged repos are done; the rest wait for the next sync.
                        stats.repos_scan_skipped += 1
                        continue
                    try:
                        findings, complete, files = await scan_repository(
                            client, repo, max_files=min(MAX_FILES_PER_REPO, budget)
                        )
                    except GitHubApiError as exc:
                        logger.warning("GitHub secret scan failed for %s: %s", repo.get("full_name"), exc)
                        stats.repos_scan_skipped += 1
                        continue
                    stats.files_scanned += files
                    if not complete:
                        stats.repos_scan_partial += 1
                    store_secret_findings(db, asset, repo, findings, complete=complete, stats=stats)
                    metadata = dict(asset.metadata_ or {})
                    metadata["github"] = {
                        **github_meta,
                        "last_scanned_pushed_at": repo.get("pushed_at"),
                        "last_scan_complete": complete,
                        "last_scanned_at": datetime.utcnow().isoformat(),
                    }
                    asset.metadata_ = metadata
                    stats.repos_scanned += 1
                    db.commit()

        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = True
        integration.last_error = None
        integration.last_sync_stats = stats.as_dict()
        db.commit()
        message = (
            f"Imported {stats.repos_seen} repositories"
            + (f" and {stats.member_repos_seen} member-owned repositories" if stats.member_repos_seen else "")
            + f" ({stats.assets_created} new assets)."
        )
        if integration.scan_secrets:
            message += (
                f" Scanned {stats.files_scanned} files in {stats.repos_scanned} repositories for secrets;"
                f" {stats.secrets_created} new secret(s)."
            )
            if stats.repos_scan_partial:
                message += (
                    f" {stats.repos_scan_partial} large repositories were only partly scanned "
                    "(highest-risk files first)."
                )
        if stats.members_skipped:
            message += " Member repositories were skipped: the credential can't list organization members."
        return {"ok": True, "message": message, **stats.as_dict()}
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.exception("GitHub sync failed for integration %s", integration.id)
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = str(exc)[:1000]
        db.commit()
        return {"ok": False, "message": f"Sync failed: {exc}", **stats.as_dict()}


# ══════════════════════════════════════════════════════════════════════════════
# Fix pull requests
# ══════════════════════════════════════════════════════════════════════════════


def _branch_name(vulnerability_id: int) -> str:
    return f"judah/fix-{vulnerability_id}-{secrets.token_hex(3)}"


async def create_fix_pull_request(
    db: Session,
    integration: GitHubIntegration,
    vulnerability: Vulnerability,
    *,
    repository: Optional[str],
    title: str,
    body: Optional[str],
    base_branch: Optional[str],
    commit_message: Optional[str],
    changes: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Open a pull request with a patch. Never merges."""
    if not integration.can_open_pull_requests:
        raise GitHubApiError(
            "This GitHub connection is read-only. Fix pull requests need a personal access token "
            "connection with 'Allow fix pull requests' enabled.",
            400,
        )
    asset = vulnerability.asset
    if asset is None or asset.organization_id != integration.organization_id:
        raise GitHubApiError("The finding does not belong to this GitHub connection's organization.", 404)
    full_name = (
        repository
        or (vulnerability.metadata_ or {}).get("repository")
        or ((asset.metadata_ or {}).get("github") or {}).get("full_name")
        or ""
    ).strip()
    if not _REPO_RE.match(full_name):
        raise GitHubApiError("Specify the repository (owner/name) for the pull request.", 400)
    repo_asset = db.query(Asset).filter(
        Asset.organization_id == integration.organization_id,
        Asset.value == repo_asset_value(full_name),
        Asset.asset_type == AssetType.REPOSITORY,
    ).first()
    if repo_asset is None or ((repo_asset.metadata_ or {}).get("github") or {}).get("member_owned"):
        raise GitHubApiError("Pull requests can only target repositories imported by this connection.", 400)
    paths = [validate_repo_path(change["path"]) for change in changes]
    if len(set(paths)) != len(paths):
        raise GitHubApiError("The change set lists the same file more than once.", 400)

    async with GitHubClient(await _token_for(integration)) as client:
        repo = await client.get_json(f"/repos/{full_name}")
        if not (repo.get("permissions") or {}).get("push"):
            raise GitHubApiError(
                f"The token can't write to {full_name}. Grant Contents and Pull requests write access.", 403
            )
        base = base_branch or str(repo.get("default_branch") or "main")
        ref = await client.get_json(f"/repos/{full_name}/git/ref/heads/{quote(base, safe='/')}")
        base_sha = ref["object"]["sha"]
        base_commit = await client.get_json(f"/repos/{full_name}/git/commits/{base_sha}")
        tree_entries = [
            {"path": path, "mode": "100644", "type": "blob",
             **({"content": change["content"]} if change.get("content") is not None else {"sha": None})}
            for path, change in zip(paths, changes)
        ]
        tree = (await client.request(
            "POST", f"/repos/{full_name}/git/trees",
            json={"base_tree": base_commit["tree"]["sha"], "tree": tree_entries},
        )).json()
        commit = (await client.request(
            "POST", f"/repos/{full_name}/git/commits",
            json={
                "message": commit_message or f"Fix: {vulnerability.title}"[:1000],
                "tree": tree["sha"],
                "parents": [base_sha],
            },
        )).json()
        branch = _branch_name(vulnerability.id)
        await client.request(
            "POST", f"/repos/{full_name}/git/refs",
            json={"ref": f"refs/heads/{branch}", "sha": commit["sha"]},
        )
        pull = (await client.request(
            "POST", f"/repos/{full_name}/pulls",
            json={
                "title": title,
                "head": branch,
                "base": base,
                "body": body or f"Automated fix for finding #{vulnerability.id}: {vulnerability.title}",
                "maintainer_can_modify": True,
            },
        )).json()

    result = {
        "number": int(pull["number"]),
        "html_url": str(pull["html_url"]),
        "branch": branch,
        "repository": full_name,
    }
    metadata = dict(vulnerability.metadata_ or {})
    metadata["github_pull_request"] = {
        **result,
        "integration_id": integration.id,
        "created_at": datetime.utcnow().isoformat(),
    }
    vulnerability.metadata_ = metadata
    db.commit()
    return result
