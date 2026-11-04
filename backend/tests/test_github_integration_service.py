"""GitHub source-code-manager integration (mocked GitHub REST API)."""

import base64
import functools
from datetime import datetime, timedelta

import pytest

httpx = pytest.importorskip("httpx")

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.db.database import Base  # noqa: E402
import app.models  # noqa: E402,F401
from app.models.asset import Asset, AssetStatus, AssetType  # noqa: E402
from app.models.github_integration import (  # noqa: E402
    AUTH_METHOD_APP,
    AUTH_METHOD_PAT,
    GitHubAppInstallRequest,
    GitHubIntegration,
)
from app.models.organization import Organization  # noqa: E402
from app.models.user import User  # noqa: E402
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus  # noqa: E402
from app.services import github_integration_service as gh  # noqa: E402
from app.services.github_integration_service import GitHubApiError, GitHubClient  # noqa: E402

AWS_KEY = "AKIAQWERTYUIOPLKJHGF"


# ── Fake GitHub ──────────────────────────────────────────────────────────────


class FakeGitHub:
    """Routes ``(METHOD, path)`` to canned JSON; records every request."""

    def __init__(self):
        self.routes = {}
        self.calls = []

    def add(self, method, path, body=None, status=200, headers=None):
        self.routes[(method, path)] = (status, body, headers or {})

    def handler(self, request):
        self.calls.append((request.method, request.url.path, request))
        route = self.routes.get((request.method, request.url.path))
        if route is None:
            return httpx.Response(404, json={"message": "Not Found"})
        status, body, headers = route
        if callable(body):
            body = body(request)
        return httpx.Response(status, json=body, headers=headers) if body is not None else httpx.Response(status, headers=headers)

    @property
    def transport(self):
        return httpx.MockTransport(self.handler)


@pytest.fixture()
def fake(monkeypatch):
    fake = FakeGitHub()
    monkeypatch.setattr(gh, "GitHubClient", functools.partial(GitHubClient, transport=fake.transport))
    return fake


@pytest.fixture()
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=[
        Organization.__table__, User.__table__, Asset.__table__, Vulnerability.__table__,
        GitHubIntegration.__table__, GitHubAppInstallRequest.__table__,
    ])
    session = sessionmaker(bind=engine)()
    session.add_all([Organization(id=1, name="Acme"), Organization(id=2, name="Other")])
    session.add_all([
        User(id=1, email="a@acme.test", username="a", hashed_password="x", organization_id=1),
        User(id=2, email="b@other.test", username="b", hashed_password="x", organization_id=2),
    ])
    session.commit()
    yield session
    session.close()


def _repo(full_name, *, private=False, pushed_at="2026-11-01T00:00:00Z", owner_type="Organization"):
    owner = full_name.split("/")[0]
    return {
        "id": abs(hash(full_name)) % 10**8,
        "full_name": full_name,
        "private": private,
        "visibility": "private" if private else "public",
        "default_branch": "main",
        "archived": False,
        "fork": False,
        "language": "Python",
        "size": 10,
        "pushed_at": pushed_at,
        "html_url": f"https://github.com/{full_name}",
        "owner": {"login": owner, "type": owner_type},
    }


def _b64(text):
    return {"encoding": "base64", "content": base64.b64encode(text.encode()).decode()}


# ── Input normalization ──────────────────────────────────────────────────────


@pytest.mark.parametrize("value", [
    "github.com/acme", "https://github.com/acme", "https://github.com/acme/", "acme",
    "https://www.github.com/acme/some-repo", "https://github.com/orgs/acme/people",
])
def test_parse_account_login_accepts_github_forms(value):
    assert gh.parse_account_login(value) == "acme"


@pytest.mark.parametrize("value", [
    "", "https://gitlab.com/acme", "https://github.com.evil.test/acme", "ftp://github.com/acme",
    "https://github.com/", "acme/../x", "-bad",
])
def test_parse_account_login_rejects_other_hosts_and_junk(value):
    with pytest.raises(GitHubApiError):
        gh.parse_account_login(value)


@pytest.mark.parametrize("path", ["../etc/passwd", "/abs", "a//b", ".git/config", "a/./b", "a\\b", ""])
def test_validate_repo_path_rejects_escapes(path):
    with pytest.raises(GitHubApiError):
        gh.validate_repo_path(path)


def test_validate_repo_path_accepts_normal_paths():
    assert gh.validate_repo_path("src/app/config.py") == "src/app/config.py"


def test_find_secrets_reports_full_value_and_line():
    findings = gh.find_secrets(f"x = 1\nkey = '{AWS_KEY}'\n", "settings.py")
    aws = [item for item in findings if item["type"] == "aws_access_key"]
    assert aws and aws[0]["match"] == AWS_KEY and aws[0]["line"] == 2
    assert aws[0]["severity"] == Severity.CRITICAL


def test_find_secrets_ignores_placeholders():
    assert not [f for f in gh.find_secrets("AKIAEXAMPLEEXAMPLE12", "a.py") if f["type"] == "aws_access_key"]


def test_should_scan_path_filters_vendored_binary_and_large_files():
    assert gh._should_scan_path("config/.env.production", 100)
    assert gh._should_scan_path("src/settings.py", 100)
    assert not gh._should_scan_path("node_modules/pkg/index.js", 100)
    assert not gh._should_scan_path("assets/logo.png", 100)
    assert not gh._should_scan_path("src/big.json", gh.MAX_BLOB_BYTES + 1)


# ── Client ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_client_follows_link_pagination():
    def handler(request):
        page = request.url.params.get("page", "1")
        if page == "1":
            return httpx.Response(200, json=[{"id": 1}], headers={
                "link": '<https://api.github.com/orgs/acme/repos?per_page=100&page=2>; rel="next"'
            })
        return httpx.Response(200, json=[{"id": 2}])

    async with GitHubClient("t", transport=httpx.MockTransport(handler)) as client:
        items = await client.paginate("/orgs/acme/repos")
    assert [item["id"] for item in items] == [1, 2]


@pytest.mark.asyncio
async def test_client_refuses_pagination_to_other_hosts():
    def handler(request):
        return httpx.Response(200, json=[{"id": 1}], headers={"link": '<https://evil.test/x>; rel="next"'})

    async with GitHubClient("t", transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(GitHubApiError):
            await client.paginate("/orgs/acme/repos")


@pytest.mark.asyncio
async def test_client_reports_rate_limit_exhaustion():
    def handler(request):
        return httpx.Response(403, json={"message": "rate"}, headers={"x-ratelimit-remaining": "0"})

    async with GitHubClient("t", transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(GitHubApiError, match="rate limit"):
            await client.get_json("/user")


# ── Installer verification ───────────────────────────────────────────────────


def _installer_fake(fake, account, membership=None, visible=True):
    fake.routes.clear()
    fake.add("GET", "/user", {"login": "octo", "id": 7})
    fake.add("GET", "/user/installations", {
        "installations": [{"id": 55, "account": account, "repository_selection": "selected"}] if visible else []
    })
    if membership is not None:
        fake.add("GET", f"/user/memberships/orgs/{account['login']}", membership)


@pytest.mark.asyncio
async def test_verify_installer_accepts_org_admin(fake):
    _installer_fake(fake, {"login": "acme", "type": "Organization", "id": 9}, {"state": "active", "role": "admin"})
    login, installation = await gh.verify_installer("user-token", 55)
    assert login == "octo" and installation["id"] == 55


@pytest.mark.asyncio
async def test_verify_installer_rejects_org_member(fake):
    _installer_fake(fake, {"login": "acme", "type": "Organization", "id": 9}, {"state": "active", "role": "member"})
    with pytest.raises(GitHubApiError, match="owner"):
        await gh.verify_installer("user-token", 55)


@pytest.mark.asyncio
async def test_verify_installer_rejects_invisible_installation(fake):
    _installer_fake(fake, {"login": "acme", "type": "Organization", "id": 9}, visible=False)
    with pytest.raises(GitHubApiError, match="cannot access"):
        await gh.verify_installer("user-token", 55)


@pytest.mark.asyncio
async def test_verify_installer_user_account_must_match(fake):
    _installer_fake(fake, {"login": "someone", "type": "User", "id": 8})
    with pytest.raises(GitHubApiError):
        await gh.verify_installer("user-token", 55)
    _installer_fake(fake, {"login": "octo", "type": "User", "id": 7})
    login, _ = await gh.verify_installer("user-token", 55)
    assert login == "octo"


# ── PAT validation ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_pat_without_member_access_still_connects(fake):
    fake.add("GET", "/user", {"login": "octo"})
    fake.add("GET", "/users/acme", {"login": "Acme", "type": "Organization", "id": 9})
    fake.add("GET", "/orgs/acme/repos", [])
    fake.add("GET", "/orgs/acme/members", {"message": "forbidden"}, status=403)
    result = await gh.test_pat("pat", "acme")
    assert result["ok"] and result["account_type"] == "Organization"
    assert result["account_login"] == "Acme"
    assert result["members_accessible"] is False
    assert "member-owned" in result["message"]


@pytest.mark.asyncio
async def test_pat_rejected_token(fake):
    fake.add("GET", "/user", {"message": "Bad credentials"}, status=401)
    result = await gh.test_pat("bad", "acme")
    assert result["ok"] is False and "401" in result["message"]


# ── Sync ─────────────────────────────────────────────────────────────────────


def _pat_integration(db, **overrides):
    integration = GitHubIntegration(
        organization_id=1, auth_method=AUTH_METHOD_PAT, account_login="acme",
        account_type="Organization", **overrides,
    )
    integration.set_token("pat")
    db.add(integration)
    db.commit()
    return integration


def _org_fake(fake, *, secret_file_text, pushed_at="2026-11-01T00:00:00Z"):
    fake.add("GET", "/orgs/acme/repos", [
        _repo("acme/api", pushed_at=pushed_at), _repo("acme/private-infra", private=True),
    ])
    fake.add("GET", "/orgs/acme/members", [{"login": "dev1"}])
    fake.add("GET", "/users/dev1/repos", [
        _repo("dev1/dotfiles", owner_type="User"), _repo("dev1/secret", private=True, owner_type="User"),
    ])
    fake.add("GET", "/repos/acme/api/git/trees/main", {"truncated": False, "tree": [
        {"path": "config/settings.py", "type": "blob", "size": 60, "sha": "b1"},
        {"path": "node_modules/x/index.js", "type": "blob", "size": 60, "sha": "b2"},
        {"path": "logo.png", "type": "blob", "size": 60, "sha": "b3"},
    ]})
    fake.add("GET", "/repos/acme/api/git/blobs/b1", _b64(secret_file_text))
    fake.add("GET", "/repos/acme/private-infra/git/trees/main", {"message": "empty"}, status=409)


@pytest.mark.asyncio
async def test_sync_imports_repos_member_repos_and_secrets(db, fake):
    integration = _pat_integration(db)
    _org_fake(fake, secret_file_text=f"AWS_KEY = '{AWS_KEY}'\n")

    result = await gh.sync_integration(db, integration)

    assert result["ok"], result["message"]
    assets = {a.value: a for a in db.query(Asset).all()}
    assert set(assets) == {
        "https://github.com/acme/api", "https://github.com/acme/private-infra", "https://github.com/dev1/dotfiles",
    }
    api = assets["https://github.com/acme/api"]
    assert api.asset_type == AssetType.REPOSITORY and api.status == AssetStatus.DISCOVERED
    assert api.is_public is True
    assert assets["https://github.com/acme/private-infra"].is_public is False
    member = assets["https://github.com/dev1/dotfiles"]
    assert member.status == AssetStatus.PENDING and member.metadata_["github"]["member_owned"] is True

    vulns = db.query(Vulnerability).all()
    assert len(vulns) == 1 and vulns[0].asset_id == api.id
    assert AWS_KEY in vulns[0].evidence  # full value, as documented
    assert vulns[0].metadata_["file"] == "config/settings.py"
    # Vendored and binary paths are never fetched.
    fetched = {path for _, path, _ in fake.calls}
    assert "/repos/acme/api/git/blobs/b2" not in fetched and "/repos/acme/api/git/blobs/b3" not in fetched
    assert result["repos_scanned"] == 2 and result["secrets_created"] == 1
    assert integration.last_sync_ok is True


@pytest.mark.asyncio
async def test_resync_skips_unchanged_repos_and_resolves_removed_secrets(db, fake):
    integration = _pat_integration(db)
    _org_fake(fake, secret_file_text=f"AWS_KEY = '{AWS_KEY}'\n")
    await gh.sync_integration(db, integration)

    unchanged = await gh.sync_integration(db, integration)
    assert unchanged["repos_scanned"] == 0 and unchanged["repos_scan_skipped"] == 2

    _org_fake(fake, secret_file_text="AWS_KEY = os.environ['AWS_KEY']\n", pushed_at="2026-11-03T00:00:00Z")
    result = await gh.sync_integration(db, integration)
    assert result["secrets_resolved"] == 1
    assert db.query(Vulnerability).one().status == VulnerabilityStatus.RESOLVED


@pytest.mark.asyncio
async def test_sync_skips_members_without_permission(db, fake):
    integration = _pat_integration(db, scan_secrets=False)
    fake.add("GET", "/orgs/acme/repos", [_repo("acme/api")])
    fake.add("GET", "/orgs/acme/members", {"message": "forbidden"}, status=403)
    result = await gh.sync_integration(db, integration)
    assert result["ok"] and result["members_skipped"] is True
    assert db.query(Asset).count() == 1


@pytest.mark.asyncio
async def test_sync_records_failure(db, fake):
    integration = _pat_integration(db)
    fake.add("GET", "/orgs/acme/repos", {"message": "Bad credentials"}, status=401)
    result = await gh.sync_integration(db, integration)
    assert result["ok"] is False
    assert integration.last_sync_ok is False and "401" in integration.last_error


# ── App install flow ─────────────────────────────────────────────────────────


@pytest.fixture()
def app_settings(monkeypatch):
    for key, value in {
        "GITHUB_APP_ID": "123", "GITHUB_APP_SLUG": "judah-guard", "GITHUB_APP_CLIENT_ID": "Iv1.abc",
        "GITHUB_APP_CLIENT_SECRET": "s", "GITHUB_APP_PRIVATE_KEY": "pem",
    }.items():
        monkeypatch.setattr(gh.settings, key, value)


def _state_from(url):
    return httpx.URL(url).params["state"]


@pytest.mark.asyncio
async def test_owner_install_links_after_authorization(db, app_settings, monkeypatch):
    url, _ = gh.start_app_install(db, organization_id=1, user_id=1, options={"scan_secrets": False})
    assert url.startswith("https://github.com/apps/judah-guard/installations/new?state=")
    state = _state_from(url)
    stored = db.query(GitHubAppInstallRequest).one()
    assert stored.state_digest != state  # only the digest is stored

    first = await gh.handle_app_callback(
        db, organization_id=1, user_id=1, state=state, installation_id=55, setup_action="install", code=None
    )
    assert first["status"] == "authorize" and "client_id=Iv1.abc" in first["authorize_url"]

    async def fake_exchange(code):
        return "user-token"

    async def fake_verify(token, installation_id):
        return "octo", {"id": installation_id, "repository_selection": "selected",
                        "account": {"login": "acme", "type": "Organization", "id": 9}}

    monkeypatch.setattr(gh, "exchange_oauth_code", fake_exchange)
    monkeypatch.setattr(gh, "verify_installer", fake_verify)
    done = await gh.handle_app_callback(
        db, organization_id=1, user_id=1, state=state, installation_id=None, setup_action=None, code="c"
    )
    assert done["status"] == "connected"
    integration = db.query(GitHubIntegration).one()
    assert integration.auth_method == AUTH_METHOD_APP and integration.installation_id == 55
    assert integration.pat_encrypted is None and integration.scan_secrets is False
    assert integration.installed_by_github_login == "octo"
    assert integration.can_open_pull_requests is False

    # The same installation can't be attached to another platform organization.
    url2, _ = gh.start_app_install(db, organization_id=2, user_id=2, options={})
    with pytest.raises(GitHubApiError) as err:
        await gh.handle_app_callback(
            db, organization_id=2, user_id=2, state=_state_from(url2), installation_id=55,
            setup_action="install", code="c",
        )
    assert err.value.status_code == 409


@pytest.mark.asyncio
async def test_callback_rejects_other_users_state_and_expired_state(db, app_settings):
    url, _ = gh.start_app_install(db, organization_id=1, user_id=1, options={})
    with pytest.raises(GitHubApiError, match="invalid"):
        await gh.handle_app_callback(
            db, organization_id=2, user_id=2, state=_state_from(url), installation_id=55,
            setup_action="install", code="c",
        )
    db.query(GitHubAppInstallRequest).one().expires_at = datetime.utcnow() - timedelta(seconds=1)
    db.commit()
    with pytest.raises(GitHubApiError, match="expired"):
        await gh.handle_app_callback(
            db, organization_id=1, user_id=1, state=_state_from(url), installation_id=55,
            setup_action="install", code="c",
        )


@pytest.mark.asyncio
async def test_member_request_is_recorded_then_linked_on_approval(db, app_settings, monkeypatch, fake):
    url, _ = gh.start_app_install(db, organization_id=1, user_id=1, options={})
    state = _state_from(url)
    prompt = await gh.handle_app_callback(
        db, organization_id=1, user_id=1, state=state, installation_id=None, setup_action="request", code=None
    )
    assert prompt["status"] == "authorize"

    async def fake_exchange(code):
        return "user-token"

    monkeypatch.setattr(gh, "exchange_oauth_code", fake_exchange)
    fake.add("GET", "/user", {"login": "member1", "id": 3})
    requested = await gh.handle_app_callback(
        db, organization_id=1, user_id=1, state=state, installation_id=None, setup_action=None, code="c"
    )
    assert requested["status"] == "requested"
    request = db.query(GitHubAppInstallRequest).one()
    assert request.status == "requested" and request.github_login == "member1"

    # Owner approves: a new installation appears; the requester is an org member.
    monkeypatch.setattr(gh, "_app_jwt", lambda: "app-jwt")

    async def fake_installation_token(installation_id):
        return "inst-token"

    monkeypatch.setattr(gh, "create_installation_token", fake_installation_token)
    created = (datetime.utcnow() + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    fake.add("GET", "/app/installations", [
        {"id": 77, "created_at": created, "repository_selection": "all",
         "account": {"login": "acme", "type": "Organization", "id": 9}},
    ])
    fake.add("GET", "/orgs/acme/members/member1", None, status=204)

    assert await gh.reconcile_install_requests(db) == 1
    integration = db.query(GitHubIntegration).one()
    assert integration.installation_id == 77 and integration.organization_id == 1
    assert db.query(GitHubAppInstallRequest).one().status == "linked"
    # Idempotent.
    assert await gh.reconcile_install_requests(db) == 0


@pytest.mark.asyncio
async def test_reconcile_expires_stale_requests(db, app_settings):
    db.add(GitHubAppInstallRequest(
        state_digest="d" * 64, organization_id=1, user_id=1, status="requested", github_login="m",
        expires_at=datetime.utcnow() - timedelta(days=1),
    ))
    db.commit()
    assert await gh.reconcile_install_requests(db) == 0
    assert db.query(GitHubAppInstallRequest).one().status == "expired"


# ── Fix pull requests ────────────────────────────────────────────────────────


def _repo_with_secret(db, integration):
    asset = Asset(
        name="acme/api", value="https://github.com/acme/api", asset_type=AssetType.REPOSITORY,
        organization_id=1, metadata_={"github": {"full_name": "acme/api", "member_owned": False}},
    )
    db.add(asset)
    db.flush()
    vuln = Vulnerability(
        title="Exposed AWS Access Key ID in acme/api", severity=Severity.CRITICAL, asset_id=asset.id,
        detected_by=gh.SECRET_DETECTOR, metadata_={"repository": "acme/api"},
    )
    db.add(vuln)
    db.commit()
    return vuln


@pytest.mark.asyncio
async def test_fix_pull_request_requires_opt_in(db):
    integration = _pat_integration(db)
    vuln = _repo_with_secret(db, integration)
    with pytest.raises(GitHubApiError, match="read-only"):
        await gh.create_fix_pull_request(
            db, integration, vuln, repository=None, title="Fix", body=None, base_branch=None,
            commit_message=None, changes=[{"path": "a.py", "content": "x"}],
        )


@pytest.mark.asyncio
async def test_fix_pull_request_opens_pr_without_merging(db, fake):
    integration = _pat_integration(db, allow_fix_pull_requests=True)
    vuln = _repo_with_secret(db, integration)
    fake.add("GET", "/repos/acme/api", {"default_branch": "main", "permissions": {"push": True}})
    fake.add("GET", "/repos/acme/api/git/ref/heads/main", {"object": {"sha": "base"}})
    fake.add("GET", "/repos/acme/api/git/commits/base", {"tree": {"sha": "tree0"}})
    fake.add("POST", "/repos/acme/api/git/trees", {"sha": "tree1"}, status=201)
    fake.add("POST", "/repos/acme/api/git/commits", {"sha": "commit1"}, status=201)
    fake.add("POST", "/repos/acme/api/git/refs", {"ref": "x"}, status=201)
    fake.add("POST", "/repos/acme/api/pulls", {"number": 42, "html_url": "https://github.com/acme/api/pull/42"}, status=201)

    result = await gh.create_fix_pull_request(
        db, integration, vuln, repository=None, title="Remove hardcoded key", body=None, base_branch=None,
        commit_message=None, changes=[{"path": "config/settings.py", "content": "KEY = os.environ['K']\n"}],
    )

    assert result["number"] == 42 and result["branch"].startswith(f"judah/fix-{vuln.id}-")
    assert vuln.metadata_["github_pull_request"]["html_url"].endswith("/pull/42")
    methods = [(method, path) for method, path, _ in fake.calls]
    assert not any("merge" in path for _, path in methods)
    assert ("PUT", "/repos/acme/api/pulls/42/merge") not in methods


@pytest.mark.asyncio
async def test_fix_pull_request_only_targets_imported_repos(db, fake):
    integration = _pat_integration(db, allow_fix_pull_requests=True)
    vuln = _repo_with_secret(db, integration)
    with pytest.raises(GitHubApiError, match="imported"):
        await gh.create_fix_pull_request(
            db, integration, vuln, repository="someone/else", title="x", body=None, base_branch=None,
            commit_message=None, changes=[{"path": "a.py", "content": "x"}],
        )
    with pytest.raises(GitHubApiError, match="Invalid file path"):
        await gh.create_fix_pull_request(
            db, integration, vuln, repository=None, title="x", body=None, base_branch=None,
            commit_message=None, changes=[{"path": "../a.py", "content": "x"}],
        )


def test_app_jwt_is_rs256_signed_with_the_app_key(monkeypatch):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from jose import jwt

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    monkeypatch.setattr(gh.settings, "GITHUB_APP_ID", "123")
    monkeypatch.setattr(gh.settings, "GITHUB_APP_PRIVATE_KEY", pem.replace("\n", "\\n"))

    claims = jwt.decode(gh._app_jwt(), public, algorithms=["RS256"])
    assert claims["iss"] == "123" and 0 < claims["exp"] - claims["iat"] <= 600
