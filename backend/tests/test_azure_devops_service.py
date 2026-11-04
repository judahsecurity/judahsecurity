"""Azure DevOps source code manager integration (mocked REST API)."""

import asyncio
import base64
import os
from urllib.parse import parse_qs

import pytest

httpx = pytest.importorskip("httpx")

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.db.database import Base  # noqa: E402
import app.models  # noqa: E402,F401
from app.models.asset import Asset, AssetType  # noqa: E402
from app.models.organization import Organization  # noqa: E402
from app.models.scan import Scan, ScanType  # noqa: E402
from app.models.scm_integration import SourceCodeManagerIntegration  # noqa: E402
from app.services import azure_devops_service as ado  # noqa: E402
from app.services.azure_devops_service import (  # noqa: E402
    AzureDevOpsClient,
    AzureDevOpsError,
    _git_env,
    _PatAuth,
    _retry_after_seconds,
    discover_repositories,
    parse_scope_url,
    repository_web_url,
    safe_clone_url,
)


def run(coro):
    return asyncio.run(coro)


async def _no_sleep(_seconds):
    return None


def _repo(name, project="Web", **extra):
    return {
        "id": f"id-{name}",
        "name": name,
        "webUrl": f"https://dev.azure.com/acme/{project}/_git/{name}",
        "remoteUrl": f"https://acme@dev.azure.com/acme/{project}/_git/{name}",
        "defaultBranch": "refs/heads/main",
        "size": 1024,
        "project": {"id": f"pid-{project}", "name": project, "visibility": "private"},
        **extra,
    }


# ── Scope URL parsing ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "url, org, project",
    [
        ("https://dev.azure.com/acme", "acme", None),
        ("https://dev.azure.com/acme/", "acme", None),
        ("https://dev.azure.com/acme/Web%20Platform", "acme", "Web Platform"),
        ("https://dev.azure.com/acme/Web/_git/frontend", "acme", "Web"),
        ("https://dev.azure.com/acme/_settings/users", "acme", None),
        ("  https://DEV.AZURE.COM/acme  ", "acme", None),
    ],
)
def test_parse_scope_url_accepts_org_project_and_repo_urls(url, org, project):
    scope = parse_scope_url(url)
    assert (scope.organization, scope.project) == (org, project)


@pytest.mark.parametrize(
    "url",
    [
        "http://dev.azure.com/acme",
        "https://dev.azure.com",
        "https://dev.azure.com.attacker.example/acme",
        "https://user:pat@dev.azure.com/acme",
        "https://dev.azure.com:8443/acme",
        "https://tfs.acme.internal/tfs/DefaultCollection",
        "https://dev.azure.com/-bad-",
        "not a url",
    ],
)
def test_parse_scope_url_rejects_invalid_urls(url):
    with pytest.raises(AzureDevOpsError, match="valid Azure DevOps"):
        parse_scope_url(url)


def test_parse_scope_url_rejects_legacy_visualstudio_urls():
    with pytest.raises(AzureDevOpsError, match="visualstudio.com"):
        parse_scope_url("https://acme.visualstudio.com/Web")


def test_scope_url_is_canonicalised():
    assert parse_scope_url("https://dev.azure.com/acme/Web Platform/_git/x").url == (
        "https://dev.azure.com/acme/Web%20Platform"
    )


# ── Helpers ───────────────────────────────────────────────────────────────────


def test_retry_after_defaults_and_caps():
    assert _retry_after_seconds(None) == 10
    assert _retry_after_seconds("3") == 3
    assert _retry_after_seconds("9999") == 120
    assert _retry_after_seconds("garbage") == 10


def test_web_and_clone_urls_strip_userinfo_and_stay_in_org():
    repo = _repo("api")
    assert repository_web_url("acme", repo) == "https://dev.azure.com/acme/Web/_git/api"
    assert safe_clone_url("acme", repo) == "https://dev.azure.com/acme/Web/_git/api"
    assert safe_clone_url("other-org", repo) is None
    assert safe_clone_url("acme", {"remoteUrl": "https://evil.example/acme/Web/_git/api"}) is None


def test_pat_auth_uses_basic_with_empty_username():
    header = run(_PatAuth("s3cret").authorization())
    assert header == "Basic " + base64.b64encode(b":s3cret").decode()


def test_git_env_keeps_token_out_of_argv_and_disables_prompts():
    env = _git_env("Basic abc")
    assert env["GIT_CONFIG_KEY_0"] == "http.extraHeader"
    assert env["GIT_CONFIG_VALUE_0"] == "Authorization: Basic abc"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull


# ── REST client ───────────────────────────────────────────────────────────────


def _client(handler, org="acme"):
    return AzureDevOpsClient(org, _PatAuth("pat"), transport=httpx.MockTransport(handler), sleep=_no_sleep)


def test_list_projects_follows_continuation_token():
    calls = []

    def handler(request):
        calls.append(dict(request.url.params))
        assert request.headers["Authorization"].startswith("Basic ")
        assert request.url.params["api-version"] == "7.1"
        if "continuationToken" not in request.url.params:
            return httpx.Response(200, json={"value": [{"id": "1", "name": "A"}]},
                                  headers={"x-ms-continuationtoken": "next"})
        return httpx.Response(200, json={"value": [{"id": "2", "name": "B"}]})

    async def go():
        async with _client(handler) as client:
            return await client.list_projects()

    assert [p["name"] for p in run(go())] == ["A", "B"]
    assert calls[1]["continuationToken"] == "next"


def test_rate_limit_retries_after_retry_after():
    responses = [httpx.Response(429, headers={"Retry-After": "2"}),
                 httpx.Response(200, json={"value": [{"id": "1", "name": "A"}]})]
    slept = []

    async def sleep(seconds):
        slept.append(seconds)

    async def go():
        client = AzureDevOpsClient("acme", _PatAuth("pat"),
                                   transport=httpx.MockTransport(lambda r: responses.pop(0)), sleep=sleep)
        async with client:
            return await client.list_projects()

    assert len(run(go())) == 1
    assert slept == [2]


@pytest.mark.parametrize(
    "response, message",
    [
        (httpx.Response(401), "rejected the supplied access token"),
        (httpx.Response(203, text="<html>sign in</html>", headers={"content-type": "text/html"}),
         "rejected the supplied access token"),
        (httpx.Response(404, json={}), "cannot access organization 'acme'"),
    ],
)
def test_error_mapping(response, message):
    async def go():
        async with _client(lambda r: response) as client:
            await client.list_projects()

    with pytest.raises(AzureDevOpsError, match=message):
        run(go())


def test_discovery_filters_forks_and_disabled_repositories():
    def handler(request):
        path = request.url.path
        if path == "/acme/_apis/projects":
            return httpx.Response(200, json={"value": [{"id": "pid-Web", "name": "Web"},
                                                      {"id": "pid-Ops", "name": "Ops"}]})
        if path == "/acme/pid-Web/_apis/git/repositories":
            return httpx.Response(200, json={"value": [_repo("frontend"), _repo("fork", isFork=True)]})
        if path == "/acme/pid-Ops/_apis/git/repositories":
            return httpx.Response(200, json={"value": [_repo("infra", "Ops"), _repo("old", "Ops", isDisabled=True)]})
        return httpx.Response(404, json={})

    async def go():
        async with _client(handler) as client:
            return await discover_repositories(client)

    result = run(go())
    assert sorted(r["name"] for r in result.repositories) == ["frontend", "infra"]
    assert (result.forks_skipped, result.disabled_skipped) == (1, 1)


def test_test_connection_reports_zero_visible_projects():
    transport = httpx.MockTransport(lambda r: httpx.Response(200, json={"value": []}))
    result = run(ado.test_connection("https://dev.azure.com/acme", "pat",
                                     personal_access_token="pat", transport=transport))
    assert result["ok"] is False
    assert "cannot access any project" in result["message"]


def test_test_connection_with_entra_id_exchanges_client_credentials():
    seen = {}

    def handler(request):
        if request.url.host == "login.microsoftonline.com":
            form = parse_qs(request.content.decode())
            seen["scope"] = form["scope"][0]
            seen["path"] = request.url.path
            return httpx.Response(200, json={"access_token": "aad-token", "expires_in": 3600})
        seen["auth"] = request.headers["Authorization"]
        return httpx.Response(200, json={"id": "pid", "name": "Web"})

    result = run(ado.test_connection(
        "https://dev.azure.com/acme/Web", "entra_id",
        tenant_id="tenant-1", client_id="app-1", client_secret="secret",
        transport=httpx.MockTransport(handler),
    ))
    assert result["ok"] is True
    assert seen["path"] == "/tenant-1/oauth2/v2.0/token"
    assert seen["scope"] == ado.AZURE_DEVOPS_RESOURCE_SCOPE
    assert seen["auth"] == "Bearer aad-token"


def test_entra_id_token_failure_is_reported():
    transport = httpx.MockTransport(lambda r: httpx.Response(
        401, json={"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret."}))
    result = run(ado.test_connection("https://dev.azure.com/acme", "entra_id", tenant_id="t",
                                     client_id="c", client_secret="bad", transport=transport))
    assert result["ok"] is False
    assert "AADSTS7000215" in result["message"]


# ── Sync (database) ───────────────────────────────────────────────────────────


@pytest.fixture()
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine, tables=[
        Organization.__table__, Asset.__table__, Scan.__table__, SourceCodeManagerIntegration.__table__,
    ])
    session = sessionmaker(bind=engine)()
    session.add(Organization(id=1, name="Acme"))
    session.commit()
    yield session
    session.close()


def _integration(db, **overrides):
    integration = SourceCodeManagerIntegration(
        organization_id=1, provider="azure_devops", connection_name="Prod",
        scope_url="https://dev.azure.com/acme/Web", scm_organization="acme", scm_project="Web",
        auth_method="pat", **overrides,
    )
    integration.set_access_token("pat-value")
    db.add(integration)
    db.commit()
    return integration


def _project_handler(repos):
    def handler(request):
        if request.url.path == "/acme/_apis/projects/Web":
            return httpx.Response(200, json={"id": "pid-Web", "name": "Web", "visibility": "private"})
        if request.url.path == "/acme/pid-Web/_apis/git/repositories":
            return httpx.Response(200, json={"value": repos})
        return httpx.Response(404, json={})
    return handler


def test_sync_imports_repositories_and_queues_secret_scan(db, monkeypatch):
    monkeypatch.setattr(ado, "_notify_worker", lambda scan: None)
    integration = _integration(db)
    transport = httpx.MockTransport(_project_handler([_repo("frontend"), _repo("forked", isFork=True)]))

    result = run(ado.sync_integration(db, integration, transport=transport))

    assert result["ok"] is True, result["message"]
    assert result["repositories_created"] == 1 and result["forks_skipped"] == 1
    asset = db.query(Asset).one()
    assert asset.asset_type == AssetType.REPOSITORY
    assert asset.value == "https://dev.azure.com/acme/Web/_git/frontend"
    assert asset.metadata_["azure_devops"]["project"] == "Web"
    assert asset.is_public is False

    scan = db.query(Scan).one()
    assert scan.scan_type == ScanType.TRUFFLEHOG_SCAN
    assert scan.config["scm_integration_id"] == integration.id
    assert scan.config["repositories"][0]["clone_url"] == "https://dev.azure.com/acme/Web/_git/frontend"
    assert "pat-value" not in str(scan.config)
    assert integration.last_scan_id == scan.id

    # A second run refreshes the asset instead of duplicating it.
    run(ado.sync_integration(db, integration, transport=transport))
    assert db.query(Asset).count() == 1
    assert integration.last_sync_stats["repositories_updated"] == 1


def test_sync_without_secret_scanning_queues_nothing(db, monkeypatch):
    monkeypatch.setattr(ado, "_notify_worker", lambda scan: None)
    integration = _integration(db, secret_scanning_enabled=False)
    run(ado.sync_integration(db, integration, transport=httpx.MockTransport(_project_handler([_repo("x")]))))
    assert db.query(Scan).count() == 0
    assert db.query(Asset).count() == 1


def test_sync_failure_records_safe_error(db):
    integration = _integration(db)
    result = run(ado.sync_integration(db, integration, transport=httpx.MockTransport(lambda r: httpx.Response(401))))
    assert result["ok"] is False
    assert integration.last_sync_ok is False
    assert "rejected the supplied access token" in integration.last_error


def test_repository_scan_attributes_findings_to_repository(db, monkeypatch):
    from app.services import trufflehog_service
    from app.services.trufflehog_service import TruffleFinding, TruffleScanResult

    integration = _integration(db)
    cloned = []

    async def fake_clone(url, destination, authorization):
        cloned.append((url, authorization))

    async def fake_trufflehog(source_type, source_name, **kwargs):
        assert source_type == "git" and source_name.startswith("file://")
        return TruffleScanResult(source_type="git", source_name=source_name, findings=[
            TruffleFinding(source_type="git", source_name=source_name, detector="AWS", verified=True,
                           severity="critical", raw_hash="abc123", file="config.py", line=3,
                           commit="deadbeef", extras={"repository": source_name}),
        ])

    monkeypatch.setattr(ado, "clone_repository", fake_clone)
    monkeypatch.setattr(trufflehog_service, "run_trufflehog", fake_trufflehog)
    persisted = []
    monkeypatch.setattr(trufflehog_service, "persist_trufflehog_findings",
                        lambda db_, org, scan_id, result, asset_value=None: persisted.append(
                            (asset_value, result.source_name, result.findings[0].extras["repository"])) or 1)

    config = {
        "scm_integration_id": integration.id,
        "repositories": [
            {"web_url": "https://dev.azure.com/acme/Web/_git/api",
             "clone_url": "https://dev.azure.com/acme/Web/_git/api", "size": 10},
            {"web_url": "https://dev.azure.com/acme/Web/_git/huge",
             "clone_url": "https://dev.azure.com/acme/Web/_git/huge", "size": 10 ** 13},
        ],
    }
    summary = run(ado.run_repository_secret_scan(db, 7, 1, config))

    assert cloned == [("https://dev.azure.com/acme/Web/_git/api", "Basic " + base64.b64encode(b":pat-value").decode())]
    assert persisted == [("https://dev.azure.com/acme/Web/_git/api",) * 3]
    assert summary["repositories_scanned"] == 1
    assert summary["repositories_skipped"] == 1
    assert summary["persisted"] == 1


def test_repository_scan_refuses_other_tenants_integration(db):
    integration = _integration(db)
    with pytest.raises(AzureDevOpsError, match="no longer exists"):
        run(ado.run_repository_secret_scan(db, 1, 2, {"scm_integration_id": integration.id}))
