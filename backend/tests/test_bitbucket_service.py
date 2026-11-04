"""Focused tests for the Bitbucket Cloud integration service."""

import base64
import os
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from app.models.vulnerability import Severity
from app.services import bitbucket_service as bb


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://bitbucket.org/acme", "acme"),
        ("https://bitbucket.org/Acme-Corp/", "acme-corp"),
        ("bitbucket.org/acme_dev", "acme_dev"),
        ("https://www.bitbucket.org/acme", "acme"),
    ],
)
def test_parse_workspace_url_accepts_cloud_workspaces(url, expected):
    workspace, canonical = bb.parse_workspace_url(url)
    assert workspace == expected
    assert canonical == f"https://bitbucket.org/{expected}"


@pytest.mark.parametrize(
    "url",
    [
        "",
        "http://bitbucket.org/acme",
        "https://bitbucket.example.com/acme",
        "https://bitbucket.org.attacker.example/acme",
        "https://user:pass@bitbucket.org/acme",
        "https://bitbucket.org:8443/acme",
        "https://bitbucket.org/acme/repo",
        "https://bitbucket.org/",
        "https://bitbucket.org/acme?x=1",
        "https://bitbucket.org/-acme",
    ],
)
def test_parse_workspace_url_rejects_invalid(url):
    with pytest.raises(ValueError, match="valid Bitbucket workspace URL"):
        bb.parse_workspace_url(url)


def _response(status, payload=None):
    request = httpx.Request("GET", f"{bb.API_BASE}/repositories/acme")
    return httpx.Response(status, json=payload or {}, request=request)


@pytest.mark.asyncio
async def test_list_repositories_follows_next_links():
    client = bb.BitbucketClient("acme", "token")
    pages = [
        {"values": [{"full_name": "acme/one"}], "next": f"{bb.API_BASE}/repositories/acme?page=2"},
        {"values": [{"full_name": "acme/two"}]},
    ]
    client._get = AsyncMock(side_effect=pages)
    repos = await client.list_repositories()
    assert [r["full_name"] for r in repos] == ["acme/one", "acme/two"]
    assert client._get.await_args_list[1].args[1].endswith("page=2")
    assert client._get.await_args_list[1].kwargs["params"] is None


@pytest.mark.asyncio
async def test_get_refuses_non_bitbucket_next_url():
    client = bb.BitbucketClient("acme", "token")
    with pytest.raises(bb.BitbucketApiError):
        await client._get(MagicMock(), "https://attacker.example/2.0/repositories")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,error,fragment",
    [
        (401, bb.BitbucketAuthError, "rejected the supplied access token"),
        (403, bb.BitbucketAccessError, "cannot access workspace 'acme'"),
        (404, bb.BitbucketAccessError, "cannot access workspace 'acme'"),
    ],
)
async def test_get_maps_http_errors_to_user_messages(status, error, fragment):
    client = bb.BitbucketClient("acme", "token")
    http = MagicMock()
    http.get = AsyncMock(return_value=_response(status))
    with pytest.raises(error, match=fragment):
        await client._get(http, f"{bb.API_BASE}/repositories/acme")


@pytest.mark.asyncio
async def test_test_connection_reports_invalid_url_without_network():
    result = await bb.test_connection("https://gitlab.com/acme", "token")
    assert result["ok"] is False
    assert "valid Bitbucket workspace URL" in result["message"]


def test_repo_normalisation_and_fork_detection():
    assert bb.is_fork({"parent": {"full_name": "upstream/x"}}) is True
    assert bb.is_fork({"parent": None}) is False
    assert bb.repo_full_name({"full_name": "Acme/Repo.Name"}) == "acme/repo.name"
    assert bb.repo_full_name({"full_name": "../etc"}) is None
    assert bb.repo_asset_value("acme/api") == "https://bitbucket.org/acme/api"


def test_git_env_keeps_token_out_of_argv_and_scopes_header():
    env = bb._git_env("s3cret", "/tmp/home")
    header_key = env["GIT_CONFIG_KEY_0"]
    assert header_key == "http.https://bitbucket.org/.extraHeader"
    encoded = env["GIT_CONFIG_VALUE_0"].split("Basic ", 1)[1]
    assert base64.b64decode(encoded).decode() == "x-token-auth:s3cret"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_CONFIG_VALUE_1"] == "false"  # core.symlinks


def test_scrub_removes_token_forms():
    basic = base64.b64encode(b"x-token-auth:s3cret").decode()
    assert "s3cret" not in bb._scrub(f"fatal: s3cret {basic}", "s3cret")
    assert basic not in bb._scrub(f"fatal: {basic}", "s3cret")


def test_secret_severity_mapping():
    assert bb.secret_severity({"rule_id": "private-key"}) == Severity.CRITICAL
    assert bb.secret_severity({"rule_id": "aws-access-token"}) == Severity.CRITICAL
    assert bb.secret_severity({"rule_id": "generic-api-key"}) == Severity.MEDIUM
    assert bb.secret_severity({"rule_id": "slack-bot-token"}) == Severity.HIGH
    assert bb.secret_severity({"rule_id": "x", "severity": Severity.LOW}) == Severity.LOW


def test_fingerprint_is_stable_and_location_sensitive():
    a = bb._fingerprint("config/.env", "aws-access-token", 3)
    assert a == bb._fingerprint("config/.env", "aws-access-token", 3)
    assert a != bb._fingerprint("config/.env", "aws-access-token", 4)


def test_regex_fallback_finds_secret_and_skips_placeholders(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "settings.py").write_text(
        "AWS_KEY = 'AKIAQ7RZ2KLMN4PDSTUV'\nOTHER = 'AKIAEXAMPLEEXAMPLE12'\n"
    )
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text("AKIAQ7RZ2KLMN4PDSTUW")
    findings = bb._run_regex_fallback(str(tmp_path))
    aws = [f for f in findings if f["rule_id"] == "aws_access_key"]
    assert len(aws) == 1
    assert aws[0]["file"] == "app/settings.py"
    assert aws[0]["line"] == 1


def test_needs_scan_skips_empty_large_and_unchanged():
    asset = MagicMock()
    asset.metadata_ = {}
    assert bb._needs_scan(asset, {"mainbranch": None}, 500) == (False, "empty repository")
    big = {"mainbranch": {"name": "main"}, "size": 600 * 1024 * 1024}
    assert bb._needs_scan(asset, big, 500)[0] is False
    repo = {"mainbranch": {"name": "main"}, "size": 1024, "updated_on": "2026-01-01T00:00:00Z"}
    assert bb._needs_scan(asset, repo, 500) == (True, None)
    asset.metadata_ = {"bitbucket": {"secret_scan_status": "ok", "secret_scanned_updated_on": "2026-01-01T00:00:00Z"}}
    assert bb._needs_scan(asset, repo, 500) == (False, "unchanged since last scan")


@pytest.mark.skipif(not os.path.exists("/usr/bin/git") and not os.path.exists("/usr/local/bin/git"), reason="git missing")
def test_clone_rejects_bad_repo_name(tmp_path):
    with pytest.raises(RuntimeError, match="Invalid repository name"):
        bb._clone_repository("../../etc", None, "token", str(tmp_path))
