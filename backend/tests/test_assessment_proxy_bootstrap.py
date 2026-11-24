"""Caido project bootstrap and proxy preflight (Strix-style readiness)."""

import json

import httpx
import pytest

from app.services.agent import assessment_proxy_bootstrap as boot


def _caido(projects, calls):
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        query = body["query"]
        calls.append(query.split("(")[0].split("{")[0].strip())
        if "loginAsGuest" in query:
            return httpx.Response(200, json={"data": {"loginAsGuest": {"token": {"accessToken": "t"}}}})
        assert request.headers["Authorization"] == "Bearer t"
        if "projects" in query and "createProject" not in query:
            return httpx.Response(200, json={"data": {"projects": projects}})
        if "createProject" in query:
            assert body["variables"]["input"]["name"] == boot.PROJECT_NAME
            return httpx.Response(200, json={"data": {"createProject": {"project": {"id": "new"}, "error": None}}})
        if "selectProject" in query:
            return httpx.Response(200, json={"data": {"selectProject": {
                "currentProject": {"project": {"id": body["variables"]["id"]}}, "error": None}}})
        return httpx.Response(400)
    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_creates_and_selects_project_when_missing():
    calls = []
    async with httpx.AsyncClient(transport=_caido([], calls)) as client:
        assert await boot.ensure_project("http://caido:8080", client=client) == "new"
    assert any("CreateProject" in c for c in calls)
    assert any("SelectProject" in c for c in calls)


@pytest.mark.asyncio
async def test_selects_existing_project_without_creating():
    calls = []
    existing = [{"id": "p1", "name": boot.PROJECT_NAME}, {"id": "p2", "name": "other"}]
    async with httpx.AsyncClient(transport=_caido(existing, calls)) as client:
        assert await boot.ensure_project("http://caido:8080", client=client) == "p1"
    assert not any("CreateProject" in c for c in calls)


@pytest.mark.asyncio
async def test_guest_login_failure_explains_the_fix(monkeypatch):
    async def no_sleep(_):
        return None
    monkeypatch.setattr(boot.asyncio, "sleep", no_sleep)
    transport = httpx.MockTransport(lambda r: httpx.Response(401, text="unauthorized"))
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(boot.AssessmentProxyNotReady, match="--allow-guests"):
            await boot.ensure_project("http://caido:8080", client=client)


@pytest.fixture
def proxied(monkeypatch):
    monkeypatch.setattr("app.services.agent.assessment_proxy.assessment_proxy_url",
                        lambda: "http://caido:8082")


@pytest.mark.asyncio
async def test_preflight_rejects_caido_error_page(proxied):
    page = "<html><head><title>Caido</title></head><body>No project</body></html>"
    transport = httpx.MockTransport(lambda r: httpx.Response(
        500, text=page, headers={"content-type": "text/html"}))
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(boot.AssessmentProxyNotReady, match="AEGIS_ASSESSMENT_PROXY_URL"):
            await boot.preflight("https://app.test/", client=client)


@pytest.mark.asyncio
async def test_preflight_accepts_target_responses_including_target_errors(proxied):
    for status, title in ((200, "Shop"), (500, "Internal Server Error")):
        transport = httpx.MockTransport(lambda r, s=status, t=title: httpx.Response(
            s, text=f"<title>{t}</title>", headers={"content-type": "text/html", "server": "nginx"}))
        async with httpx.AsyncClient(transport=transport) as client:
            await boot.preflight("https://app.test/", client=client)


@pytest.mark.asyncio
async def test_ready_check_is_noop_without_proxy_and_cached_with_one(monkeypatch):
    boot.reset_cache()
    monkeypatch.setattr("app.services.agent.assessment_proxy.assessment_proxy_url", lambda: None)
    await boot.ensure_assessment_proxy_ready("https://app.test/x")  # no network, no error

    monkeypatch.setattr("app.services.agent.assessment_proxy.assessment_proxy_url",
                        lambda: "http://caido:8082")
    monkeypatch.delenv("AEGIS_ASSESSMENT_PROXY_API_URL", raising=False)
    seen = []

    async def fake_preflight(target, client=None):
        seen.append(target)

    monkeypatch.setattr(boot, "preflight", fake_preflight)
    await boot.ensure_assessment_proxy_ready("https://app.test/a")
    await boot.ensure_assessment_proxy_ready("https://app.test/b?q=1")
    assert seen == ["https://app.test/"], "one preflight per origin, cached"
    boot.reset_cache()
