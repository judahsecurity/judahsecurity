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


def test_bootstrap_requests_a_temporary_project():
    # Caido 0.58 refuses guests a persistent project (PermissionDeniedUserError);
    # Strix uses a temporary one for the same reason.
    seen = {}

    def handler(request):
        body = json.loads(request.content)
        if "loginAsGuest" in body["query"]:
            return httpx.Response(200, json={"data": {"loginAsGuest": {"token": {"accessToken": "t"}}}})
        if "createProject" in body["query"]:
            seen.update(body["variables"]["input"])
            return httpx.Response(200, json={"data": {"createProject": {"project": {"id": "p"}, "error": None}}})
        if "selectProject" in body["query"]:
            return httpx.Response(200, json={"data": {"selectProject": {"currentProject": {"project": {"id": "p"}}, "error": None}}})
        return httpx.Response(200, json={"data": {"projects": []}})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await boot.ensure_project("http://caido:8080", client=client)

    import asyncio
    asyncio.run(run())
    assert seen["temporary"] is True


def test_invalidate_forgets_one_origin():
    boot._ready_until["https://a.test"] = 9e18
    boot._ready_until["https://b.test"] = 9e18
    boot.invalidate("https://a.test/some/path?x=1")
    assert "https://a.test" not in boot._ready_until and "https://b.test" in boot._ready_until
    boot.reset_cache()


async def _browser_with_proxy_error_once(monkeypatch, operation):
    from app.services.agent.assessment_scope import register_scope
    from app.services.agent.scoped_assessment import browser
    from app.services.agent.tools import ASMToolsManager

    readiness, calls = [], []

    async def fake_ready(url):
        readiness.append(url)

    async def fake_browser(**kwargs):
        calls.append(kwargs["operation"])
        if len(calls) == 1:
            raise browser.AssessmentProxyError("proxy answered")
        return ({"operation": kwargs["operation"], "final_origin": "https://app.example.test",
                 "final_path": "/", "requests": [], "actions": [], "status": 200,
                 "pages": []}, b"")

    monkeypatch.setattr(boot, "ensure_assessment_proxy_ready", fake_ready)
    monkeypatch.setattr("app.services.agent.scoped_assessment_tools.browser.check_browser", fake_browser)
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    register_scope(manager, "app.example.test")
    return manager, readiness, calls


@pytest.mark.asyncio
async def test_read_only_browser_operation_rebootstraps_and_retries_once(monkeypatch):
    manager, readiness, calls = await _browser_with_proxy_error_once(monkeypatch, "inspect_js")
    await manager.scoped_browser_assessment("inspect_js", "https://app.example.test/")
    assert calls == ["inspect_js", "inspect_js"]
    assert len(readiness) == 2, "readiness re-checked after the proxy error"


@pytest.mark.asyncio
async def test_write_capable_browser_operation_is_not_retried(monkeypatch):
    from app.services.agent.scoped_assessment import browser

    manager, readiness, calls = await _browser_with_proxy_error_once(monkeypatch, "check_xss")
    with pytest.raises(browser.AssessmentProxyError):
        await manager.scoped_browser_assessment(
            "check_xss", "https://app.example.test/search?q=1")
    assert calls == ["check_xss"]
