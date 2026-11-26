"""Caido's own error page must never be recorded as the target's response.

When the assessment proxy has no selected project (a restart drops Caido's
temporary project) or cannot reach the target, it answers every request with
the same branded 500 page. Replays, mutations and comparisons then all look
identical and no check can conclude anything. These tests cover the httpx and
urllib transports and the replay path's re-bootstrap and retry.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import build_opener

import httpx
import pytest

from app.services.agent import assessment_proxy_bootstrap as bootstrap
from app.services.agent.assessment_proxy import (
    AssessmentProxyAnswered,
    assessment_httpx_options,
    assessment_urllib_handlers,
    proxy_answered,
    proxy_page_reason,
)

CAIDO_PAGE = (
    "<html><head><title>Caido - Error</title><style>p{}</style></head>"
    "<body><h1>Caido</h1><p>No project is currently selected</p></body></html>"
)
TARGET_500 = "<html><head><title>Internal Server Error</title></head><body>boom</body></html>"


@pytest.fixture
def proxied(monkeypatch, tmp_path):
    bundle = tmp_path / "ca.crt"
    bundle.write_text("test certificate")
    monkeypatch.setenv("AEGIS_ASSESSMENT_PROXY_URL", "http://caido-assessment:8082")
    monkeypatch.setenv("AEGIS_ASSESSMENT_CA_BUNDLE", str(bundle))
    monkeypatch.delenv("AEGIS_ALLOW_INSECURE_TLS", raising=False)
    monkeypatch.delenv("AEGIS_ASSESSMENT_PROXY_API_URL", raising=False)
    bootstrap.reset_cache()
    yield
    bootstrap.reset_cache()


def _mock_client(handler):
    """A client with the real assessment options, minus the proxy and placeholder CA."""
    options = assessment_httpx_options()
    options.pop("proxy", None)
    options.pop("proxies", None)
    options["verify"] = True
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), **options)


def test_detection_needs_a_proxy_and_a_5xx(monkeypatch, proxied):
    assert proxy_answered(500, {}, CAIDO_PAGE)
    assert proxy_answered(502, {"Server": "Caido"}, "")
    assert proxy_answered(503, {"X-Caido-Error": "1"}, "")
    assert not proxy_answered(500, {}, TARGET_500)
    assert not proxy_answered(200, {}, CAIDO_PAGE)
    monkeypatch.delenv("AEGIS_ASSESSMENT_PROXY_URL")
    assert not proxy_answered(500, {}, CAIDO_PAGE)


def test_reason_is_the_visible_page_text():
    assert proxy_page_reason(CAIDO_PAGE) == "Caido - Error Caido No project is currently selected"


@pytest.mark.asyncio
async def test_httpx_rejects_caido_page_and_forgets_readiness(proxied):
    bootstrap._ready_until["https://app.test"] = float("inf")
    async with _mock_client(lambda req: httpx.Response(500, text=CAIDO_PAGE)) as client:
        with pytest.raises(AssessmentProxyAnswered) as error:
            await client.get("https://app.test/search?q=1")
    assert "/search" in str(error.value)
    assert "No project is currently selected" in str(error.value)
    assert "https://app.test" not in bootstrap._ready_until


@pytest.mark.asyncio
async def test_httpx_passes_the_targets_own_errors_through(proxied):
    async with _mock_client(lambda req: httpx.Response(500, text=TARGET_500)) as client:
        response = await client.get("https://app.test/")
    assert response.status_code == 500 and "boom" in response.text


@pytest.mark.asyncio
async def test_preflight_reports_the_proxy_page(proxied, monkeypatch):
    async with _mock_client(lambda req: httpx.Response(500, text=CAIDO_PAGE)) as client:
        with pytest.raises(bootstrap.AssessmentProxyNotReady, match="No project"):
            await bootstrap.preflight("https://app.test/", client=client)


class _FakeProxy(BaseHTTPRequestHandler):
    body = CAIDO_PAGE

    def do_GET(self):  # noqa: N802 - http.server API
        data = self.body.encode()
        self.send_response(500)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_args):
        pass


@pytest.fixture
def fake_proxy(monkeypatch, proxied):
    import certifi

    # urllib loads the CA bundle for real; any valid bundle works for http targets.
    monkeypatch.setenv("AEGIS_ASSESSMENT_CA_BUNDLE", certifi.where())
    servers = []

    def start(body):
        handler = type("Handler", (_FakeProxy,), {"body": body})
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        monkeypatch.setenv("AEGIS_ASSESSMENT_PROXY_URL", f"http://127.0.0.1:{server.server_port}")
        return server

    yield start
    for server in servers:
        server.shutdown()


def test_urllib_probes_reject_caido_page(fake_proxy):
    fake_proxy(CAIDO_PAGE)
    opener = build_opener(*assessment_urllib_handlers())
    with pytest.raises(AssessmentProxyAnswered, match="No project is currently selected"):
        opener.open("http://app.test/item?id=1", timeout=5)


def test_urllib_probes_still_see_target_errors(fake_proxy):
    fake_proxy(TARGET_500)
    opener = build_opener(*assessment_urllib_handlers())
    with pytest.raises(HTTPError) as error:
        opener.open("http://app.test/item?id=1", timeout=5)
    assert error.value.code == 500
    assert b"boom" in error.value.read()


# ------------------------------------------------------------ replay path

@pytest.fixture
def manager(request):
    from app.services.agent.tools import (
        ASMToolsManager, current_organization_id, current_session_id,
    )

    org = current_organization_id.set(98765)
    session = current_session_id.set(f"proxy-error-page-{request.node.name}")
    instance = ASMToolsManager()
    instance._assessment_scope.update({"app.test"})
    yield instance
    current_session_id.reset(session)
    current_organization_id.reset(org)


@pytest.fixture
def scripted(monkeypatch, proxied):
    """Install a transport that answers from a list, and count proxy setups."""
    original = httpx.AsyncClient
    setups = []

    async def ensure_ready(url):
        setups.append(url)

    monkeypatch.setattr(bootstrap, "ensure_assessment_proxy_ready", ensure_ready)

    def install(responses):
        queue = list(responses)

        def client(**kwargs):
            kwargs.pop("proxy", None)
            kwargs.pop("proxies", None)
            kwargs["verify"] = True
            return original(transport=httpx.MockTransport(lambda req: queue.pop(0)), **kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", client)
        return queue

    install.setups = setups
    return install


@pytest.mark.asyncio
async def test_replay_sets_up_proxy_again_and_retries_once(manager, scripted):
    queue = scripted([httpx.Response(500, text=CAIDO_PAGE), httpx.Response(200, text="real page")])
    result = await manager._http_exchange("GET", "https://app.test/", use_auth_session=False)
    assert result["response"]["status"] == 200
    assert result["_body_text"] == "real page"
    assert queue == []
    # Once before the first send, once after Caido answered.
    assert scripted.setups == ["https://app.test/", "https://app.test/"]


@pytest.mark.asyncio
async def test_replay_never_records_a_persistent_caido_page(manager, scripted):
    scripted([httpx.Response(500, text=CAIDO_PAGE), httpx.Response(500, text=CAIDO_PAGE)])
    with pytest.raises(AssessmentProxyAnswered):
        await manager._http_exchange("GET", "https://app.test/", use_auth_session=False)
    from app.services.agent.evidence_store import evidence_store

    assert len(evidence_store(manager).records) == 0


@pytest.mark.asyncio
async def test_writes_are_not_retried(manager, scripted):
    queue = scripted([httpx.Response(500, text=CAIDO_PAGE), httpx.Response(200, text="x")])
    with pytest.raises(AssessmentProxyAnswered):
        await manager._http_exchange("POST", "https://app.test/", body="a=1",
                                     use_auth_session=False)
    assert len(queue) == 1
