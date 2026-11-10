"""CSRF proof replays what a browser would send from a foreign page.

A write that succeeds with every session cookie and header proves nothing
about CSRF. The proof requires a cross-site replay (only cookies a browser
attaches cross-site, foreign Origin, no custom headers or token), a rejected
no-cookie control, and the victim's own readback of the canary.
"""

from urllib.parse import parse_qs

import httpx
import pytest

from app.services.agent.assessment_sessions import identity_registry
from app.services.agent.cross_site import (
    cross_site_cookies,
    cross_site_headers,
    same_site_of,
    simple_request,
)
from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.evidence_store import VerificationRun, verification_run
from app.services.agent.independent_verify import (
    apply_verdict,
    check_verify_receipt,
    submit_candidate,
)
from app.services.agent.tools import (
    ASMToolsManager,
    current_organization_id,
    current_session_id,
)

TARGET = "https://app.test/profile/email"


@pytest.fixture
def manager():
    org = current_organization_id.set(98766)
    session = current_session_id.set("csrf-proof-test")
    instance = ASMToolsManager()
    instance._assessment_scope.update({"app.test"})
    yield instance
    current_session_id.reset(session)
    current_organization_id.reset(org)


def _app(monkeypatch, *, public=False):
    """A tiny profile app: POST /profile/email needs session=v1 unless public."""
    state = {"email": "victim@example.test"}
    original = httpx.AsyncClient

    def handler(req):
        authed = "session=v1" in req.headers.get("cookie", "")
        if req.url.path == "/login":
            return httpx.Response(200, text="Please sign in")
        if not authed and not (public and req.method == "POST"):
            return httpx.Response(302, headers={"location": "https://app.test/login"})
        if req.url.path == "/profile/email" and req.method == "POST":
            state["email"] = parse_qs(req.content.decode()).get("email", [""])[0]
            return httpx.Response(200, text="saved")
        if req.url.path == "/profile" and req.method == "GET":
            return httpx.Response(200, text=f"<p>Email: {state['email']}</p>")
        if req.url.path == "/profile/email/reset" and req.method == "POST":
            state["email"] = "victim@example.test"
            return httpx.Response(200, text="reset")
        return httpx.Response(404)

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: original(
        transport=httpx.MockTransport(handler), **kw))
    return state


def _victim(manager, same_site="None"):
    registry = identity_registry(manager)
    registry.register("victim", "https://app.test", cookies=[{
        "name": "session", "value": "v1", "domain": "app.test", "path": "/",
        "secure": True, "sameSite": same_site,
    }])
    registry.resolve("victim", "https://app.test")["authenticated"] = True


async def _verdict(manager, *, write_body=None, write_headers=None, cross_site=True):
    brain = EngagementBrain()
    cand = submit_candidate(brain, title="CSRF on email change", target=TARGET,
                            vulnerability_class="csrf")
    manager._engagement_brain = brain.to_dict()
    canary = "aegis-verify-" + cand.nonce
    token = verification_run.set(VerificationRun("csrf-run", cand.id, 1, cand.nonce))
    form = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        write = await manager._http_exchange(
            "POST", TARGET, identity="victim", cross_site=cross_site,
            headers=write_headers or form, body=write_body or f"email={canary}")
        control = await manager._http_exchange(
            "POST", TARGET, use_auth_session=False, headers=form, body=f"email={canary}")
        read = await manager._http_exchange("GET", "https://app.test/profile", identity="victim")
        cleanup = await manager._http_exchange(
            "POST", "https://app.test/profile/email/reset", identity="victim",
            headers=form, body="confirm=1")
        ids = [x["evidence_id"] for x in (write, control, read, cleanup)]
        verdict = apply_verdict(
            manager, candidate_id=cand.id, verdict="confirmed",
            evidence="Cross-site form post changed the victim's email",
            evidence_ids=ids,
            proof={"kind": "csrf_state_change", "write_id": ids[0], "control_id": ids[1],
                   "read_id": ids[2], "cleanup_id": ids[3], "value": canary},
        )
        receipt = check_verify_receipt(manager._verify_receipts, title=cand.title,
                                       target=cand.target, tools_manager=manager)[0]
        return verdict, receipt, write
    finally:
        verification_run.reset(token)


@pytest.mark.asyncio
async def test_samesite_none_session_without_token_is_confirmed(manager, monkeypatch):
    _app(monkeypatch)
    _victim(manager, "None")
    verdict, receipt, write = await _verdict(manager)
    assert verdict.status == "confirmed" and receipt
    assert write["request"]["cross_site_sent_names"] == ["session"]
    assert "x-aegis-verify" not in {k.lower() for k in write["request"]["headers"]}


@pytest.mark.asyncio
async def test_lax_session_cookie_is_not_sent_cross_site_so_no_csrf(manager, monkeypatch):
    _app(monkeypatch)
    _victim(manager, "Lax")
    verdict, receipt, _ = await _verdict(manager)
    assert verdict.status == "inconclusive" and not receipt
    assert "victim cookie" in verdict.proof_gap["reason"]


@pytest.mark.asyncio
async def test_unset_samesite_defaults_to_lax(manager, monkeypatch):
    _app(monkeypatch)
    _victim(manager, "")
    verdict, _, _ = await _verdict(manager)
    assert verdict.status == "inconclusive"


@pytest.mark.asyncio
@pytest.mark.parametrize("kwargs,gap", [
    ({"cross_site": False}, "cross_site=true"),
    ({"write_body": "email=aegis-verify-{nonce}&csrf_token=abc"}, "anti-CSRF token"),
])
async def test_same_site_replay_and_tokens_cannot_confirm(manager, monkeypatch, kwargs, gap):
    _app(monkeypatch)
    _victim(manager, "None")
    if "write_body" in kwargs:
        # The canary must still match; patch the nonce in after the candidate exists.
        original = manager._http_exchange
        template = kwargs["write_body"]

        async def with_nonce(method, url, **kw):
            if kw.get("cross_site"):
                cand_nonce = manager._engagement_brain["candidates"][0]["nonce"]
                kw["body"] = template.format(nonce=cand_nonce)
            return await original(method, url, **kw)

        manager._http_exchange = with_nonce
        kwargs = {}
    verdict, receipt, _ = await _verdict(manager, **kwargs)
    assert verdict.status == "inconclusive" and not receipt
    assert gap in verdict.proof_gap["reason"]


@pytest.mark.asyncio
async def test_public_endpoint_that_accepts_anonymous_writes_is_not_csrf(manager, monkeypatch):
    _app(monkeypatch, public=True)
    _victim(manager, "None")
    verdict, receipt, _ = await _verdict(manager)
    assert verdict.status == "inconclusive" and not receipt
    assert "public endpoint" in verdict.proof_gap["reason"]


@pytest.mark.asyncio
async def test_cross_site_replay_keeps_the_victims_full_cookie_set(manager, monkeypatch):
    _app(monkeypatch)
    _victim(manager, "Lax")
    await manager._http_exchange("POST", TARGET, identity="victim", cross_site=True,
                                 headers={"Content-Type": "text/plain"}, body="x")
    session = identity_registry(manager).resolve("victim", "https://app.test")
    assert [(c["name"], same_site_of(c)) for c in session["cookies"]] == [("session", "lax")]
    # A normal request still authenticates afterwards, and keeps SameSite.
    read = await manager._http_exchange("GET", "https://app.test/profile", identity="victim")
    assert read["response"]["status"] == 200
    assert same_site_of(identity_registry(manager).resolve(
        "victim", "https://app.test")["cookies"][0]) == "lax"


def test_browser_rules():
    stored = [
        {"name": "none_secure", "sameSite": "None", "secure": True},
        {"name": "none_insecure", "sameSite": "None", "secure": False},
        {"name": "lax", "sameSite": "Lax"},
        {"name": "unset"},
        {"name": "strict", "sameSite": "Strict"},
    ]
    assert [c["name"] for c in cross_site_cookies(stored, "POST")] == ["none_secure"]
    assert [c["name"] for c in cross_site_cookies(stored, "GET")] == ["none_secure", "lax", "unset"]
    with pytest.raises(ValueError, match="X-Requested-With"):
        cross_site_headers({"X-Requested-With": "XMLHttpRequest"})
    assert cross_site_headers({"Origin": "https://app.test"})["Origin"] == "https://aegis-csrf.invalid"
    assert simple_request("POST", {"content-type": "text/plain;charset=utf-8"})
    assert not simple_request("POST", {"content-type": "application/json"})
    assert not simple_request("PUT", {})
