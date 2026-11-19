"""Judah Outrider drives ARTEX over REST and imports its findings only as pending leads."""

import json

import httpx
import pytest

from app.services.agent import judah_outrider as outrider


class FakeArtex:
    def __init__(self, findings):
        self.findings = findings
        self.calls = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b"{}") if request.content else {}
        self.calls.append((request.method, request.url.path, body, request.headers.get("authorization")))
        path = request.url.path
        if path == "/api/auth/login":
            return httpx.Response(200, json={"token": "jwt-1"})
        if request.headers.get("authorization") != "Bearer jwt-1":
            return httpx.Response(401)
        if path == "/api/tasks" and request.method == "POST":
            return httpx.Response(201, json={"id": 77, "status": "pending"})
        if path == "/api/tasks/77/scope":
            return httpx.Response(201, json={"ok": True})
        if path == "/api/tasks/77":
            return httpx.Response(200, json={"id": 77, "status": "done"})
        if path == "/api/exploration/findings":
            assert request.url.params["task"] == "77"
            return httpx.Response(200, json=self.findings)
        return httpx.Response(404)


@pytest.fixture(autouse=True)
def _creds(monkeypatch):
    monkeypatch.setenv("JUDAH_OUTRIDER_USERNAME", "judah")
    monkeypatch.setenv("JUDAH_OUTRIDER_PASSWORD", "pw")
    monkeypatch.delenv("JUDAH_OUTRIDER_TOKEN", raising=False)


def _client(fake):
    return outrider.OutriderClient("http://artex.internal:8787", transport=httpx.MockTransport(fake))


@pytest.mark.asyncio
async def test_dispatch_sends_only_scope_goal_and_gate():
    fake = FakeArtex([])
    async with _client(fake) as client:
        out = await outrider.dispatch(client, "sess-1", ["shop.acme.test", "*.api.acme.test"])
    assert out["task_id"] == 77
    create = next(c for c in fake.calls if c[1] == "/api/tasks")
    assert create[2]["target_gate"] is True and "credentials" not in create[2]
    assert "shop.acme.test" in create[2]["description"]
    scopes = [c[2] for c in fake.calls if c[1] == "/api/tasks/77/scope"]
    assert {(s["kind"], s["value"]) for s in scopes} == {("subdomain", "shop.acme.test"),
                                                          ("root_domain", "api.acme.test")}
    with pytest.raises(outrider.OutriderError):
        async with _client(fake) as client:
            await outrider.dispatch(client, "sess-1", [])


@pytest.mark.asyncio
async def test_import_submits_pending_leads_and_skips_junk():
    findings = [
        {"finding_id": "f1", "vulnclass": "idor", "name": "Order IDOR", "severity": "high",
         "status": "confirmed", "summary": "GET https://shop.acme.test/api/orders/12 leaks other users",
         "assets": []},
        {"finding_id": "f2", "vulnclass": "xss", "severity": "medium", "status": "false_positive",
         "summary": "x", "assets": [{"label": "https://shop.acme.test/s"}]},
        {"finding_id": "f3", "vulnclass": "sqli", "severity": "critical", "status": "pending",
         "summary": "no url here", "assets": []},
        {"finding_id": "f4", "vulnclass": "weird thing", "severity": "bogus", "status": "pending",
         "summary": "", "assets": [{"label": "https://shop.acme.test/cart"}]},
    ]
    submitted = []

    def submit(org, session, **candidate):
        submitted.append(candidate)
        return {"accepted": True, "queued": False, "candidate": {"id": f"c{len(submitted)}"}}

    async with _client(FakeArtex(findings)) as client:
        summary = await outrider.import_findings(client, 1, "sess-1", 77, already={"f9"}, submit=submit)
    assert [s["id"] for s in summary["submitted"]] == ["f1", "f4"]
    assert {s["id"] for s in summary["skipped"]} == {"f2", "f3"}
    assert submitted[0]["vulnerability_class"] == "authz"
    assert submitted[0]["target"] == "https://shop.acme.test/api/orders/12"
    assert submitted[1]["vulnerability_class"] == "business_logic" and submitted[1]["severity"] == "medium"
    assert all("not accepted as proof" in c["evidence_note"] for c in submitted)
    assert set(summary["imported_ids"]) == {"f1", "f2", "f3", "f4", "f9"}

    async with _client(FakeArtex(findings)) as client:  # second import is a no-op
        again = await outrider.import_findings(client, 1, "sess-1", 77,
                                               already=set(summary["imported_ids"]), submit=submit)
    assert again["submitted"] == []


@pytest.mark.asyncio
async def test_intake_rejection_is_recorded_not_raised():
    from app.services.agent.external_candidates import IntakeError

    def submit(org, session, **candidate):
        raise IntakeError(400, "Target is outside this session's scope")

    rows = [{"finding_id": "f1", "vulnclass": "ssrf", "severity": "high", "status": "pending",
             "summary": "https://evil.test/x", "assets": []}]
    async with _client(FakeArtex(rows)) as client:
        summary = await outrider.import_findings(client, 1, "s", 77, submit=submit)
    assert summary["submitted"] == [] and "outside" in summary["skipped"][0]["reason"]


def test_state_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("JUDAH_OUTRIDER_STATE_DIR", str(tmp_path))
    outrider.save_state(1, "sess", {"task_id": 77, "imported_ids": ["f1"]})
    assert outrider.load_state(1, "sess")["task_id"] == 77
    assert outrider.load_state(2, "sess") == {}


def test_url_without_credentials_required(monkeypatch):
    monkeypatch.setenv("JUDAH_OUTRIDER_URL", "http://user:pw@artex:8787")
    with pytest.raises(outrider.OutriderError):
        outrider.OutriderClient()
