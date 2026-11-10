"""Account enumeration proof: a controlled account vs fresh nonexistent ones.

The existing account must be a verified test identity's login, never a real
user. Requests differ only in the account; responses must split consistently
between the groups, with the probes interleaved so rate limiting or lockout
drift cannot fake the split.
"""

from urllib.parse import parse_qs

import httpx
import pytest

from app.services.agent.assessment_sessions import identity_registry
from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.evidence_store import VerificationRun, verification_run
from app.services.agent.independent_verify import apply_verdict, submit_candidate
from app.services.agent.tools import (
    ASMToolsManager,
    current_organization_id,
    current_session_id,
)

TARGET = "https://app.test/password/reset"
ALICE = "alice@app.example"


@pytest.fixture
def manager():
    org = current_organization_id.set(98767)
    session = current_session_id.set("account-oracle-test")
    instance = ASMToolsManager()
    instance._assessment_scope.update({"app.test"})
    registry = identity_registry(instance)
    registry.register("alice", "https://app.test", cookies=[], login=ALICE)
    registry.resolve("alice", "https://app.test")["authenticated"] = True
    registry.register("bob", "https://app.test", cookies=[], login="bob@app.example")
    yield instance
    current_session_id.reset(session)
    current_organization_id.reset(org)


def _app(monkeypatch, respond):
    original = httpx.AsyncClient
    calls = []

    def handler(req):
        email = parse_qs(req.content.decode()).get("email", [""])[0]
        calls.append(email)
        status, text = respond(email, len(calls))
        return httpx.Response(status, text=text)

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: original(
        transport=httpx.MockTransport(handler), **kw))


def _leaky(email, _n):
    if email in (ALICE, "bob@app.example", "ceo@app.example"):
        return 200, f"Reset link sent to {email}. Request id 81723."
    return 404, "No account with that email. Request id 99812."


async def _verdict(manager, order=("m", "e", "m", "e"), existing=ALICE, extra=None):
    brain = EngagementBrain()
    cand = submit_candidate(brain, title="Account enumeration via password reset",
                            target=TARGET, vulnerability_class="account_enumeration")
    manager._engagement_brain = brain.to_dict()
    token = verification_run.set(VerificationRun("enum-run", cand.id, 1, cand.nonce))
    form = {"Content-Type": "application/x-www-form-urlencoded"}
    existing_ids, missing_ids = [], []
    try:
        for index, kind in enumerate(order):
            account = existing if kind == "e" else f"aegis-verify-{cand.nonce}-{index}@example.invalid"
            body = f"email={account}" + (extra if extra and index == len(order) - 1 else "")
            exchange = await manager._http_exchange("POST", TARGET, headers=form, body=body,
                                                    use_auth_session=False)
            (existing_ids if kind == "e" else missing_ids).append(exchange["evidence_id"])
        return apply_verdict(
            manager, candidate_id=cand.id, verdict="confirmed",
            evidence="Reset answers differ for a registered account",
            evidence_ids=existing_ids + missing_ids,
            proof={"kind": "account_oracle", "existing_account": existing,
                   "existing_ids": existing_ids, "missing_ids": missing_ids},
        )
    finally:
        verification_run.reset(token)


@pytest.mark.asyncio
async def test_consistent_split_with_controlled_account_confirms(manager, monkeypatch):
    _app(monkeypatch, _leaky)
    verdict = await _verdict(manager)
    assert verdict.status == "confirmed", verdict.proof_gap


@pytest.mark.asyncio
@pytest.mark.parametrize("respond,kwargs,gap", [
    # The response only echoes the submitted email: no oracle.
    (lambda email, n: (200, f"If {email} exists, we sent a link."), {}, "same response"),
    # An unverified identity's login is not a controlled account.
    (_leaky, {"existing": "bob@app.example"}, "verified test identity"),
    # A real user's email.
    (_leaky, {"existing": "ceo@app.example"}, "verified test identity"),
    # A rate limit starts mid-run, so one group drifts.
    (lambda email, n: (429, "Slow down") if n >= 4 else _leaky(email, n), {}, "not stable"),
    # All existing probes first, then all missing ones.
    (_leaky, {"order": ("e", "e", "m", "m")}, "Interleave"),
    # Requests differ in more than the account.
    (_leaky, {"extra": "&lang=fr"}, "identical apart from the account"),
])
async def test_echoes_drift_and_uncontrolled_accounts_cannot_confirm(
    manager, monkeypatch, respond, kwargs, gap,
):
    _app(monkeypatch, respond)
    verdict = await _verdict(manager, **kwargs)
    assert verdict.status == "inconclusive"
    assert gap in verdict.proof_gap["reason"]


def test_controlled_logins_need_a_verified_session(manager):
    registry = identity_registry(manager)
    assert registry.controlled_logins("https://app.test") == frozenset({ALICE})
    assert registry.describe("alice", "https://app.test")["login"] == ALICE
