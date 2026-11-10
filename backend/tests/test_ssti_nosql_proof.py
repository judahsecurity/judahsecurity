"""SSTI and NoSQL operator injection proofs reject the usual false positives."""

import json
import re
from urllib.parse import parse_qs, unquote, urlsplit

import httpx
import pytest

from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.evidence_store import VerificationRun, verification_run
from app.services.agent.independent_verify import (
    apply_verdict,
    submit_candidate,
    verifier_mission,
)
from app.services.agent.proof_policy import inferred_vulnerability_class
from app.services.agent.tools import (
    ASMToolsManager,
    current_organization_id,
    current_session_id,
)


@pytest.fixture
def manager():
    org = current_organization_id.set(98768)
    session = current_session_id.set("ssti-nosql-test")
    instance = ASMToolsManager()
    instance._assessment_scope.update({"app.test"})
    yield instance
    current_session_id.reset(session)
    current_organization_id.reset(org)


def _serve(monkeypatch, handler):
    original = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: original(
        transport=httpx.MockTransport(handler), **kw))


def _candidate(manager, title, cls, target):
    brain = EngagementBrain()
    cand = submit_candidate(brain, title=title, target=target, vulnerability_class=cls)
    manager._engagement_brain = brain.to_dict()
    return cand


# --- SSTI -----------------------------------------------------------------

def _jinja_like(req):
    """Greets the name; evaluates {{a*b}} the way a vulnerable template would."""
    name = unquote(parse_qs(urlsplit(str(req.url)).query).get("name", [""])[0])
    rendered = re.sub(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}",
                      lambda m: str(int(m.group(1)) * int(m.group(2))), name)
    return httpx.Response(200, text=f"<h1>Hello {rendered}</h1>")


async def _ssti(manager, monkeypatch, handler, probes=("{{7919*13}}", "{{8191*17}}")):
    _serve(monkeypatch, handler)
    cand = _candidate(manager, "SSTI in greeting", "ssti", "https://app.test/hello")
    token = verification_run.set(VerificationRun("ssti-run", cand.id, 1, cand.nonce))
    try:
        control = await manager._http_exchange("GET", "https://app.test/hello?name=ada")
        ids = [(await manager._http_exchange("GET", f"https://app.test/hello?name={p}"))["evidence_id"]
               for p in probes]
        return apply_verdict(
            manager, candidate_id=cand.id, verdict="confirmed",
            evidence="Template arithmetic evaluated server-side",
            evidence_ids=[control["evidence_id"], *ids],
            proof={"kind": "template_eval", "baseline_id": control["evidence_id"],
                   "artifact_ids": ids},
        )
    finally:
        verification_run.reset(token)


@pytest.mark.asyncio
async def test_ssti_confirms_two_server_side_evaluations(manager, monkeypatch):
    verdict = await _ssti(manager, monkeypatch, _jinja_like)
    assert verdict.status == "confirmed", verdict.proof_gap


@pytest.mark.asyncio
@pytest.mark.parametrize("handler,probes,gap", [
    # Plain reflection: the expression comes back unevaluated (or AngularJS-style CSTI).
    (lambda req: httpx.Response(200, text=unquote(str(req.url))), ("{{7919*13}}", "{{8191*17}}"),
     "does not contain the evaluated product"),
    # Only one expression.
    (_jinja_like, ("{{7919*13}}",), "two fresh probe"),
    # The same expression twice.
    (_jinja_like, ("{{7919*13}}", "{{7919*13}}"), "two different expressions"),
    # A small product could be any number on the page.
    (_jinja_like, ("{{17*19}}", "{{23*29}}"), "five digits"),
    # The page always shows the number.
    (lambda req: httpx.Response(200, text="Order 102947 and 139247"), ("{{7919*13}}", "{{8191*17}}"),
     "control response already contains"),
])
async def test_ssti_rejects_reflection_coincidence_and_single_probes(
    manager, monkeypatch, handler, probes, gap,
):
    verdict = await _ssti(manager, monkeypatch, handler, probes)
    assert verdict.status == "inconclusive" and gap in verdict.proof_gap["reason"]


# --- NoSQL ----------------------------------------------------------------

def _mongo_like(req):
    """Login that passes the username object straight into the query."""
    username = json.loads(req.content or b"{}").get("username")
    if isinstance(username, dict) and "$ne" in username:
        return httpx.Response(200, text='{"ok": true, "user": "admin"}')
    return httpx.Response(401, text='{"ok": false, "error": "invalid credentials"}')


async def _nosql(manager, monkeypatch, handler, order=("t", "f", "t", "f"), extra=None):
    _serve(monkeypatch, handler)
    cand = _candidate(manager, "NoSQL injection in login", "nosql_injection",
                      "https://app.test/api/login")
    marker = "aegis-verify-" + cand.nonce
    token = verification_run.set(VerificationRun("nosql-run", cand.id, 1, cand.nonce))
    true_ids, false_ids = [], []
    try:
        for index, kind in enumerate(order):
            # Password values are redacted in evidence, so inject a non-secret field.
            body = {"username": {("$ne" if kind == "t" else "$eq"): marker}, "pin": "0000"}
            if extra and index == len(order) - 1:
                body.update(extra)
            exchange = await manager._http_exchange(
                "POST", "https://app.test/api/login",
                headers={"Content-Type": "application/json"}, body=json.dumps(body))
            (true_ids if kind == "t" else false_ids).append(exchange["evidence_id"])
        return apply_verdict(
            manager, candidate_id=cand.id, verdict="confirmed",
            evidence="$ne logs in, $eq does not",
            evidence_ids=true_ids + false_ids,
            proof={"kind": "nosql_operator", "true_ids": true_ids, "false_ids": false_ids},
        )
    finally:
        verification_run.reset(token)


@pytest.mark.asyncio
async def test_nosql_confirms_consistent_operator_split(manager, monkeypatch):
    verdict = await _nosql(manager, monkeypatch, _mongo_like)
    assert verdict.status == "confirmed", verdict.proof_gap


@pytest.mark.asyncio
@pytest.mark.parametrize("handler,kwargs,gap", [
    # Operators are stringified, so both get the same rejection.
    (lambda req: httpx.Response(200, text='{"results": []}'), {}, "same response"),
    # The response echoes the operator name; that alone is not a split.
    (lambda req: httpx.Response(200, text="unknown key " + (
        "$ne" if "$ne" in req.content.decode() else "$eq")), {}, "same response"),
    # Grouped rather than interleaved.
    (_mongo_like, {"order": ("t", "t", "f", "f")}, "Interleave"),
    # Something else changed between requests.
    (_mongo_like, {"extra": {"remember": True}}, "identical apart from"),
])
async def test_nosql_rejects_stringified_echoed_and_uncontrolled_probes(
    manager, monkeypatch, handler, kwargs, gap,
):
    verdict = await _nosql(manager, monkeypatch, handler, **kwargs)
    assert verdict.status == "inconclusive" and gap in verdict.proof_gap["reason"]


def test_claim_inference_and_verifier_guidance():
    def infer(title):
        return inferred_vulnerability_class(type("C", (), {"title": title, "description": ""}))

    assert infer("SSTI leading to RCE in profile") == "ssti"
    assert infer("Server-side template injection") == "ssti"
    assert infer("Client-side template injection") == "client_template_injection"
    assert infer("NoSQL injection in login") == "nosql_injection"
    assert infer("SQL injection in search") == "sql_injection"
    from app.services.agent.independent_verify import FindingCandidate
    mission = verifier_mission(FindingCandidate(id="x", title="SSTI in greeting", target="https://app.test/"))
    assert "kind: template_eval" in mission
    mission = verifier_mission(FindingCandidate(id="y", title="NoSQL injection", target="https://app.test/"))
    assert "kind: nosql_operator" in mission
