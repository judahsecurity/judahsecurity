import asyncio
from types import SimpleNamespace

from app.services.agent.evidence_store import (
    VerificationRun,
    evidence_store,
    verification_run,
)
from app.services.agent.oob_callback_workflow import (
    CALLBACK_PLACEHOLDER,
    _inject_callback,
    run_callback_workflow,
)
from app.services.agent.proof_policy import validate_proof


class _Manager:
    async def _http_exchange(self, method, url, headers=None, body=None, **kwargs):
        exchange = {
            "request": {
                "method": method,
                "url": url,
                "headers": headers or {},
                "body": body or "",
            },
            "response": {
                "status": 200,
                "url": url,
                "headers": {},
                "body": "queued",
            },
        }
        artifact_id = evidence_store(self).record(
            "http_exchange",
            exchange,
            target=url,
            hypothesis_id=kwargs.get("hypothesis_id", ""),
            success=True,
        )
        return {**exchange, "evidence_id": artifact_id, "_body_text": "queued"}


def test_custom_oast_workflow_returns_verifier_ready_proof(monkeypatch):
    from app.services import interactsh_service

    manager = _Manager()
    polls = [
        {
            "success": True,
            "session_id": "session-1",
            "payload_domain": "abc123456789.oast.test",
            "interactions": [],
        },
        {
            "success": True,
            "session_id": "session-1",
            "payload_domain": "abc123456789.oast.test",
            "interactions": [
                {"protocol": "dns", "unique_id": "abc123456789"}
            ],
        },
    ]
    stopped = []
    monkeypatch.setattr(
        interactsh_service,
        "register",
        lambda server=None, token=None: {
            "success": True,
            "session_id": "session-1",
            "payload_domain": "abc123456789.oast.test",
            "payload_url": "https://abc123456789.oast.test",
            "reused": False,
        },
    )
    monkeypatch.setattr(interactsh_service, "poll", lambda session_id: polls.pop(0))
    monkeypatch.setattr(
        interactsh_service,
        "stop",
        lambda session_id: stopped.append(session_id) or {"success": True},
    )

    async def no_sleep(_seconds):
        return None

    monkeypatch.setattr(
        "app.services.agent.oob_callback_workflow.asyncio.sleep", no_sleep
    )
    run = VerificationRun("run-1", "candidate-1", 1, "nonce-1")
    token = verification_run.set(run)
    try:
        result = asyncio.run(
            run_callback_workflow(
                manager,
                url="https://app.test/fetch",
                field="resource",
                hypothesis_id="hyp-1",
                poll_interval_seconds=0.25,
            )
        )
    finally:
        verification_run.reset(token)

    assert result["callback_observed"] is True
    assert result["proof"]["kind"] == "oob_callback"
    assert result["poll_attempts"] == 2
    assert stopped == ["session-1"]

    records = evidence_store(manager).records
    register_id, plant_id, first_poll_id, matched_poll_id = result["evidence_ids"]
    assert records[register_id]["kind"] == "oob_register"
    assert records[plant_id]["kind"] == "http_exchange"
    assert "resource=https%3A%2F%2Fabc123456789.oast.test" in records[plant_id][
        "payload"
    ]["request"]["url"]
    assert records[first_poll_id]["success"] is False
    assert records[matched_poll_id]["success"] is True

    candidate = SimpleNamespace(
        title="Blind SSRF callback",
        description="The target issued a DNS callback.",
        nonce="nonce-1",
    )
    ok, why = validate_proof(
        evidence_store(manager), candidate, result["proof"], result["evidence_ids"]
    )
    assert ok, why


def test_raw_callback_injection_requires_placeholder():
    url, headers, body = _inject_callback(
        url="https://app.test/xml",
        payload_url="https://abc123456789.oast.test",
        location="raw",
        field="",
        headers={"Content-Type": "application/xml"},
        body=f'<!ENTITY x SYSTEM "{CALLBACK_PLACEHOLDER}">',
    )
    assert url == "https://app.test/xml"
    assert headers["Content-Type"] == "application/xml"
    assert body == '<!ENTITY x SYSTEM "https://abc123456789.oast.test">'


def test_registration_failure_is_structured(monkeypatch):
    from app.services import interactsh_service

    monkeypatch.setattr(
        interactsh_service,
        "register",
        lambda server=None, token=None: {
            "success": False,
            "error": "interactsh-client not installed",
        },
    )
    result = asyncio.run(
        run_callback_workflow(_Manager(), url="https://app.test/fetch")
    )
    assert result == {
        "success": False,
        "error": "interactsh-client not installed",
        "callback_observed": False,
    }
