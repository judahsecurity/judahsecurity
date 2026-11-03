"""scoped_owner_only_write is operator-gated and runs the real write recipe."""

import hashlib
import json

import pytest

from app.services.agent.assessment_scope import register_scope
from app.services.agent.assessment_sessions import identity_registry
from app.services.agent.scoped_assessment.browser_traffic import package_exchange
from app.services.agent.tools import ASMToolsManager

TARGET = "https://app.example.test"


class FakeApp:
    """One reflected field, mutated by the real plan_observed_write body."""

    def __init__(self, other_may_write=True):
        self.value = "original"
        self.other_may_write = other_may_write

    def send(self, url, method, mime, body, *, allowed_origins, storage_state, replay_headers=None):
        canary = json.loads(body)["note"]
        # The owner's state carries the owner cookie; anything else is "other".
        is_owner = bool(storage_state and any(
            c.get("name") == "sid_owner" for c in storage_state.get("cookies", [])))
        if not is_owner and not self.other_may_write:
            return {"status": 403, "redirected": False}
        self.value = canary
        return {"status": 200, "redirected": False}

    def observe(self, url, allowed_origins, storage_state=None, markers=None):
        markers = markers or []
        return {
            "operation": "http_get", "status": 200, "content_type": "application/json",
            "body_sha256": hashlib.sha256(self.value.encode()).hexdigest(),
            "truncated": False, "redirected": False,
            "markers": {m: (m == self.value) for m in markers},
        }


def _manager():
    manager = ASMToolsManager()
    manager._fallback_target = TARGET
    register_scope(manager, "app.example.test")
    reg = identity_registry(manager)
    # Distinguishable cookies so the fake app can tell the identities apart.
    reg.register("owner", TARGET, cookies=[
        {"name": "sid_owner", "value": "1", "domain": "app.example.test", "path": "/"}])
    reg.register("other", TARGET, cookies=[
        {"name": "sid_other", "value": "1", "domain": "app.example.test", "path": "/"}])
    public, private = package_exchange(
        url=TARGET + "/api/orders/42", expected_origin=TARGET, action_ref="ui-1",
        method="PUT", resource_type="fetch", status=200,
        content_type="application/json", request_content_type="application/json",
        request_body=b'{"note":"hello"}', response_body=b"{}",
    )
    manager._scoped_browser_exchanges = {
        "wcap": {"identity": "owner", "private": private, "public": public}}
    return manager


POLICY = {
    "body_replay_paths": ["/api/orders/42"],
    "owner_only_write_resources": [{
        "target": TARGET + "/api/orders/42",
        "readback_target": TARGET + "/api/orders/42/view",
        "method": "PUT", "field": "/note",
        "owner_identity": "owner", "other_identity": "other",
    }],
}


def _patch(monkeypatch, app):
    monkeypatch.setattr(
        "app.services.agent.scoped_assessment_tools.body_probe.send_observed_write", app.send)
    monkeypatch.setattr(
        "app.services.agent.scoped_assessment_tools.http_observe.observe_get", app.observe)


@pytest.mark.asyncio
async def test_requires_operator_policy_before_running(monkeypatch):
    manager = _manager()
    _patch(monkeypatch, FakeApp())
    with pytest.raises(ValueError, match="not declared|not approved"):
        await manager.scoped_owner_only_write("wcap", "owner")


@pytest.mark.asyncio
async def test_vulnerable_app_confirms_and_records_evidence(monkeypatch):
    manager = _manager()
    manager.set_scoped_assessment_policy(POLICY)
    _patch(monkeypatch, FakeApp(other_may_write=True))
    result = json.loads(await manager.scoped_owner_only_write("wcap", "owner"))
    assert result["proof_confirmed"] is True
    assert result["finding"] is False
    assert result["method"] == "PUT" and result["field"] == "/note"
    assert result["owner_identity"] == "owner" and result["other_identity"] == "other"
    assert result["cleanup_confirmed"] is True
    assert result["source_artifact_id"] == "wcap"
    assert result.get("evidence_id")


@pytest.mark.asyncio
async def test_secure_app_does_not_confirm(monkeypatch):
    manager = _manager()
    manager.set_scoped_assessment_policy(POLICY)
    _patch(monkeypatch, FakeApp(other_may_write=False))
    result = json.loads(await manager.scoped_owner_only_write("wcap", "owner"))
    assert result["proof_confirmed"] is False


def test_rejects_unapproved_write_path():
    manager = _manager()
    # A write resource whose path is not among the approved write paths is
    # rejected when the operator policy is installed, before any tool runs.
    with pytest.raises(ValueError, match="approved write path"):
        manager.set_scoped_assessment_policy({**POLICY, "body_replay_paths": ["/something-else"]})
