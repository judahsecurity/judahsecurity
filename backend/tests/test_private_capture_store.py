"""Captured request values survive a restart without entering agent evidence."""

import json

import pytest

from app.services.agent.assessment_scope import register_scope
from app.services.agent.evidence_store import (
    VerificationRun, evidence_store, purge_session_evidence, verification_run,
)
from app.services.agent.scoped_assessment.browser_traffic import package_exchange
from app.services.agent.private_capture_store import persist_capture
from app.services.agent.tools import (
    ASMToolsManager, current_organization_id, current_session_id,
)


@pytest.mark.asyncio
async def test_capture_recovery_is_encrypted_and_scoped(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_EVIDENCE_DIR", str(tmp_path))
    org = current_organization_id.set(4747)
    session = current_session_id.set("capture-recovery")
    try:
        manager = ASMToolsManager()
        manager._fallback_target = "https://app.example.test"
        register_scope(manager, "app.example.test")
        public, private = package_exchange(
            url="https://app.example.test/api/search?term=private-value",
            expected_origin="https://app.example.test", action_ref="click-search",
            method="GET", resource_type="fetch", status=200,
            content_type="application/json", request_body=b"",
            response_body=b'{"secret":"private-response"}',
        )

        async def fake_browser(**kwargs):
            kwargs["traffic_exchanges"].append({"public": public, "private": private})
            return ({"operation": "map", "final_origin": "https://app.example.test",
                     "final_path": "/", "status": 200, "requests": []}, None)

        monkeypatch.setattr(
            "app.services.agent.scoped_assessment_tools.browser.check_browser", fake_browser,
        )
        result = json.loads(await manager.scoped_browser_assessment(
            "map", "https://app.example.test/"))
        artifact_id = result["traffic"][0]["artifact_id"]
        namespace = evidence_store(manager).namespace
        encrypted = tmp_path / namespace / f"{artifact_id}.capture"
        assert encrypted.exists()
        assert encrypted.stat().st_mode & 0o777 == 0o600
        assert b"private-value" not in encrypted.read_bytes()
        assert b"private-response" not in encrypted.read_bytes()
        assert "private-value" not in json.dumps(evidence_store(manager).read(artifact_id))

        restarted = ASMToolsManager()
        rows = json.loads(await restarted.list_scoped_browser_exchanges())["exchanges"]
        assert rows[0]["artifact_id"] == artifact_id
        assert "private-value" not in json.dumps(rows)
        assert restarted._scoped_exchange(artifact_id, "anonymous") == private
        with pytest.raises(ValueError, match="identity"):
            restarted._scoped_exchange(artifact_id, "other-user")

        other_org = current_organization_id.set(4748)
        try:
            with pytest.raises(ValueError, match="Unknown browser exchange"):
                ASMToolsManager()._scoped_exchange(artifact_id, "anonymous")
        finally:
            current_organization_id.reset(other_org)

        other_session = current_session_id.set("other-assessment")
        try:
            with pytest.raises(ValueError, match="Unknown browser exchange"):
                ASMToolsManager()._scoped_exchange(artifact_id, "anonymous")
        finally:
            current_session_id.reset(other_session)

        tampered = bytearray(encrypted.read_bytes())
        tampered[-1] ^= 1
        encrypted.write_bytes(tampered)
        with pytest.raises(ValueError, match="Unknown browser exchange"):
            ASMToolsManager()._scoped_exchange(artifact_id, "anonymous")

        purge_session_evidence(4747, "capture-recovery")
        assert not encrypted.exists()
        with pytest.raises(ValueError, match="Unknown browser exchange"):
            ASMToolsManager()._scoped_exchange(artifact_id, "anonymous")
    finally:
        current_session_id.reset(session)
        current_organization_id.reset(org)


@pytest.mark.asyncio
async def test_recovered_capture_still_requires_fresh_verifier_run(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_EVIDENCE_DIR", str(tmp_path))
    org = current_organization_id.set(4747)
    session = current_session_id.set("capture-verifier")
    run = VerificationRun("run-1", "candidate-1", 1, "nonce-1")
    token = verification_run.set(run)
    try:
        manager = ASMToolsManager()
        manager._fallback_target = "https://app.example.test"
        register_scope(manager, "app.example.test")
        public, private = package_exchange(
            url="https://app.example.test/search?q=seed",
            expected_origin="https://app.example.test", action_ref="search",
            method="GET", resource_type="document", status=200,
            content_type="text/html", request_body=b"", response_body=b"result",
        )

        async def fake_browser(**kwargs):
            kwargs["traffic_exchanges"].append({"public": public, "private": private})
            return ({"operation": "map", "final_origin": "https://app.example.test",
                     "final_path": "/", "status": 200, "requests": []}, None)

        monkeypatch.setattr(
            "app.services.agent.scoped_assessment_tools.browser.check_browser", fake_browser,
        )
        result = json.loads(await manager.scoped_browser_assessment(
            "map", "https://app.example.test/"))
        artifact_id = result["traffic"][0]["artifact_id"]
        restarted = ASMToolsManager()
        assert restarted._scoped_exchange(artifact_id, "anonymous") == private
        different = verification_run.set(VerificationRun("run-2", "candidate-1", 1, "nonce-2"))
        try:
            with pytest.raises(ValueError, match="fresh for this verifier run"):
                restarted._scoped_exchange(artifact_id, "anonymous")
        finally:
            verification_run.reset(different)
    finally:
        verification_run.reset(token)
        current_session_id.reset(session)
        current_organization_id.reset(org)


@pytest.mark.asyncio
async def test_capture_limit_survives_process_recovery(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_EVIDENCE_DIR", str(tmp_path))
    org = current_organization_id.set(4747)
    session = current_session_id.set("capture-bound")
    try:
        manager = ASMToolsManager()
        store = evidence_store(manager)
        ids = []
        for _ in range(120):
            artifact_id = store.record(
                "scoped_browser_exchange", {"path": "/search", "method": "GET"},
                target="https://app.example.test/search", identity="anonymous",
            )
            persist_capture(store.namespace, artifact_id, {
                "identity": "anonymous", "verifier_run_id": None, "private": b"{}",
            })
            ids.append(artifact_id)

        restarted = ASMToolsManager()
        restarted._fallback_target = "https://app.example.test"
        register_scope(restarted, "app.example.test")
        public, private = package_exchange(
            url="https://app.example.test/search?q=seed",
            expected_origin="https://app.example.test", action_ref="search",
            method="GET", resource_type="document", status=200,
            content_type="text/html", request_body=b"", response_body=b"result",
        )

        async def fake_browser(**kwargs):
            kwargs["traffic_exchanges"].append({"public": public, "private": private})
            return ({"operation": "map", "final_origin": "https://app.example.test",
                     "final_path": "/", "status": 200, "requests": []}, None)

        monkeypatch.setattr(
            "app.services.agent.scoped_assessment_tools.browser.check_browser", fake_browser,
        )
        result = json.loads(await restarted.scoped_browser_assessment(
            "map", "https://app.example.test/"))
        assert result["traffic_store_dropped"] == 0
        assert not (tmp_path / store.namespace / f"{ids[0]}.capture").exists()
        assert len(list((tmp_path / store.namespace).glob("*.capture"))) == 120
        assert len(json.loads(await restarted.list_scoped_browser_exchanges())["exchanges"]) == 40
    finally:
        current_session_id.reset(session)
        current_organization_id.reset(org)
